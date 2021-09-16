import threading
from datetime import datetime
from base64 import urlsafe_b64encode, b64decode
import sys
import os
import re
import yaml, json
from contextlib import contextmanager
import subprocess
from app import current_state, globals

# GLOBAL VARS

# flag DEBUG=True if '--debug' was passed as 1st cli argument
#DEBUG = True if len(sys.argv) > 1 and sys.argv[1] == '--debug' else False
INVENTORY_PATH = os.environ.get('INVENTORY_PATH') # shell var should be defined in k8s deployment
WORKING_DIR = "/tmp/certs" # shell var should be defined in k8s deployment
POLL_TIME_SEC = int(os.environ.get('POLL_TIME_SEC')) if os.environ.get('POLL_TIME_SEC') else 600 # time = seconds, default 600 sec
RETRY_LIMIT = int(os.environ.get('RETRY_LIMIT')) if os.environ.get('RETRY_LIMIT') else 3 # default 3 retries

# global vars
# wildcard domain for clusters
WILDCARD_DOMAIN = "" if not os.environ.get('WILDCARD_DOMAIN') else os.environ.get('WILDCARD_DOMAIN')

old_print = print

def timestamped_print(*args, **kwargs):
  old_print(datetime.now(), *args, **kwargs)

print = timestamped_print

@contextmanager
def run_subprocess(cmd, **kwargs):

    # spawn new process
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True, shell=True, **kwargs)
    # Context breakdown, and yield control to calling function
    yield proc

    # when calling function exits, resume run_process context:

    # To check if a process has terminated, call subprocess.Popen.poll() with subprocess.Popen as the process.
    # If a None value is returned, it indicates that the process hasn’t terminated yet.
    # CLEANUP: if calling function has exited, then terminate current process to prevent zombie attacks :P
    if proc.poll() is not None:
        proc.terminate()

    # emit warning message if process terminated with an unsuccessful return code
    if proc.returncode != 0:
        print("WARN: Process \'{}\' terminated with code {}".format(cmd[0], proc.returncode) + "\n")
    err = proc.stderr.read()
    if err:
        print("WARN: Received error output: {}".format(err))

# Read in cluster list from configuration file, parse to create list and remove hidden characters such as new line



def yaml_file_to_dict(path) -> dict:
    """
    Load file defined in 'path' and parse as yaml.

    :param path: The full path to the config file formatted as yaml
    :type: str

    :return inventory: the dictionary representation of the yaml file provided in path
    :type: dict
    """
    # validate that path is in fact a string, and fail with AssertionError if it is not
    assert isinstance(path, str), "func: yaml_file_to_dict(), param: path, path must be of type str()"
    # validate yaml file extension
    assert (path.endswith('.yaml') or path.endswith('.yml')), "func: yaml_file_to_dict(), param: path, path must be a yaml file with .yaml or .yml file extension!"

    # load config from 'path' variable
    with open(path, 'r') as f:
        # safe_load() is more secure; the parser won't evaluate code snippets inside yaml
        # safe_load() reads the file stream and converts yaml formatted text to a python dict() object
        d = yaml.safe_load(f)

    print("Clusters in Configuration: ")
    print(", ".join(d['clusters'].keys())) # dict.keys() returns an iterable list of key names
    return d

def deploy_cert(cert=None, key=None, from_master=False, cluster_name=None, cluster_token=None):
    """
    Checks for any existing sealed secret certs inside a specific cluster

    :param cert: The raw TLS certificate, which will be included in the k8s secret
    :type: str

    :param key: The raw pem-formatted key associated with cert, which will be included in the k8s secret
    :type: str

    :param from_master: If True, deploy_cert() will attempt to create a k8s secret using the master_cert and master_key stored in-memory
    :type: bool

    :param cluster_name: must correspond to one of the name aliases defined in the inventory file
    :type: str

    :param cluster_token: must be a valid kubenetes API token. Token must provide read-write access to secrets within the destination cluster and namespace
    :type: str
    """
    
    assert not (from_master and (cert or key)), "func: deploy_cert(), keyword argument 'from_master' cannot be used with arguments 'cert' or 'key'."
    
    if from_master:
        assert current_state.get('master_cert') and current_state.get('master_key'), "func: deploy_cert(), Missing Dependency - master_cert or master_key not set."

    if not from_master:
        assert cert and key, "func: deploy_cert(), params: cert, key - Both a plaintext, PEM-formatted certificate and unencrypted key must be provided."
        assert isinstance(cert, str) and isinstance(key, str), "func: deploy_cert(), params: cert, key - 'cert' and 'key' parameters must be of type str()"
        
    # cluster_token is the auth token stored inside a shell variable
    # variable is exported by running the secrets_export.sh script
    # e.g. SAT_OCP_OPS = myclustertokenhere
    if not cluster_token:
        cluster_token = os.environ.get( cluster_name.replace('-','_').upper() )
    
    tls_signer_secret = yaml_file_to_dict('k8s_templates/secret_tls.yaml')
    tls_signer_secret['metadata']['name'] = "sealing-secret-" + create_uuid()

    # cert must be in standard PEM format
    tls_signer_secret['data']['tls.crt'] = current_state['master_cert'] if from_master else cert

    # key must be in unencrypted PEM format
    tls_signer_secret['data']['tls.key'] = current_state['master_key']  if from_master else key

    # set custom labels
    labels = { "sealedsecrets.bitnami.com/sealed-secrets-key": "active"
            }

    # add labels to template
    tls_signer_secret['metadata']['labels'].update(labels)

    # when 'cmd' executes, it will:
    # create a k8s secret using the the k8s_secret_tls_template
    # inside the namespace 'sealed-secrets'
    # ignores mutual TLS handshake (one-way SSL only... we're lazy)
    #
    # and requires:
    # 1. destination api server
    # 2. auth token
    
    # setup process
    deployCmd = " ".join([ "oc create secret",
                         cert,
                         "--token={}".format(cluster_token),
                         "--server https://api.{}{}:6443/".format(cluster_name, WILDCARD_DOMAIN),
                         "--insecure-skip-tls-verify",
                         "--namespace sealed-secrets",
                         "-f -"
                       ])

    print("Distributing Cert to " + cluster_name)

    with run_subprocess(deployCmd, stdin=subprocess.PIPE) as proc:
        # covert tls_signer_secret to yaml-formatted text and send to cli command stdin
        # communicate() returns a 2-tuple of bytes objects, 0 = stdin, 1 = stderr
        # Note: in python 3.4+, input to stdin must be encoded as bytes
        output = proc.communicate( input=yaml.dumps(tls_signer_secret).encode() )[0]
        returncode = proc.returncode

        # stderr will be logged by the run_subprocess() context manager
        
    return None
        

def delete_ss_pod(cluster_name=None, cluster_token=None):

    delCmd = " ".join([ "oc delete pod",
                         "-l name=sealed-secrets-controller",
                         "--token={}".format(cluster_token),
                         "--server https://api.{}{}:6443/".format(cluster_name, WILDCARD_DOMAIN),
                         "--insecure-skip-tls-verify",
                         "--namespace sealed-secrets"
                       ])

    with run_subprocess(delCmd) as proc:
        returncode = proc.returncode

    return None


def is_valid_age(age) -> bool:
    """
    :param age: A string which should match the pattern '[0-9][0-9][0-9][ydms]'
    :type: str

    :return bool: True/False based on evaluation of age parameter
    """

    # age must be a string at this time
    assert isinstance(age, str), "func: is_valid_age(), param: age, age must be of type str()"

    # age is in the format of NNNI, where I is the interval and N is the number
    # e.g. 17s = 17 seconds, 3m = 3 minutes, 50d = 50 days, 1y = 1 year
    # X seconds or X minutes is too new, therefore always valid
    if age.endswith('s') or age.endswith('m'):
        return True
    # X years > 100 days and is too old, therefore always invalid
    elif age.endswith('y'):
        return False
    elif age.endswith('d'):
        # age is a string with format 'NNNI'
        # age[:-1] gives the substring 'NNN'
        # if age[:-1] converts to a number equal to or greater than 100, then age is invalid
        if int(age[:-1]) >= 100:
            return False
        else:
            return True
    else:
        # returns false generally, if str doesn't match the expected 'NNNI' format
        print("WARN: func: is_valid_age(), param: age, 'age' does not match any expected format. 'age' is assumed to be invalid")
        return False

def get_secret_age(secret_name=None, cluster_name=None, cluster_token=None) -> bool:
    """
    Check if the provided cert is more than 100days old

    :param secret_name: name of the secret which will be examined
    :type: str

    :param cluster_name: must correspond to one of the name aliases defined in the inventory file
    :type: str

    :param cluster_token: must be a valid kubenetes API token. Token must provide read-write access to secrets within the destination cluster and namespace
    :type: str

    :return secret_age: the age of the secret resource which matches the provided parameters. 'age' is a string which should match the pattern '[0-9][0-9][0-9][ydms]'
    :type: str
    """

    print("Checking age of {}".format(secret_name))


    # cluster_token is the auth token stored inside a shell variable
    # variable is exported by running the secrets_export.sh script
    # e.g. SAT_OCP_OPS = myclustertokenhere
    if (cluster_token is None):
        cluster_token = os.environ.get( cluster_name.replace('-','_').upper() )

    # when 'cmd' executes, it will:
    # retrieve the name of all k8s secrets
    # from the namespace 'sealed-secrets'
    # ignores mutual TLS handshake (one-way SSL only... we're lazy)
    #
    # then:
    # filters the tab-delimited output by 'secret_name' via grep
    # then:
    # if awk matches the regex pattern against the entry in 4th column (age), prints 1st column (secret name) to stdout
    # otherwise print empty string ''
    #
    # and requires:
    # 1. destination api server
    # 2. auth token

    cmd = " ".join(["oc get secrets",
                     "-l masked-maestro/generated=true",
                     "--namespace sealed-secrets",
                     "--insecure-skip-tls-verify",
                     "--server https://api.{}{}:6443/".format(cluster_name, WiLDCARD_DOMAIN),
                     "--token={}".format(cluster_token),
                     "| grep {} ".format(secret_name),
                     "| awk \'{print $4}\'"
                   ])
    #                         "| awk \'match($4,/1[0-9][0-9]+d/) {print $1}\'"
    #                   ])
    print("Checking age of the secret '{}' containing the certificate with command:\n{}".format(secret_name, cmd))

    # spawn process to run oc command, and send output to stdout
    with run_subprocess(cmd) as proc:
    # read command output from stdout, returns str()
        secret_age = proc.stdout.read()

    return secret_age

def fetch_cert_key_from_secret(secret_name, cluster_name=None, cluster_token=None) -> str:
    """
    Checks for any existing sealed secret certs inside a specific cluster

    :param cluster_name: must correspond to one of the name aliases defined in the inventory file
    :type: str

    :param cluster_token: must be a valid kubenetes API token. Token must provide read-write access to secrets within the destination cluster and namespace
    :type: str

    :return cert_key: Tuple contains two strings (1) the plaintext certificate and (2) the plaintext pem-formatted key retrieved from the provided secret
    :type: tuple(str, str)
    """
    if not isinstance(secret_name, str):
        secret_name = str(secret_name) # enforce str() typing

    # cluster_token is the auth token stored inside a shell variable
    # variable is exported by running the secrets_export.sh script
    # e.g. DC_OCP_OPS = myclustertokenhere
    if not cluster_token:
        cluster_token = os.environ.get( cluster_name.replace('-','_').upper() )

    # when 'cmd' executes, it will:
    # retrieve the name of a specific k8s secret
    # from the namespace 'sealed-secrets'
    # ignores mutual TLS handshake (one-way SSL only... we're lazy)
    #
    # and requires:
    # 1. destination api server
    # 2. auth token
    certCmd = " ".join([ "oc get secret",
                         secret_name,
                         "-o json",
                         "--token={}".format(cluster_token),
                         "--server https://api.{}{}:6443/".format(cluster_name, WILDCARD_DOMAIN),
                         "--insecure-skip-tls-verify",
                         "--namespace sealed-secrets"
                        #  "| jq -r \'.data.\"tls.crt\"\'",
                        #  "| base64 -d"
                       ])

    # spawn process to run oc command, and send output to stdout
    with run_subprocess(certCmd) as proc:
        # read command output from stdout, returns str()
        secret = json.loads( proc.stdout.read() )

    #TODO: Determine if schema validation is needed:
    #assert secret.get('type') == 'kubernetes.io/tls', "func: fetch_cert_key_from_secret - field 'type' in secret must be 'kubernetes.io/tls'"

    cert_key = ( b64decode( secret['data']['tls.crt'] ), b64decode( secret['data']['tls.key'] ) )
    return cert_key

def create_new_cert():
    """
    Calls openssl tool to create a new certificate and key

    :returns (cert, key): Tuple containing the plaintext x509 certificate and the plaintext pem-formatted key
    
    :type: tuple(str, str)
    """

    # test command:
    # openssl req -x509 -nodes -newkey rsa:4096 -keyout /dev/stdout -out /dev/stdout  -subj "/CN=sealed-secret/O=sealed-secret"
    genCertCmd = " ".join(["openssl req",
                           "-x509",
                           "-nodes",
                           "-newkey rsa:4096",
                           "-keyout /dev/stdout", #.format(output_keypath),
                           "-out /dev/stdout", #.format(output_certpath),
                           "-subj \"/CN=sealed-secret/O=sealed-secret\""
                         ])
    # spawn process to run oc command, and send output to stdout
    with run_subprocess(genCertCmd) as proc:
        # read command output from stdout, returns str()
        raw_output = proc.stdout.read()

    # may receive bytes or str depending on host env
    if isinstance(raw_output, bytes):
        raw_output = raw_output.decode('utf-8')

    # create list containg line-by-line of raw_output
    lines = raw_output.split("\n")

    #print(lines)
    priv_key_l = []
    cert_l = []

    # GOAL: scan raw_output line-by-line and create cert and priv_key from input text
    # iterate through raw_output
    # if we match a string prefix to the line,
    # then pop the current line and add to associated list
    flag = False
    cursor = 0
    for i, line in enumerate(lines):
        if line == '-----BEGIN PRIVATE KEY-----':
            priv_key_l.append(line)
            flag = True
        elif line == '-----END PRIVATE KEY-----':
            priv_key_l.append(line)
            flag = False
            # set line cursor to skip ahead alrady visited lines in next loop
            cursor = i
            # terminate loop early to set correct cursor value
            break
        elif flag:
            priv_key_l.append(line)

    # continue from cursor
    for line in lines[cursor:]:
        if line == '-----BEGIN CERTIFICATE-----':
            cert_l.append(line)
            flag = True
        elif line == '-----END CERTIFICATE-----':
            cert_l.append(line)
            flag = False
        elif flag:
            cert_l.append(line)

    # combine lists into single string for priv_key and cert
    priv_key = "\n".join(priv_key_l)
    cert = "\n".join(cert_l)

    return cert, priv_key


def get_cluster_creds(current_state, env=None, cluster_name=None) -> dict:
    """
    """
    # assert current_state
    assert cluster_name and isinstance(cluster_name, str), "func: get_cluster_creds, param: cluster_name -- 'cluster_name' must be a non-empty string"

    creds = dict()

    # apiserver_token is the auth token stored inside a shell variable
    # shell variable corresponds to the cluster name
    # variable is exported by running the secrets_export.sh script
    # e.g. if cluster = my-dev, then a shell variable exists where MY_DEV = myclustertokenhere
    apiserver_token = os.environ.get( cluster_name.replace('-','_').upper() )

    #TODO: add error handling
    creds['cluster_name'] = cluster_name
    creds['apiserver_url'] = current_state[env]['clusters'][cluster_name]['apiserver_url']
    creds['apiserver_token'] = apiserver_token

    return creds

def get_existing_certs(cluster_name=None, apiserver_url=None, apiserver_token=None) -> list:
    """
    Checks for any existing sealed secret certs inside a specific cluster

    :param cluster_name: must correspond to one of the name aliases defined in the inventory file
    :type: str

    :param cluster_token: must be a valid kubenetes API token. Token must provide read-write access to secrets within the destination cluster and namespace
    :type: str

    :return existing_certs: TODO
    :type: list[str]
    """

    assert cluster_name and isinstance(cluster_name, str), "func: get_existing_certs, param: cluster_name -- 'cluster_name' must be a non-empty string"

    print("Checking for certs in " + cluster_name)

    # when 'cmd' executes, it will:
    # retrieve the name of all k8s secrets
    # with the label 'masked-maestro/generated=true'
    # from the namespace 'sealed-secrets'
    # sorts output by oldest timestamp first
    # ignores mutual TLS handshake (one-way SSL only... we're lazy)
    #
    # and requires:
    # 1. destination api server
    # 2. auth token
    cmd = " ".join(["oc get secrets",
                    "--sort-by=.metadata.creationTimestamp",
                    '-o jsonpath=\'{.items[:].metadata.name}\'',
                    "-l masked-maestro/generated=true",
                    "--namespace sealed-secrets",
                    "--insecure-skip-tls-verify",
                    "--server {}".format(apiserver_url),
                    " --token={}".format(apiserver_token)
              ])

    print("Checking existing certs with command:\n" + cmd)

    existing_certs = []
    # spawn process to run oc command, and send output to stdout
    with run_subprocess(cmd) as proc:
        # read command output from stdout, returns str()
        # output should be a series of space-delimited secret names
        # .split() returns a list()
        existing_certs = proc.stdout.read().split()


    return existing_certs


def config_to_state(config=None) -> dict:
    """
    Parses dict() of inventory config, and creates an index of environment->cluster data mappings

    :return initial_env_state: The mapping of environment names to cluster names and config. Represents an indexing of 'shared_env' fields from the yaml inventory file.
    :type: dict
    """

    print('Building initial state from inventory...')
    # if config param empty or None/null, fetch and assign inventory data automatically
    if not config:
        config = yaml_file_to_dict(INVENTORY_PATH)

    # validation of config param
    assert isinstance(config, dict), "func: gen_cluster_map(), param: config, variable 'config' must be of type dict()."
    assert config.get('clusters'), "func: gen_cluster_map(), param: config, unable to assign value to variable 'config'. Provided dict() has no key named 'clusters'."
    # ignore other top-level config, and only use the key-value tree nest inside the top-level 'clusters' key
    clusters = config.get('clusters').keys()

    # acceptable list of env names:
    sharedEnvs = ['dev','qa','cap','psp','prod']

    # initialize empty to dict() for index of envs
    initial_env_state = {}

    for cluster in clusters:
        # if cluster has active=true in yaml, and shared_env=$env is valid, begin processing
        if config['clusters'][cluster].get('active') is True and config['clusters'][cluster].get('shared_env'):
            # emit error if the provided env is not correct/acceptable
            assert config['clusters'][cluster]['shared_env'] in sharedEnvs, "ERROR: @ file {inventory}, key clusters.{cluster}.shared_env does not have expected value. Must be one of {envs}".format(inventory=INVENTORY_PATH, cluster=cluster, envs=", ".join(sharedEnvs))

            # edge case:
            # initial_env_state does not contain a key matching the value of config[cluster]['shared_env'], e.g. 'dev' or 'qa'
            # therefore, we populate a new key-value tree into initial_env_state  e.g. { 'dev': { 'clusters' : { 'sat-ocp-dev': dict() } } }
            if not initial_env_state.get( config['clusters'][cluster].get('shared_env') ):
                initial_env_state.update({ config['clusters'][cluster].get('shared_env') : { 'clusters': {cluster: dict() } } })
                # Note: the dict() stored at initial_env_state['dev']['clusters']['sat-ocp-dev'] is empty and will be populated later in the code

            # general case:
            # existing key path initial_env_state[env]['clusters'] contains a dict(), so we add a new entry; e.g. { 'sat-ocp-dev': dict() }
            else:
                initial_env_state[ config['clusters'][cluster].get('shared_env') ]['clusters'].update( {cluster: dict() } )

            # populate the apiserver_url field for the current cluster using the inventory file
            assert config['clusters'][cluster].get('apiserver_url'), "apiserver_url field is missing"
            initial_env_state[ config['clusters'][cluster].get('shared_env') ]['clusters'][cluster]['apiserver_url'] = config['clusters'][cluster].get('apiserver_url')

    return initial_env_state

def create_uuid() -> str:
    """
    generates and returns a new, 6-character UUID 

    :return UUID: string containing 6 random alphanumeric characters
    :type: str
    """
    uuidTmp = urlsafe_b64encode(os.urandom(6)).decode('utf-8').lower()
    # enforce alphanumeric chars in UUID: strip any character that does not occur in the set [A-Za-z0-9]
    uuid = re.sub('[^A-Za-z0-9]+', '', uuidTmp)
    
    return uuid

def set_defaults_in_state(state):
    print("setting defaults in current state...")
    ####################################################
    # sample structure of 'current_state':
    # {
    #  'dev':
    #    {
    #     'clusters':
    #       {
    #        'dev1':
    #          {
    #           'existing_cert': str(), # default = None, should be str()
    #           'valid_age': bool() # default = False ... may need default = None???
    #           'matches_master': bool() # default = False
    #           'apiserver_url': str() # default = None, should be str()
    #           ...
    #          },
    #        'sandbox': { ... }
    #       },
    #     'master_cert': str(), # raw cert contents
    #     'master_key': str(), # raw key contents 
    #     'all_certs_exist': bool(),
    #     'all_certs_valid': bool(),
    #     'all_certs_match': bool(),
    #     'ready': bool(),
    #     ...
    #    },
    #  'qa': { ... },
    #  'cap': { ... }
    # }
    ####################################################
    #
    # sample structure of globals:
    # {
    #  'wildcard_domain': ".sample.com",
    #  ...
    # }
    #
    globals['wildcard_domain'] = WILDCARD_DOMAIN if WILDCARD_DOMAIN else None

    #Initialize all envs into a 'not ready' state
    for env in state:
        if not state[env].get('ready'):
            state[env]['ready'] = False
        
        if not state[env].get('all_certs_exist'):
            state[env]['all_certs_exist'] = False    
        
        if not state[env].get('all_certs_valid'):
            state[env]['all_certs_valid'] = False
        
        if not state[env].get('all_certs_match'):
            state[env]['all_certs_match'] = False
        
        if not state[env].get('master_cert'):
            state[env]['master_cert'] = None
        
        if not state[env].get('master_key'):
            state[env]['master_key'] = None
        
        for cluster in state[env]['clusters']:
            if not state[env]['clusters'][cluster].get('existing_cert'):
                state[env]['clusters'][cluster]['existing_cert'] = None

            if not state[env]['clusters'][cluster].get('valid_age'):
                state[env]['clusters'][cluster]['valid_age'] = False

            if not state[env]['clusters'][cluster].get('matches_master'):
                state[env]['clusters'][cluster]['matches_master'] = False            

            if not state[env]['clusters'][cluster].get('apiserver_url'):
                state[env]['clusters'][cluster]['apiserver_url'] = None
    
    return state


def enforce_desired_state(current_state):

    # Use while loop later to constantly update the in-memory state of the environments
    #while not current_state[env]['ready']:

    for env in current_state:

        ######## (1) Represent state of cluster certs in-memory for current env  #######
        # check state of clusters and certs; push state info into current_state{}
        for cluster in current_state[env]['clusters']:
            
            creds = get_cluster_creds(current_state, env=env, cluster_name=cluster)
            print("Retrieving existing cluster certs, if any...")
            cluster_certs = get_existing_certs(cluster_name=cluster, apiserver_url=creds['apiserver_url'], apiserver_token=creds['apiserver_token']) # returns list[]
            
            print("Determining state of clusters and certs for current env. env={}".format(env))
            # outofsync if cert is not deployed
            if not cluster_certs:
                # case) no cert exists, therefore cert is also invalid
                current_state[env]['clusters'][cluster]['existing_cert'] = None
                current_state[env]['clusters'][cluster]['valid_age'] = False

            else:
                # cert exists, therefore assign newest cert from list (index 0) to 'existing_cert'
                current_state[env]['clusters'][cluster]['existing_cert'] = cluster_certs[0]

                # check validity of cert age, and assign the result
                if is_valid_age( get_secret_age( cluster_certs[0], cluster_name=cluster ) ):
                    print("Certs are still valid, not greater than 100 days old. Flag to ensure consistency then pull into container.")
                    current_state[env]['clusters'][cluster]['valid_age'] = True
                else:
                    # is_valid_age() returned False, so assign False
                    current_state[env]['clusters'][cluster]['valid_age'] = False

        ######## (2) Set state of master_cert in-memory for current env  #######
        # given current env, verify master_cert and master_key is populated inside current_state[env] 
        if not current_state[env]['master_cert'] or not current_state[env]['master_key']:

            print("Master Cert or Key not set, attempting to re-use existing from clusters in current env. env={}".format(env))

            # recursively attempt to fetch a valid cert from one of the current cluster states in current_state{}
            for cluster in current_state[env]['clusters']:
                # 'existing_cert' contains the name of the secret which contains the certificate and key
                secret_name = current_state[env]['clusters'][cluster]['existing_cert']
                valid = current_state[env]['clusters'][cluster]['valid_age']
                if current_state[env]['clusters'][cluster]['existing_cert'] is not None and valid:
                    master_cert, master_key = fetch_cert_key_from_secret(secret_name, cluster_name=cluster)
                    current_state[env]['master_cert'] = master_cert
                    current_state[env]['master_key'] = master_key
                    break
                else:
                    continue

            # if no valid cert is retrieved, generate a new one
            try:
                # master_cert and master_key are created as a pair... if one exists, but not the other, we will overwrite both with a new pair
                current_state[env]['master_cert'], current_state[env]['master_key'] = create_new_cert()
                
                print('master_key: {}'.format(current_state[env]['master_key']))
                # validate master_cert and master_key MUST NOT be empty strings or None
                assert current_state[env]['master_key'] is True, "Missing Value: Empty string or null value @ key = current_state[{}]['master_key']".format(env)
                assert current_state[env]['master_cert'] is True, "Missing Value: Empty string or null value @ key = current_state[{}]['master_cert']".format(env)
            except AssertionError as err:
                # if either 'master_cert' or 'master_key' is still None, program breaks~
                raise err
            except:
                # Not sure how we got here... time to panic!
                raise
        else:
            # cert and key must exist, so...
            print("Master Cert and Key found for env. env={}".format(env))

        ######## (2.1) Compare cluster certs to master_cert for current env ########
        for cluster in current_state[env]['clusters']:
            secret_name = current_state[env]['clusters'][cluster]['existing_cert']
            cluster_cert = fetch_cert_key_from_secret( secret_name, cluster_name=cluster )[0]
            
            if cluster_cert == current_state[env]['master_cert']:
                current_state[env]['clusters'][cluster]['matches_master'] = True
            else:
                current_state[env]['clusters'][cluster]['matches_master'] = False


        ######## (3) Evaluate in-memory state of env in current iteration #######
        # run checks and set env state:
        # env state checks
        # env healthy - case 1) 
        # env is in healthy state if:
            # 1. for all clusters, cert exists (existing_cert is not None)
            # if all clusters has existing_cert=str()
            # 2. for all clusters, cert is valid (valid_age=True)
            # AND if all clusters has valid_age=True
            # 3. for all clusters, existing_cert matches master_cert
            # AND if all clusters have existing_cert=master_cert
      
        # dict() of cluster->'existing_cert' value mappings in current env 
        # sample data: { 'sat-ocp-dev': '-----BEGIN CERTIFICATE-----....', ... }
        existing_cert_results = { cluster : current_state[env]['clusters'][cluster]['existing_cert'] for cluster in current_state[env]['clusters'] }

        # dict() of cluster->True/False value mappings in current env 
        # sample data: { 'sat-ocp-dev': False, ... }
        valid_age_results = { cluster: current_state[env]['clusters'][cluster]['valid_age'] for cluster in current_state[env]['clusters'] }
        
        # dict() of cluster->True/False value mappings after comparing each entry in existing_cert_results to the 'master_cert' for env
        
        matched_cert_results = { cluster: current_state[env]['clusters'][cluster]['matches_master'] for cluster in current_state[env]['clusters'] }

        # set boolean flags for conditions 1 & 2 & 3 above
        # note: applying all() to a list[] is the same as writing the boolean expression 'list[0] and list[1] and ... and list[n]'
        if all(existing_cert_results.values()):
            current_state[env]['all_certs_exist'] = True
        else:
            current_state[env]['all_certs_exist'] = False
        
        if all(valid_age_results.values()):
            current_state[env]['all_certs_valid'] = True
        else:
            current_state[env]['all_certs_valid'] = False

        if all(matched_cert_results.values()):
            current_state[env]['all_certs_match'] = True
        else:
            current_state[env]['all_certs_match'] = False

        # evaluate state of env:
        if all( current_state[env]['all_certs_exist'],
                current_state[env]['all_certs_valid'],
                current_state[env]['all_certs_match'] ):
            current_state[env]['ready'] = True
        else:
            current_state[env]['ready'] = False

        ##############################
        # check current env state
        # env 'not ready':
        # env is not ready if any of the following are True:
        # 1. any cluster, existing_cert=None or empty str()
        # 2. any cluster, valid_age=False
        # 3. any cluster, matched_master=False
        
        # All conditions must be true for env to be 'ready', otherwise something is out of sync
        # if any condition is not true, enforce desired cluster state...
        # -- Note --
        # Given R = A & B & C,
        # These expressions are equivalent: -R = -(A & B & C) ⇔ -R = -A ∥ -B ∥ -C
        # Thus, not all(A, B, C) == any(not A, not B, not C)
        # 
        if not all( current_state[env]['all_certs_exist'],
                    current_state[env]['all_certs_valid'],
                    current_state[env]['all_certs_match'] ):

            # just redeploy all certs from master, until the desired state is reached 
            deploy_targets = []
            
            for cluster in current_state[env]['clusters']:
                # All 3 cluster conditions ('existing_cert','valid_age','matched_master') must evaluate to True,
                # otherwise the cluster cert will be redeployed using 'master_cert'
                if all( current_state[env]['clusters'][cluster]['existing_cert'], 
                        current_state[env]['clusters'][cluster]['valid_age'], 
                        current_state[env]['clusters'][cluster]['matched_master'] ):
                    pass # do nothing because cluster is fine
                else:               
                    # flag cluster for new cert deployment
                    deploy_targets.append(cluster)
                            
            for cluster in deploy_targets:
                # deploy master cert 
                deploy_cert(cluster_name=cluster, from_master=True)
                
                # TODO: add validations... Just blindly assuming that the cert exists, even if the deploy_cert() operation fails
                current_state[env]['clusters'][cluster]['existing_cert'] = current_state[env]['master_cert']
                current_state[env]['clusters'][cluster]['valid_age'] = True
                current_state[env]['clusters'][cluster]['matched_master'] = True
        else:
            # all 3 readiness conditions are true, thus env is 'ready'
            # so skip to next env in loop
            continue

    return