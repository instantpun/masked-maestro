# standard libs #
import sys
import os
import json
import subprocess
import io
import datetime
import errno
import shlex

from contextlib import contextmanager
from random import choices
from string import ascii_lowercase, ascii_uppercase, digits
from base64 import urlsafe_b64encode, b64decode, b64encode

# 3rd party libs #
import yaml
import dateutil.parser

# custom libs #
import cfg

DEBUG = cfg.DEBUG
K8S_TEMPLATE_PATH = cfg.K8S_TEMPLATE_PATH
INVENTORY_PATH = cfg.INVENTORY_PATH
WILDCARD_DOMAIN = cfg.WILDCARD_DOMAIN

old_print = print

def timestamped_print(*args, **kwargs):
  old_print(datetime.datetime.now(), *args, **kwargs)

print = timestamped_print

### custom Exceptions ###
class ProcessError(Exception):
    def __init__(self, cmd="", code=None, msg=""):
        self.code = code
        # grab only the first argument
        if isinstance(cmd, str):
            self.cmd = shlex.split(cmd)[0]
        elif isinstance(cmd, list) and cmd[0]:
            self.cmd = cmd[0]
        else:
            self.cmd = "Unknown"
        self.msg = 'stderr buffer is empty' if not msg else msg
        super().__init__(self.msg)

    def __str__(self):
        return f'ERROR: {self.msg} -- Process {self.cmd} exited with code {self.code}. Code Description = {errno.errorcode[self.code]}'


### custom context managers ###

@contextmanager
def run_subprocess(cmd, **kwargs):

    try:
        # spawn new process
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True, **kwargs)
        # Context breakdown, and yield control to calling function
        yield proc
        # when calling function exits, resume run_process context:

        out, err = proc.communicate()
        # communicate() waits for process to complete if it hasn't already, and terminates it. Should help prevent zombie attacks :P

        # emit warning message if process terminated with an unsuccessful return code
        if proc.returncode > 0:
            raise ProcessError(cmd = cmd, code = proc.returncode, msg = err)
        elif not err and proc.returncode > 0:
            raise ProcessError(cmd = cmd, code = proc.returncode, msg = 'stderr buffer is empty')
    except AttributeError as err: #TODO - improve lazy error handling
        print(err)
    except ProcessError as err:
        print(err)


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

    with open(path, 'r') as f:
        # safe_load() is more secure; the parser won't evaluate code snippets inside yaml
        # safe_load() reads the file stream and converts yaml formatted text to a python dict() object
        d = yaml.safe_load(f)

    return d

def deploy_cert(cert=None, key=None, secret_name=None, apiserver_url=None, apiserver_token=None, from_master=False, env=None):
    """
    Checks for any existing sealed secret certs inside a specific cluster

    :param cert: The raw TLS certificate, which will be included in the k8s secret.
    :type: str

    :param key: The raw pem-formatted key associated with cert, which will be included in the k8s secret.
    :type: str

    :param from_master: If True, deploy_cert() will attempt to create a k8s secret using the master_cert and master_key stored in-memory.
    :type: bool

    :param secret_name: The name of the resulting k8s secret resource.
    :type: str

    :param apiserver_url: Must be a valid k8s api server address. 
    :type: str

    :param apiserver_token: Must be a valid k8s API token. Token must provide read-write access to secrets within the destination cluster and namespace.
    :type: str
    """

    current_state = cfg.current_state

    master_cert = None
    master_key = None

    assert not (from_master and (cert or key)), "func: deploy_cert(), Arguments Mutually Exclusive [from_master,(cert,key)]: keyword argument 'from_master' cannot be used with keyword arguments 'cert' or 'key'."

    assert env is not None, "func: deploy_cert(), Argument Type Invalid [env]: 'env' cannot be NoneType."
    #TODO: enforce str() type here or not?
    assert env, "func: deploy_cert(), Argument Data Invalid [env]: 'env' must match one the corresponding fields in the inventory config."
    assert current_state, "func: deploy_cert(), State Invalid [current_state]: current_state is None" #TODO: improve messages

    if from_master:
        assert current_state.get(env), "func: deploy_cert(), State Malformed [current_state]: current_state does not contain key '{}'".format(env) # TODO: Need better message"
        assert current_state[env].get('master_cert'), "func: deploy_cert(), State Malformed [current_state]: master_cert for provided env is not set."
        assert current_state[env].get('master_key'), "func: deploy_cert(), State Malformed [current_state]: master_key for provided env is not set."

    if not from_master:
        assert isinstance(cert, str) , "func: deploy_cert(), Argument Type Invalid [cert,key]: 'cert' must be of type str()"
        assert isinstance(key, str), "func: deploy_cert(), Argument Type Invalid [cert,key]: 'key' must be of type str()"
        assert cert, "func: deploy_cert(), Argument Data Invalid [cert]: A plaintext, PEM-formatted certificate must be provided."
        assert key, "func: deploy_cert(), Argument Data Invalid [key]: A plaintext, unencrypted key must be provided."
    
    if not secret_name:
        secret_name = "sealing-secret-" + create_uuid()

    tls_signer_secret = yaml_file_to_dict(f'{K8S_TEMPLATE_PATH}/secret_tls.yaml')
    tls_signer_secret['metadata']['name'] = secret_name

    # cert must be in standard PEM format, and base64 encoded
    tls_crt = master_cert if from_master else cert
    tls_crt = b64decode( tls_crt.encode() ).decode()
    tls_signer_secret['data']['tls.crt'] = tls_crt

    # key must be in unencrypted PEM format, and base64 encoded
    tls_key = master_key if from_master else key
    tls_key = b64decode( tls_key.encode() ).decode()
    tls_signer_secret['data']['tls.key'] = tls_key

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
    deployCmd = " ".join([ "oc create",
                         f"--token={apiserver_token}",
                         f"--server={apiserver_url}",
                         "--insecure-skip-tls-verify",
                         "--namespace sealed-secrets",
                         "--filename=-"
                       ])

    input_json = json.dumps(tls_signer_secret)

    print("Distributing Cert to " + apiserver_url)

    with io.StringIO(input_json) as outfile:
        with run_subprocess(deployCmd) as proc:
            output = proc.stdin.write(outfile.read())

    return None        

def delete_ss_pod(apiserver_url=None, apiserver_token=None):

    delCmd = " ".join([ "oc delete pod",
                         "-l name=sealed-secrets-controller",
                         f"--token={apiserver_token}",
                         f"--server={apiserver_url}",
                         "--insecure-skip-tls-verify",
                         "--namespace sealed-secrets",
                       ])

    with run_subprocess(delCmd) as proc:
        returncode = proc.returncode

    return returncode


def is_valid_age(age, time_format="ISO") -> bool:
    """
    :param age: A string which should match the pattern '[0-9][0-9][0-9][ydms]'
    :type: str

    :return bool: True/False based on evaluation of age parameter
    """

    # age must be a string at this time
    assert isinstance(age, str), "func: is_valid_age(), param: age, age must be of type str()"

    if time_format == "ISO":
        # convert k8s ISO-formatted timestamp to common datetime object
        age_dt = dateutil.parser.isoparse(age)

        # set expiration time to 100days prior to now
        expiry_dt = datetime.datetime.now() - datetime.timedelta(days=100)

        if age_dt.timestamp() <= expiry_dt.timestamp():
            return False
        else:
            return True        

    # TODO: Discuss if parsing HR format is even needed
    if time_format == "HR": # human-readable
        # age is in the format of NNNI, where I is the interval and N is the number
        # e.g. 17s = 17 seconds, 3m = 3 minutes, 50d = 50 days, 1y = 1 year
        # X seconds or X minutes is too new, therefore always valid
        if age.endswith('s') or age.endswith('m') or age.endswith('h'):
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
            print(age)
            return False

def get_secret_age(secret_name=None, apiserver_url=None, apiserver_token=None) -> bool:
    """
    Check if the provided cert is more than 100days old

    :param secret_name: name of the secret which will be fetched and evaluated.
    :type: str

    :param apiserver_url: Must be a valid k8s api server address. 
    :type: str

    :param apiserver_token: Must be a valid k8s API token. Token must provide read-write access to secrets within the destination cluster and namespace.
    :type: str

    :return secret_age: the age of the secret resource which matches the provided parameters. 'age' is a string which should match the pattern '[0-9][0-9][0-9][ydms]'
    :type: str
    """

    print("Checking age of {}".format(secret_name))

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

    cmd = " ".join(["oc get secret",
                     secret_name,
                     "-o jsonpath='{.metadata.creationTimestamp}'",
                    f"--token={apiserver_token}",
                    f"--server={apiserver_url}",
                     "--insecure-skip-tls-verify",
                     "--namespace sealed-secrets",
                ])
                    #     "| awk \'match($4,/1[0-9][0-9]+d/) {print $1}\'"
                    # ])

    #print("Checking age of the secret '{}' containing the certificate with command:\n{}".format(secret_name, cmd))

    # spawn process to run oc command, and send output to stdout
    with run_subprocess(cmd) as proc:
    # read command output from stdout, returns str()
        secret_age = proc.stdout.read()

    return secret_age

def fetch_cert_key_from_secret(secret_name=None, apiserver_url=None, apiserver_token=None) -> str:
    """
    Checks for any existing sealed secret certs inside a specific cluster

    :param secret_name: name of the secret which will be fetched and evaluated.
    :type: str

    :param apiserver_url: Must be a valid k8s api server address. 
    :type: str

    :param apiserver_token: Must be a valid k8s API token. Token must provide read-write access to secrets within the destination cluster and namespace.
    :type: str

    :return (cert, key): Tuple contains two strings (1) the plaintext certificate and (2) the plaintext pem-formatted key retrieved from the provided secret
    :type: tuple(str, str)
    """

    cert = None
    key = None

    try:
        assert secret_name, "func: fetch_cert_key_from_secret, param: secret_name -- 'secret_name' must be a non-empty string"
        if not isinstance(secret_name, str):
            secret_name = str(secret_name) # enforce str() typing

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
                            "--namespace sealed-secrets",
                            f"--token={apiserver_token}",
                            f"--server={apiserver_url}",
                            "--insecure-skip-tls-verify"
                        ])
                            #  "| jq -r \'.data.\"tls.crt\"\'",
                            #  "| base64 -d"

        # spawn process to run oc command, and send output to stdout
        with run_subprocess(certCmd) as proc:
            out = proc.stdout.read()
            # read command output from stdout, returns str()
            secret = json.loads( out )

        #TODO: Determine if schema validation is needed:
        #assert secret.get('type') == 'kubernetes.io/tls', "func: fetch_cert_key_from_secret - field 'type' in secret must be 'kubernetes.io/tls'"

        # b64decode accepts str() and bytes(), but returns bytes()
        # need str() for later
        cert = b64decode( secret['data']['tls.crt'] ).decode()
        key = b64decode( secret['data']['tls.crt'] ).decode()

    except json.decoder.JSONDecodeError as err:
        print(err)
    except KeyError as err:
        print(err)

    return cert, key

def create_new_cert():
    """
    Calls openssl tool to create a new certificate and key

    :returns (cert, key): Tuple containing the plaintext x509 certificate and the plaintext pem-formatted key
    
    :type: tuple(str, str)
    """

    print("create_new_cert()")
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

    # create list containing line-by-line of raw_output
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
            # set line cursor to skip ahead of lines which have already been visited
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

    :param secret_name: name of the secret which will be fetched and evaluated.
    :type: str

    :param apiserver_url: Must be a valid k8s api server address. 
    :type: str

    :param apiserver_token: Must be a valid k8s API token. Token must provide read-write access to secrets within the destination cluster and namespace.
    :type: str

    :return existing_certs: TODO
    :type: list[str]
    """

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
                    f"--token={apiserver_token}",
                    f"--server={apiserver_url}"
              ])

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
    Assigns mapping to cfg.current_state

    :return None:
    :type: NoneType
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
    #sharedEnvs = ['dev','qa','cap','psp','prod']

    # initialize empty to dict() for index of envs
    initial_env_state = {}

    for cluster in clusters:
        # if cluster has active=true in yaml, and shared_env=$env is valid, begin processing
        if config['clusters'][cluster].get('active') is True and config['clusters'][cluster].get('shared_env'):
            # emit error if the provided env is not correct/acceptable
            # assert config['clusters'][cluster]['shared_env'] in sharedEnvs, "ERROR: @ file {inventory}, key clusters.{cluster}.shared_env does not have expected value. Must be one of {envs}".format(inventory=INVENTORY_PATH, cluster=cluster, envs=", ".join(sharedEnvs))

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

    set_current_state(initial_env_state)
    # global current_state
    # current_state = initial_env_state

    return

def create_uuid(size=6, base64=False) -> str:
    """
    generates and returns a new, 8-character UUID 

    :return UUID: string containing 8 random alphanumeric characters
    :type: str
    """

    char_set = ascii_lowercase + ascii_uppercase + digits

    # enforce alphanumeric chars in UUID: strip any character that does not occur in the set [A-Za-z0-9]
    uuid = ''.join(choices(char_set, k=size))
    
    return uuid

def set_defaults_in_state():
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
    #           'existing_cert_name': str(), # default = None, should be str()
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

    current_state = cfg.current_state
    global_vars = cfg.global_vars
    
    # global_vars['wildcard_domain'] = WILDCARD_DOMAIN if WILDCARD_DOMAIN else None

    # Initialize all envs into a 'not ready' current_state
    for env in current_state.keys():
        if not current_state[env].get('ready'):
            current_state[env]['ready'] = False
        
        if not current_state[env].get('all_certs_exist'):
            current_state[env]['all_certs_exist'] = False    
        
        if not current_state[env].get('all_certs_valid'):
            current_state[env]['all_certs_valid'] = False
        
        if not current_state[env].get('all_certs_match'):
            current_state[env]['all_certs_match'] = False
        
        if not current_state[env].get('master_cert'):
            current_state[env]['master_cert'] = None
        
        if not current_state[env].get('master_key'):
            current_state[env]['master_key'] = None
        
        for cluster in current_state[env]['clusters']:
            if not current_state[env]['clusters'][cluster].get('existing_cert_name'):
                current_state[env]['clusters'][cluster]['existing_cert_name'] = None

            if not current_state[env]['clusters'][cluster].get('existing_cert'):
                current_state[env]['clusters'][cluster]['existing_cert'] = None

            if not current_state[env]['clusters'][cluster].get('existing_key'):
                current_state[env]['clusters'][cluster]['existing_key'] = None

            if not current_state[env]['clusters'][cluster].get('valid_age'):
                current_state[env]['clusters'][cluster]['valid_age'] = False

            if not current_state[env]['clusters'][cluster].get('matches_master'):
                current_state[env]['clusters'][cluster]['matches_master'] = False            

            if not current_state[env]['clusters'][cluster].get('apiserver_url'):
                current_state[env]['clusters'][cluster]['apiserver_url'] = None
    
    set_current_state(current_state)

    return


def enforce_desired_state():

    print("Enforcing Desired State...")
    current_state = cfg.current_state
    # Use while loop later to constantly update the in-memory state of the environments
    #while not current_state[env]['ready']:

    for env in current_state.keys():

        ######## (1) Represent state of cluster certs in-memory for current env  #######
        # check state of clusters and certs; push state info into current_state{}
        for cluster in current_state[env]['clusters']:
            
            #
            creds = get_cluster_creds(current_state, env=env, cluster_name=cluster)
            print("INFO: Retrieving existing cluster certs, if any...")
            # get_existing_certs -> list()
            cluster_certs = get_existing_certs(cluster_name=creds['cluster_name'], apiserver_url=creds['apiserver_url'], apiserver_token=creds['apiserver_token'])
            
            if not cluster_certs:
                # special case: no cert exists, therefore cert is also invalid
                print("WARN: No existing certs found. New certs will be deployed...")
                current_state[env]['clusters'][cluster]['existing_cert_name'] = None
                current_state[env]['clusters'][cluster]['valid_age'] = False

            else:
                # general case: cert exists, therefore assign newest cert from list (index 0) to 'existing_cert_name'
                print("Certs found for current env. Validating age...")
                current_state[env]['clusters'][cluster]['existing_cert_name'] = cluster_certs[0]

                # load cert and key into memory for later use
                secret_name = current_state[env]['clusters'][cluster]['existing_cert_name']

                if secret_name:
                    print(f"INFO: Attempting to load cert in cluser={cluster}")
                    cluster_cert, cluster_key = fetch_cert_key_from_secret(secret_name, apiserver_url=creds['apiserver_url'], apiserver_token=creds['apiserver_token'])
                    current_state[env]['clusters'][cluster]['existing_cert'] = cluster_cert
                    current_state[env]['clusters'][cluster]['existing_key'] = cluster_key
                else:
                    print(f"ERROR: Unable to laod cert found in cluster={cluster}")
                    # current_state[env]['clusters'][cluster]['existing_cert'] = None
                    # current_state[env]['clusters'][cluster]['existing_key'] = None

                # check validity of cert age, and assign the result
                if is_valid_age( get_secret_age( cluster_certs[0], apiserver_url=creds['apiserver_url'], apiserver_token=creds['apiserver_token'] ) ):
                    print("Certs are still valid, not greater than 100 days old. Flag to ensure consistency then pull into container.")
                    current_state[env]['clusters'][cluster]['valid_age'] = True
                else:
                    print("Certs are not valid, a new certificate will be deployed")
                    current_state[env]['clusters'][cluster]['valid_age'] = False

        ######## (2) Set state of master_cert in-memory for current env  #######
        # given current env, verify master_cert and master_key is populated inside current_state[env] 
        if not current_state[env]['master_cert'] or not current_state[env]['master_key']:

            print(f"Master Cert or Key not set, attempting to re-use existing from clusters in current env. env={env}")

            # recursively attempt to fetch a valid cert from one of the current cluster states in current_state{}
            for cluster in current_state[env]['clusters']:

                creds = get_cluster_creds(current_state, env=env, cluster_name=cluster)

                # 'existing_cert_name' contains the name of the secret which contains the certificate and key
                secret_name = current_state[env]['clusters'][cluster]['existing_cert_name']
                valid = current_state[env]['clusters'][cluster]['valid_age']

                if current_state[env]['master_cert'] and valid:
                    print(f"INFO: Master cert and key for env={env} will based on cluster={cluster}")
                    master_cert, master_key = fetch_cert_key_from_secret(secret_name, apiserver_url=creds['apiserver_url'], apiserver_token=creds['apiserver_token'] )
                    current_state[env]['master_cert'] = master_cert
                    current_state[env]['master_key'] = master_key
                    break
                else:
                    continue

            # if no valid cert is retrieved, generate a new one
            try:
                if not current_state[env]['master_cert'] or not current_state[env]['master_key']:
                    # master_cert and master_key are created as a pair... if one exists, but not the other, we will overwrite both with a new pair
                    current_state[env]['master_cert'], current_state[env]['master_key'] = create_new_cert()
                
                # validate master_cert and master_key MUST NOT be empty strings or None
                assert current_state[env]['master_key'], "Missing Value: Empty string or null value @ key = current_state[{}]['master_key']".format(env)
                assert current_state[env]['master_cert'], "Missing Value: Empty string or null value @ key = current_state[{}]['master_cert']".format(env)
            except AssertionError as err:
                # if either 'master_cert' or 'master_key' is still None, program breaks~
                raise err
        else:
            # cert and key must exist, so...
            print("Master Cert and Key found for env. env={}".format(env))

        ######## (2.1) Compare cluster certs to master_cert for current env ########
        for cluster in current_state[env]['clusters']:
            print(f'Comparing cert for cluster={cluster} with known master cert for env={env}...')
            secret_name = current_state[env]['clusters'][cluster]['existing_cert_name']
            cert = current_state[env]['clusters'][cluster]['existing_cert']
            key = current_state[env]['clusters'][cluster]['existing_key']

            if all([ secret_name,
                    cert == current_state[env]['master_cert'],
                    key == current_state[env]['master_key']
            ]):
                print(f"INFO: cluster=cluster is in sync with master state for env={env}")
                current_state[env]['clusters'][cluster]['matches_master'] = True
            else:
                print(f"WARN: cluster=cluster is NOT in sync with master state for env={env}")
                current_state[env]['clusters'][cluster]['matches_master'] = True

                #TODO: add more verbose logging to troubleshoot errors with secret_name, cert, & key

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
      
        # dict() of cluster->'existing_cert_name' value mappings in current env 
        # sample data: { 'sat-ocp-dev': '-----BEGIN CERTIFICATE-----....', ... }
        existing_cert_results = { cluster : current_state[env]['clusters'][cluster]['existing_cert_name'] for cluster in current_state[env]['clusters'] }

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
        if all([ current_state[env]['all_certs_exist'],
                 current_state[env]['all_certs_valid'],
                 current_state[env]['all_certs_match'] ]):
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
        # These expressions are equivalent: -R = -(A & B & C) ??? -R = -A ??? -B ??? -C
        # Thus, not all(A, B, C) == any(not A, not B, not C)
        # 
        if not all([ current_state[env]['all_certs_exist'],
                     current_state[env]['all_certs_valid'],
                     current_state[env]['all_certs_match']
        ]):
            # just redeploy all certs from master, until the desired state is reached 
            deploy_targets = []
            
            for cluster in current_state[env]['clusters']:
                # All 3 cluster conditions ('existing_cert_name','valid_age','matches_master') must evaluate to True,
                # otherwise the cluster cert will be redeployed using 'master_cert'
                if not all([ current_state[env]['clusters'][cluster]['existing_cert_name'], 
                         current_state[env]['clusters'][cluster]['valid_age'], 
                         current_state[env]['clusters'][cluster]['matches_master']
                ]):
                    deploy_targets.append(cluster)
                            
            for cluster in deploy_targets:
                # deploy master cert 
                creds = get_cluster_creds(current_state, env=env, cluster_name=cluster)
                name = "sealing-secret-{}".format(create_uuid())
                deploy_cert(secret_name=name, from_master=True, env=env, apiserver_url= creds['apiserver_url'], apiserver_token= creds['apiserver_token'])
                
                # TODO: add validations... Just blindly assuming that the cert exists, even if the deploy_cert() operation fails
                #current_state[env]['clusters'][cluster]['existing_cert_name'] = current_state[env]['master_cert']
                current_state[env]['clusters'][cluster]['valid_age'] = True
                current_state[env]['clusters'][cluster]['matched_master'] = True
        else:
            # all 3 readiness conditions are true, thus env is 'ready'
            # so skip to next env in loop
            continue

    set_current_state(current_state)

    return

def set_current_state(current_state):
    cfg.current_state = current_state
    print("set_current_state()")
    return

def get_current_state():
    return cfg.current_state