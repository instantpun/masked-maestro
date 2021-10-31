# standard libs #
import os
import subprocess
import shlex

from random import choices
from string import ascii_lowercase, digits

# 3rd party libs #
from flask import Flask, render_template, request
import requests

# custom libs #
import controller as ctl

# Define the WSGI application object
app = Flask(__name__)

#### Custom Errors ####

class NotFoundError(Exception):
  code = 404
  description = "Resource Not Found"

##### List of defined API routes within Flask #####
@app.route('/', methods = ['POST', 'GET'])
def data():
    current_state = ctl.get_current_state()

    # mapping of cluster -> master_cert
    cert_map = {}

    for env in current_state:
        for cluster in current_state[env]['clusters']:
            if isinstance(current_state[env]['master_cert'], bytes):
                cert = current_state[env]['master_cert'].decode('utf-8')
            else:
                cert = current_state[env]['master_cert']
            cert_map.update( { cluster: cert } )
  
    cluster_list = cert_map.keys()

    if request.method == 'GET':
        return render_template('form.html', clusters = cluster_list)
    if request.method == 'POST':
        form_data = request.form.to_dict()

        uuid = ''.join(choices(ascii_lowercase + digits, k=8))
        tmpfile = f'/tmp/cert-{uuid}'

        try:
            with open(tmpfile, 'w') as f:
                f.write(cert)
          
            # stdin pipe use later, requires bytes as input
            stdin_data = form_data["String"].encode() if isinstance(form_data["String"], str) else form_data["String"]
            
            # raw command
            seal_cmd = f"/usr/local/bin/kubeseal --raw --scope cluster-wide  --from-file=/dev/stdin --cert={tmpfile}"

            # safely split into list of shell args
            cmd = shlex.split(seal_cmd)

            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE) as proc:
                
                # write user input to stdin & execute
                proc.stdin.write(stdin_data)
                out, err = proc.communicate()

            result = out.decode() if isinstance(out, bytes) else out

            if proc.returncode > 0:
                print(err)

            # simple html to diplay word wrap string
            response_template = f"""<p style="word-wrap: break-word; word-break: break-all;">
{result}
</p>
"""

        finally:
            # ensure tmpfile is always deleted
            if os.path.exists(tmpfile):
                os.remove(tmpfile)

        return response_template

@app.route('/template')
def template():
    returnTemplate = """---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  annotations:
    sealedsecrets.bitnami.com/cluster-wide: "true"
  creationTimestamp: null
  name: <secret_name>
spec:
  encryptedData:
    <key>: <encrypted_string>
  template:
    metadata:
      annotations:
        sealedsecrets.bitnami.com/cluster-wide: "true"
      creationTimestamp: null
      name: <secret_name>
"""
    return returnTemplate

@app.route('/cert/<string:env>')
def cert(env):
    """
    :param env: This parameter should correspond to one of the top-level fields in the inventory.yaml file (e.g. 'dev','test','prod', etc)
    :type: str
    """
    try:
      current_state = ctl.get_current_state()

      if not current_state.get(env): 
        raise NotFoundError('No resource was found for the env provided')
      
      return current_state[env]['master_cert']

    except requests.exceptions.HTTPError as http_err:
      print(f'HTTP error occurred: {http_err}')  # Python 3.6
    except NotFoundError as err:
      # render empty string, and respond with HTTP 404 code
      return "Page Not Found", 404
