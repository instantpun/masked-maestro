import threading
from datetime import datetime
from flask import Flask,render_template,request,send_from_directory
from base64 import urlsafe_b64encode
import os
import re
import yaml

# initialize the Flask app object
app = Flask(__name__)

old_print = print

def timestamped_print(*args, **kwargs):
  old_print(datetime.now(), *args, **kwargs)

print = timestamped_print

# Read in cluster list from configuration file, parse to create list and remove hidden characters such as new line
def get_cluster_list(path):
    """
    path is the full path to a config file formatted as an ini

    :param path: The full path to the config file
    :type: str
    """
    # validate that path is in fact a string, and fail with AssertionError if it is not
    assert isinstance(path, str), "func: get_cluster_list(), param: path, path must be a string!"

    # load config from 'path' variable
    with open(path, 'r') as f:
        cluster_map = yaml.safe_load(f) # safe_load() is more secure; the parser won't evaluate code snippets inside yaml

    print("Clusters in Configuration: ")
    print("\n".join(cluster_map['clusters'].keys()))
    return cluster_map['clusters'].keys() # dict.keys() returns an iterable list of keys

@app.route('/', methods = ['POST', 'GET'])
def data():
    if request.method == 'GET':
        return render_template('form.html', clusters = get_cluster_list())
    if request.method == 'POST':
        form_data = request.form.to_dict()
        command = "/usr/bin/echo -n " + form_data["String"] + " | kubeseal --raw --scope cluster-wide --from-file=/dev/stdin --cert " + directory + "/" + form_data["cluster"] + ""
        encryptedSecret = os.popen(command).read()
        return encryptedSecret


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

@app.route('/cert/<path:path>')
def cert(path):
    #TODO: refactor as dictionary lookup
    return send_from_directory('/tmp/certs', path)

make_thread()
#app.run(host='0.0.0.0', port=5000, debug=True)
