##### List of defined API routes within Flask #####
import requests 

#### Custom Errors ####

class NotFoundError(Exception):
  code = 404
  description = "Resource Not Found"

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

@app.route('/cert/<env:env>')
def cert(env):
    """
    :param env: This parameter should correspond to one of the top-level fields in the inventory.yaml file (e.g. 'dev','test','prod', etc)
    :type: str
    """
    try:
      if not current_state.get('env'): 
        raise NotFoundError('No resource was found for the URI path provided')
      
      return current_state[env]['master_cert']
    except requests.exceptions.HTTPError as http_err:
      print(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
      print(f'Other error occurred: {err}')  # Python 3.6

