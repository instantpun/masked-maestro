# standard libs #
import os

# Configurations
#app.config.from_object('config')

current_state = dict()
global_vars = dict()

# GLOBAL VARS

# flag DEBUG=True if '--debug' was passed as 1st cli argument
#DEBUG = True if len(sys.argv) > 1 and sys.argv[1] == '--debug' else False
K8S_TEMPLATE_PATH = os.environ.get('K8S_TEMPLATE_PATH') if os.environ.get('K8S_TEMPLATE_PATH') else 'k8s_templates/'
INVENTORY_PATH = os.environ.get('INVENTORY_PATH') # shell var should be defined in k8s deployment
WORKING_DIR = "/tmp/certs" # shell var should be defined in k8s deployment
POLL_TIME_SEC = int(os.environ.get('POLL_TIME_SEC')) if os.environ.get('POLL_TIME_SEC') else 600 # time = seconds, default 600 sec
RETRY_LIMIT = int(os.environ.get('RETRY_LIMIT')) if os.environ.get('RETRY_LIMIT') else 3 # default 3 retries

# global vars
# wildcard domain for clusters
WILDCARD_DOMAIN = "" if not os.environ.get('WILDCARD_DOMAIN') else os.environ.get('WILDCARD_DOMAIN')