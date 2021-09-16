import threading
from datetime import datetime
#from flask import render_template,request,send_from_directory
import os
import yaml
from app import app as webapp, current_state
import app.api_routes
import app.controller as ctl


# Statement for enabling the development environment
DEBUG = True

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__)) 


old_print = print

def timestamped_print(*args, **kwargs):
  old_print(datetime.now(), *args, **kwargs)

print = timestamped_print

def main():
    config = ctl.yaml_file_to_dict(ctl.INVENTORY_PATH)
    default_state = ctl.init_default_state(config)
    current_state = ctl.enforce_desired_state(default_state)

    # possible one-liner = enforce_desired_state(init_default_state(yaml_file_to_dict(INVENTORY_PATH)))
    # TODO: Implement control loop...
    
    # retry_counter = 0 # self-terminate if failed 5 times
    # 
    # while current_state != desired_state:
    #
    #     enforce_desired_state(default_state)
    #     if current_state == desired_state:
    #         retry_counter = 0 # reset counter
    #
    #         
    #         sleep(POLL_TIME_SEC) # sleep 1 hr and check again
    #         continue
    #     else:
    #         retry_counter += 1
    #         assert retry_counter < RETRY_LIMIT, "Unable to establish desired state after 5 attempts, terminating..."
    #         

if __name__ == '__main__':
  #make_thread()
  #app.run(host='0.0.0.0', port=5000, debug=True)
  main()
  webapp.run(host='0.0.0.0', port=8080, debug=True)