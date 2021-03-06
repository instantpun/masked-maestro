import threading #TODO: implement multithreading
from datetime import datetime
import apis
import cfg
import controller as ctl

old_print = print

def timestamped_print(*args, **kwargs):
  old_print(datetime.now(), *args, **kwargs)

print = timestamped_print

def main():
  config = ctl.yaml_file_to_dict(ctl.INVENTORY_PATH)
  print("Clusters in Configuration: ")
  print(",".join(config['clusters'].keys())) # dict.keys() returns an iterable list of key names
  #current_state = ctl.config_to_state(config)
  ctl.config_to_state(config)
  print("initial:\n" + str(ctl.get_current_state()))
  ctl.set_defaults_in_state()
  print("with defaults:\n" + str(ctl.get_current_state()))
  # current_state = ctl.enforce_desired_state(current_state)
  ctl.enforce_desired_state()
  print("with desired:\n" + str(ctl.get_current_state()))
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

# if __name__ == '__main__':

main()
apis.app.run(host='0.0.0.0', port=5000, debug=True)
