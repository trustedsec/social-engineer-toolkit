#!/usr/bin/python
import subprocess
import os
import re
import sys
from src.core.setcore import *

# definepath
definepath=os.getcwd()
sys.path.append(definepath)


meta_path = meta_path()

# launch msf listener
print_info("The payload can be found in the SET home directory.")
# j0fer 06-27-2012 # choice = raw_input(setprompt("0", "Start the listener now? [yes|no]"))
choice = yesno_prompt("0", "Start the listener now? [yes|no]")
# j0fer 06-27-2012 # if choice == "yes" or choice == "y":
if choice == "YES":
    # if we didn't select the SET interactive shell as our payload
    if not os.path.isfile(setdir + "/set.payload"):
        print_info("Please wait while the Metasploit listener is loaded...")
        if os.path.isfile(setdir + "/meta_config"):
            listen_path = (setdir + "/meta_config")

        if os.path.isfile(setdir + "/meta_config_multipyinjector"):
            listen_path = (setdir + "/meta_config_multipyinjector")

        subprocess.Popen("ruby %s/msfconsole -L -n -r %s" % (meta_path,listen_path), shell=True).wait()

    # if we did select the set payload as our option
    if os.path.isfile(setdir + "/set.payload"):
        if check_options("PORT=") != 0:
            port = check_options("PORT=")

        set_payload = file(setdir + "/set.payload", "r")

        set_payload = set_payload.read().rstrip()
        if set_payload == "SETSHELL":
            print_info("Starting the SET Interactive Shell Listener on %s." % (port))
            subprocess.Popen("python src/payloads/set_payloads/listener.py %s" % (port), shell=True).wait()
        if set_payload == "RATTE":
            print_info("Starting the RATTE Shell on %s." % (port))
            subprocess.Popen("src/payloads/ratte/ratteserver %s" % (port), shell=True).wait()
