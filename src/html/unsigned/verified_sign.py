#!/usr/bin/env python

import subprocess
import os
import sys
from src.core import setcore as core

# keytool -import -storepass pw -alias MyCert -file mycert.spc
# jarsigner -verbose -storepass <pw> -keypass <pw> unsigned.jar MyCert

###########################################################
#                                                         #
# SET - Use codesigning for the java applet attack vector #
#                                                         #
###########################################################

# based on the new update to Java, this no longer works and just shows a big "UNKNOWN".
# to get around that you can purchase your own digital certificate through verisign/thawte

# grab current path
definepath = os.getcwd()

# print warning message that we need to install sun-java or openjdk
print """
 This menu will allow you to import or create a valid code signing certificate for the Java Applet attack. 

 You will need to purchase a code signing certificate through GoDaddy, Thawte, Verisign, etc. in order to 
 make this work. This menu will automate the portions for you to either create the request to submit to the
 certificate authority or allow you to import a code signing certificate that you may already have.

 Note that purchasing a code signing certificate is somewhat difficult. It requires you to have a business name and 
 prove the legitimacy of that certificate. That means you have to register a business with the state and everything else.

 Good news is, the process to do that is extremely simple. All in all, it should cost roughly around $300-350 to setup your
 business, buy a code signing certificate, and publish an applet to be whatever you want.
"""

core.print_error("*** WARNING ***")
core.print_error("IN ORDER FOR THIS TO WORK YOU MUST INSTALL sun-java6-jdk or openjdk-6-jdk, so apt-get install openjdk-6-jdk")
core.print_error("*** WARNING ***")

# use flag is in case someone already has a code signing certificate, in that case it bypasses the "no" answer
use_flag = 0

# prompt for a different certificate
prompt = raw_input(core.setprompt("0", "Have you already generated a code signing-certificate? [yes|no]")).lower()
# if we selected yes if we generated a code signing certificate
if prompt == "yes" or prompt == "y":
        # prompt the user to import the code signing certificate
        cert_path=raw_input(core.setprompt("0", "Path to the code signing certificate file"))
        if not os.path.isfile(cert_path):
                # loop forever
                while 1 == 1:
                        core.print_error("ERROR:Filename not found. Try again.")
                        # re-prompt if we didn't file the filename
                        cert_path=raw_input(core.setprompt("0", "Path to the .cer certificate file"))
                        # if we find the filename then break out of loop
                        if os.path.isfile(cert_path): break

        # here is where we import the certificate
        try:
                core.print_info("Importing the certificate into SET...")


        
                subprocess.Popen("keytool -import -alias MyCert -file %s" % (cert_path), shell=True).wait()
                # trigger that we have our certificate already and bypass the request process below
                use_flag = 1

        # exception here in case it was already imported before
        except: pass

# this will exit the menu
if prompt == "quit" or prompt == "q": 
        use_flag = 0
        prompt = "yes"
        cert_path = ""
# if we have a cert now or if we need to generate one
if use_flag == 1 or prompt == "no" or prompt == "n":

        # if we selected no we need to create one
        if prompt == "no" or prompt == "n":
                # get the stuff ready to do it
                core.print_info("Generating the initial request for Verisign...")
                # grab input from user, fqdn
                answer1=raw_input(core.setprompt("0", "FQDN (ex. www.thisisafakecert.com)"))
                # grab name of organizaton
                answer2=raw_input(core.setprompt("0", "Name of the organization"))
                # grab two letter country code
                answer3=raw_input(core.setprompt("0", "Two letter country code (ex. US)"))
                # if blank, default to US
                if answer3 == "": answer3 = "US"
                # grab state
                answer4=raw_input(core.setprompt("0", "State"))
                # grab city
                answer5=raw_input(core.setprompt("0", "City"))
                # generate the request crl
                subprocess.Popen('keytool -genkey -alias MyCert -keyalg RSA -keysize 2048 -dname "CN=%s,O=%s,C=%s,ST=%s,L=%s"' % (answer1,answer2,answer3, answer4, answer5), shell=True).wait()
                core.print_info("Exporting the cert request to text file...")
                # generate the request and export to certreq
                subprocess.Popen("keytool -certreq -alias MyCert > %s/certreq.txt" % (definepath), shell=True).wait()
                core.print_status("Export successful. Exported certificate under the SET root under certreq.txt")
                core.print_warning("You will now need to pay for a code signing certificate through Verisign/Thawte/GoDaddy/etc.")
                core.print_warning("Be sure to purchase a code signing certificate, not a normal website SSL certificate.")
                core.print_info("When finished, enter the path to the .cer file below")
                # cert_path is used for the certificate path when generating

                cert_path = raw_input(core.setprompt("0", "Path for the code signing certificate file (.spc file)"))
                # if we can't find the filename
                if not os.path.isfile(cert_path):
                        while 1 == 1:
                                core.print_error("ERROR:Filename not found. Please try again.")
                                # re-prompt if file name doesn't exist
                                cert_path = raw_input(core.setprompt("0", "Path to the .cer certificate file from Verisign"))
                                # if we detect file, then break out of loop
                                if os.path.isfile(cert_path): break

                # import the certificate
                subprocess.Popen("keytool -import -alias MyCert -file %s" % (cert_path), shell=True).wait()

# if our certificate is in the data store
if os.path.isfile(cert_path):
        # sign the applet with the imported certificate
        subprocess.Popen("jarsigner -signedjar Signed_Update.jar %s/src/html/unsigned/unsigned.jar MyCert" % (definepath), shell=True).wait()
        # move it into our html directory
        subprocess.Popen("mv Signed_Update.jar %s/src/program_junk/Signed_Update.jar.orig" % (definepath), shell=True).wait()
        # move back to original directory
        core.print_status("Java Applet is now signed and will be imported into the java applet website attack from now on...")
