#!/usr/bin/env python
# coding=utf-8

import os
import shutil
import subprocess

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass
# keytool -import -storepass pw -alias MyCert -file mycert.spc
# jarsigner -verbose -storepass <pw> -keypass <pw> unsigned.jar MyCert

###########################################################
#                                                         #
# SET - Use codesigning for the java applet attack vector #
#                                                         #
###########################################################

# based on the new update to Java, this no longer works and just shows a big "UNKNOWN".
# to get around that you can purchase your own digital certificate through
# verisign/thawte

# grab current path
definepath = core.definepath()

# print warning message that we need to install sun-java or openjdk
print("""
 This menu will allow you to import or create a valid code signing certificate for the Java Applet attack.

 You will need to purchase a code signing certificate through GoDaddy, Thawte, Verisign, etc. in order to
 make this work. This menu will automate the portions for you to either create the request to submit to the
 certificate authority or allow you to import a code signing certificate that you may already have.

 Note that purchasing a code signing certificate is somewhat difficult. It requires you to have a business name and
 prove the legitimacy of that certificate. That means you have to register a business with the state and everything else.

 Good news is, the process to do that is extremely simple. All in all, it should cost roughly around $300-350 to setup your
 business, buy a code signing certificate, and publish an applet to be whatever you want. You can also do a "DBA" or doing
 business as which is also much easier to use.
""")

core.print_error("*** WARNING ***")
core.print_error("IN ORDER FOR THIS TO WORK YOU MUST INSTALL sun-java6-jdk or openjdk-6-jdk, so apt-get install openjdk-6-jdk")
core.print_error("*** WARNING ***")

# use flag is in case someone already has a code signing certificate, in
# that case it bypasses the "no" answer
use_flag = 0

print("""
[--------------------------------]
Initial Selection Process
[--------------------------------]

There are a few choice here, the first is do you want to import your own Java Applet that you've already signed. If you already have the certificate and want to use the SET applet, you can find an unsigned version under src/html/unsigned/unsigned.jar. If you want to use this menu, you can as well.

Option 1 will import your own SIGNED applet that you already have.
Option 2 will go through the process of either creating the code signing certificate to be submitted to the CA or allow you to import your own certificate. If you already have your certificate and want to have SET handle the signing, this is the option you want.

1. Import your own java applet into SET (needs to be SIGNED).
2. Either create a code-signing csr or use a code-signing certificate you already own.
""")
firstprompt = input("Enter your choice [1-2]: ")
if not firstprompt:
    firstprompt = "2"

# if we want to import our own java applet
if firstprompt == "1":
    newpath = input("Enter the path to the .jar file: ")
    if not os.path.isfile(newpath):
        while True:
            core.print_error("Unable to locate the file. Please try again.")
            newpath = input("Enter the path to the .jar file: ")
            if os.path.isfile(newpath):
                break

    # import into SET
    core.print_status("Importing the applet into SET for weaponization...")
    shutil.copyfile(newpath, os.path.join(core.userconfigpath, "Signed_Update.jar.orig"))
    shutil.copyfile(newpath, os.path.join(core.userconfigpath, "Signed_Update.jar"))
    core.print_status("The applet has been successfully imported into SET.")

# if we want to either generate a certificate or use our own certificate
# this is it
if firstprompt == "2":
    cert_path = ""
    # prompt for a different certificate
    prompt = input(core.setprompt("0", "Have you already generated a code signing-certificate? [yes|no]")).lower()
    # if we selected yes if we generated a code signing certificate
    if prompt == "yes" or prompt == "y":
        # prompt the user to import the code signing certificate
        cert_path = input(core.setprompt("0", "Path to the code signing certificate file (provided by CA)"))
        if not os.path.isfile(cert_path):
            # loop forever
            while True:
                core.print_error("ERROR:Filename not found. Try again.")
                # re-prompt if we didn't file the filename
                cert_path = input(core.setprompt("0", "Path to the .cer certificate file"))
                # if we find the filename then break out of loop
                if os.path.isfile(cert_path):
                    break

        # here is where we import the certificate
        try:
            core.print_info("Importing the certificate into SET...")

            subprocess.Popen("keytool -import -alias MyCert -file {}".format(cert_path), shell=True).wait()
            # trigger that we have our certificate already and bypass the
            # request process below
            use_flag = 1

        # exception here in case it was already imported before
        except:
            pass

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
            answer1 = input(core.setprompt("0", "FQDN (ex. www.thisisafakecert.com)"))
            # grab name of organizaton
            answer2 = input(core.setprompt("0", "Name of the organization"))
            # grab two letter country code
            answer3 = input(core.setprompt("0", "Two letter country code (ex. US)"))
            # if blank, default to US
            if not answer3:
                answer3 = "US"
            # grab state
            answer4 = input(core.setprompt("0", "State"))
            # grab city
            answer5 = input(core.setprompt("0", "City"))
            # generate the request crl
            subprocess.Popen('keytool '
                             '-genkey '
                             '-alias MyCert '
                             '-keyalg RSA '
                             '-keysize 2048 '
                             '-dname "CN={a1},O={a2},C={a3},ST={a4},L={a5}"'.format(a1=answer1,
                                                                                    a2=answer2,
                                                                                    a3=answer3,
                                                                                    a4=answer4,
                                                                                    a5=answer5),
                             shell=True).wait()

            core.print_info("Exporting the cert request to text file...")
            # generate the request and export to certreq
            subprocess.Popen("keytool -certreq -alias MyCert > {}".format(os.path.join(definepath, "certreq.txt")), shell=True).wait()
            core.print_status("Export successful. Exported certificate under the SET root under certreq.txt")
            core.print_warning("You will now need to pay for a code signing certificate through Verisign/Thawte/GoDaddy/etc.")
            core.print_warning("Be sure to purchase a code signing certificate, not a normal website SSL certificate.")
            core.print_info("When finished, enter the path to the .cer file below")
            # cert_path is used for the certificate path when generating

            cert_path = input(core.setprompt("0", "Path for the code signing certificate file (.spc file)"))
            # if we can't find the filename
            if not os.path.isfile(cert_path):
                while True:
                    core.print_error("ERROR:Filename not found. Please try again.")
                    # re-prompt if file name doesn't exist
                    cert_path = input(core.setprompt("0", "Path to the .cer certificate file from Verisign"))
                    # if we detect file, then break out of loop
                    if os.path.isfile(cert_path):
                        break

            # import the certificate
            subprocess.Popen("keytool -import -alias MyCert -file {0}".format(cert_path), shell=True).wait()

    # if our certificate is in the data store
    if os.path.isfile(cert_path):
        # sign the applet with the imported certificate
        subprocess.Popen("jarsigner -signedjar Signed_Update.jar {0} MyCert".format(os.path.join(definepath, "src/html/unsigned/unsigned.jar")), shell=True).wait()
        # move it into our html directory
        subprocess.Popen("mv Signed_Update.jar {0}".format(os.path.join(core.userconfigpath, "Signed_Update.jar.orig")), shell=True).wait()
        # move back to original directory
        core.print_status("Java Applet is now signed and will be imported into the java applet website attack from now on...")
