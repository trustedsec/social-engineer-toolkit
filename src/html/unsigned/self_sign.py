#!/usr/bin/env python
# coding=utf-8

import os
import subprocess

import src.core.setcore as core

#########################
# Simple signer for signing the java applet attack
#########################

# create Key: keytool -genkey -alias signapplet -keystore mykeystore -keypass mykeypass -storepass mystorepass
# sign: jarsigner -keystore mykeystore -storepass mystorepass -keypass
# mykeypass -signedjar SignedMicrosoft.jar oMicrosoft.jar signapplet

os.chdir("src/html/unsigned")

print("""
 Simply enter in the required fields, easy example below:

 Name: FakeCompany
 Organization: Fake Company
 Organization Name: Fake Company
 City: Cleveland
 State: Ohio
 Country: US
 Is this correct: yes
""")

core.print_error("*** WARNING ***")
core.print_error("IN ORDER FOR THIS TO WORK YOU MUST INSTALL sun-java6-jdk or openjdk-6-jdk, so apt-get install openjdk-6-jdk")
core.print_error("*** WARNING ***")

# random string used to generate signature of java applet
random_string = core.generate_random_string(10, 30)

# grab keystore to use later
subprocess.Popen("keytool -genkey -alias {0} "
                 "-keystore mykeystore "
                 "-keypass mykeypass "
                 "-storepass mystorepass".format(random_string), shell=True).wait()

# self-sign the applet
subprocess.Popen("jarsigner -keystore mykeystore "
                 "-storepass mystorepass "
                 "-keypass mykeypass "
                 "-signedjar Signed_Update.jar unsigned.jar {0}".format(random_string), shell=True).wait()

# move it into our html directory
subprocess.Popen("cp Signed_Update.jar ../", shell=True).wait()
subprocess.Popen("mv Signed_Update.jar {0}".format(core.userconfigpath), shell=True)

# move back to original directory
os.chdir("../../../")
core.print_status("Java Applet is now signed and will be imported into the website")
