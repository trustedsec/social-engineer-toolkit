#!/usr/bin/python
#
# simple jar file
#
import subprocess
import os
subprocess.Popen("rm Java_Update.jar", stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
subprocess.Popen("rm Java.class", stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
subprocess.Popen("javac Java.java", shell=True).wait()
subprocess.Popen("jar cvf Java_Update.jar Java.class", shell=True).wait()
print "[*] Jar file exported as Java_Update.jar"
pause = raw_input("Sign and import the new java file into SET? [yes|no]")
if pause == "yes" or pause == "y":
    print """
Simply enter in the required fields, easy example below:

Name: FakeCompany
Organization: Fake Company
Organization Name: Fake Company
City: Cleveland
State: Ohio
Country: US
Is this correct: yes

"""
    print """*** WARNING ***\nIN ORDER FOR THIS TO WORK YOU MUST INSTALL sun-java6-jdk or openjdk-6-jdk, so apt-get install openjdk-6-jdk\n*** WARNING ***"""
    # grab keystore to use later
    subprocess.Popen("keytool -genkey -alias signapplet2 -keystore mykeystore -keypass mykeypass -storepass mystorepass", shell=True).wait()
    # self-sign the applet
    subprocess.Popen("jarsigner -keystore mykeystore -storepass mystorepass -keypass mykeypass -signedjar Signed_Update.jar Java_Update.jar signapplet2", shell=True).wait()
    # move it into our html directory
    subprocess.Popen("rm ../../html/Signed_Update.jar.orig", shell=True).wait()
    subprocess.Popen("cp Signed_Update.jar ../../html/Signed_Update.jar.orig", shell=True).wait()
    subprocess.Popen("cp Java_Update.jar ../../html/unsigned/unsigned.jar", shell=True).wait()
    print "[*] New java applet has been successfully imported into The Social-Engineer Toolkit (SET)"
