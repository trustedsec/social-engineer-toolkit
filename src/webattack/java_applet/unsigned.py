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
