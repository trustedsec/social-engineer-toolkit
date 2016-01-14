#!/usr/bin/python
#
# simple jar file
#
import subprocess
import os
subprocess.Popen("rm Java_Update.jar", stderr=subprocess.PIPE,
                 stdout=subprocess.PIPE, shell=True)
subprocess.Popen("rm Java.class", stderr=subprocess.PIPE,
                 stdout=subprocess.PIPE, shell=True)
subprocess.Popen("javac Java.java", shell=True).wait()
subprocess.Popen("jar cvf Java_Update.jar Java.class", shell=True).wait()
subprocess.Popen("jar ufm Java_Update.jar manifest.mf", shell=True).wait()
subprocess.Popen(
    "cp Java_Update.jar ../../html/unsigned/unsigned.jar", shell=True)
print("[*] Jar file exported as Java_Update.jar")
