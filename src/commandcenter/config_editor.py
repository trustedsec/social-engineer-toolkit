#!/usr/bin/python
##############################
#
# Configuration Editor
#
##############################
import subprocess
import os
import sys

# grab SET directory
definepath=os.getcwd()

# open configuration file

counter=0
def html_form(description,field):
    html_char=(r'%s: <input type="text" name="html_param%s" value="%s"/><br />' % (description,counter,field))
    print html_char

# start a loop for the set_config
fileopen=file("config/set_config","r")
for line in fileopen:
    # strip any garbage trailing characters
    line=line.rstrip()
    # grab anything without comments on it
    if line[0:1] != "#": 
        line=line.split("=")
        html_form(line[0],line[1])
        counter=counter+1
