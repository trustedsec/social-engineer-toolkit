#!/usr/bin/env python
# coding=utf-8
import os
import shutil

from src.core.setcore import *

# Py2/3 compatibility
# Python3 renamed raw_input to input
try: input = raw_input
except NameError: pass

dest = ("src/html/")
url = ("")

debug_msg(mod_name(), "entering src.html.templates.template'", 1)

#
# used for pre-defined templates
#
print("""
--------------------------------------------------------
             **** Important Information ****

For templates, when a POST is initiated to harvest
credentials, you will need a site for it to redirect.

You can configure this option under:

      /etc/setoolkit/set.config

Edit this file, and change HARVESTER_REDIRECT and
HARVESTER_URL to the sites you want to redirect to
after it is posted. If you do not set these, then
it will not redirect properly. This only goes for
templates.

--------------------------------------------------------""")

print("""
  1. Java Required
  2. Google
  3. Twitter
""")
choice = raw_input(setprompt(["2"], "Select a template"))

if choice == "exit":
    exit_set()

# file used for nextpage in java applet attack

# if nothing is selected
if choice == "":
    choice = "1"

# if java required
if choice == "1":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/java/index.template", "src/html/index.template")
    url = ""

# if google
if choice == "2":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/google/index.template", "src/html/index.template")
    url = "http://www.google.com"

# if twitter
if choice == "3":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/twitter/index.template", "src/html/index.template")
    url = "http://www.twitter.com"

if not os.path.isdir(os.path.join(userconfigpath, "web_clone")):
    os.makedirs(os.path.join(userconfigpath, "web_clone/"))
if os.path.isfile(os.path.join(userconfigpath, "web_clone/index.html")):
    os.remove(os.path.join(userconfigpath, "web_clone/index.html"))
shutil.copyfile("src/html/index.template", os.path.join(userconfigpath, "web_clone/index.html"))

with open(os.path.join(userconfigpath, "site.template"), 'w') as filewrite:
    filewrite.write("TEMPLATE=SELF\nURL={0}".format(url))

debug_msg(mod_name(), "exiting src.html.templates.template'", 1)
