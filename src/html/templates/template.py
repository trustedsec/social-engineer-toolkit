#!/usr/bin/env python
# coding=utf-8
import os
import shutil

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

dest = "src/html/"
url = ""

core.debug_msg(core.mod_name(), "entering src.html.templates.template'", 1)

#
# used for pre-defined templates
#
print("""
  1. Java Required
  2. Google
  3. Facebook
  4. Twitter
  5. Yahoo
""")
choice = raw_input(core.setprompt(["2"], "Select a template"))

if choice == "exit":
    core.exit_set()

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

# if facebook
if choice == "3":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/facebook/index.template", "src/html/index.template")
    url = "http://www.facebook.com"

# if twitter
if choice == "4":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/twitter/index.template", "src/html/index.template")
    url = "http://www.twitter.com"

# if yahoo
if choice == "5":
    if os.path.isfile("src/html/index.template"):
        os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/yahoo/index.template", "src/html/index.template")
    url = "http://mail.yahoo.com"

if not os.path.isdir(os.path.join(core.userconfigpath, "web_clone")):
    os.makedirs(os.path.join(core.userconfigpath, "web_clone/"))
if os.path.isfile(os.path.join(core.userconfigpath, "web_clone/index.html")):
    os.remove(os.path.join(core.userconfigpath, "web_clone/index.html"))
shutil.copyfile("src/html/index.template", os.path.join(core.userconfigpath, "web_clone/index.html"))

with open(os.path.join(core.userconfigpath, "site.template"), 'w') as filewrite:
    filewrite.write("TEMPLATE=SELF\nURL={0}".format(url))

core.debug_msg(core.mod_name(), "exiting src.html.templates.template'", 1)
