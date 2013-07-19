#!/usr/bin/env python
import subprocess
import os
import shutil
from src.core.setcore import *

me = mod_name()

debug_msg(me,"entering src.html.templates.template'",1)

#
# used for pre-defined templates
#
print """
  1. Java Required
  2. Gmail
  3. Google
  4. Facebook
  5. Twitter
  6. Yahoo
"""
choice=raw_input(setprompt(["2"],"Select a template"))

if choice == "exit":
    exit_set()

# file used for nextpage in java applet attack
filewrite=file(setdir + "/site.template", "w")

# if nothing is selected
if choice == "": choice = "1"

# if java required
if choice == "1":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/java/index.template", "src/html/index.template")
    URL=""

# if gmail
if choice == "2":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/gmail/index.template", "src/html/index.template")
    URL="https://gmail.com"

# if google
if choice == "3":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/google/index.template", "src/html/index.template")
    URL="http://www.google.com"

# if facebook
if choice == "4":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/facebook/index.template", "src/html/index.template")
    URL="http://www.facebook.com"

# if twitter
if choice == "5":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/twitter/index.template", "src/html/index.template")
    URL="http://www.twitter.com"

# if yahoo
if choice =="6":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/yahoo/index.template", "src/html/index.template")
    URL="http://mail.yahoo.com"

if not os.path.isdir(setdir + "/web_clone"):
    os.makedirs(setdir + "/web_clone/")
if os.path.isfile(setdir + "/web_clone/index.html"): os.remove(setdir + "/web_clone/index.html")
shutil.copyfile("src/html/index.template", setdir + "/web_clone/index.html")
filewrite.write("TEMPLATE=SELF" + "\n"+"URL=%s" % (URL))
filewrite.close()

debug_msg(me,"exiting src.html.templates.template'",1)
