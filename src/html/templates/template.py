#!/usr/bin/env python
import subprocess
import os
import shutil
import glob
from src.core.setcore import *

me = mod_name()
dest = "src/html/"

debug_msg(me,"entering src.html.templates.template'",1)

#
# used for pre-defined templates
#
print """
  1. Java Required
  2. Google
  3. Facebook
  4. Twitter
  5. Yahoo
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

# if google
if choice == "2":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/google/index.template", "src/html/index.template")
    URL="http://www.google.com"

# if facebook
if choice == "3":
    if os.path.isfile("src/html/index.template"): os.remove("src/html/index.template")
    for files in glob.glob('src/html/templates/facebook/*.*'): shutil.copy(files, "src/html/")
    URL="http://www.facebook.com"

# if twitter
if choice == "4":
    if os.path.isfile("src/html/index.template"): 
      os.remove("src/html/index.template")
    shutil.copyfile("src/html/templates/twitter/index.template", "src/html/index.template")
    URL="http://www.twitter.com"

# if yahoo
if choice =="5":
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
