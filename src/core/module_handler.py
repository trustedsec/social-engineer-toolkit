#!/usr/bin/env python

# module_handler.py

import glob
import re
import sys
from src.core.setcore import *

# this is just if the user wants to return to menu
menu_return = "false"

# base counter to identify numbers
counter = 0

# get the menu going
print("\n")
print_info_spaces("Social-Engineer Toolkit Third Party Modules menu.")
print_info_spaces(
    "Please read the readme/modules.txt for information on how to create your own modules.\n")

for name in glob.glob("modules/*.py"):

    counter = counter + 1
    fileopen = open(name, "r")

    for line in fileopen:
        line = line.rstrip()
        match = re.search("MAIN=", line)
        if match:
            line = line.replace('MAIN="', "")
            line = line.replace('"', "")
            line = "  " + str(counter) + ". " + line
            print(line)

print("\n  99. Return to the previous menu\n")
choice = raw_input(setprompt(["9"], ""))

if choice == 'exit':
    exit_set()

if choice == '99':
    menu_return = "true"

# throw error if not integer
try:
    choice = int(choice)
except:
    print_warning("An integer was not used try again")
    choice = raw_input(setprompt(["9"], ""))

# start a new counter to match choice
counter = 0

if menu_return == "false":
    # pull any files in the modules directory that starts with .py
    for name in glob.glob("modules/*.py"):

        counter = counter + 1

        if counter == int(choice):
            # get rid of .modules extension
            name = name.replace("modules/", "")
            # get rid of .py extension
            name = name.replace(".py", "")
            # changes our system path to modules so we can import the files
            sys.path.append("modules/")
            # this will import the third party module

            try:
                exec("import " + name)
            except:
                pass

            # this will call the main() function inside the python file
            # if it doesn't exist it will still continue just throw a warning
            try:
                exec("%s.main()" % (name))
            # handle the exception if main isn't there
            except Exception as e:
                raw_input("   [!] There was an issue with a module: %s." % (e))
                return_continue()
