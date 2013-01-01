#!/usr/bin/env python
#
# Python installer
#
# I could use others to build it for me but find I like to customize my installers.
#
import subprocess
import sys
import os
import platform

# if nix then run installer
if platform.system() == "Linux":
    # give installer a null value
    installer=""

    try:
        # if our command option is true then install stuff
        if sys.argv[1] == "install":
            installer = True

    # if index is out of range then flag options
    except IndexError:
        print "** SET Dependancy Installer v0.2 **"
        print "\nTo install: setup.py install" 

    # if user specified install then lets to the installation
    if installer == True:

        # if we trigger on sources.list then we know its ubuntu
        if os.path.isfile("/etc/apt/sources.list"):
        
            # force install of debian packages 
            subprocess.Popen("apt-get --force-yes -y install build-essential python-pexpect python-beautifulsoup python-pefile python-crypto python-openssl python-pymssql", shell=True).wait()

        # if sources.list is not available then we're running something offset
        else:
            print "[*] Your not running a Debian variant. Installer not finished for this type of Linux distro."
            print "[*] Install subversion, python-pexpect, python-beautifulsoup, python-crypto, python-openssl, python-pefile manually for all of SET dependancies."
            sys.exit()

if platform.system() =='Darwin':
	subprocess.Popen("easy_install pexpect beautifulsoup pycrypto pyopenssl pefile pymssql beautifulsoup", shell=True).wait()
	print "[!] Note that you will need to install XCODE for OSX and run 'sudo easy_install cython pymssql' to finish."

if platform.system != "Linux":
	if platform.system != "Darwin":
		print "[!] Sorry this installer is not designed for any other system other than Linux and Mac. Please install the python depends manually."
