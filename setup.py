#!/usr/bin/env python
#
# Python installer
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
        print "** SET Dependancy Installer v1.0 **"
        print "** Written by: Dave Kennedy (ReL1K) **"
        print "** Visit: https://www.trustedsec.com **"
        print "\nTo install: setup.py install"

    # if user specified install then lets to the installation
    if installer == True:

        # if we trigger on sources.list then we know its ubuntu
        if os.path.isfile("/etc/apt/sources.list"):

            # force install of debian packages
            subprocess.Popen("apt-get --force-yes -y install git build-essential python-pexpect python-pefile python-crypto python-openssl python-pymssql", shell=True).wait()

        # if sources.list is not available then we're running something offset
        else:
            print "[!] Your not running a Debian variant. Installer not finished for this type of Linux distro."
            print "[!] Install git, python-pexpect, python-crypto, python-openssl, python-pefile manually for all of SET dependancies."
            sys.exit()

        if os.path.isdir("/usr/share/setoolkit"):
            print "[!] SET is already installed in /usr/share/setoolkit, remove and start again."
            sys.exit()

        if not os.path.isfile("/usr/bin/git"):
            print "[-] Install failed. GIT is not installed... SET will not continue." 
            print "[!] Install GIT and run the installer again."
            sys.exit()

        print "[*] Installing SET into the /usr/share/setoolkit folder through git..."		
        subprocess.Popen("git clone https://github.com/trustedsec/social-engineer-toolkit /usr/share/setoolkit", shell=True).wait()
        print "[*] Installing setoolkit installer to /usr/bin/setoolkit..."
        subprocess.Popen("cp /usr/share/setoolkit/se-toolkit /usr/bin", shell=True).wait()
        subprocess.Popen("cp /usr/share/setoolkit/set-update /usr/bin/", shell=True).wait()
        subprocess.Popen("chmod +x /usr/bin/se-toolkit", shell=True).wait()
        print "[*] We are no finished! To run SET, type se-toolkit..."

if platform.system() =='Darwin':
    subprocess.Popen("easy_install pexpect pycrypto pyopenssl pefile pymssql", shell=True).wait()
    print "[!] Note that you will need to install XCODE for OSX and run 'sudo easy_install cython pymssql' to finish."

if platform.system() != "Linux":
    if platform.system != "Darwin":
        print "[!] Sorry this installer is not designed for any other system other than Linux and Mac. Please install the python depends manually."


