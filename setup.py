#!/usr/bin/env python
# coding=utf-8
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
    installer = False

    # Check user ID
    if os.getuid() != 0:
        print("Are you root? Please execute as root")
        exit()

    try:
        # if our command option is true then install stuff
        if sys.argv[1] == "install":
            installer = True

    # if index is out of range then flag options
    except IndexError:
        print("** SET Dependency Installer **")
        print("** Written by: Dave Kennedy (ReL1K) **")
        print("** Visit: https://www.trustedsec.com **")
        print("\nTo install: setup.py install")

    # if user specified install then lets to the installation
    if installer is True:

        # if we trigger on sources.list then we know its ubuntu
        if os.path.isfile("/etc/apt/sources.list"):

            # force install of debian packages
            subprocess.Popen("apt-get --force-yes -y install "
                             "git apache2 python-requests libapache2-mod-php "
                             "python-pymssql build-essential python-pexpect "
                             "python-pefile python-crypto python-openssl", shell=True).wait()

        # If pacman.conf exists, we have a Arch based system
        elif os.path.isfile("/etc/pacman.conf"):
            subprocess.Popen("pacman -S --noconfirm --needed git python2 "
                             "python2-beautifulsoup3 python2-pexpect python2-crypto", shell=True).wait()

            subprocess.Popen("wget https://pefile.googlecode.com/files/pefile-1.2.10-139.tar.gz", shell=True).wait()
            subprocess.Popen("tar xvfz pefile-1.2.10-139.tar.gz", shell=True).wait()
            subprocess.Popen("chmod a+x pefile-1.2.10-139/setup.py", shell=True).wait()
            subprocess.Popen("rm -rf pefile-1.2.10-139*", shell=True).wait()

        # if dnf.conf is there, we are dealing with a >= fedora 22 - added thanks to whoismath pr
        elif os.path.isfile("/etc/dnf/dnf.conf"):
            subprocess.Popen("dnf -y install git python-pexpect python-pefile python-crypto pyOpenSSL", shell=True).wait()

        # if sources.list or pacman.conf is not available then we're running
        # something offset
        else:
            print("[!] You're not running a Debian, Fedora or Arch variant. Installer not finished for this type of Linux distro.")
            print("[!] Install git, python-pexpect, python-crypto, python-openssl, python-pefile manually for all of SET dependancies.")
            sys.exit()

        if os.path.isdir("/usr/share/setoolkit"):
            print("[!] SET is already installed in /usr/share/setoolkit. Remove and start again.")
            sys.exit()

        if not os.path.isfile("/usr/bin/git"):
            print("[-] Install failed. GIT is not installed. SET will not continue.")
            print("[!] Install GIT and run the installer again.")
            sys.exit()

        print("[*] Copying SET into the /usr/share/setoolkit directory...")
        cwdpath = os.getcwd()
        subprocess.Popen("cd ..;cp -rf %s /usr/share/setoolkit" % cwdpath, shell=True).wait()
        print("[*] Installing setoolkit installer to /usr/bin/setoolkit...")
        subprocess.Popen("echo #!/bin/bash > /usr/bin/setoolkit", shell=True).wait()
        subprocess.Popen("echo cd /usr/share/setoolkit >> /usr/bin/setoolkit", shell=True).wait()
        subprocess.Popen("echo exec python2 setoolkit $@ >> /usr/bin/setoolkit", shell=True).wait()
        subprocess.Popen("cp /usr/share/setoolkit/seupdate /usr/bin/", shell=True).wait()
        subprocess.Popen("chmod +x /usr/bin/setoolkit", shell=True).wait()
        #print("[*] Note you will manually need to install Core Security 'Impacket'")
        #print("[*] Download link: http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket")
        # https://impacket.googlecode.com/files/impacket-0.9.10.tar.gz
        #print("[*] Once downloaded, tar -zxvf impacket*, go to the directory and run python setup.py install.")
        print("[*] We are now finished! To run SET, type setoolkit...")

if platform.system() == 'Darwin':
    subprocess.Popen("easy_install pexpect pycrypto pyopenssl pefile", shell=True).wait()

if platform.system() not in  ["Linux", "Darwin"]:
    print("[!] Sorry this installer is not designed for any other system other "
          "than Linux and Mac. Please install the Python dependencies manually.")
