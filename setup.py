#!/usr/bin/env python
# coding=utf-8
#
# Python installer
#
import os
import platform
import shutil
import subprocess
import sys


## pre-install sanity checks ##

# if our command option is true then install stuff
if len(sys.argv) != 2 or sys.argv[1] != "install":
    print("** SET Installer **")
    print("** Written by: Dave Kennedy (ReL1K) **")
    print("** Visit: https://www.trustedsec.com **")
    print("\nTo install, run: `# setup.py install'")
    exit()

platformOS = platform.system()
if platformOS not in  ["Linux", "Darwin"]:
    print("[!] Sorry this installer is not designed for %s (only Linux and Mac)"
          ". Please install the Python dependencies manually." % platformOS)

# Check user ID
if os.getuid() != 0:
    print("** SET Installer **")
    print("[!] Please execute as root: `$ sudo python setup.py install'")
    exit()

## SET installation ##

# do install of SET itself
def install(prefix):
    destdir = "%s/share/setoolkit" % prefix
    bindir = "%s/bin" % prefix
    print("[*] Copying setoolkit into the %s directory..." % destdir)
    subprocess.Popen("cp -rf . %s" % destdir, shell=True).wait()

    print("[*] Installing setoolkit runner to %s..." % bindir)
    subprocess.Popen("echo \#!/bin/bash > %s/setoolkit" % bindir, shell=True).wait()
    subprocess.Popen("echo cd {0} >> {1}/setoolkit".format(destdir, bindir), shell=True).wait()
    subprocess.Popen("echo exec python setoolkit $@ >> %s/setoolkit" % bindir, shell=True).wait()
    subprocess.Popen("chmod +x %s/setoolkit" % bindir, shell=True).wait()

    print("[*] Installing setoolkit updater to %s..." % bindir)
    subprocess.Popen("cp {0}/seupdate {1}/".format(destdir, bindir), shell=True).wait()
    subprocess.Popen("chmod +x %s/seupdate" % bindir, shell=True).wait()

    if not os.path.isdir("/etc/setoolkit/"):
        print("[*] Creating setoolkit config dir /etc/setoolkit./..")
        os.makedirs("/etc/setoolkit/")
    if not os.path.isfile("/etc/setoolkit/set.config"):
        print("[*] Installing default setoolkit config to /etc/setoolkit./..")
        shutil.copyfile("src/core/config.baseline", "/etc/setoolkit/set.config")

    print("[*] We are now finished! To run SET, type `setoolkit'...")

# if linux then run installer
if platformOS == "Linux":
    print("[*] Installing dependencies...")

    # if we trigger on sources.list then we know its ubuntu
    if os.path.isfile("/etc/apt/sources.list"):

        # force install of debian packages
        subprocess.Popen("apt-get -y install "
                         "git apache2 python-requests libapache2-mod-php "
                         "python-pymssql build-essential python-pexpect "
                         "python-pefile python-crypto python-openssl", shell=True).wait()

    # If pacman.conf exists, we have a Arch based system
    elif os.path.isfile("/etc/pacman.conf"):
        subprocess.Popen("pacman -S --noconfirm --needed git python2 "
                         "python2-beautifulsoup3 python2-pexpect python2-crypto", shell=True).wait()

        subprocess.Popen("wget https://github.com/erocarrera/pefile/archive/master.zip", shell=True).wait()
        subprocess.Popen("unzip master.zip", shell=True).wait()
        subprocess.Popen("chmod a+x pefile-master/setup.py", shell=True).wait()
        subprocess.Popen("rm -rf pefile-master*", shell=True).wait()

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

    try:
        install(prefix="/usr")
    except Exception as e:
        print("[!] Error installing setoolkit", e)

if platformOS == 'Darwin':
    print("[*] Installing dependencies...")
    subprocess.Popen("easy_install pexpect pycrypto pyopenssl pefile", shell=True).wait()
    try:
        install(prefix="/usr/local")
    except Exception as e:
        print("[!] Error installing setoolkit", e)
