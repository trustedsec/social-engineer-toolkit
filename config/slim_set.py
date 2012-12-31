#!/usr/bin/python
import subprocess
#
#
# small script to slim down set
#
#
choice=raw_input("Do you want to slim the size of SET down? This will remove SET interactive payloads and other executables.\nEnter your choice [yes|no]: ")
if choice == "y" or choice == "yes":
        if os.path.isfile("src/payloads/set_payloads/set.payload"):
                path = "src/payloads/set_payloads/"
        if os.path.isfile("../src/payloads/set_payloads/set.payload"):
                path = "../src/payloads/set_payloads/"
        subprocess.Popen("rm -rf %s/* 1> /dev/null 2> /dev/null" % (path), shell=True).wait()
        print "Done. Be sure to change the set_config to SET_PAYLOADS=OFF"
