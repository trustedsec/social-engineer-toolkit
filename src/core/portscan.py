#
#
# SET SIMPLE PORT SCANNER
#
#

from src.core.setcore import *
import socket
import sys
import Queue
import re
import thread
import threading
import time

MAX_THREADS = 200
host_list = ""

class Scanner(threading.Thread):
    def __init__(self, inq, outq):
        threading.Thread.__init__(self)
        self.setDaemon(1)
        # queues for (host, port)
        self.inq = inq
        self.outq = outq

    def run(self):
        while 1:
            host, port = self.inq.get()
            sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sd.settimeout(1.0)
            try:
                # connect to the given host:port
                sd.connect((host, port))
            except socket.error:
                # set the CLOSED flag
                self.outq.put((host, port, 'CLOSED'))
                sd.close()
            else:
                self.outq.put((host, port, 'OPEN'))
                sd.close()

def scan(host, start, stop):
    global host_list
    toscan = Queue.Queue()
    scanned = Queue.Queue()
    host_down = 0
    scanners = [Scanner(toscan, scanned)]
    for scanner in scanners:
        scanner.start()

    hostports = [(host, port) for port in xrange(start, stop+1)]
    for hostport in hostports:
        toscan.put(hostport)

    results = {}
    for host, port in hostports:
        while (host, port) not in results:
            nhost, nport, nstatus = scanned.get()
            results[(nhost, nport)] = nstatus
        status = results[(host, port)]
        if status <> 'CLOSED':
                port_open = '%s:%d %s' % (host, port, status)
                print_status(port_open)
                host_list = host_list + "," + port_open               
                host_down = 1

    # if no hosts were up then report host down
    if host_down == 0:
                return False
    # else host is up and return those hosts
    if host_down == 1:
                time.sleep(1)
                #host_list = str(host_list[1:])
                return host_list

# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - 2007

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified
def printCIDR(c,lowport,highport):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        ipaddr = bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            ipaddr = bin2ip(ipPrefix+dec2bin(i, (32-subnet)))
            ip_check = is_valid_ip(ipaddr)
            if ip_check != False:
                scan(str(ipaddr), int(lowport), int(highport))
                time.sleep(1)

# input validation routine for the CIDR block specified
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            #print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True

# start the actual stuff to grab cidr and port scan    
def launch(cidrBlock,lowport,highport):
        print_status("SET is now scanning the IPs specified... please be patient.")    
        if not validateCIDRBlock(cidrBlock):
                # validate its really an ip address if solo
                ip_check = is_valid_ip(cidrBlock)
                if ip_check != False:
                        print_status("CIDR notation not specified. Trying single IP address.")
                        scan(cidrBlock, int(lowport), int(highport))
                        return host_list
                else:
                        print_warning("Invalid IP Address, try again.")
        else:
                printCIDR(cidrBlock,lowport,highport)
                return host_list

