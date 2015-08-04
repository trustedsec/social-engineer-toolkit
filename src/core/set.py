#!/usr/bin/env python
#########################################
#
# The Social-Engineer Toolkit
# Written by: David Kennedy (ReL1K)
#
###############################################
import shutil
import os
import time
import re
import sys
import socket
from src.core.setcore import *
from src.core.menu import text

me = mod_name()
###############################################
# Define path and set it to the SET root dir
###############################################

definepath = os.getcwd()
sys.path.append(definepath)

################################################
# ROOT CHECK
################################################

# grab the operating system
operating_system = check_os()

# grab metasploit path
msf_path = meta_path()

if operating_system == "posix":
    if os.geteuid() != 0:
        print "\n The Social-Engineer Toolkit (SET) - by David Kennedy (ReL1K)"
        print "\n Not running as root. \n\nExiting the Social-Engineer Toolkit (SET).\n"
        sys.exit(1)

define_version = get_version()

try:
    while 1:
        show_banner(define_version, '1')

       ###################################################
       #        USER INPUT: SHOW MAIN MENU               #
       ###################################################
        debug_msg(me, "printing 'text.main'", 5)
        show_main_menu = create_menu(text.main_text, text.main)

        # special case of list item 99
        print '\n  99) Return back to the main menu.\n'

        main_menu_choice = (raw_input(setprompt("0", "")))

        if main_menu_choice == 'exit':
            break

        if operating_system == "windows" or msf_path == False:
            if main_menu_choice == "1" or main_menu_choice == "4" or main_menu_choice == "8" or main_menu_choice == "3":
                print_warning("Sorry. This feature is not yet supported in Windows or Metasploit was not found.")
                return_continue()
                break

        if main_menu_choice == '1': #'Spearphishing Attack Vectors
            while 1:

             ###################################################
             #        USER INPUT: SHOW SPEARPHISH MENU         #
             ###################################################


                if operating_system != "windows":
                    debug_msg(me, "printing 'text.spearphish_menu'", 5)
                    show_spearphish_menu = create_menu(text.spearphish_text, text.spearphish_menu)
                    spearphish_menu_choice = raw_input(setprompt(["1"], ""))

                    if spearphish_menu_choice == 'exit':
                        exit_set()

                    if spearphish_menu_choice == 'help':
                        print text.spearphish_text

                    # Spearphish menu choice 1: Perform a Mass Email Attack
                    if spearphish_menu_choice == '1':
                        sys.path.append("src/core/msf_attacks/")
                        debug_msg(me, "importing 'src.core.msf_attacks.create_payload'", 1)
                        try:
                            reload(create_payload)
                        except:
                            pass
                        import create_payload
                    # Spearphish menu choice 2: Create a FileFormat Payload
                    if spearphish_menu_choice == '2':
                        sys.path.append("src/core/msf_attacks/")
                        debug_msg(me, "importing 'src.core.msf_attacks.create_payload'", 1)
                        try:
                            reload(create_payload)
                        except:
                            import create_payload
                    #Spearphish menu choice 3: Create a Social-Engineering Template
                    if spearphish_menu_choice == '3':
                        debug_msg(me, "calling function 'custom_template' from 'src.core.setcore'", 3)
                        custom_template()
                    #Spearphish menu choice 99
                    if spearphish_menu_choice == '99': break

 #####################
 # Web Attack Menu
 #####################
        # Main Menu choice 2: Website Attack Vectors
        if main_menu_choice == '2':
            while 1:

    ###################################################
    #        USER INPUT: SHOW WEB ATTACK MENU         #
    ###################################################

                debug_msg(me, "printing 'text.webattack_menu'", 5)
                show_webattack_menu = create_menu(text.webattack_text, text.webattack_menu)
                attack_vector = raw_input(setprompt(["2"], ""))
                choice3 = ""
                if attack_vector == 'exit':
                    exit_set()

                if attack_vector == "":
                    debug_msg(me, "no attack vector entered, defaulting to '1) Java Applet Attack Method'", 3)
                    attack_vector = "1"

                # check unsupported features
                if operating_system == "windows" or msf_path == False:
                    if attack_vector == "2" or attack_vector == "9":
                        print_warning("Sorry. This option is not yet available in Windows or Metasploit was not found.")
                        return_continue()
                        break

                # full screen attack vector
                if attack_vector == '7':
                    # dont need site cloner
                    site_cloned = False
                    # skip nat section and exit out
                    choice3 = "-1"
                    sys.path.append("src/webattack/fsattack")
                    debug_msg(me, "importing 'src.webattack.fsaattack'", 1)
                    try:
                        reload(full)
                    except:
                        import full

                # Web Attack menu choice 9: Return to the Previous Menu
                if attack_vector == '99': break

                try:
                    attack_check = int(attack_vector)
                except:
                    print_error("ERROR:Invalid selection, going back to menu.")
                    break
                if attack_check > 9:
                    print_warning("Invalid option")
                    return_continue()
                    break


                ###############################################################
                # HTA ATTACK VECTOR METHOD HERE
                ###############################################################
                if attack_vector == '8':
                        from src.webattack.hta.main import *
                        # update config
                        update_options("ATTACK_VECTOR=HTA")
                        gen_hta_cool_stuff()
                        attack_vector = "hta"
			print_status("Automatically starting Apache for you...")
			subprocess.Popen("service apache2 start", shell=True).wait()

                # Removed to delete MLITM
                if attack_vector != "99999":

                    ###################################################
                    #     USER INPUT: SHOW WEB ATTACK VECTORS MENU    #
                    ###################################################

                    if attack_vector != "7":
                        debug_msg(me, "printing 'text.webattack_vectors_menu'", 5)
                        show_webvectors_menu = create_menu(text.webattack_vectors_text, text.webattack_vectors_menu)
                        print '  99) Return to Webattack Menu\n'
                        choice3 = raw_input(setprompt(["2"], ""))

                        if choice3 == 'exit':
                            exit_set()

                        if choice3 == "99": break

                        if choice3 == "quit" or choice3 == '4': break


                try:
                    # write our attack vector to file to be called later
		    #print definepath()
                    #os.chdir(definepath)
                    filewrite = file(setdir + "/attack_vector", "w")

                    # webjacking and web templates are not allowed
                    if attack_vector == "5" and choice3 == "1":
                        print bcolors.RED+ "\n Sorry, you can't use the Web Jacking vector with Web Templates."+ bcolors.ENDC
                        return_continue()
                        break

                    # if we select multiattack, web templates are not allowed
                    if attack_vector == "6" and choice3 == "1":
                        print bcolors.RED+ "\n Sorry, you can't use the Multi-Attack vector with Web Templates." + bcolors.ENDC
                        return_continue()
                        break

                    # if we select web template and tabnabbing, throw this error and bomb out to menu
                    if attack_vector == "4" and choice3 == "1":
                        print bcolors.RED+ "\n Sorry, you can only use the cloner option with the tabnabbing method." + bcolors.ENDC
                        return_continue()
                        break

                    # if attack vector is default or 1 for java applet
                    if attack_vector == '': attack_vector = '1'
                    # specify java applet attack
                    if attack_vector == '1':
                        attack_vector = "java"
                        filewrite.write(attack_vector)
                        filewrite.close()

                    # specify browser exploits
                    if attack_vector == '2':
                        attack_vector = "browser"
                        filewrite.write(attack_vector)
                        filewrite.close()

                    if attack_vector == '': attack_vector = '3'
                    # specify web harvester method
                    if attack_vector == '3':
                        attack_vector = "harvester"
                        filewrite.write(attack_vector)
                        filewrite.close()
                        print_info("Credential harvester will allow you to utilize the clone capabilities within SET")
                        print_info("to harvest credentials or parameters from a website as well as place them into a report")

                    # specify tab nabbing attack vector
                    if attack_vector == '4':
                        attack_vector = "tabnabbing"
                        filewrite.write(attack_vector)
                        filewrite.close()

                    # specify webjacking attack vector
                    if attack_vector == "5":
                        attack_vector = "webjacking"
                        filewrite.write(attack_vector)
                        filewrite.close()

                    # specify Multi-Attack Vector
                    attack_vector_multi = ""
                    if attack_vector == '6':
                        # trigger the multiattack flag in SET
                        attack_vector = "multiattack"
                        # write the attack vector to file
                        filewrite.write(attack_vector)
                        filewrite.close()

                    # pull ip address
                    if choice3 != "-1":
                        fileopen = file("/etc/setoolkit/set.config", "r").readlines()
                        for line in fileopen:
                            line = line.rstrip()
                            match = re.search("AUTO_DETECT=ON", line)
                            if match:
                                try:
                                    ipaddr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    ipaddr.connect(('google.com', 0))
                                    ipaddr.settimeout(2)
                                    ipaddr = ipaddr.getsockname()[0]
                                    update_options("IPADDR=" + ipaddr)
                                except Exception, error:
                                    log(error)
                                    ipaddr = raw_input(setprompt(["2"], "Your interface IP Address"))
                                    update_options("IPADDR=" + ipaddr)

                        # if AUTO_DETECT=OFF prompt for IP Address
                        for line in fileopen:
                            line = line.rstrip()
                            match = re.search("AUTO_DETECT=OFF", line)
                            if match:
                                if attack_vector != "harvester":
                                    if attack_vector != "tabnabbing":
                                        if attack_vector != "webjacking":
					    if attack_vector != "hta":
	                                            # this part is to determine if NAT/port forwarding is used
	                                            # if it is it'll prompt for additional questions
	                                            print_info("NAT/Port Forwarding can be used in the cases where your SET machine is")
	                                            print_info("not externally exposed and may be a different IP address than your reverse listener.")
	                                            nat_or_fwd = yesno_prompt('0', 'Are you using NAT/Port Forwarding [yes|no]')
	                                            if nat_or_fwd == "YES":
	                                                ipquestion = raw_input(setprompt(["2"], "IP address to SET web server (this could be your external IP or hostname)"))
	
	                                                filewrite2 = file(setdir + "/interface", "w")
	                                                filewrite2.write(ipquestion)
	                                                filewrite2.close()
	                                                # is your payload/listener on a different IP?
	                                                natquestion = yesno_prompt(["2"], "Is your payload handler (metasploit) on a different IP from your external NAT/Port FWD address [yes|no]")
	                                                if natquestion == 'YES':
	                                                    ipaddr = raw_input(setprompt(["2"], "IP address for the reverse handler (reverse payload)"))
	                                                if natquestion == "NO":
	                                                    ipaddr = ipquestion
	                                            # if you arent using NAT/Port FWD
	                                            if nat_or_fwd == "NO":
	                                                print_info("Enter the IP address of your interface IP or if your using an external IP, what")
	                                                print_info("will be used for the connection back and to house the web server (your interface address)")
	                                                ipaddr = raw_input(setprompt(["2"], "IP address or hostname for the reverse connection"))
	                                                # here we check if they are using a hostname else we loop through until they have a legit one
	                                                if validate_ip(ipaddr) == False:
	                                                    while 1:
	                                                        choice = raw_input(setprompt(["2"], "This is not an IP address. Are you using a hostname? [y/n] "))
	                                                        if choice == "" or choice.lower() == "y":
	                                                            print_status("Roger that. Using hostnames moving forward..")
	                                                            break
	                                                        else:
	                                                            ipaddr = raw_input(setprompt(["2"], "IP address for the reverse connection"))
	                                                            if validate_ip(ipaddr) == True: break

                                if attack_vector == "harvester" or attack_vector == "tabnabbing" or attack_vector == "webjacking":
                                    print_info("This option is used for what IP the server will POST to.")
                                    print_info("If you're using an external IP, use your external IP for this")
                                    ipaddr = raw_input(setprompt(["2"], "IP address for the POST back in Harvester/Tabnabbing"))
				if check_options("IPADDR=") != 0: ipaddr = check_options("IPADDR=")
                                update_options("IPADDR=" + ipaddr)

                        # if java applet attack
                        if attack_vector == "java":
                            applet_choice()

                    # Select SET quick setup
                    if choice3 == '1':

                            # get the template ready
                        sys.path.append("src/html/templates")
                        debug_msg(me, "importing src.html.templates.template'", 1)
                        try:
                            reload(template)
                        except:
                            import template

                        # grab browser exploit selection
                        if attack_vector == "browser":
                                # grab clientattack
                            sys.path.append("src/webattack/browser_exploits")
                            debug_msg(me, "line 357: importing 'src.webattack.browser_exploits.gen_payload'", 1)
                            try:
                                reload(gen_payload)
                            except:
                                import gen_payload

                        # arp cache attack, will exit quickly
                        # if not in config file
                        sys.path.append("src/core/arp_cache")
                        debug_msg(me, "line 364: importing 'src.core.arp_cache.arp'", 1)
                        try:
                            reload(arp)
                        except:
                            import arp

                        # actual website attack here
                        # web_server.py is main core
                        sys.path.append("src/html/")

                        # clean up stale file
                        if os.path.isfile(setdir + "/cloner.failed"):
                            os.remove(setdir + "/cloner.failed")

                        site_cloned = True

                        debug_msg(me, "line 375: importing 'src.webattack.web_clone.cloner'", 1)
                        try: reload(src.webattack.web_clone.cloner)
                        except: import src.webattack.web_clone.cloner

                        # grab java applet attack
                        if attack_vector == "java":
                            debug_msg(me, "importing 'src.core.payloadgen.create_payloads'", 1)
                            try: reload(src.core.payloadgen.create_payloads)
                            except: import src.core.payloadgen.create_payloads

                        if os.path.isfile(setdir + "/cloner.failed"):
                            site_cloned = False

                        if site_cloned == True:

                            # cred harvester for auto site here
                            if attack_vector == "harvester" or attack_vector == "tabnabbing" or attack_vector == "webjacking":
                                if attack_vector == "tabnabbing" or attack_vector == "webjacking":
                                    debug_msg(me, "importing 'src.webattack.tabnabbing.tabnabbing'", 1)
                                    try:reload(src.webattack.tabnabbing)
                                    except: import src.webattack.tabnabbing
                                # start web cred harvester here
                                # sys.path.append("src/webattack/harvester")
                                debug_msg(me, "importing 'src.webattack.harvester.harvester'", 1)
                                try: reload(src.webattack.harvester.harvester)
                                except: import src.webattack.harvester.harvester

                            # if we are using profiler lets prep everything to get ready
                            if attack_vector == "profiler":
                                from src.webattack.profiler.webprofiler import *
                                prep_website()

                            if attack_vector != "harvester":
                                if attack_vector != "tabnabbing":
                                    if attack_vector != "multiattack":
                                        if attack_vector != "webjacking":
                                            if attack_vector != "multiattack":
                                                if attack_vector != "profiler":
						    if attack_vector != "hta":
	                                                    # spawn web server here
	                                                    debug_msg(me, "importing 'src.html.spawn'", 1)
	                                                    import src.html.spawn


                            # multi attack vector here
                            if attack_vector == "multiattack":
                                if choice3 == "1":
                                    try:
                                        filewrite = file("src/progam_junk/multiattack.template","w")
                                        filewrite.write("TEMPLATE=TRUE")
                                        filewrite.close()
                                    except:
                                        pass
                                    debug_msg(me, "importing 'src.webattack.multi_attack.multiattack'", 1)
                                    import src.webattack.multi_attack.multiattack


                    # Create a website clone
                    if choice3 == '2':
                        # flag that we want a custom website
                        sys.path.append("src/webattack/web_clone/")
                        if os.path.isfile(setdir + "/site.template"):
                            os.remove(setdir + "/site.template")
                        filewrite = file(setdir + "/site.template", "w")
                        filewrite.write("TEMPLATE=CUSTOM")
                        print_info("SET supports both HTTP and HTTPS")
                        # specify the site to clone
                        print_info("Example: http://www.thisisafakesite.com")
                        URL = raw_input(setprompt(["2"], "Enter the url to clone"))
                        match = re.search("http://", URL)
                        match1 = re.search("https://", URL)
                        if not match:
                            if not match1:
                                URL = ("http://"+URL)

                        match2 = re.search("facebook.com", URL)
                        if match2:
                            URL = ("https://login.facebook.com/login.php")

                        # changed based on new landing page for gmail.com
                        match3 = re.search("gmail.com", URL)
                        if match3: URL = ("https://accounts.google.com")

                        filewrite.write("\nURL=%s" % (URL))
                        filewrite.close()

                        # grab browser exploit selection
                        if attack_vector == "browser":
                            # grab clientattack
                            sys.path.append("src/webattack/browser_exploits")
                            debug_msg(me, "importing 'src.webattack.browser_exploits.gen_payload'", 1)
                            try:
                                reload(gen_payload)
                            except:
                                import gen_payload

                        # set site cloner to true
                        site_cloned = True

                        if attack_vector != "multiattack":
                            # import our website cloner

                            site_cloned = True
                            debug_msg(me, "importing 'src.webattack.web_clone.cloner'", 1)
                            try:
                                reload(src.webattack.web_clone.cloner)
                            except:
                                import src.webattack.web_clone.cloner

                            if os.path.isfile(setdir + "/cloner.failed"):
                                site_cloned = False

                        if site_cloned == True:

                            if attack_vector == "java":
                                # import our payload generator
                                debug_msg(me, "importing 'src.core.payloadgen.create_payloads'", 1)
                                try:
                                    reload(src.core.payloadgen.create_payloads)
                                except:
                                    import src.core.payloadgen.create_payloads

                            # arp cache if applicable
                            sys.path.append("src/core/arp_cache")
                            debug_msg(me, "line 500: importing 'src.core.arp_cache.arp'", 1)
                            try:
                                reload(arp)
                            except:
                                import arp

                            # tabnabbing and harvester selection here
                            if attack_vector == "harvester" or attack_vector == "tabnabbing" or attack_vector == "webjacking":
                                if attack_vector == "tabnabbing" or attack_vector == "webjacking":
                                    sys.path.append("src/webattack/tabnabbing")
                                    debug_msg(me, "importing 'src.webattack.tabnabbing.tabnabbing'", 1)
                                    try:
                                        reload(tabnabbing)
                                    except:
                                        import tabnabbing
                                sys.path.append("src/webattack/harvester")
                                debug_msg(me, "importing 'src.webattack.harvester.harvester'", 1)

                                try:
                                    reload(harvester)
                                except:
                                    import harvester

                            # multi_attack vector here
                            if attack_vector == "multiattack":
                                sys.path.append("src/webattack/multi_attack/")
                                debug_msg(me, "importing 'src.webattack.multi_attack.multiattack'", 1)
                                try:
                                    reload(multiattack)
                                except:
                                    import multiattack

                            # if we arent using credential harvester or tabnabbing
                            if attack_vector != "harvester":
                                if attack_vector != "tabnabbing":
                                    if attack_vector != "multiattack":
                                        if attack_vector != "webjacking":
						if attack_vector != "hta":
	                                            sys.path.append("src/html")
	                                            debug_msg(me, "importing 'src.html.spawn'", 1)
	                                            try:
	                                                reload(spawn)
	                                            except:
	                                                import spawn

                    # Import your own site
                    if choice3 == '3':

                        sys.path.append("src/webattack/web_clone/")
                        if os.path.isfile(setdir + "/site.template"):
                            os.remove(setdir + "/site.template")
                        filewrite = file(setdir + "/site.template", "w")
                        filewrite.write("TEMPLATE=SELF")
                        # specify the site to clone
                        if not os.path.isdir(setdir + "/web_clone"):
                            os.makedirs(setdir + "/web_clone")
                        print_warning("Example: /home/website/ (make sure you end with /)")
                        print_warning("Also note that there MUST be an index.html in the folder you point to.")
                        URL = raw_input(setprompt(["2"], "Path to the website to be cloned"))
                        if not URL.endswith("/"):
                            if not URL.endswith("index.html"):
                                URL = URL + "/"
                        if not os.path.isfile(URL+"index.html"):
                            if os.path.isfile(URL):
                                shutil.copyfile("%s" % (URL), setdir + "/web_clone/index.html")
                            if not os.path.isfile(URL):
                                if URL.endswith("index.html"):
                                    shutil.copyfile(URL, "%s/web_clone/index.html" % (setdir))
                                else:
                                    print_error("ERROR:index.html not found!!")
                                    print_error("ERROR:Did you just put the path in, not file?")
                                    print_error("Exiting the Social-Engineer Toolkit...Hack the Gibson.\n")
                                    exit_set()

                        if os.path.isfile(URL+"index.html"):
                            print_status("Index.html found. Do you want to copy the entire folder or just index.html?")
                            choice = raw_input("\n1. Copy just the index.html\n2. Copy the entire folder\n\nEnter choice [1/2]: ")
                            if choice == "1" or choice == "":
                                if os.path.isfile("%s/web_clone/index.html" % (setdir)):
                                    os.remove("%s/web_clone/index.html" % (setdir))
                                shutil.copyfile(URL + "index.html", "%s/web_clone/" % (setdir))
                            if choice == "2":
                                if os.path.isdir(URL + "src/webattack"):
                                    print_error("You cannot specify a folder in the default SET path. This goes into a loop Try something different.")
                                    URL = raw_input("Enter the folder to import into SET, this CANNOT be the SET directory: ")
                                    if os.path.isdir(URL + "src/webattack" % (URL)):
                                        print_error("You tried the same thing. Exiting now.")
                                        sys.exit()
                                copyfolder(URL, "%s/web_clone/" % setdir)

                        filewrite.write("\nURL=%s" % (URL))
                        filewrite.close()

                        # if not harvester then load up cloner
                        if attack_vector == "java" or attack_vector == "browser":
                            # import our website cloner
                            debug_msg(me, "importing 'src.webattack.web_clone.cloner'", 1)
                            import src.webattack.web_clone.cloner

                        # if java applet attack
                        if attack_vector == "java":
                            # import our payload generator

                            debug_msg(me, "importing 'src.core.payloadgen.create_payloads'", 1)
                            import src.core.payloadgen.create_payloads

                        # grab browser exploit selection
                        if attack_vector == "browser":
                            # grab clientattack
                            sys.path.append("src/webattack/browser_exploits")
                            debug_msg(me, "importing 'src.webattack.browser_exploits.gen_payload'", 1)
                            try:
                                reload(gen_payload)
                            except:
                                import gen_payload

                        # arp cache if applicable
                        sys.path.append("src/core/arp_cache")
                        debug_msg(me, "line 592: importing 'src.core.arp_cache.arp'", 1)
                        try:
                            reload(arp)
                        except:
                            import arp

                        # if not harvester spawn server
                        if attack_vector == "java" or attack_vector == "browser":
                                # import web_server and do magic
                            sys.path.append("src/html")
                            debug_msg(me, "importing 'src.html.spawn'", 1)
                            try:
                                reload(spawn)
                            except:
                                import spawn

                        # cred harvester for auto site here
                        if attack_vector == "harvester":
                            # get the url
                            print_info("Example: http://www.blah.com")
                            URL = raw_input(setprompt(["2"], "URL of the website you imported"))
                            match = re.search("http://", URL)
                            match1 = re.search("https://", URL)
                            if not match:
                                if not match1:
                                    URL = ("http://"+URL)
                            filewrite = file(setdir + "/site.template","w")
                            filewrite.write("\nURL=%s" % (URL))
                            filewrite.close()

                            # start web cred harvester here
                            sys.path.append("src/webattack/harvester")
                            debug_msg(me, "importing 'src.webattack.harvester.harvester'", 1)
                            try:
                                reload(harvester)
                            except:
                                import harvester

                        # tabnabbing for auto site here
                        if attack_vector == "tabnabbing" or attack_vector == "webjacking":
                            # get the url
                            print_info("Example: http://www.blah.com")
                            URL = raw_input(setprompt(["2"], "URL of the website you imported"))
                            match = re.search("http://", URL)
                            match1 = re.search("https://", URL)
                            if not match:
                                if not match1:
                                    URL = ("http://"+URL)
                            filewrite = file(setdir + "/site.template","w")
                            filewrite.write("\nURL=%s" % (URL))
                            filewrite.close()
                            # start tabnabbing here
                            sys.path.append("src/webattack/tabnabbing")
                            debug_msg(me, "importing 'src.webattack.tabnabbing.tabnabbing'", 1)
                            try:
                                reload(tabnabbing)
                            except:
                                import tabnabbing

                            # start web cred harvester here
                            sys.path.append("src/webattack/harvester")
                            debug_msg(me, "importing 'src.webattack.harvester.harvester'", 1)
                            try:
                                reload(harvester)
                            except:
                                import harvester

                        # multi attack vector here
                        if attack_vector == "multiattack":
                            try:
                                filewrite = file("src/progam_junk/multiattack.template","w")
                                filewrite.write("TEMPLATE=TRUE")
                                filewrite.close()
                            except:
                                pass
                            debug_msg(me, "importing 'src.webattack.multi_attack.multiattack'", 1)
                            import src.webattack.multi_attack.multiattack


                    # Return to main menu
                    if choice3 == '4':
                        print (" Returning to main menu.\n")
                        break
                except KeyboardInterrupt:
                    print " Control-C detected, bombing out to previous menu.."
                    break

        # Define Auto-Infection USB/CD Method here
        if main_menu_choice == '3':

                ###################################################
                #     USER INPUT: SHOW INFECTIOUS MEDIA MENU      #
                ###################################################
                # Main Menu choice 3: Infectious Media Generator
            debug_msg(me, "printing 'text.infectious_menu'", 5)
            show_infectious_menu = create_menu(text.infectious_text, text.infectious_menu)
            infectious_menu_choice = raw_input(setprompt(["3"], ""))

            if infectious_menu_choice == 'exit':
                exit_set()

            if infectious_menu_choice == "99":
                menu_back()

            if infectious_menu_choice == "":
                infectious_menu_choice = "1"

            # if fileformat
            if infectious_menu_choice == "1":
                ipaddr = raw_input(setprompt(["3"], "IP address for the reverse connection (payload)"))
                update_options("IPADDR=" + ipaddr)

            filewrite1 = file(setdir + "/payloadgen", "w")
            filewrite1.write("payloadgen=solo")
            filewrite1.close()

            # if choice is file-format
            if infectious_menu_choice == "1":
                filewrite = file(setdir + "/fileformat.file","w")
                filewrite.write("fileformat=on")
                filewrite.close()
                sys.path.append("src/core/msf_attacks/")
                debug_msg(me, "importing 'src.core.msf_attacks.create_payload'", 1)
                try:
                    reload(create_payload)
                except:
                    import create_payload

            # if choice is standard payload
            if infectious_menu_choice == "2":
		# trigger set options for infectious media
		update_options("INFECTION_MEDIA=ON")
		try: import src.core.payloadgen.solo
		except: reload(src.core.payloadgen.solo)

	    # if we aren't exiting, then launch autorun
            if infectious_menu_choice != "99":
		try: import src.autorun.autolaunch
		except: reload(src.autorun.autolaunch)


        #
        #
        # Main Menu choice 4: Create a Payload and Listener
        #
        #
        if main_menu_choice == '4':
	    update_options("PAYLOADGEN=SOLO")
	    import src.core.payloadgen.solo
	    #try: import src.core.payloadgen.solo
	    #except: reload(src.core.payloadgen.solo)
            # if the set payload is there
            if os.path.isfile(setdir + "/msf.exe"):
                shutil.copyfile(setdir + "/msf.exe", "payload.exe")
            return_continue()

        # Main Menu choice 5: Mass Mailer Attack
        if main_menu_choice == '5':
            debug_msg(me, "importing 'src.phishing.smtp.client.smtp_web'", 1)
            try: reload(src.phishing.smtp.client.smtp_web)
            except: import src.phishing.smtp.client.smtp_web

        # Main Menu choice 6: Teensy USB HID Attack Vector
        if main_menu_choice == '6':

            ###################################################
            #        USER INPUT: SHOW TEENSY MENU             #
            ###################################################
            debug_msg(me, "printing 'text.teensy_menu'", 5)
            show_teensy_menu = create_menu(text.teensy_text, text.teensy_menu)
            teensy_menu_choice = raw_input(setprompt(["6"], ""))

            if teensy_menu_choice == 'exit':
                exit_set()

            # if not return to main menu
            yes_or_no = ''

            if teensy_menu_choice != "99":
                # set our teensy info file in program junk
                filewrite = file(setdir + "/teensy", "w")
                filewrite.write(teensy_menu_choice+"\n")
                if teensy_menu_choice != "3" and teensy_menu_choice != "7" and teensy_menu_choice !="8" and teensy_menu_choice !="9" and teensy_menu_choice !="10" and teensy_menu_choice != "11" and teensy_menu_choice != "12" and teensy_menu_choice != "13":
                    yes_or_no = yesno_prompt("0","Do you want to create a payload and listener [yes|no]: ")
                    if yes_or_no == "YES":
                        filewrite.write("payload")
                        filewrite.close()
                        # load a payload
                        sys.path.append("src/core/payloadgen")
                        debug_msg(me, "importing 'src.core.payloadgen.create_payloads'", 1)
                        try:
                            reload(create_payloads)
                        except:
                            import create_payloads
                if yes_or_no == "NO":
                    filewrite.close()
                # need these default files for web server load
                filewrite = file(setdir + "/site.template", "w")
                filewrite.write("TEMPLATE=CUSTOM")
                filewrite.close()
                filewrite = file(setdir + "/attack_vector", "w")
                filewrite.write("hid")
                filewrite.close()
                # if we are doing binary2teensy
                if teensy_menu_choice != "7" and teensy_menu_choice !="8" and teensy_menu_choice != "9" and teensy_menu_choice !="10" and teensy_menu_choice != "11" and teensy_menu_choice != "12":
                    sys.path.append("src/teensy")
                    debug_msg(me, "importing 'src.teensy.teensy'", 1)
                    try:
                        reload(teensy)
                    except:
                        import teensy
                if teensy_menu_choice == "7":
                    debug_msg(me, "importing 'src.teensy.binary2teensy'", 1)
                    import src.teensy.binary2teensy
                # if we are doing sd2teensy attack
                if teensy_menu_choice == "8":
                    debug_msg(me, "importing 'src.teensy.sd2teensy'", 1)
                    import src.teensy.sd2teensy

                # if we are doing the sd2teensy osx attack
                if teensy_menu_choice == "9":
                    print_status("Generating the SD2Teensy OSX pde file for you...")
                    if not os.path.isdir(setdir + "/reports/osx_sd2teensy"):
                        os.makedirs(setdir + "/reports/osx_sd2teensy")
                    shutil.copyfile("src/teensy/osx_sd2teensy.pde", "%s/reports/osx_sd2teensy/osx_sd2teensy.pde" % (setdir))
                    print_status("File has been exported to ~/.set/reports/osx_sd2teensy/osx_sd2teensy.pde")
                    return_continue()

                # if we are doing the X10 Arduino Sniffer
                if teensy_menu_choice == "10":
                    print_status("Generating the Arduino sniffer and libraries pde..")
                    if not os.path.isdir(setdir + "/reports/arduino_sniffer"):
                        os.makedirs(setdir + "/reports/arduino_sniffer")
                    shutil.copyfile("src/teensy/x10/x10_sniffer.pde", setdir + "/reports/arduino_sniffer/x10_sniffer.pde")
                    shutil.copyfile("src/teensy/x10/libraries.zip", setdir + "/reports/arduino_sniffer/libraries.zip")
                    print_status("Arduino sniffer files and libraries exported to ~/.set/reports/arduino_sniffer")
                    return_continue()

                # if we are doing the X10 Jammer
                if teensy_menu_choice == "11":
                    print_status("Generating the Arduino jammer pde and libraries...")
                    if not os.path.isdir(setdir + "/reports/arduino_jammer"):
                        os.makedirs(setdir + "/reports/arduino_jammer")
                    shutil.copyfile("src/teensy/x10/x10_blackout.pde", setdir + "/reports/arduino_jammer/x10_blackout.pde")
                    shutil.copyfile("src/teensy/x10/libraries.zip", setdir + "/reports/arduino_hammer/libraries.zip")
                    print_status("Arduino jammer files and libraries exported to ~/.set/reports/arduino_jammer")
                    return_continue()

                # powershell shellcode injection
                if teensy_menu_choice == "12":
                    print_status("Generating the Powershell - Shellcode injection pde..")
                    debug_msg(me, "importing 'src.teensy.powershell_shellcode'", 1)
                    import src.teensy.powershell_shellcode

            if teensy_menu_choice == "99": teensy_menu_choice = None

        #
        # Main Menu choice 8: Wireless Attack Point Attack Vector
        #
        if main_menu_choice == '7':

            if operating_system == "windows":
                print_warning("Sorry. The wireless attack vector is not yet supported in Windows.")
                return_continue()

            if operating_system != "windows":

                # set path to nothing
                airbase_path = ""
                dnsspoof_path = ""
                # need to pull the SET config file
                fileopen = file("/etc/setoolkit/set.config", "r")
                for line in fileopen:
                    line = line.rstrip()
                    match = re.search("AIRBASE_NG_PATH=", line)
                    if match:
                        airbase_path = line.replace("AIRBASE_NG_PATH=", "")

                    match1 = re.search("DNSSPOOF_PATH=", line)
                    if match1: dnsspoof_path = line.replace("DNSSPOOF_PATH=", "")

                if not os.path.isfile(airbase_path):
                    if not os.path.isfile("/usr/local/sbin/airbase-ng"):
                        print_warning("Warning airbase-ng was not detected on your system. Using one in SET.")
                        print_warning("If you experience issues, you should install airbase-ng on your system.")
                        print_warning("You can configure it through the set_config and point to airbase-ng.")
                        airbase_path = ("src/wireless/airbase-ng")
                    if os.path.isfile("/usr/local/sbin/airbase-ng"):
                        airbase_path = "/usr/local/sbin/airbase-ng"

                if not os.path.isfile(dnsspoof_path):
                    if os.path.isfile("/usr/local/sbin/dnsspoof"):
                        dnsspoof_path = "/usr/local/sbin/dnsspoof"
                    if os.path.isfile("/usr/sbin/dnsspoof"):
                        dnsspoof_path = "/usr/sbin/dnsspoof"

                # if we can find airbase-ng
                if os.path.isfile(airbase_path):
                    if os.path.isfile(dnsspoof_path):
                        # start the menu here
                        while 1:

                                ###################################################
                                #        USER INPUT: SHOW WIRELESS MENU           #
                                ###################################################
                            debug_msg(me, "printing 'text.wireless_attack_menu'", 5)
                            show_wireless_menu = create_menu(text.wireless_attack_text, text.wireless_attack_menu)
                            wireless_menu_choice = raw_input(setprompt(["8"], ""))
                            # if we want to start access point
                            if wireless_menu_choice == "1":
                                sys.path.append("src/wireless/")
                                debug_msg(me, "importing 'src.wireless.wifiattack'", 1)
                                try:
                                    reload(wifiattack)
                                except:
                                    import wifiattack

                            # if we want to stop the wifi attack
                            if wireless_menu_choice == "2":
                                sys.path.append("src/wireless/")
                                debug_msg(me, "importing 'src.wireless.stop_wifiattack'", 1)
                                try:
                                    reload(stop_wifiattack)
                                except:
                                    import stop_wifiattack

                            # if we want to return to the main menu
                            if wireless_menu_choice == "99":
                                print (" [*] Returning to the main menu ...")
                                break

                if not os.path.isfile(dnsspoof_path):
                    if not os.path.isfile("/usr/local/sbin/dnsspoof"):
                        print_error("ERROR:DNS Spoof was not detected. Check the set_config file.")
                        return_continue()

        #
        # END WIFI ATTACK MODULE
        #


        # Main Menu choice 9: QRCode Generator
        if main_menu_choice == '8':
            try:
                from PIL import Image, ImageDraw
                from src.qrcode.qrgenerator import *
                print """
The QRCode Attack Vector will create a QRCode for you with whatever URL you want.

When you have the QRCode Generated, select an additional attack vector within SET and
deploy the QRCode to your victim. For example, generate a QRCode of the SET Java Applet
and send the QRCode via a mailer.
"""
                url = raw_input("Enter the URL you want the QRCode to go to (99 to exit): ")
                if url != "99":
                    # if the reports directory does not exist then create it
                    if not os.path.isdir("%s/reports" % (setdir)):
                        os.makedirs("%s/reports" % (setdir))
                    gen_qrcode(url)
                    return_continue()

            except ImportError:
                    print_error("This module requires python-imaging to work properly.")
                    print_error("In Ubuntu do apt-get install python-imaging")
                    print_error("Else refer to here for installation: http://code.google.com/appengine/docs/python/images/installingPIL.html")
                    return_continue()

        # Main Menu choice 10: PowerShell Attacks
        if main_menu_choice == '9':
            try: import src.powershell.powershell
            except: reload(src.powershell.powershell)

        # Main Menu choice 11: Third Party Modules
        if main_menu_choice == '10':
            sys.path.append("src/core")
            debug_msg(me, "importing 'src.core.module_handler'", 1)
            try:
                reload(module_handler)
            except:
                import module_handler

        # Main Menu choice 99: Exit the Social-Engineer Toolkit
        if main_menu_choice == '99':
            break

# handle keyboard interrupts
except KeyboardInterrupt:
    print "\n\n Thank you for " + bcolors.RED+"shopping" + bcolors.ENDC+" with the Social-Engineer Toolkit.\n\n Hack the Gibson...and remember...hugs are worth more than handshakes.\n"
