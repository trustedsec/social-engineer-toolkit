#!/usr/bin/env python
import smtplib
import os
import getpass
import sys
import thread
import subprocess
import re
import glob
import random
import time
import base64
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders

# default the email messages to plain text
# unless otherwise specified
message_flag="plain"

# impor the core modules
from src.core.setcore import *

# do we want to track the users that click links
track_email = check_config("TRACK_EMAIL_ADDRESSES=").lower()

definepath = os.getcwd()

# DEFINE SENDMAIL CONFIG and WEB ATTACK
sendmail=0

# need to do this if we aren't in the SET root
if "program_junk" in definepath:
	definepath = definepath.replace("src/program_junk/web_clone", "")

sendmail_file=file("%s/config/set_config" % (definepath),"r").readlines()
for line in sendmail_file:
        # strip carriage returns
        line=line.rstrip()
        match=re.search("SENDMAIL=",line)
        if match: 
                # if match and if line is flipped on continue on
                if line == ("SENDMAIL=ON"):
                        print_info("Sendmail is a Linux based SMTP Server, this can be used to spoof email addresses.")
                        print_info("Sendmail can take up to three minutes to start")
                        print_status("Sendmail is set to ON")
                        sendmail_choice = yesno_prompt(["1"], "Start Sendmail? [yes|no]")
                        # if yes, then do some good stuff
                        if sendmail_choice == "YES":
                                print_info("Sendmail can take up to 3-5 minutes to start")
                                if os.path.isfile("/etc/init.d/sendmail"):
                                        subprocess.Popen("/etc/init.d/sendmail start", shell=True).wait()
                                if not os.path.isfile("/etc/init.d/sendmail"):
                                        pause = raw_input("[!] Sendmail was not found. Try again and restart.")
                                        sys.exit()
                                smtp = ("localhost")
                                port = ("25")
                                # Flip sendmail switch to get rid of some questions             
                                sendmail=1 
                                # just throw user and password to blank, needed for defining below
                                user=''
                                pwd=''

        # Search for SMTP provider we will be using
        match1=re.search("EMAIL_PROVIDER=", line)
        if match1:

                # if we hit on EMAIL PROVIDER
                email_provider=line.replace("EMAIL_PROVIDER=", "").lower()

                # support smtp for gmail
                if email_provider == "gmail":
                        if sendmail == 0:
                                smtp = ("smtp.gmail.com")
                                port = ("587")

                # support smtp for yahoo
                if email_provider == "yahoo":
                        if sendmail == 0:
                                smtp = ("smtp.mail.yahoo.com")
                                port = ("25")

                # support smtp for hotmail
                if email_provider == "hotmail":
                        if sendmail == 0:
                                smtp = ("smtp.hotmail.com")
                                port = ("25")

            
print ("""
   Social Engineer Toolkit Mass E-Mailer

   There are two options on the mass e-mailer, the first would
   be to send an email to one individual person. The second option
   will allow you to import a list and send it to as many people as
   you want within that list.

   What do you want to do:

    1.  E-Mail Attack Single Email Address
    2.  E-Mail Attack Mass Mailer
    
    99. Return to main menu.
   """)

option1=raw_input(setprompt(["5"], ""))

if option1 == 'exit':
        exit_set()

# single email
if option1 == '1':
   to = raw_input(setprompt(["1"], "Send email to"))

# mass emailer
if option1 == '2':
   print ("""
 The mass emailer will allow you to send emails to multiple 
 individuals in a list. The format is simple, it will email
 based off of a line. So it should look like the following:

 john.doe@ihazemail.com
 jane.doe@ihazemail.com
 wayne.doe@ihazemail.com

 This will continue through until it reaches the end of the
 file. You will need to specify where the file is, for example
 if its in the SET folder, just specify filename.txt (or whatever
 it is). If its somewhere on the filesystem, enter the full path, 
 for example /home/relik/ihazemails.txt
""")
   filepath = raw_input(setprompt(["1"], "Path to the file to import into SET"))

# exit mass mailer menu
if option1 == '99': 
        print "Returning to main menu..."
        sys.exit(1)
print ("""\n  1. Use a %s Account for your email attack.\n  2. Use your own server or open relay\n""" % (email_provider)) 
relay = raw_input(setprompt(["1"], ""))

counter=0
# Specify mail Option Here
if relay == '1':
   user = raw_input(setprompt(["1"], "Your %s email address" % (email_provider)))
   user1 = user
   pwd = getpass.getpass("Email password: ")
   #smtp = ("smtp.gmail.com")
   #port = ("587")

# Specify Open-Relay Option Here
if relay == '2':
   user1 = raw_input(setprompt(["1"], "From address (ex: moo@example.com)"))

   if sendmail==0:
      user = raw_input(setprompt(["1"], "Username for open-relay [blank]"))
      pwd =  getpass.getpass("Password for open-relay [blank]: ")

   if sendmail==0:
      smtp = raw_input(setprompt(["1"], "SMTP email server address (ex. smtp.youremailserveryouown.com)"))
      port = raw_input(setprompt(["1"], "Port number for the SMTP server [25]"))
      if port == "":
         port = ("25")

# specify if its a high priority or not
highpri=yesno_prompt(["1"], "Flag this message/s as high priority? [yes|no]")
if not "YES" in highpri:
        prioflag1 = ""
        prioflag2 = ""
else:
        prioflag1 = ' 1 (Highest)'
        prioflag2 = ' High'

subject=raw_input(setprompt(["1"], "Email subject"))
try:
	html_flag=raw_input(setprompt(["1"], "Send the message as html or plain? 'h' or 'p' [p]"))

	# if we are specifying plain or defaulting to plain
	if html_flag == "" or html_flag == "p":
        	message_flag="plain"
	# if we are specifying html 
    	if html_flag == "h":
        	message_flag="html"
	# start the body off blank
    	body = ""
        ## Here we start to check if we want to track users when they click
        ## essentially if this flag is turned on, a quick search and replace
        ## occurs via base64 encoding on the user name. that is then added
        ## during the def mail function call and the username is posted as
        ## part of the URL. When we check the users, they can be coorelated
        ## back to the individual user when they click the link.

        # track email is pulled dynamically from the config as TRACK_EMAIL_ADDRESSES
        if track_email.lower() == "on":
                print "You have specified to track user email accounts when they are sent. In"
                print "order for this to work, you will need to specify the URL within the body"
                print "of the email and where you would like to inject the base64 encoded name."
                print "\nWhen a user clicks on the link, the URL Will post back to SET and track"
                print "each of the users clicks and who the user was. As an example, say my SET"
                print "website is hosted at http://www.trustedsec.com/index.php and I want to track users."
                print "I would type below " + bcolors.BOLD + "http://www.trustedsec.com/index.php?INSERTUSERHERE" + bcolors.ENDC + ". Note that in"
                print "order for SET to work, you will need to specify index.php?INSERTUSERHERE. That is the"
                print "keyword that SET uses in order to replace the base name with the URL."
                print "\nInsert the FULL url and the " + bcolors.BOLD + "INSERTUSERHERE" + bcolors.ENDC + "on where you want to insert the base64 name.\n\nNOTE: You must have a index.php and a ? mark seperating the user. YOU MUST USE PHP!"

    	body=raw_input(setprompt(["1"], "Enter the body of the message, hit return for a new line. Control+c when finished"))

	# loop through until they are finished with the body of the subject line
    	while body != 'exit':
       		try:

          		body+=("\n")
          		body+=raw_input("Next line of the body: ")

		# except KeyboardInterrupts (control-c) and pass through.
		except KeyboardInterrupt:
         	       break

	# if we are tracking emails, this is some cleanup and detection to see if they entered .html instead or didn't specify insertuserhere
        if track_email.lower() == "on":
                # here we replace url with .php if they made a mistake
                body = body.replace(".html", ".php")
                if not "?INSERTUSERHERE" in body:
                        print_error("You have track email to on however did not specify ?INSERTUSERHERE.")
                        print_error("Tracking of users will not work and is disabled. Please re-read the instructions.")
                        pause = raw_input("Press {" + bcolors.BOLD + "return" + bcolors.ENDC + "} to continue.")


# except KeyboardInterrupts (control-c) and pass through.
except KeyboardInterrupt:
    pass

def mail(to, subject, prioflag1, prioflag2, text):

	msg = MIMEMultipart()
        msg['From'] = user1
        msg['To'] = to
        msg['X-Priority'] = prioflag1
        msg['X-MSMail-Priority'] = prioflag2
        msg['Subject'] = subject

        body_type=MIMEText(text, "%s" % (message_flag))
        msg.attach(body_type)

        mailServer = smtplib.SMTP(smtp, port)

        if sendmail == 0:

		if email_provider == "gmail":
			try:
        	                 mailServer.starttls()
                	except: 
				pass
 		               	mailServer.ehlo()

			else: mailServer.ehlo()

 	try:
		if user != "" or pwd != "":
	               mailServer.login(user, pwd)
        	       thread.start_new_thread(mailServer.sendmail,(user, to, msg.as_string()))

	except:
		# try logging in with base64 encoding here
		import base64
		try:
 			mailServer.docmd("AUTH LOGIN", base64.b64encode(user))
			mailServer.docmd(base64.b64encode(pwd), "")

		# except exceptions and print incorrect passowrd
		except Exception, e: 
			print_warning("It appears your password was incorrect.\nPrinting response: "+(str(e)))
                	return_continue()

	if sendmail == 1: 
		thread.start_new_thread(mailServer.sendmail,(user, to, msg.as_string()))    

# if we specified a single address
if option1 == '1':
	# re-assign body to temporary variable to not overwrite original body
	body_new = body
	## if we specify to track users, this will replace the INSERTUSERHERE with the "TO" field.
	if track_email.lower() == "on":
		body_new = body_new.replace("INSERTUSERHERE", base64.b64encode(to))
	# call the function to send email
	mail(to,subject,prioflag1,prioflag2,body_new)

# if we specified the mass mailer for multiple users
if option1 == '2':
	email_num=0
	fileopen=file(filepath, "r").readlines()
	for line in fileopen:
        	to = line.rstrip()
	  	# re-assign body to temporary variable to not overwrite original body
	  	body_new = body
	  	## if we specify to track users, this will replace the INSERTUSERHERE with the "TO" field.
	  	if track_email.lower() == "on":
			body_new = body_new.replace("INSERTUSERHERE", base64.b64encode(to))
		# send the actual email
          	mail(to,subject,prioflag1,prioflag2,body_new)
          	email_num=email_num+1
		# simply print the statement
          	print_status("Sent e-mail number: " + (str(email_num)) + " to address: " + to)

# finish up here
print_status("SET has finished sending the emails")
return_continue()
