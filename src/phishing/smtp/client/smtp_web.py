#!/usr/bin/env python
import smtplib
import os
import getpass
import sys
import subprocess
import re
import glob
import random
import time
import base64
# fix for python2 to 3 compatibility
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO
import email
import email.encoders
import email.mime.text
import email.mime.base
try:
    from email.MIMEMultipart import MIMEMultipart
except:
    from email.mime.multipart import MIMEMultipart
try:
    from email.MIMEBase import MIMEBase
except:
    from email.mime.base import MIMEBase
try:
    from email.MIMEText import MIMEText
except:
    from email.mime.text import MIMEText
from email.header import Header
from email.generator import Generator
try:
    from email import Charset
except:
    from email import charset as Charset
try:
    from email import Encoders
except:
    from email import encoders as Encoders

Charset.add_charset('utf-8', Charset.BASE64, Charset.BASE64, 'utf-8')

# default the email messages to plain text
# unless otherwise specified
message_flag = "plain"

# import the core modules
from src.core.setcore import *

# do we want to track the users that click links
track_email = check_config("TRACK_EMAIL_ADDRESSES=").lower()

definepath = os.getcwd()

# DEFINE SENDMAIL CONFIG and WEB ATTACK
sendmail = 0

sendmail_file = open("/etc/setoolkit/set.config", "r").readlines()
for line in sendmail_file:
    # strip carriage returns
    line = line.rstrip()
    match = re.search("SENDMAIL=", line)
    if match:
        # if match and if line is flipped on continue on
        if line == ("SENDMAIL=ON"):
            print_info(
                "Sendmail is a Linux based SMTP Server, this can be used to spoof email addresses.")
            print_info("Sendmail can take up to three minutes to start")
            print_status("Sendmail is set to ON")
            sendmail_choice = yesno_prompt(["1"], "Start Sendmail? [yes|no]")
            # if yes, then do some good stuff
            if sendmail_choice == "YES":
                print_info("Sendmail can take up to 3-5 minutes to start")
                if os.path.isfile("/etc/init.d/sendmail"):
                    subprocess.Popen(
                        "/etc/init.d/sendmail start", shell=True).wait()

                # added for osx
                if not os.path.isfile("/usr/sbin/sendmail"):
                    if not os.path.isfile("/etc/init.d/sendmail"):
                        pause = input("[!] Sendmail was not found. Try again and restart. (For Kali - apt-get install sendmail-bin)")
                        sys.exit()
                smtp = ("localhost")
                port = ("25")
                # Flip sendmail switch to get rid of some questions
                sendmail = 1
                # just throw provideruser and password to blank, needed for
                # defining below
                provideruser = ''
                pwd = ''

    # Search for SMTP provider we will be using
    match1 = re.search("EMAIL_PROVIDER=", line)
    if match1:

        # if we hit on EMAIL PROVIDER
        email_provider = line.replace("EMAIL_PROVIDER=", "").lower()

        # support smtp for gmail
        if email_provider == "gmail":
            if sendmail == 0:
                smtp = ("smtp.gmail.com")
                port = ("587")

        # support smtp for yahoo
        if email_provider == "yahoo":
            if sendmail == 0:
                smtp = ("smtp.mail.yahoo.com")
                port = ("587")

        # support smtp for hotmail
        if email_provider == "hotmail":
            if sendmail == 0:
                smtp = ("smtp.live.com")
                port = ("587")


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

option1 = input(setprompt(["5"], ""))

if option1 == 'exit':
    exit_set()

# single email
if option1 == '1':
    to = input(setprompt(["1"], "Send email to"))

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
    filepath = input(
        setprompt(["1"], "Path to the file to import into SET"))
    if not os.path.isfile(filepath):
        while 1:
            print(
                "[!] File not found! Please try again and enter the FULL path to the file.")
            filepath = input(
                setprompt(["1"], "Path to the file to import into SET"))
            if os.path.isfile(filepath):
                break

# exit mass mailer menu
if option1 == '99':
    print("Returning to main menu...")

if option1 != "99":
    print(("""\n  1. Use a %s Account for your email attack.\n  2. Use your own server or open relay\n""" % (
        email_provider)))
    relay = input(setprompt(["1"], ""))

    counter = 0
    # Specify mail Option Here
    if relay == '1':
        provideruser = input(
            setprompt(["1"], "Your %s email address" % (email_provider)))
        from_address = provideruser
        from_displayname = input(
            setprompt(["1"], "The FROM NAME the user will see"))
        pwd = getpass.getpass("Email password: ")

    # Specify Open-Relay Option Here
    if relay == '2':
        from_address = input(
            setprompt(["1"], "From address (ex: moo@example.com)"))
        from_displayname = input(
            setprompt(["1"], "The FROM NAME the user will see"))
        if sendmail == 0:
            # Ask for a username and password if we aren't using sendmail
            provideruser = input(
                setprompt(["1"], "Username for open-relay [blank]"))
            pwd = getpass.getpass("Password for open-relay [blank]: ")

        if sendmail == 0:
            smtp = input(setprompt(
                ["1"], "SMTP email server address (ex. smtp.youremailserveryouown.com)"))
            port = input(
                setprompt(["1"], "Port number for the SMTP server [25]"))
            if port == "":
                port = ("25")

    # specify if its a high priority or not
    highpri = yesno_prompt(
        ["1"], "Flag this message/s as high priority? [yes|no]")
    if not "YES" in highpri:
        prioflag1 = ""
        prioflag2 = ""
    else:
        prioflag1 = ' 1 (Highest)'
        prioflag2 = ' High'

    # if we want to attach a file
    file_format = ""
    yesno = raw_input("Do you want to attach a file - [y/n]: ")
    if yesno.lower() == "y" or yesno.lower() == "yes":
        file_format = raw_input(
            "Enter the path to the file you want to attach: ")
        if not os.path.isfile(file_format):
            file_format = ""

    inline_files = []
    while True:
        yesno = raw_input("Do you want to attach an inline file - [y/n]: ")
        if yesno.lower() == "y" or yesno.lower() == "yes":
            inline_file = raw_input(
                "Enter the path to the inline file you want to attach: ")
            if os.path.isfile(inline_file):
                inline_files.append( inline_file )
        else:
            break

    subject = input(setprompt(["1"], "Email subject"))
    try:
        html_flag = input(
            setprompt(["1"], "Send the message as html or plain? 'h' or 'p' [p]"))

        # if we are specifying plain or defaulting to plain
        if html_flag == "" or html_flag == "p":
            message_flag = "plain"
        # if we are specifying html
        if html_flag == "h":
            message_flag = "html"
        # start the body off blank
        body = ""
        # Here we start to check if we want to track users when they click
        # essentially if this flag is turned on, a quick search and replace
        # occurs via base64 encoding on the user name. that is then added
        # during the def mail function call and the username is posted as
        # part of the URL. When we check the users, they can be coorelated
        # back to the individual user when they click the link.

        # track email is pulled dynamically from the config as
        # TRACK_EMAIL_ADDRESSES
        if track_email.lower() == "on":
            print(
                "You have specified to track user email accounts when they are sent. In")
            print(
                "order for this to work, you will need to specify the URL within the body")
            print(
                "of the email and where you would like to inject the base64 encoded name.")
            print(
                "\nWhen a user clicks on the link, the URL Will post back to SET and track")
            print(
                "each of the users clicks and who the user was. As an example, say my SET")
            print(
                "website is hosted at http://www.trustedsec.com/index.php and I want to track users.")
            print("I would type below " + bcolors.BOLD +
                  "http://www.trustedsec.com/index.php?INSERTUSERHERE" + bcolors.ENDC + ". Note that in")
            print(
                "order for SET to work, you will need to specify index.php?INSERTUSERHERE. That is the")
            print(
                "keyword that SET uses in order to replace the base name with the URL.")
            print("\nInsert the FULL url and the " + bcolors.BOLD + "INSERTUSERHERE" + bcolors.ENDC +
                  "on where you want to insert the base64 name.\n\nNOTE: You must have a index.php and a ? mark seperating the user. YOU MUST USE PHP!")
            print(
                "\nNote that the actual URL does NOT need to contain index.php but has to be named that for the php code in Apache to work.")
        print_warning(
            "IMPORTANT: When finished, type END (all capital) then hit {return} on a new line.")
        body = input(setprompt(
            ["1"], "Enter the body of the message, type END (capitals) when finished"))

        # loop through until they are finished with the body of the subject
        # line
        while body != 'exit':
            try:

                body += ("\n")
                body_1 = input("Next line of the body: ")
                if body_1 == "END":
                    break
                else:
                    body = body + body_1

            # except KeyboardInterrupts (control-c) and pass through.
            except KeyboardInterrupt:
                break

        # if we are tracking emails, this is some cleanup and detection to see
        # if they entered .html instead or didn't specify insertuserhere
        if track_email.lower() == "on":
            # here we replace url with .php if they made a mistake
            body = body.replace(".html", ".php")
            if not "?INSERTUSERHERE" in body:
                print_error(
                    "You have track email to on however did not specify ?INSERTUSERHERE.")
                print_error(
                    "Tracking of users will not work and is disabled. Please re-read the instructions.")
                pause = input(
                    "Press {" + bcolors.BOLD + "return" + bcolors.ENDC + "} to continue.")

    # except KeyboardInterrupts (control-c) and pass through.
    except KeyboardInterrupt:
        pass


def mail(to, subject, prioflag1, prioflag2, text):

    msg = MIMEMultipart()
    msg['From'] = str(
        Header(from_displayname, 'UTF-8').encode() + ' <' + from_address + '> ')
    msg['To'] = to
    msg['X-Priority'] = prioflag1
    msg['X-MSMail-Priority'] = prioflag2
    msg['Subject'] = Header(subject, 'UTF-8').encode()

    body_type = MIMEText(text, "%s" % (message_flag), 'UTF-8')
    msg.attach(body_type)

    # now attach the file
    if file_format != "":
        fileMsg = email.mime.base.MIMEBase('application', '')
        fileMsg.set_payload(file(file_format).read())
        email.encoders.encode_base64(fileMsg)
        fileMsg.add_header(
            'Content-Disposition', 'attachment; filename="%s"' % os.path.basename(file_format) )
        msg.attach(fileMsg)

    for inline_file in inline_files:
        if inline_file != "":
            fileMsg = email.mime.base.MIMEBase('application', '')
            fileMsg.set_payload(file(inline_file).read())
            email.encoders.encode_base64(fileMsg)
            fileMsg.add_header(
                'Content-Disposition', 'inline; filename="%s"' % os.path.basename(inline_file) )
            fileMsg.add_header( "Content-ID", "<%s>" % os.path.basename(inline_file) )
            msg.attach(fileMsg)

    mailServer = smtplib.SMTP(smtp, port)

    io = StringIO()
    msggen = Generator(io, False)
    msggen.flatten(msg)

    if sendmail == 0:

        if email_provider == "gmail" or email_provider == "yahoo" or email_provider == "hotmail":
            try:
                mailServer.starttls()
            except:
                pass
                mailServer.ehlo()

            else:
                mailServer.ehlo()

    try:
        if provideruser != "" or pwd != "":
            mailServer.login(provideruser, pwd)
            mailServer.sendmail(from_address, to, io.getvalue())
        else:
            mailServer.sendmail(from_address, to, io.getvalue())
    except:
        # try logging in with base64 encoding here
        import base64
        try:
            mailServer.docmd("AUTH LOGIN", base64.b64encode(provideruser))
            mailServer.docmd(base64.b64encode(pwd), "")

        # except exceptions and print incorrect password
        except Exception as e:
            print_warning(
                "It appears your password was incorrect.\nPrinting response: " + (str(e)))
            return_continue()

    if sendmail == 1:
        mailServer.sendmail(from_address, to, io.getvalue())

# if we specified a single address
if option1 == '1':
    # re-assign body to temporary variable to not overwrite original body
    body_new = body
    # if we specify to track users, this will replace the INSERTUSERHERE with
    # the "TO" field.
    if track_email.lower() == "on":
        body_new = body_new.replace("INSERTUSERHERE", base64.b64encode(to))
    # call the function to send email
    try:
        mail(to, subject, prioflag1, prioflag2, body_new)
    except socket.error:
        print_error(
            "Unable to establish a connection with the SMTP server. Try again.")
        sys.exit()
    except KeyboardInterrupt:
        print_error("Control-C detected, exiting out of SET.")
        sys.exit()
#    except Exception as err:
#        print_error("Something went wrong.. Printing error: " + str(err))
#        sys.exit()

# if we specified the mass mailer for multiple users
if option1 == '2':
    email_num = 0
    fileopen = open(filepath, "r").readlines()
    for line in fileopen:
        to = line.rstrip()
        # re-assign body to temporary variable to not overwrite original body
        body_new = body
        # if we specify to track users, this will replace the INSERTUSERHERE
        # with the "TO" field.
        if track_email.lower() == "on":
            body_new = body_new.replace("INSERTUSERHERE", base64.b64encode(to))
        # send the actual email
        time_delay = check_config("TIME_DELAY_EMAIL=").lower()
        time.sleep(int(time_delay))
        mail(to, subject, prioflag1, prioflag2, body_new)
        email_num = email_num + 1
        # simply print the statement
        print_status("Sent e-mail number: " +
                     (str(email_num)) + " to address: " + to)

if option1 != "99":
    # finish up here
    print_status("SET has finished sending the emails")
    return_continue()
