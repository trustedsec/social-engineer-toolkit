#!/usr/bin/env python
import os
import subprocess
import time
import re
import string
import pexpect
import cgi
import urllib

# Command center for generating webserver

# import web modules
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler

from src.core.setcore import *

definepath=os.getcwd()

# grab port for command center
port=44444
fileopen=file("%s/config/set_config" % (definepath), "r")
for line in fileopen:
        line=line.rstrip()
        match=re.search("COMMAND_CENTER_PORT=",line)
        if match:
              port=line.replace("COMMAND_CENTER_PORT=","")

# define command center template
fileopen=file("src/commandcenter/command_center.html", "r")

# kill old process
def kill_process():
        try:
                # a.terminate only works on Python > 2.6
                process.terminate()
        except AttributeError:
                # if it fails pull pid for subprocess thread then terminate it
                process.kill( a.pid , signal.SIGTERM)

os.chdir("src/commandcenter/")

class myRequestHandler(BaseHTTPRequestHandler):

  # Print custom HTTP Response
  def printCustomHTTPResponse(self, respcode):
     self.send_response(respcode)
     self.send_header("Content-type", "text/html")
     self.send_header("Server", "myRequestHandler")
     self.end_headers()

  # GET Request here
  def do_GET(self):

        webattack_email="off"
        self_signed="off"
        auto_detect="on"
        ettercap="off"
        sendmail="off"

        fileopen=file("%s/config/set_config" % (definepath), "r")
        for line in fileopen:
                line=line.rstrip()
                # check for webattack email
                match1=re.search("WEBATTACK_EMAIL=ON", line)
                if match1:
                        webattack_email="on"
        
                # check for auto detect IP address
                match2=re.search("AUTO_DETECT=OFF", line)
                if match2:
                        auto_detect="off"

                # self signed check
                match3=re.search("SELF_SIGNED_APPLET=ON", line)
                if match3:
                        self_signed="on"
        
                match4=re.search("ETTERCAP=ON", line)
                if match4:
                        ettercap="on"
        
                match5=re.search("SENDMAIL=ON", line)
                if match5:
                        sendmail="on"

                match6=re.search("DSNIFF=ON", line)
                if match6:
                        ettercap="on"


        def post_load(filename):
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("%s" % (filename),"r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        # load files via read binary
        def load_file(filename):
                fileopen=file("files/%s" % (filename), "rb")
                for line in fileopen:
                        self.wfile.write(line)

        # import proper style css files here
        if self.path == "/files/style.css":
                self.send_response(200)
                self.send_header('Content_type', 'text/css')
                self.end_headers()
                cssopen=file("files/style.css","r")
                for line in cssopen:
                        self.wfile.write(line)

        # rest is importing javascript and images etc.
        if self.path == "/files/ga.js":
                load_file("ga.js")

        if self.path == "/files/jquery.js":
                load_file("jquery.js")

        if self.path == "/files/external-tracking.js":
                load_file("external-tracking.js")

        if self.path == "/files/rss.png":
                load_file("rss.png")

        if self.path == "/files/setman.jpg":
                load_file("setman.jpg")

        if self.path == "/files/header.jpg":
                load_file("header.jpg")

        if self.path == "/files/date-icon.png":
                load_file("date-icon.png")

        if self.path == "/files/tweet.png":
                load_file("tweet.png")

        if self.path == "/files/logo.png":
                load_file("logo.png")

        if self.path == "/files/main.png":
                load_file("main.png")

        if self.path == "/files/spear-phish.png":
                load_file("spear-phish.png")

        if self.path == "/files/web-attack.png":
                load_file("web-attack.png")

        if self.path == "/files/infectious.png":
                load_file("infectious.png")

        if self.path == "/files/mass-mailer.png":
                load_file("mass-mailer.png")

        if self.path == "/files/teensy.png":
                load_file("teensy.png")

        if self.path == "/files/updates.png":
                load_file("updates.png")

        if self.path == "/files/wireless.png":
                load_file("wireless.png")

        # Site root: Main Menu
        if self.path == "/":
                self.printCustomHTTPResponse(200)
                post_load("main.site")
                        
        # get request for web_attack
        if self.path == "/web_attack":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")

                #auto_detect="on"
                for line in fileopen:
                        self.wfile.write(line)

                # this will dynamically import web_attack vector and check for flags to add additional options
                fileopen=file("web_attack.site","r")
                for line in fileopen:
                        match=re.search("<CHECKHERE>", line)
                        if match:
                                line=line.replace("<CHECKHERE>","")

                                if webattack_email == "on":
                                        webattackemail=file("webattack_email.site","r")
                                        for line in webattackemail:
                                                self.wfile.write(line)

                                # if the auto_detect flag is set to off
                                if auto_detect == "off":
                                        autodetect=file("auto_detect.site","r")
                                        for line in autodetect:
                                                self.wfile.write(line)

                                # if the self signed applet is turned to on
                                if self_signed == "on":
                                        selfsigned=file("self_signed.site","r")
                                        for line in selfsigned:
                                                self.wfile.write(line)

                                # ettercap on or off
                                if ettercap == "on":
                                        ettercapread=file("ettercap.site","r")
                                        for line in ettercapread:
                                                self.wfile.write(line)

                        self.wfile.write(line)


                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        if self.path == "/results":
                if os.path.isfile("src/program_junk/cc_harvester_hit"):

                        # define file to extract URL of site
                        if os.path.isfile("src/program_junk/full_query"):
                                post_site=file("src/program_junk/post_site", "r")
                                for line in post_site:
                                        line=line.rstrip()
                                        print line

                        indexopen=file("src/program_junk/site.template","r").readlines()
                        for line in indexopen:
                                line=line.rstrip() 
                                self.wfile.write(line)        

        # load the social-engineering attacks
        if self.path == "/social_engineering":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                # this will dynamically import web_attack vector and check for flags to add additional options
                fileopen=file("social_engineering.site","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        # load the fasttrack attacks
        if self.path == "/fasttrack":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                # this will dynamically import web_attack vector and check for flags to add additional options
                fileopen=file("fasttrack.site","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        # phishing web menu here
        if self.path == "/phish":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)

                fileopen=file("%s/config/set_config" % (definepath), "r")
                for line in fileopen:
                        match=re.search("AUTO_DETECT=OFF", line)
                        if match: auto_detect="off"

                # this will dynamically import web_attack vector and check for flags to add additional options
                fileopen=file("phish.site","r")
                for line in fileopen:
                        match=re.search("<CHECKHERE>", line)
                        if match:
                                line=line.replace("<CHECKHERE>","")
                                # if the auto_detect flag is set to off
                                if auto_detect == "off":
                                        autodetect=file("auto_detect.site","r")
                                        for line in autodetect:
                                                self.wfile.write(line)
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        # infectious site here
        if self.path == "/infectious":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("infect.site","r")
                for line in fileopen:
                        match=re.search("<CHECKHERE>", line)
                        if match:
                                line=line.replace("<CHECKHERE>","")
                                # if the auto_detect flag is set to off
                                if auto_detect == "off":
                                        autodetect=file("auto_detect.site","r")
                                        for line in autodetect:
                                                self.wfile.write(line)
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)


        # mass mailer here
        if self.path == "/mass_mailer":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)

                # this will dynamically import mass_mailer and check for flags to add additional options
                fileopen=file("mass_mailer.site","r")
                for line in fileopen:
                        match=re.search("<CHECKHERE>", line)
                        if match:
                                line=line.replace("<CHECKHERE>","")
                                webattackemail=file("webattack_email.site","r")
                                for line in webattackemail:
                                        self.wfile.write(line)
                        self.wfile.write(line)

                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)


        # wifi menu
        if self.path == "/wireless":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("wireless.site","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)


        # teensy menu
        if self.path == "/teensy":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("teensy.site","r")
                for line in fileopen:
                        match=re.search("<CHECKHERE>", line)
                        if match:
                                line=line.replace("<CHECKHERE>", "")
                                # if the auto_detect flag is set to off
                                if auto_detect == "off":
                                        autodetect=file("auto_detect.site","r")
                                        for line in autodetect:
                                                self.wfile.write(line)

                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)


        # this is the updates menu
        if self.path == "/updates":
                self.printCustomHTTPResponse(200)
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("update.site","r")
                for line in fileopen:
                        match=re.search("CONFIGEDITORHERE", line)
                        if match:
                                line=""
                                html_counter=0
                                def html_form(description,field,length):
                                        html_char=(r'%s: <input type="text" name="html_param%s" value="%s" size="%s"/><br />' % (description,html_counter,field,length))
                                        self.wfile.write(html_char)

                                # start a loop for the set_config
                                fileopen1=file("%s/config/set_config" % (definepath),"r")
                                for line1 in fileopen1:
                                                # strip any garbage trailing characters
                                        line1=line1.rstrip()
                                        # grab anything without comments on it
                                        if line1[0:1] != "#":
                                                line1=line1.split("=")
                                                try:
                                                        length=len(line1[1])-2
                                                        html_form(line1[0],line1[1],length)
                                                        html_counter=html_counter+1
                                                except: pass
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)


  # handle post requests 
  def do_POST(self):

        webattack_email="off"
        self_signed="off"
        auto_detect="on"
        ettercap="off"
        sendmail="off"

        fileopen=file("%s/config/set_config" % (definepath), "r")
        for line in fileopen:
                line=line.rstrip()
                match=re.search("COMMAND_CENTER_PORT=",line)
                if match: port=line.replace("COMMAND_CENTER_PORT=","")

                # check for webattack email
                match1=re.search("WEBATTACK_EMAIL=ON", line)
                if match1: webattack_email="on"

                # check for auto detect IP address
                match2=re.search("AUTO_DETECT=OFF", line)
                if match2: auto_detect="off"

                # self signed check
                match3=re.search("SELF_SIGNED_APPLET=ON", line)
                if match3: self_signed="on"

                match4=re.search("ETTERCAP=ON", line)
                if match4: ettercap="on"

                match5=re.search("SENDMAIL=ON", line)
                if match5: sendmail="on"

                # if dsniff is on
                match6=re.search("DSNIFF=ON", line)
                if match6: ettercap = "on"


        def post_load(filename):
                fileopen=file("header","r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("%s" % (filename),"r")
                for line in fileopen:
                        self.wfile.write(line)
                fileopen=file("footer","r")
                for line in fileopen:
                        self.wfile.write(line)

        content_length = string.atoi(self.headers.dict["content-length"])
        raw_post_data = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        url = raw_post_data
        url = urllib.unquote_plus(url)
        url=url.split("&")

        if self.path == "/updates_post":
                counter=0
                post_load("post.site")
                url=url[0].split("=")
                # update SET only
                if url[1] == "1":
                        os.chdir(definepath)
                        subprocess.Popen("svn update", shell=True).wait()
                        os.chdir(definepath + "/src/commandcenter/")
                # update metasploit
                if url[1] == "2":
                        msf_path = meta_path()
                        os.chdir(msf_path)
                        subprocess.Popen("svn update", shell=True).wait()
                        os.chdir(definepath + "/src/commandcenter/")
                # update all
                if url[1] == "3":
                        os.chdir(definepath)
                        subprocess.Popen("svn update", shell=True).wait()
                        msf_path = meta_path()
                        os.chdir(msf_path)
                        subprocess.Popen("svn update", shell=True).wait()
                        os.chdir(definepath + "/src/commandcenter/") 

        # update config menu method POST handler
        if self.path == "/update_config_post":
                post_load("post.site")
                # open up set_config
                fileopen=file("%s/config/set_config" % (definepath),"r")
                # open up the file for writing
                filewrite=file("%s/config/set_config.tmp" % (definepath),"w")
                # set the initial loop counter
                post_counter=0
                # set the second loop counter
                post_counter1=0
                counter=0
                # start loop of set_config
                for line in fileopen:
                        # strip out any weird chars
                        line=line.rstrip()
                        # if the line doesn't have a # it means its a valid option in the config
                        if line[0:1] != "#":
                                # loop through our post parameters
                                for s in url:
                                        # strip any bad chars
                                        s=s.rstrip()
                                        # split with the equal sign, this is because post paramater will look something like param9=OPTION
                                        s=s.split("=")
                                        # take the second value which is the one we want
                                        s=s[1]
                                        # if our counter is equal to our second counter then reset counter and break loop
                                        # this was needed so that the params and the file matched up properly
                                        if post_counter1 == post_counter:
                                                post_counter1=0
                                                # break out of the loop once the counters match up which means our config file
                                                # matches up
                                                break

                                        # tick up the counter
                                        post_counter1=post_counter1+1
                                # split the line by equal sign
                                line=line.split("=")
                                # our line equals line[0] (our definition of option) plus an equal sign plus our value stored in s
                                line=line[0]+"="+s
                                # tick our counter up more
                                post_counter=post_counter+1
                        # write the file
                        filewrite.write(line+"\n")
                subprocess.Popen("mv %s/config/set_config.tmp %s/config/set_config 1> /dev/null 2> /dev/null" % (definepath,definepath), shell=True).wait()

        # wireless method POST handler
        # teensy method POST handler
        if self.path == "/wireless_post":
                counter=1
                post_load("post.site")
                filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")
                for s in url:
                        match1=re.search("wireless=", s)
                        if match1:
                                s=s.replace("wireless=", "")
                                # if we want to kill everything in wifi mode
                                if s == "2":
                                        filewrite.write("1\n8\n2\n\n3\n13\n")

                        match2=re.search("wifi_interface", s)
                        if match2:
                                s=s.replace("wifi_interface=", "")
                                if s != "":
                                        filewrite.write("1\n8\n1\n%s\n\n3\n13\n" % (s))
                filewrite.close()

        # teensy method POST handler
        if self.path == "/teensy_post":
                counter=1
                post_load("post.site")
                filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")
                for s in url:
                        match1=re.search("attack=", s)
                        if match1:
                                s=s.replace("attack=", "")
                                filewrite.write("1\n6\n"+s+"\n"+"yes\n")
                                if auto_detect == "off":
                                        for s in url:
                                                match=re.search("externalip=", s)
                                                if match:
                                                        s=s.replace("externalip=", "")
                                                        filewrite.write(s+"\n")
                                                match2=re.search("reversehandler=", s)
                                                if match2:
                                                        s=s.replace("reversehandler=", "")
                                                        filewrite.write(s+"\n")
                        match2=re.search("payload_selection=", s)
                        if match2:
                                s=s.replace("payload_selection=", "")
                                if s == "" or s == "2":
                                        for s in url:
                                                match_selection=re.search("payload_selection_filename=", s)
                                                if match_selection:
                                                        s=s.replace("payload_selection_filename=","")
                                                        if s == "":
                                                                filewrite.write("2\n")
                                                        else:
                                                                filewrite.write("13\n"+s+"\n")

                                else:
                                        filewrite.write(s+"\n")

                        match3=re.search("encoding=", s)
                        if match3:
                                s=s.replace("encoding=", "")
                                if s == "":
                                        filewrite.write("16\n")
                                else:
                                        filewrite.write(s+"\n")
        
                        match4=re.search("port=", s)
                        if match4:
                                s=s.replace("port=", "")
                                if s == "":
                                        filewrite.write("443\n")
                                else:
                                        filewrite.write(s+"\n")
                filewrite.close()

        # infectious method POST handler
        if self.path == "/infect_post":
                post_load("post.site")
                port_hit=0
                dll_hijacking=0
                counter=0
                filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")
                for s in url:
                        # if we are performing file format exploits
                        if s == "attack=1":
                                filewrite.write("1\n3\n1\n")

                        # if we are using standard executable
                        if s == "attack=2":
                                filewrite.write("1\n3\n1\n")
                        
                        match1=re.search("externalip=", s)
                        if match1:
                                s=s.replace("externalip=", "")
                                filewrite.write(s+"\n")

                        match1=re.search("phish_attack=", s)
                        if match1:
                                s=s.replace("phish_attack=", "")
                                filewrite.write(s+"\n")
                                if s == "1": dll_hijacking=1

                        # payload selection here
                        if s == "payload_selection=":
                                s=s.replace("payload_selection=", "")
                                if s == "" or s == "2":
                                        for s in url:
                                                match_selection=re.search("payload_selection_filename=", s)
                                                if match_selection:
                                                        s=s.replace("payload_selection_filename=","")
                                                        if s == "":
                                                                filewrite.write("2\n")
                                                        else:
                                                                filewrite.write("13\n"+s+"\n")
                                s="completed"

                        # encoding options here
                        if dll_hijacking == 1:
                                if s == "encoding=":
                                        filewrite.write("16\n")
                                        s="completed"

                        if dll_hijacking == 1:
                                match3=re.search("encoding=", s)
                                if match3:
                                        s=s.replace("encoding=", "")
                                        filewrite.write(s+"\n")

                        # port number for listener
                        if s == "port=443":
                                filewrite.write("443\n")
                                s="completed"

                        match4=re.search("port=", s)
                        if match4:
                                s=s.replace("port=", "")
                                if s == "":
                                        s="443"
                                filewrite.write(s+"\n")
                                port_hit=1

                        # if we are using the dll hijacking
                        if dll_hijacking == 1:
                                if s == "dll_hijack=":
                                        s=s.replace("dll_hijack=", "")
                                        if s == "":
                                                filewrite.write("1\n\n")
                                        else:
                                                filewrite.write(s+"\n\n")

                                        filewrite.write("\n")


                filewrite.write("yes\n")
                filewrite.close()
                
        # mass mailer POST handler
        if self.path == "/mass_mailer_post":
                        post_load("post.site")
                        counter=1
                        filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")
                        relay="off"
                        # if sendmail is on
                        if sendmail == "on":
                                filewrite.write("yes\n")
                        for s in url:
                                match1=re.search("webattack_email=",s)
                                if match1:
                                        s=s.replace("webattack_email=","")
                                        if s == "1":
                                                filewrite.write("1\n5\n1\n")
                                        if s == "2":
                                                for s in url:
                                                        match2=re.search("massmailer_file=", s)
                                                        if match2:
                                                                s=s.replace("massmailer_file=","")
                                                                filewrite.write("1\n5\n2\n"+s+"\n")

                                match3=re.search("emailto=", s)
                                if match3:
                                        s=s.replace("emailto=","")
                                        filewrite.write(s+"\n")
                                match4=re.search("webattack_account=", s)
                                if match4:
                                        s=s.replace("webattack_account=","")
                                        filewrite.write(s+"\n")
                                        if s == "2":
                                                relay="on"

                                # if mail relay is turned on
                                if relay == "on":
                                        match5=re.search("emailfrom_relay=",s)
                                        if match5:
                                                s=s.replace("emailfrom_relay=","")
                                                filewrite.write(s+"\n")
                                        match6=re.search("username_relay=",s)
                                        if match6:
                                                s=s.replace("username_relay=","")
                                                filewrite.write(s+"\n")
                                        match7=re.search("password_relay=", s)
                                        if match7:
                                                s=s.replace("password_relay=", "")
                                                filewrite.write(s+"\n")
                                                filewrite.write("yes\n")
                                        match8=re.search("smtp_relay=",s)
                                        if match8:
                                                s=s.replace("smtp_relay=","")
                                                filewrite.write(s+"\n")

                                        match9=re.search("smtp_port_relay=",s)
                                        if match9:
                                                s=s.replace("smtp_port_relay=","")
                                                filewrite.write(s+"\n")
                                                filewrite.write("yes\n")

                                # if we are using GMAIL
                                if relay == "off":
                                        match1=re.search("emailfrom=",s)
                                        if match1:
                                                s=s.replace("emailfrom=","")
                                                filewrite.write(s+"\n")
                                        match2=re.search("password=",s)
                                        if match2:
                                                s=s.replace("password=","")
                                                filewrite.write(s+" OMGPASSWORDHERE\n")
                                                # send high priority by default
                                                filewrite.write("yes\n")
                                
                                match10=re.search("subject=",s)
                                if match10:
                                        s=s.replace("subject=","")
                                        filewrite.write(s+"\n")

                                match11=re.search("webattack_message=",s)
                                if match11:
                                        s=s.replace("webattack_message=","")
                                        if s == "": s = "1"
                                        filewrite.write(s+"\n")

                                match12=re.search("comments=",s)
                                if match12:
                                        s=s.replace("comments=","")
                                        filewrite.write(s+"\n")
                                        filewrite.write("CONTROL-C-HERE\n\n")

                        filewrite.close()

        # spear phishing method POST handler
        if self.path == "/phish_post":
                post_load("post.site")
                counter2=0
                counter3=0
                dll_hijacking=0
                predefined=0
                sendmail_counter=0
                filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")
                counter=1
                port_hit=0
                for s in url: 
                        # incremental counter to see if we need to call filewrite

                        # if we are performing a mass email attack
                        if s == "attack=1":
                                filewrite.write("1\n1\n1\n")
                        
                        # if its default use 1
                        if s == "phish_attack=":
                                filewrite.write("1\n1\n")
                                # no need to keep the parameter anymore
                                s="completed"
                                dll_hijacking=1

                        # this is our actual attack method, so like pdf, dll, etc.
                        match1=re.search("phish_attack=", s)
                        if match1:
                                s=s.replace("phish_attack=", "")
                                filewrite.write(s+"\n")
                                if s == "1": dll_hijacking=1

                        # payload selection here
                        if s == "payload_selection=":
                                s=s.replace("payload_selection=", "")
                                if s == "" or s == "2":
                                        for s in url:
                                                match_selection=re.search("payload_selection_filename=", s)
                                                if match_selection:
                                                        s=s.replace("payload_selection_filename=","")
                                                        if s == "":
                                                                filewrite.write("2\n")
                                                        else:
                                                                filewrite.write("13\n"+s+"\n")
                                        
                                else:
                                        filewrite.write(s+"\n")
                                        s="completed"

                        # if its not default payload
                        match2=re.search("payload_selection=", s)
                        if match2:
                                s=s.replace("payload_selection=", "")
                                filewrite.write(s+"\n")

                                if auto_detect == "off":
                                        for s in url:
                                                match90=re.search("reversehandler=", s)
                                                if match90:
                                                        s=s.replace("reversehandler=", "")
                                                        s.write("\n")

                        # encoding options here
                        if dll_hijacking == 1:
                                if s == "encoding=":
                                        filewrite.write("16\n")
                                        s="completed"

                        if dll_hijacking == 1:
                                match3=re.search("encoding=", s)
                                if match3:
                                        s=s.replace("encoding=", "")
                                        filewrite.write(s+"\n")
          
                        # port number for listener
                        if s == "port=443":
                                filewrite.write("443\n")
                                s="completed"


                        match4=re.search("port=", s)
                        if match4:
                                s=s.replace("port=", "")
                                if s == "":
                                        s="443"
                                filewrite.write(s+"\n")
                                port_hit=1

                        # if sendmail is on
                        if port_hit == 1:
                                if sendmail_counter == 0:
                                        if sendmail == "on":
                                                filewrite.write("yes\n")
                                                sendmail_counter=sendmail_counter+1


                        # if we are using the dll hijacking
                        if dll_hijacking == 1:
                                if s == "dll_hijack=":
                                        filewrite.write("1\n\n")
                                        s="completed"
                                match5=re.search("dll_hijack=", s)
                                if match5:
                                        s=s.replace("dll_hijack=", "")
                                        filewrite.write(s+"\n\n")

                                # we set our defaults if they didn't change template
                                if s == "attachment=template.rar":                        
                                        filewrite.write("\n\n")
                                        s="completed"
                                        
                                match6=re.search("attachment=", s)
                                if match6:
                                        s=s.replace("attachment=", "")
                                        # two returns needed for default to rar
                                        filewrite.write(s+"\n\n")


                        if s == "attachment=":
                                attachment="template.pdf"
                                filewrite.write("2\n"+attachment+"\n")
                                s="completed"
                        match7=re.search("attachment=", s)
                        if match7:
                                s=s.replace("attachment=", "")
                                attachment=s
                                if dll_hijacking == 0:
                                        attachment=attachment.split(".")
                                        attachment=attachment[0]+".pdf"
                                filewrite.write("2\n"+attachment+"\n")

                        if s == "webattack_email=":
                                s="webattack_email=1"

                        if s == "webattack_email=1":
                                filewrite.write("1\n")

                        if s == "webattack_email=2":
                                filewrite.write("2\n"+attachment+"\n")

                        if s == "predefined=1":
                                for s in url:
                                        match10=re.search("template=", s)
                                        if match10:
                                                if s == "template=":
                                                        s = "1"
                                                s=s.replace("template=","")
                                                filewrite.write("1\n"+s+"\n")
                        if s == "predefined=2":
                                for s1 in url:
                                        #predefined=1
                                        match11=re.search("message=", s1)
                                        if match11:
                                                message=s1.replace("message=", "")
                                                for s2 in url:
                                                        match12=re.search("subject=", s2)
                                                        if match12:
                                                                s2=s2.replace("subject=","")
                                                                filewrite.write("2\n"+s2+"\n1\n"+message+"\nCONTROL-C-HERE\n")
                                                                

                        match12=re.search("emailto=", s)
                        if match12:
                                s=s.replace("emailto=","")
                                filewrite.write(s+"\n")


                        match4=re.search("webattack_account=", s)
                        if match4:
                                s=s.replace("webattack_account=","")
                                filewrite.write(s+"\n")

                                # if we are using open relay
                                if s == "2":
                                        for s1 in url:
                                                match1=re.search("emailfrom_relay=", s1)
                                                if match1:
                                                        s1=s1.replace("emailfrom_relay=","")
                                                        filewrite.write(s1+"\n")

                                                if sendmail == "off":
                                                        match2=re.search("username_relay=", s1)
                                                        if match2:
                                                                s1=s1.replace("username_relay=", "")
                                                                filewrite.write(s1+"\n")
                                                        match3=re.search("password_relay=", s1)
                                                        if match3:
                                                                s1=s1.replace("password_relay=", "")
                                                                filewrite.write(s1+"\n")
                                                                filewrite.write("yes\n")
                                                        match4=re.search("smtp_relay=", s1)
                                                        if match4:
                                                                s1=s1.replace("smtp_relay=", "")
                                                                filewrite.write(s1+"\n")
                                                        match5=re.search("smtp_port_relay=", s1)
                                                        if match5:
                                                                s1=s1.replace("smtp_port_relay=", "")
                                                                filewrite.write(s1+"\n")
                                                                # add yes for high priority as default
                                                                filewrite.write("yes\n")
                                                                                                
                        match13=re.search("emailfrom=",s)
                        if match13:
                                s=s.replace("emailfrom=","")
                                filewrite.write(s+"\n")

                        if sendmail == "off":
                                match14=re.search("password=", s)
                                if match14:
                                        # did this to mask passwords on write using set-automate, but will still show up unfortnately when answering file
                                        s=s.replace("password=","")
                                        filewrite.write(s+" OMGPASSWORDHERE"+"\n"+"yes\n")

                        match11=re.search("webattack_message=",s)
                        if match11:
                                s=s.replace("webattack_message=","")
                                if s == "": s = "1"
                                filewrite.write(s+"\n")
                        match12=re.search("comments=",s)
                        if match12:
                                s=s.replace("comments=","")
                                filewrite.write(s+"\n")
                                filewrite.write("CONTROL-C-HERE\n\n")                

                filewrite.close()
        # web attack method POST handler 
        if self.path == "/web_attack_post":
                post_load("post.site")
                counter=0
                osxcounter=0
                filewrite=file("%s/src/program_junk/answer.txt" % (definepath), "w")

                # recycle config flags in multi attack vectors with a definition
                # specify the harvester flag to off
                harvester="off"
                def auto_detect_function():
                        
                        for s in url:
                               # look for external ip address
                                match1=re.search("externalip=", s)
                                if match1:
                                        s = s.replace("externalip=","")

                                        # harvester only takes one parameter
                                        if harvester == "on": filewrite.write(s+"\n")
                                        if harvester == "off":
                                                filewrite.write("yes\n"+s+"\nyes\n")
                                                for s in url:
                                                        match2=re.search("reversehandler=", s)
                                                        if match2:
                                                                s = s.replace("reversehandler=","")
                                                                filewrite.write(s+"\n")
                                        
                # recycle config flags for webattack email
                def webattack_email_function():
                        relay="off"
                        # if sendmail is on
                        if sendmail == "on":
                                filewrite.write("yes\n")
                        for s in url:
                                match1=re.search("webattack_email=",s)
                                if match1:
                                        s=s.replace("webattack_email=","")
                                        if s == "1":
                                                filewrite.write("1\n")
                                        if s == "2":
                                                for s in url:
                                                        match2=re.search("massmailer_file=", s)
                                                        if match2:
                                                                s=s.replace("massmailer_file=","")
                                                                filewrite.write("2\n"+s+"\n")

                                match3=re.search("emailto=", s)
                                if match3:
                                        s=s.replace("emailto=","")
                                        filewrite.write(s+"\n")
                                match4=re.search("webattack_account=", s)
                                if match4:
                                        s=s.replace("webattack_account=","")
                                        filewrite.write(s+"\n")
                                        if s == "2":
                                                relay="on"

                                # if mail relay is turned on
                                if relay == "on":
                                        match5=re.search("emailfrom_relay=",s)
                                        if match5:
                                                s=s.replace("emailfrom_relay=","")
                                                filewrite.write(s+"\n")
                                        match6=re.search("username_relay=",s)
                                        if match6:
                                                s=s.replace("username_relay=","")
                                                filewrite.write(s+"\n")
                                        match7=re.search("password_relay=", s)
                                        if match7:
                                                s=s.replace("password_relay=", "")
                                                filewrite.write(s+"\n")
                                                filewrite.write("yes\n")
                                        match8=re.search("smtp_relay=",s)
                                        if match8:
                                                s=s.replace("smtp_relay=","")
                                                filewrite.write(s+"\n")

                                        match9=re.search("smtp_port_relay=",s)
                                        if match9:
                                                s=s.replace("smtp_port_relay=","")
                                                filewrite.write(s+"\n")
                                                filewrite.write("yes\n")

                                # if we are using GMAIL
                                if relay == "off":
                                        match1=re.search("emailfrom=",s)
                                        if match1:
                                                s=s.replace("emailfrom=","")
                                                filewrite.write(s+"\n")
                                        match2=re.search("password=",s)
                                        if match2:
                                                s=s.replace("password=","")
                                                filewrite.write(s+" OMGPASSWORDHERE\n")
                                                filewrite.write("yes\n")
                                match10=re.search("subject=",s)
                                if match10:
                                        s=s.replace("subject=","")
                                        filewrite.write(s+"\n")

                                match11=re.search("webattack_message=",s)
                                if match11:
                                        s=s.replace("webattack_message=","")
                                        if s == "": s = "1"
                                        filewrite.write(s+"\n")

                                match12=re.search("comments=",s)
                                if match12:
                                        s=s.replace("comments=","")
                                        filewrite.write(s+"\n")
                                        filewrite.write("CONTROL-C-HERE\n\n")

                # used for if ettercap is turned to on in set_config
                def ettercap_function():
                                for s in url:
                                        match1=re.search("ettercap_ip=",s)
                                        if match1:
                                                s=s.replace("ettercap_ip=","")
                                                filewrite.write(s+"\n")
                                        match2=re.search("ettercap_bridge=",s)
                                        if match2:
                                                s=s.replace("ettercap_bridge=","")
                                                filewrite.write(s+"\n")
                                                if s == "1":
                                                        for s in url:
                                                                match3=re.search("bridged_handler=",s)
                                                                if match3:
                                                                        s=s.replace("bridged_handler=","")
                                                                        filewrite.write("yes\n"+s+"\n")
                                                if s == "2":
                                                        filewrite.write("no\n")


                # used if self signed applet is turned to on in the set_config
                def self_signed_function():
                        for s in url:
                                match1=re.search("firstname=",s)
                                if match1:
                                        s=s.replace("firstname=","")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")

                                match2=re.search("orgunit=",s)
                                if match2:
                                        s=s.replace("orgunit=", "")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")
                                match3=re.search("orgname=",s)
                                if match3:
                                        s=s.replace("orgname=","")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")
                                match4=re.search("city=",s)
                                if match4:
                                        s=s.replace("city=","")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")
                                match5=re.search("state=", s)
                                if match5:
                                        s=s.replace("state=","")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")
                                match6=re.search("country=", s)
                                if match6:
                                        s=s.replace("country=","")
                                        if s == "": s="moo"
                                        filewrite.write(s+"\n")
                        filewrite.write("yes\n")

                # start a loop through the post parameters
                for s in url:
                        # look for the attack vector java applet
                        if s == "attack=":
                                test_it=s.replace("attack=")
                                if test_it == "":
                                        s="attack=1"

                        match1=re.search("attack=1", s)
                        if match1:
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("1\n2\n")

                                if auto_detect == "off":
                                        auto_detect_function()
                                
                                if self_signed == "on":
                                        self_signed_function()

                                for s in url:
                                        # specify option 2
                                        java1=re.search("cloner=",s)
                                        if java1: 
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                        payload1=re.search("payload_selection=",s)
                                        if payload1:
                                                s=s.replace("payload_selection=","")
                                                if s == "" or s == "2": 
                                                        for s in url:
                                        
                                                                match_selection=re.search("payload_selection_filename=", s)
                                                                if match_selection:
                                                                        s=s.replace("payload_selection_filename=","")
                                                                        if s == "":
                                                                                filewrite.write("2\n")
                                                                        else:
                                                                                filewrite.write("13\n"+s+"\n")
                                                else:
                                                        filewrite.write(s+"\n")

                                        encoding1=re.search("encoding=",s)
                                        if encoding1:
                                                s=s.replace("encoding=","")
                                                if s == "": s="16"
                                                filewrite.write(s+"\n")
                        
                                        
                                        port1=re.search("port=",s)
                                        if port1:
                                                s=s.replace("port=","")
                                                if s == "": s="443"
                                                filewrite.write(s+"\n")
                                        
                                        osx1=re.search("osxlinuxtarget",s)
                                        if osx1:
                                                osxcounter=1
                                                filewrite.write("yes\n")
                                                for s in url:
                                                        osxport=re.search("portosx=",s)
                                                        if osxport:
                                                                if s == "": s="8080"
                                                                filewrite.write(s+"\n")
                                                        
                                                        linport=re.search("portlin=",s)
                                                        if linport:
                                                                if s == "": s="8081"
                                                                filewrite.write(s+"\n")                                                                

                                if osxcounter == 0:
                                        filewrite.write("no\n")        

                                if ettercap == "on":
                                        ettercap_function()

                                if webattack_email == "on":
                                        webattack_email_function()

                        # look for the metasploit attack vector
                        match1=re.search("attack=2", s)
                        if match1:
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("2\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                        # pick browser exploit
                                        msfexploit=re.search("browser=",s)
                                        if msfexploit:
                                                s=s.replace("browser=","")
                                                if s =="": s="7"
                                                filewrite.write(s+"\n")

                                        # pick payload
                                        payload=re.search("payload_selection=",s)
                                        if payload:
                                                s=s.replace("payload_selection=","")
                                                if s =="" or s == "2": 
                                                        for s in url:
                                                                match_selection=re.search("payload_selection_filename=", s)
                                                                if match_selection:
                                                                        s=s.replace("payload_selection_filename=","")
                                                                        if s == "":
                                                                                filewrite.write("2\n")
                                                                        else:
                                                                                filewrite.write("13\n"+s+"\n")
                                                else:
                                                        filewrite.write(s+"\n")


                                        # grab port
                                        port=re.search("port=",s)
                                        if port:
                                                s=s.replace("port=","")
                                                if s=="": s="443"
                                                filewrite.write(s+"\n")

                                # turn ettercap on if the flag is set
                                if ettercap == "on": ettercap_function()

                                # turn on mass mailer if the flag is set
                                if webattack_email == "on": webattack_email_function()


                        # look for the credential harvester attack vector
                        match1=re.search("attack=3", s)
                        if match1:
                                harvester="on"
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("3\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                if ettercap == 'on': ettercap_function()
                                if webattack_email == "on": webattack_email_function()

                                filewrite.write("\n")

                        # tabnabbing attack vector
                        match1=re.search("attack=4", s)
                        if match1:
                                harvester="on"
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("4\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                if ettercap == 'on': ettercap_function()
                                if webattack_email == "on": webattack_email_function()

                                filewrite.write("\n")


                        # man left in the middle attack vector
                        match1=re.search("attack=5", s)
                        if match1:
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("5\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                if ettercap == 'on': ettercap_function()
                                if webattack_email == "on": webattack_email_function()

                                filewrite.write("\n")


                        # webjacking web vector
                        match1=re.search("attack=6", s)
                        if match1:
                                harvester="on"
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify java applet attack method and clone site
                                filewrite.write("6\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                        # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")

                                if ettercap == 'on': ettercap_function()
                                if webattack_email == "on": webattack_email_function()

                                filewrite.write("\n")

                        # multi-attack vector
                        multi_counter=0
                        osx_counter=0
                        java_multi="off"
                        multi_find=0
                        mutli_counter_2=0
                        match1=re.search("attack=7", s)
                        if match1:
                                # specify web attack vector
                                filewrite.write("1\n2\n")
                                # set the counter to run the answer file
                                counter = 1
                                # specify the multiattack vector
                                filewrite.write("7\n2\n")
                                if auto_detect == "off": auto_detect_function()
                                for s in url:
                                        # specify option 2
                                        cloner=re.search("cloner=",s)
                                        if cloner:
                                                s=s.replace("cloner=","")
                                                if s == "":
                                                # let SET know there wasn't a mandatory option set
                                                        s = "http://www.google.com"
                                                filewrite.write(s+"\n")
                                for s in url:
                                                # look for the flag options in multiattack
                                                multiattack1=re.search("multiattack1=",s)
                                                if multiattack1:
                                                        s=s.replace("multiattack1=","")
                                                        filewrite.write(s+"\n\n")
                                                        java_multi="on"
                                                        multi_counter="on"
                                                multiattack2=re.search("multiattack2=",s)
                                                if multiattack2:
                                                        s=s.replace("multiattack2=","")
                                                        filewrite.write(s+"\n\n")
                                                        multi_counter="on"
                                                multiattack3=re.search("multiattack3=",s)
                                                if multiattack3:
                                                        s=s.replace("multiattack3=","")
                                                        filewrite.write(s+"\n\n")
                                                        multi_counter="on"
                                                multiattack4=re.search("multiattack4=",s)
                                                if multiattack4:
                                                        s=s.replace("multiattack4=","")
                                                        filewrite.write(s+"\n\n")
                                                        multi_counter="on" 
                                                multiattack5=re.search("multiattack5=",s)
                                                if multiattack5:
                                                        s=s.replace("multiattack5=","")
                                                        filewrite.write(s+"\n\n")
                                                        multi_counter="on"
                                                multiattack6=re.search("multiattack6=",s)
                                                if multiattack6:
                                                        s=s.replace("multiattack6=","")
                                                        filewrite.write(s+"\n\n")
                                                        multi_counter="on"
                                                multiattack7=re.search("multiattack7=",s)
                                                if multiattack7:
                                                        s=s.replace("multiattack7=","")
                                                        filewrite.write(s+"\n")
                                                        multi_counter=1
                                                        java_multi="on"

                                                multi_find=1

                                # if we don't use tactical nuke
                                if multi_counter == "on":
                                        filewrite.write("8\n")
                                        multi_counter = 0

                                payload_counter=0
                                port_counter=0
                                encoding_counter=0
                                for s in url:
                                        # see if we have our stuff for the multi attack yet
                                        if multi_find == 1:
                                                        for s in url:
                                                                if payload_counter == 0:
                                                                        # pick payload
                                                                        payload=re.search("payload_selection=",s)
                                                                        if payload:
                                                                                s=s.replace("payload_selection=","")


                                                                                if s =="" or s == "2": 
                                                                                        for s in url:
                                                                                                match_selection=re.search("payload_selection_filename=", s)
                                                                                                if match_selection:
                                                                                                        s=s.replace("payload_selection_filename=","")
                                                                                                        if s == "":
                                                                                                                filewrite.write("2\n")
                                                                                                        else:
                                                                                                                filewrite.write("13\n"+s+"\n")

                                                                                else:
                                                                                        filewrite.write(s+"\n")
                                                                                payload_counter=1        


                                                                if encoding_counter == 0:
                                                                        encoding1=re.search("encoding=",s)
                                                                        if encoding1:
                                                                                s=s.replace("encoding=","")
                                                                                if s == "": s="16"
                                                                                filewrite.write(s+"\n")
                                                                                encoding_counter=1
        
                                                                # grab port
                                                                if port_counter == 0:
                                                                        port=re.search("port=",s)
                                                                        if port:
                                                                                s=s.replace("port=","")
                                                                                if s=="": s="443"
                                                                                filewrite.write(s+"\n")
                                                                                port_counter = 1

                                                        if java_multi == "on":
                                                                osx1=re.search("osxlinuxtarget",s)
                                                                if osx1:
                                                                        osxcounter=1
                                                                        filewrite.write("yes\n")
                                                                        for s in url:
                                                                                osxport=re.search("portosx=",s)
                                                                                if osxport:
                                                                                        if s == "": s="8080"
                                                                                        filewrite.write(s+"\n")
        
                                                                                        linport=re.search("portlin=",s)
                                                                                if linport:
                                                                                        if s == "": s="8081"
                                                                                        filewrite.write(s+"\n")     
                                                                if osxcounter == 0:
                                                                        filewrite.write("no\n")
                                                                        osxcounter=2
                                
                                # see if we're using the browser attack vector
                                for s in url:
                                        # pick browser exploit
                                        msfexploit=re.search("browser=",s)
                                        if msfexploit:
                                                s=s.replace("browser=","")
                                                if s =="": 
                                                        s="7"
                                                if s == "2":
                                                        s="2\nwab"
                                                filewrite.write(s+"\n")


        # if we posted to a successful attack
                if counter == 1:
                        filewrite.close()

        if counter == 1:

                try:
                        os.chdir(definepath)
                        fileopen=file("config/set_config", "r")
                        for line in fileopen:
                                line=line.rstrip()
                                match=re.search("TERMINAL=", line)
                                if match: terminal=line.replace("TERMINAL=","")
                        if terminal == "XTERM" or terminal == "xterm" or terminal == "":
                                proc = subprocess.Popen("xterm -geometry 90x30 -bg black -fg white -fn *-fixed-*-*-*-20-* -T 'The Social-Engineer Toolkit (SET)' -e 'python set-automate src/program_junk/answer.txt' &", shell=True)

                        if terminal == "KONSOLE" or terminal == "konsole":
                                proc = subprocess.Popen("konsole -T 'The Social-Engineer Toolkit (SET)' -e sh -c '%s/set-automate src/program_junk/answer.txt' &" % (definepath), shell=True)

                        if terminal == "GNOME" or terminal == "gnome":
                                proc = subprocess.Popen("gnome-terminal -t 'The Social-Engineer Toolkit (SET)' -x sh -c '%s/set-automate src/program_junk/answer.txt' &" % (definepath), shell=True)

                        # if they jacked up the config here
                        if terminal != "XTERM":
                                if terminal != "KONSOLE":
                                        if terminal != "GNOME":
                                                proc = subprocess.Popen("python set-automate src/program_junk/answer.txt", shell=True)

                        os.chdir("src/commandcenter")
                except Exception:
                        try: 
                                os.kill( proc.pid , signal.SIGTERM)

                        except: pass

                        os.chdir("src/commandcenter")
                counter=0
                # needed to do this if an exception wasnt hit to change directory back to command center
                if counter == 1:
                        os.chdir("src/commandcenter")
                                                

print_info("Starting the SET Command Center on port: " + str(port))
show_graphic()
print """ 
 ______________________________________________________
|                                                      |              
|              The Social-Engineer Toolkit             |
|                    Web-Interface GUI                 |
|                      Command Center                  |
|______________________________________________________|

  All results from the web interface will be displayed
                   in this terminal.

""" 

fileopen=file("%s/config/set_config" % (definepath), "r")
for line in fileopen:
        line=line.rstrip()
        match=re.search("COMMAND_CENTER_INTERFACE=", line)
        if match: bind_interface=line.replace("COMMAND_CENTER_INTERFACE=", "")

print "Interface is bound to http://%s on port %s (open browser to ip/port)" % (bind_interface,str(port))
httpd = HTTPServer(('%s' % (bind_interface), int(port)), myRequestHandler)
httpd.handle_request()
httpd.serve_forever()
try:
        os.kill( a.pid , signal.SIGTERM)
except: pass
