#!/usr/bin/python

import re
import subprocess
import os
import datetime

#
# Quick report generation script
#

# Colors below
class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PINK = '\033[95m'
    ENDC = '\033[0m'

# End colors

# definepath
definepath = os.getcwd()

# grab URL and report information
now=datetime.datetime.today()
fileopen=file("%s/src/program_junk/site.template" % (definepath), "r")
site_template = file("%s/src/program_junk/site.template" % (definepath), "r").readlines()
fileopen1=file("%s/src/core/reports/index.html" % (definepath), "r")
for line in fileopen:
        match=re.search("URL=", line)
        if match:
                url=line.replace("URL=http://", "")
                url=line.replace("URL=https://", "")
                filewrite2=file("reports/%s.xml" % (now), "a")
                filewrite2.write(r"""<?xml version="1.0" encoding='UTF-8'?>""" + "\n")
                filewrite2.write(r"<harvester>" + "\n")
                for line2 in fileopen1:
                        counter=0
                        filewrite=file("reports/%s.html" % (now), "a")
                        match1=re.search("REPLACEHEREDUDE", line2)
                        if match1:
                                line2=line2.replace("REPLACEHEREDUDE", url)
                                filewrite.write(line2)
                                url_xml=url.rstrip()
                                filewrite2.write("   <url>%s" % (url_xml) + "\n")
                                counter=1
                        match2=re.search("If this is blank, SET did not get a successful attempt on the website, sorry hoss..", line2)
                        if match2:
                                line2=line2.replace("If this is blank, SET did not get a successful attempt on the website, sorry hoss..", "Report findings on %s<br><br>" % (url))
                                counter=1
                                filewrite.write(line2)
                                for line3 in site_template:
                                        match3=re.search("PARAM:", line3)
                                        if match3:
                                                xml=line3.replace("PARAM: ", "")
                                                xml=xml.rstrip()
                                                filewrite.write(line3+"<br>")
                                                filewrite2.write(r"      <param>%s</param>" % (xml) + "\n")
                                        match4=re.search("BREAKHERE", line3)
                                        if match4:
                                                filewrite2.write("   </url>" + "\n")
                                                filewrite.write("<br>~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~<br><br>")

                        # look for how many people visited the website
                        match5=re.search("VISITORSHERE", line2)
                        if match5:
                                if os.path.isfile("%s/src/program_junk/visits.file" % (definepath)):
                                        fileopen3=file("%s/src/program_junk/visits.file" % (definepath), "r")
                                        counter5=0
                                        for line in fileopen3:
                                                if line != "":
                                                        line=line.rstrip()
                                                        counter5 = counter5+1
                                                if line == "": counter5 = 0
                                if not os.path.isfile("%s/src/program_junk/visits.file" % (definepath)):
                                        counter5 = 0 

                                line2=line2.replace("VISITORSHERE", str(counter5), 2)
                                counter = 1
                                #filewrite.write(line2)

                        match6=re.search("BITESHERE", line2)
                        if match6:
                                if os.path.isfile("%s/src/program_junk/bites.file" % (definepath)):
                                        fileopen4=file("%s/src/program_junk/bites.file" % (definepath), "r")
                                        counter5 = 0
                                        for line in fileopen4:
                                                line=line.rstrip()
                                                counter5 = counter5+1
                                if not os.path.isfile("%s/src/program_junk/bites.file" % (definepath)):
                                        counter5=0

                                line2=line2.replace("BITESHERE", str(counter5))
                                counter = 1
                                filewrite.write(line2)

                        if counter == 0:
                                filewrite.write(line2)

try:
        filewrite.close()
        filewrite2.write(r"</harvester>" + "\n")
        filewrite2.close()
except: pass

subprocess.Popen("cp -rf %s/src/core/reports/files reports/" % (definepath), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
print bcolors.BLUE + "[*] File exported to reports/%s.html for your reading pleasure..."  % (now) + bcolors.ENDC
print bcolors.BLUE + "[*] File in XML format exported to reports/%s.xml for your reading pleasure..." % (now) + bcolors.ENDC
