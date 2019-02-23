#!/usr/bin/env python

import re
import subprocess
import os
import datetime
from src.core.setcore import *

# make sure the reports directory is created
if not os.path.isdir(userconfigpath + "reports/"): os.makedirs(userconfigpath + "reports/")

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
now = datetime.datetime.today()
fileopen = open(userconfigpath + "site.template", "r")
site_template = open(userconfigpath + "site.template", "r").readlines()
fileopen1 = open("%s/src/core/reports/index.html" % (definepath), "r")
for line in fileopen:
    match = re.search("URL=", line)
    if match:
        url = line.replace("URL=http://", "")
        url = line.replace("URL=https://", "")
        filewrite2 = open(userconfigpath + "reports/%s.xml" % (now), "a")
        filewrite2.write(r"""<?xml version="1.0" encoding='UTF-8'?>""" + "\n")
        filewrite2.write(r"<harvester>" + "\n")
        for line2 in fileopen1:
            counter = 0
            #filewrite = open(userconfigpath + "reports/%s.html" % (now), "a")
            match1 = re.search("REPLACEHEREDUDE", line2)
            if match1:
                line2 = line2.replace("REPLACEHEREDUDE", url)
                #filewrite.write(line2)
                url_xml = url.rstrip()
                filewrite2.write("   %s" % (url_xml) + "\n")
                counter = 1
            match2 = re.search("If this is blank, SET did not get a successful attempt on the website, sorry hoss..", line2)
            if match2:
                line2 = line2.replace(
                    "If this is blank, SET did not get a successful attempt on the website, sorry hoss..", "Report findings on %s<br><br>" % (url))
                counter = 1
                #filewrite.write(line2)
                opentag = True
                for line3 in site_template:
                    match3 = re.search("PARAM:", line3)
                    if match3:
                        xml = line3.replace("PARAM: ", "")
                        xml = xml.rstrip()
                        #filewrite.write(line3 + "<br>")
                        if opentag:
                            filewrite2.write(r"   <url>")
                            opentag = False
                        filewrite2.write(
                            r"      <param>%s</param>" % (xml) + "\n")
                    match4 = re.search("BREAKHERE", line3)
                    if match4:
                        filewrite2.write("   </url>" + "\n")
                        opentag = True
                        #filewrite.write(
                        #    "<br>~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~<br><br>")

            # look for how many people visited the website
            match5 = re.search("VISITORSHERE", line2)
            if match5:
                if os.path.isfile(userconfigpath + "visits.file"):
                    fileopen3 = open(userconfigpath + "visits.file", "r")
                    counter5 = 0
                    for line in fileopen3:
                        if line != "":
                            line = line.rstrip()
                            counter5 = counter5 + 1
                        if line == "":
                            counter5 = 0
                if not os.path.isfile(userconfigpath + "visits.file"):
                    counter5 = 0

                line2 = line2.replace("VISITORSHERE", str(counter5), 2)
                counter = 1
                # filewrite.write(line2)

            match6 = re.search("BITESHERE", line2)
            if match6:
                if os.path.isfile(userconfigpath + "bites.file"):
                    fileopen4 = open(userconfigpath + "bites.file", "r")
                    counter5 = 0
                    for line in fileopen4:
                        line = line.rstrip()
                        counter5 = counter5 + 1
                if not os.path.isfile(userconfigpath + "bites.file"):
                    counter5 = 0

                line2 = line2.replace("BITESHERE", str(counter5))
                counter = 1
                #filewrite.write(line2)

            #if counter == 0:
                #filewrite.write(line2)

try:
    #filewrite.close()
    filewrite2.write(r"</harvester>" + "\n")
    filewrite2.close()
except:
    pass

subprocess.Popen("cp -rf %s/src/core/reports/files %sreports/" % (definepath, userconfigpath), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
print(bcolors.BLUE + "[*] File in XML format exported to %sreports/%s.xml for your reading pleasure..." % (userconfigpath, now) + bcolors.ENDC)
