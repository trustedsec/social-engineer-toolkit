#!/usr/bin/env python
#
# Quick SSL Cert creation method
#
# Used if you want to create self signed

from src.core.setcore import *
import subprocess
import os
definepath = os.getcwd()
os.chdir(userconfigpath)
# create the directories for us
subprocess.Popen("mkdir CA;cd CA;mkdir newcerts private", shell=True).wait()
# move into CA directory
os.chdir("CA/")
# create necessary files
subprocess.Popen("echo '01' > serial;touch index.txt", shell=True).wait()
filewrite = open("openssl.cnf", "w")
filewrite.write("""#
# OpenSSL configuration file.
#

# Establish working directory.
dir = .
[ req ]
default_bits = 1024 # Size of keys
default_keyfile = key.pem # name of generated keys
default_md = md5 # message digest algorithm
string_mask = nombstr # permitted characters
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
# Variable name   Prompt string
#----------------------   ----------------------------------
0.organizationName = Organization Name (company)
organizationalUnitName = Organizational Unit Name (department, division)
emailAddress = Email Address
emailAddress_max = 40
localityName = Locality Name (city, district)
stateOrProvinceName = State or Province Name (full name)
countryName = Country Name (2 letter code)
countryName_min = 2
countryName_max = 2
commonName = Common Name (hostname, IP, or your name)
commonName_max = 64

# Default values for the above, for consistency and less typing.
# Variable name   Value
#------------------------------   ------------------------------
0.organizationName_default = The Sample Company
localityName_default = Metropolis
stateOrProvinceName_default = New York
countryName_default = US

[ v3_ca ]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always""")
# close editing of the file
filewrite.close()
subprocess.Popen(
    "openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem -out newcert.pem -days 3650 -config ./openssl.cnf", shell=True).wait()
subprocess.Popen(
    "cp private/cakey.pem newreq.pem;cp *.pem ../", shell=True).wait()
os.chdir(definepath)
