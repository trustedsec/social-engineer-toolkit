#!/usr/bin/env python
import urllib
import httplib
import re
import socket

def send_sohoos_sms(to, origin, text):
    try:
        params = urllib.urlencode({'body': text, 'from': origin, 'to': to})
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn = httplib.HTTPConnection('sohoos.com')
        conn.request('POST', '/crm/managekit/widget/submitsms', params, headers)
        response = conn.getresponse()
        if (response.status == 302 and 
            response.reason == "Found" and 
            response.getheader("location") == "/crm/managekit/widget/thankssms"):
            print "\nSMS sent\n"
        else:
            print "\nError while sending SMS\n"
    except:
        print "\nError sending SMS"

def send_smsgang_sms(to, origin, text, pincode):
    try:
        params = urllib.urlencode({
                                   "tonumber" : to,
                                   "senderid" : origin,
                                   "pincode" : pincode,
                                   "iso_msg" : text,
                                   "unicode_msg" : "",
                                   "B2" : "Send SMS"
                                    })
        headers = { "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-type": "application/x-www-form-urlencoded; charset=UTF-8" }
        conn = httplib.HTTPConnection('www.smsgang.com')
        conn.request('POST', '/sendsms.php?langfile=en', params, headers)
        response = conn.getresponse()
        if (response.status == 200 and 
                re.search("Your SMS was sent", response.read())):
            print "\nSMS sent\n"
        else:
            print "\nError while sending SMS\n"
    except:
        print "\nError sending SMS"

def send_lleidanet_sms(to, origin, text, user, password, email):
    try:
        params = urllib.urlencode({
                                   'xml' : '<?xml version="1.0" encoding="iso-8859-1" ?><sms><user>'+user+'</user><password>'+password+'</password><src>'+origin+'</src><dst><num>'+to+'</num></dst><txt>'+text+'</txt><delivery_receipt>'+email+'</delivery_receipt></sms>'
                                   })
        headers = {}
        conn = httplib.HTTPConnection('sms.lleida.net')
        conn.request('POST', '/xmlapi/smsgw.cgi', params, headers)
        response = conn.getresponse()
        if (response.status == 200 and 
            re.search("<status>100</status>", response.read())):
            print "\nSMS sent\n"
        else:
            print "\nError while sending SMS\n"
    except:
        print "\nError sending SMS"

def send_android_emu_sms(origin, text):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 5554))
        #s.recv(4096)
        command = 'sms send '
        s.send(command + origin + " " + text + "\x0d\x0a")
        android_response = s.recv(4096)
        s.close
        if (android_response.find("OK") >= 0 ):
            print "\nSMS sent\n"
        else:
            print "\nError sending SMS, did you install and have Android Emulator running?"
            print "Try: http://developer.android.com/guide/developing/tools/emulator.html"
    except:
        print "\nError sending SMS"

