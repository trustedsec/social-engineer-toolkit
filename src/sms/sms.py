#!/usr/bin/env python

import re
import glob
import os
from src.core.setcore import *
import httplib
import socket
import urllib

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
            print "\nSMS has been sent.\n"
        else:
            print "\nError while sending SMS - ensure that you have a valid PIN.\n"
    except Exception as e:
        print("\nError sending SMS - printing the error message: ")
	print(e)

def launch():
        while 1:
        	try:
			to = raw_input(setprompt(["7"], "Enter the phone number to send to"))
                	origin = raw_input(setprompt(["7"], "Source/spoofed number phone"))
                        body = raw_input(setprompt(["7"], "Body of the message, hit return for a new line. Type quit on a line to exit"))
			goat = ""
                        while goat != 'quit':
                                	body += ("\n")
                                        goat = raw_input("Next line of the body: ")
					if goat != "quit":
						body += goat

                except KeyboardInterrupt:
                        break

                pincode = raw_input(setprompt(["7"], "Your SMSGANG pincode"))
                send_smsgang_sms(to.rstrip(), origin.rstrip(), body.rstrip(), pincode)
                # Finish here then return to main menu
                print_status("SET has completed sending the initial message. Check for errors.")
                return_continue()
		break

print("The SMS Spoofing Method will send a message from a source number that you specify and a full message that you detail within this module.\n\nNote that the current and only supported module is through a third party called SMSGang. SMSGang requires you to purchase credits which you can purchase directly from http://www.smsgang.com/. When purchasing, you will get a specific PIN that allows you to send messages as stated. You must purchase these credits before hand in order to send randomized and spoofed source text messages. Please note that you should check the legality of SMS spoofing in your individual countries in order to ensure you are in within legal compliance with all source text spoofing laws.")
print("\n\n")
# launch the question area
launch()
