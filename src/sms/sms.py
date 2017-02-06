#!/usr/bin/env python
# coding=utf-8
#import src.core.setcore as core
from src.core.setcore import *
import sys
import getpass

# Py2/3 compatibility
# Python3 renamed raw_input to input
try: input = raw_input
except NameError: pass


trigger = 0
try:
    import requests

except ImportError:
    print_error("Looks like you dont have python-requests installed. "
                     "Please install (apt-get install python-requests) and try again.")
    input("Press {return} to continue.")
    trigger = 1

def _do_sms():
    print("""\n        ----- The Social-Engineer Toolkit (SET) SMS Spoofing Attack Vector -----\n""")
    print("This attack vector relies upon a third party service called www.spoofmytextmessage.com. "
          "This is a third party service outside of the control from the Social-Engineer Toolkit. "
          "The fine folks over at spoofmytextmessage.com have provided an undocumented API for us "
          "to use in order to allow SET to perform the SMS spoofing. You will need to visit "
          "https://www.spoofmytextmessage.com and sign up for an account. They example multiple "
          "payment methods such as PayPal, Bitcoin, and many more options. Once you purchase your "
          "plan that you want, you will need to remember your email address and password used for "
          "the account. SET will then handle the rest.\n")

    print("In order for this to work you must have an account over at spoofmytextmessage.com\n")
    print("Special thanks to Khalil @sehnaoui for testing out the service for me and finding "
          "spoofmytextmessage.com\n")

    print_error("DISCLAIMER: By submitting yes, you understand that you accept all terms and "
                     "services from spoofmytextmessage.com and you are fully aware of your countries "
                     "legal stance on SMS spoofing prior to performing any of these. By accepting yes "
                     "you fully acknowledge these terms and will not use them for unlawful purposes.")

    message = input("\nDo you accept these terms (yes or no): ")

    if message == "yes":
        print_status("Okay! Moving on - SET needs some information from you in order to spoof the message.")


        print_status("Please note that spoofing may not work with all carriers. If it doesn't work, SET cannot be changed or modified in order to make it work. Would recommend trying different routes to get it working, if that doesn't work, you will need to contact spoofmytextmessages.com")

        email = input(setprompt(["7"], "Enter your email address for the spoofmytextmessage.com account"))
        print_status("Note that the password below will be masked and you will not see the output.")
        pw = getpass.getpass(setprompt(["7"], "Enter your password for the spoofmytextmessage.com account"))
        print_status("The next section requires a country code, this is the code you would use to dial "
                          "to the specific country, for example if I was sending a message to 555-555-5555 to "
                          "the United States (or from) you would enter +1 below.")

        tocountry = input(setprompt(["7"], "Enter the country code for the number you are sending TO "
                                                "(for example U.S would be '+1')[+1]"))
        if tocountry == "":
            tocountry = "+1"

        fromcountry = input(setprompt(["7"], "Enter the country code for the number you are sending FROM "
                                              "(for example U.S. would be '+1')[+1]"))
        if fromcountry == "":
            fromcountry = "+1"

        tonumber = input(setprompt(["7"], "Enter the number to send the SMS TO - be sure to include "
                                           "country code (example: +15551234567)"))

        fromnumber = input(setprompt(["7"], "Enter the number you want to come FROM - be sure to include "
                                             "country code (example: +15551234567)"))

        message = input(setprompt(["7"], "Enter the message you want to send via the text message"))

        print_status("Routes provide different methods for different carriers. Usually auto is the best option, but you may want to try 1 or 2. The options are [a] (auto), 1, or 2.")
        route = input(setprompt(["7"], "Enter the route (test different routes) (options a, 1, or 2)[a]"))
        if route == "": route = ("auto")
        if route == "a": route = ("auto")

        # note that the function for this is in a compiled python file with no source -
        # this was done at the request of the third party we use since the API is not documented.
        # I hand wrote the code and can validate its authenticity - it imports python requests
        # and json and uses that to interact with the API. From a security standpoint if you are
        # uncomfortable using this - feel free to ping me and I can walk you through what I do
        # without giving away the API from the third party.
        from src.sms.spoofapi import send_sms
        send_sms(email, pw, tocountry, fromcountry, fromnumber, tonumber, message, route)

    else:
        print_status("Okay! Exiting out of the Social-Engineer Toolkit SMS Spoofing Attack Vector...")

# launch sms
try:
    if trigger == 0:
        _do_sms()
except Exception as err: print_error("Something went wrong, printing error: " + str(err))
