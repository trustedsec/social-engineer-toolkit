#!/usr/bin/env python

try:
    from src.core.setcore import *
    from src.sms.protectedapi import send_sms
    import requests

    print("""\n        ----- The Social-Engineer Toolkit (SET) SMS Spoofing Attack Vector -----\n""")
    print("This attack vector relies upon a third party service called www.spoofmytextmessage.com. This is a third party service outside of the control from the Social-Engineer Toolkit. The fine folks over at spoofmytextmessage.com have provided an undocumented API for us to use in order to allow SET to perform the SMS spoofing. You will need to visit https://www.spoofmytextmessage.com and sign up for an account. They example multiple payment methods such as PayPal, Bitcoin, and many more options. Once you purchase your plan that you want, you will need to remember your email address and password used for the account. SET will then handle the rest.\n")
    print("In order for this to work you must have an account over at spoofmytextmessage.com\n")
    print("Special thanks to Khalil @sehnaoui for testing out the service for me and finding spoofmytextmessage.com\n")
    print_error("DISCLAIMER: By submitting yes, you understand that you accept all terms and services from spoofmytextmessage.com and you are fully aware of your countries legal stance on SMS spoofing prior to performing any of these. By accepting yes you fully acknowledge these terms and will not use them for unlawful purposes.") 
    message = raw_input("\nDo you accept these terms (yes or no): ")
    if message == "yes": 
        print_status("Okay! Moving on - SET needs some information from you in order to spoof the message.")
        email = raw_input(setprompt(["7"], "Enter your email address for the spoofmytextmessage.com account"))
        pw = raw_input(setprompt(["7"], "Enter your password for the spoofmytextmessage.com account"))
        print_status("The next section requires a country code, this is the code you would use to dial to the specific country, for example if I was sending a message to 555-555-5555 to the United States (or from) you would enter +1 below.")
        tocountry = raw_input(setprompt(["7"], "Enter the country code for the number you are sending TO (for example U.S would be '+1')[+1]"))
        if tocountry == "": tocountry = "+1"
        fromcountry = raw_input(setprompt(["7"], "Enter the country code for the number you are sending FROM (for example U.S. would be '+1')[+1]"))
        if fromcountry == "": fromcountry = "+1"
        tonumber = raw_input(setprompt(["7"], "Enter the number to send the SMS TO - be sure to include country code (example: +15551234567)"))
        fromnumber = raw_input(setprompt(["7"], "Enter the number you want to come FROM - be sure to include country code (example: +15551234567)"))
        message = raw_input(setprompt(["7"], "Enter the message you want to send via the text message"))

        # note that the function for this is in a compiled python file with no source - this was done at the request of the third party we use since the API is not documented. I hand wrote the code and can validate its authenticity - it imports python requests and json and uses that to interact with the API. From a security standpoint if you are uncomfortable using this - feel free to ping me and I can walk you through what I do without giving away the API from the third party.
        send_sms(email, pw, tocountry, fromcountry, fromnumber, tonumber, message)

    else:
        print_status("Okay! Exiting out of the Social-Engineer Toolkit SMS Spoofing Attack Vector...") 

except ImportError:
    print_error("Looks like you dont have python-requests installed. Please install (apt-get install python-requests) and try again.")
