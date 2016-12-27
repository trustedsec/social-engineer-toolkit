#
#
# API integration into spoofmytextmessage.com for SMS spoofing
#
#
#
import json
import requests
from src.core.setcore import *

def send_sms(email, pw, tocountry, fromcountry, fromnumber, tonumber, message):

    try: input = raw_input
    except: pass

    try:
        print_status("Grabbing initial ID from spoofmytextmessage.com...")
        payload = {'email': email, 'pass': pw}
        url = ('https://api.spoofmytextmessage.com/2.0/index.php?task=login')
        r = requests.get(url, params=payload)
        # hack job - json not loading right through site
        data = r.json()
        secureid = (str(data)).split("secureid': u'")[1].split("', u'verifycode")[0]
        id = (str(data)).split("u'id': u'")[1].split("', u'online")[0]
        # pull status codes
        print_status("Pulling unique identifier for SMS codes to send from spoofmytextmessage.com...")
        url = 'https://api.spoofmytextmessage.com/2.0/index.php?task=getCodes&mid=%s&email=%s&secureid=%s' % (id,email,secureid)
        r = requests.get(url)
        data = str(r.json())
        print_status("Received valid response codes from spoofmytextmessage.com.") 
        if "count': 0" in data: 
            print_status("It does not appear you have any valid credits on spoofmytextmessage.com. Purchase more.")
            prompter = input("Press {return} to return to the previous menu.")

        else:
            code = data.split("messages': [u'")[1].split("', u'")[0]
            print_status("Crafting the SMS message and sending through spoofmytextmessage.com...")
            url = 'https://api.spoofmytextmessage.com/2.0/index.php?task=send'
            payload = {'non': 'number', 'fromnumber': fromnumber, 'to': tonumber, 'tocountry': tocountry, 'fromcountry': fromcountry,
                       'text': message, 'code': code, 'task': 'send', 'terms': '1', 'secureid': secureid, 'mid': id, 'email': email,
                       'source': 'settoolkit', 'osname': 'settoolkit', 'app': 'settoolkit', 'selves': '1'}

            r = requests.post(url, data=payload)

            if "successfully" in r.content:
                print_status("You have successfully sent your text message.")
                input("Press {return} to return the previous menu.")

            else:

                print_error("We were unable to successfully send the text message. Check all your settings and try again.")
                print("Printing error from spoofmytextmessage.com: " + r.content)
                input("Press {return} to return to the previous menu.")

    except IndexError as error:
        print_error("Unable to authenticate and pull down from the site. Check your settings and try again.")
        print_error("Printing response from spoofmytextmessage.com: " + str(data))
        input("Press {return} to return to the previous menu.")

    except Exception as err:
        print_error("Something went wrong while attempting to locate the site. Will print the error message below in a second.")
        print_error("If you are getting an SSL23_GET_SERVER_HELLO:tlsv1 alert internal error, this is likely caused by an out of date version of pyopenssl.")
        print_error("Recommend apt-get remove python-openssl, and run pip install pyopenssl to resolve this issue.")
        print_error("Printing the error: " + str(err))
        input("Press {return} to return to the previous menu.")
