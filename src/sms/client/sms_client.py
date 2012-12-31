#!/usr/bin/env python

import sys
from src.core import setcore as core
from src.core.setcore import debug_msg, mod_name

me = mod_name()
while 1:
    print """
   SMS Attack Menu

   There are diferent attacks you can launch in the context of SMS spoofing, 
   select your own.

    1.  SMS Attack Single Phone Number
    2.  SMS Attack Mass SMS

    99. Return to SMS Spoofing Menu\n"""

    attack_option=raw_input(core.setprompt("0",""))

    if attack_option == 'exit':
        core.exit_set()
    # exit 
    if attack_option == '1':
        print("\nSingle SMS Attack")
        to = raw_input(core.setprompt(["7"], "Send sms to"))
        phones = list()
        phones.append(to)
        sys.path.append("src/sms/client/")
        try:
            # ugly but "compliant" with SET architecture 
            debug_msg(me,"importing 'src.sms.client.sms_launch'",1)
            reload(sms_launch)
            sms_launch.phones = phones
            sms_launch.launch()
        except:
            import sms_launch
            sms_launch.phones = phones
            sms_launch.launch() 
        break
    if attack_option == '2':
        # TO DO: MASS SMS ATTACK
        print("\nMass SMS Attack")
        try:
            address_book_path = raw_input(core.setprompt(["7"], "Enter the phone's address book absolute path"))
            address_book = open(address_book_path, "r")
            phones = list()
            phone = address_book.readline()
            while phone:
                phones.append(phone)
                print("\n" + phone)
                phone = address_book.readline()
        except:
            break
        sys.path.append("src/sms/client/")
        try:
            # ugly but "compliant" with SET architecture 
            debug_msg(me,"importing 'src.sms.client.sms_launch'",1)
            reload(sms_launch)
            sms_launch.phones = phones
            sms_launch.launch()
        except:
            import sms_launch 
            sms_launch.phones = phones
            sms_launch.launch()
        break
    if attack_option == '99': 
        break
