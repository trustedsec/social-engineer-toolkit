#!/usr/bin/env python
########################################################################
#
# text menu for set menu stuff
#
########################################################################
from src.core.setcore import bcolors, get_version, check_os, meta_path

# grab version of SET
define_version = get_version()

# check operating system
operating_system = check_os()

# grab metasploit path
msf_path = meta_path()

PORT_NOT_ZERO = "Port cannot be zero!"
PORT_TOO_HIGH = "Let's stick with the LOWER 65,535 ports..."

main_text = " Select from the menu:\n"

main_menu = ['Social-Engineering Attacks',
             'Penetration Testing (Fast-Track)',
             'Third Party Modules',
             'Update the Social-Engineer Toolkit',
             'Update SET configuration',
             'Help, Credits, and About']

main = ['Spear-Phishing Attack Vectors',
        'Website Attack Vectors',
        'Infectious Media Generator',
        'Create a Payload and Listener',
        'Mass Mailer Attack',
        'Arduino-Based Attack Vector',
        'Wireless Access Point Attack Vector',
        'QRCode Generator Attack Vector',
        'Powershell Attack Vectors',
        'Third Party Modules']

spearphish_menu = ['Perform a Mass Email Attack',
                   'Create a FileFormat Payload',
                   'Create a Social-Engineering Template',
                   '0D']

spearphish_text = ("""
 The """ + bcolors.BOLD + """Spearphishing""" + bcolors.ENDC + """ module allows you to specially craft email messages and send
 them to a large (or small) number of people with attached fileformat malicious
 payloads. If you want to spoof your email address, be sure "Sendmail" is in-
 stalled (apt-get install sendmail) and change the config/set_config SENDMAIL=OFF
 flag to SENDMAIL=ON.

 There are two options, one is getting your feet wet and letting SET do
 everything for you (option 1), the second is to create your own FileFormat
 payload and use it in your own attack. Either way, good luck and enjoy!
""")

webattack_menu = ['Java Applet Attack Method',
                  'Metasploit Browser Exploit Method',
                  'Credential Harvester Attack Method',
                  'Tabnabbing Attack Method',
                  'Web Jacking Attack Method',
                  'Multi-Attack Web Method',
                  'HTA Attack Method',
                  '0D']

fasttrack_menu = ['Microsoft SQL Bruter',
                  'Custom Exploits',
                  'SCCM Attack Vector',
                  'Dell DRAC/Chassis Default Checker',
                  'RID_ENUM - User Enumeration Attack',
                  'PSEXEC Powershell Injection',
                  '0D']

fasttrack_text = ("""
Welcome to the Social-Engineer Toolkit - """ + bcolors.BOLD + """Fast-Track Penetration Testing platform""" + bcolors.ENDC + """. These attack vectors
have a series of exploits and automation aspects to assist in the art of penetration testing. SET
now incorporates the attack vectors leveraged in Fast-Track. All of these attack vectors have been
completely rewritten and customized from scratch as to improve functionality and capabilities.
""")

fasttrack_exploits_menu1 = ['MS08-067 (Win2000, Win2k3, WinXP)',
                            'Mozilla Firefox 3.6.16 mChannel Object Use After Free Exploit (Win7)',
                            'Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit',
                            'RDP | Use after Free - Denial of Service',
                            'MySQL Authentication Bypass Exploit',
                            'F5 Root Authentication Bypass Exploit',
                            '0D']

fasttrack_exploits_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Exploits Section""" + bcolors.ENDC + """. This
menu has obscure exploits and ones that are primarily python driven. This will continue to grow over time.
""")

fasttrack_mssql_menu1 = ['Scan and Attack MSSQL',
                         'Connect directly to MSSQL',
                         '0D']

fasttrack_mssql_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Microsoft SQL Brute Forcer""" + bcolors.ENDC + """. This
attack vector will attempt to identify live MSSQL servers and brute force the weak account passwords that
may be found. If that occurs, SET will then compromise the affected system by deploying a binary to
hexadecimal attack vector which will take a raw binary, convert it to hexadecimal and use a staged approach
in deploying the hexadecimal form of the binary onto the underlying system. At this point, a trigger will occur
to convert the payload back to a binary for us.
""")

webattack_text = ("""
The Web Attack module is a unique way of utilizing multiple web-based attacks in order to compromise the intended victim.

The """ + bcolors.BOLD + """Java Applet Attack""" + bcolors.ENDC + """ method will spoof a Java Certificate and deliver a metasploit based payload. Uses a customized java applet created by Thomas Werth to deliver the payload.

The """ + bcolors.BOLD + """Metasploit Browser Exploit""" + bcolors.ENDC + """ method will utilize select Metasploit browser exploits through an iframe and deliver a Metasploit payload.

The """ + bcolors.BOLD + """Credential Harvester""" + bcolors.ENDC + """ method will utilize web cloning of a web- site that has a username and password field and harvest all the information posted to the website.

The """ + bcolors.BOLD + """TabNabbing""" + bcolors.ENDC + """ method will wait for a user to move to a different tab, then refresh the page to something different.

The """ + bcolors.BOLD + """Web-Jacking Attack""" + bcolors.ENDC + """ method was introduced by white_sheep, emgent. This method utilizes iframe replacements to make the highlighted URL link to appear legitimate however when clicked a window pops up then is replaced with the malicious link. You can edit the link replacement settings in the set_config if its too slow/fast.

The """ + bcolors.BOLD + """Multi-Attack""" + bcolors.ENDC + """ method will add a combination of attacks through the web attack menu. For example you can utilize the Java Applet, Metasploit Browser, Credential Harvester/Tabnabbing all at once to see which is successful.

The """ + bcolors.BOLD + """HTA Attack""" + bcolors.ENDC + """ method will allow you to clone a site and perform powershell injection through HTA files which can be used for Windows-based powershell exploitation through the browser.
""")

webattack_vectors_menu = ['Web Templates',
                          'Site Cloner',
                          'Custom Import\n',
                          ]

webattack_vectors_text = ("""
 The first method will allow SET to import a list of pre-defined web
 applications that it can utilize within the attack.

 The second method will completely clone a website of your choosing
 and allow you to utilize the attack vectors within the completely
 same web application you were attempting to clone.

 The third method allows you to import your own website, note that you
 should only have an index.html when using the import website
 functionality.
   """)

teensy_menu = ['Powershell HTTP GET MSF Payload',
               'WSCRIPT HTTP GET MSF Payload',
               'Powershell based Reverse Shell Payload',
               'Internet Explorer/FireFox Beef Jack Payload',
               'Go to malicious java site and accept applet Payload',
               'Gnome wget Download Payload',
               'Binary 2 Teensy Attack (Deploy MSF payloads)',
               'SDCard 2 Teensy Attack (Deploy Any EXE)',
               'SDCard 2 Teensy Attack (Deploy on OSX)',
               'X10 Arduino Sniffer PDE and Libraries',
               'X10 Arduino Jammer PDE and Libraries',
               'Powershell Direct ShellCode Teensy Attack',
               'Peensy Multi Attack Dip Switch + SDCard Attack',
	       'HID Msbuild compile to memory Shellcode Attack',
               '0D']

teensy_text = ("""
 The """ + bcolors.BOLD + """Arduino-Based Attack""" + bcolors.ENDC + """ Vector utilizes the Arduin-based device to
 program the device. You can leverage the Teensy's, which have onboard
 storage and can allow for remote code execution on the physical
 system. Since the devices are registered as USB Keyboard's it
 will bypass any autorun disabled or endpoint protection on the
 system.

 You will need to purchase the Teensy USB device, it's roughly
 $22 dollars. This attack vector will auto generate the code
 needed in order to deploy the payload on the system for you.

 This attack vector will create the .pde files necessary to import
 into Arduino (the IDE used for programming the Teensy). The attack
 vectors range from Powershell based downloaders, wscript attacks,
 and other methods.

 For more information on specifications and good tutorials visit:

 http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle

 To purchase a Teensy, visit: http://www.pjrc.com/store/teensy.html
 Special thanks to: IronGeek, WinFang, and Garland

 This attack vector also attacks X10 based controllers, be sure to be leveraging
 X10 based communication devices in order for this to work.

 Select a payload to create the pde file to import into Arduino:
""")

wireless_attack_menu = ['Start the SET Wireless Attack Vector Access Point',
                        'Stop the SET Wireless Attack Vector Access Point',
                        '0D']


wireless_attack_text = """
 The """ + bcolors.BOLD + """Wireless Attack""" + bcolors.ENDC + """ module will create an access point leveraging your
 wireless card and redirect all DNS queries to you. The concept is fairly
 simple, SET will create a wireless access point, dhcp server, and spoof
 DNS to redirect traffic to the attacker machine. It will then exit out
 of that menu with everything running as a child process.

 You can then launch any SET attack vector you want, for example the Java
 Applet attack and when a victim joins your access point and tries going to
 a website, will be redirected to your attacker machine.

 This attack vector requires AirBase-NG, AirMon-NG, DNSSpoof, and dhcpd3.

"""

infectious_menu = ['File-Format Exploits',
                   'Standard Metasploit Executable',
                   '0D']


infectious_text = """
 The """ + bcolors.BOLD + bcolors.GREEN + """Infectious """ + bcolors.ENDC + """USB/CD/DVD module will create an autorun.inf file and a
 Metasploit payload. When the DVD/USB/CD is inserted, it will automatically
 run if autorun is enabled.""" + bcolors.ENDC + """

 Pick the attack vector you wish to use: fileformat bugs or a straight executable.
"""

# used in create_payloads.py
if operating_system != "windows":
    if msf_path != False:
        payload_menu_1 = [
            'Meterpreter Memory Injection (DEFAULT)  This will drop a meterpreter payload through powershell injection',
            'Meterpreter Multi-Memory Injection      This will drop multiple Metasploit payloads via powershell injection',
            'SE Toolkit Interactive Shell            Custom interactive reverse toolkit designed for SET',
            'SE Toolkit HTTP Reverse Shell           Purely native HTTP shell with AES encryption support',
            'RATTE HTTP Tunneling Payload            Security bypass payload that will tunnel all comms over HTTP',
            'ShellCodeExec Alphanum Shellcode        This will drop a meterpreter payload through shellcodeexec',
            'Import your own executable              Specify a path for your own executable',
            'Import your own commands.txt            Specify payloads to be sent via command line\n']

if operating_system == "windows" or msf_path == False:
    payload_menu_1 = [
        'SE Toolkit Interactive Shell    Custom interactive reverse toolkit designed for SET',
        'SE Toolkit HTTP Reverse Shell   Purely native HTTP shell with AES encryption support',
        'RATTE HTTP Tunneling Payload    Security bypass payload that will tunnel all comms over HTTP\n']

payload_menu_1_text = """
What payload do you want to generate:

  Name:                                       Description:
"""

# used in gen_payload.py
payload_menu_2 = [
    'Windows Shell Reverse_TCP               Spawn a command shell on victim and send back to attacker',
    'Windows Reverse_TCP Meterpreter         Spawn a meterpreter shell on victim and send back to attacker',
    'Windows Reverse_TCP VNC DLL             Spawn a VNC server on victim and send back to attacker',
    'Windows Shell Reverse_TCP X64           Windows X64 Command Shell, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP X64     Connect back to the attacker (Windows x64), Meterpreter',
    'Windows Meterpreter Egress Buster       Spawn a meterpreter shell and find a port home via multiple ports',
    'Windows Meterpreter Reverse HTTPS       Tunnel communication over HTTP using SSL and use Meterpreter',
    'Windows Meterpreter Reverse DNS         Use a hostname instead of an IP address and use Reverse Meterpreter',
    'Download/Run your Own Executable        Downloads an executable and runs it\n'
]


payload_menu_2_text = """\n"""

payload_menu_3_text = ""
payload_menu_3 = [
    'Windows Reverse TCP Shell              Spawn a command shell on victim and send back to attacker',
    'Windows Meterpreter Reverse_TCP        Spawn a meterpreter shell on victim and send back to attacker',
    'Windows Reverse VNC DLL                Spawn a VNC server on victim and send back to attacker',
    'Windows Reverse TCP Shell (x64)        Windows X64 Command Shell, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP (X64)  Connect back to the attacker (Windows x64), Meterpreter',
    'Windows Shell Bind_TCP (X64)           Execute payload and create an accepting port on remote system',
    'Windows Meterpreter Reverse HTTPS      Tunnel communication over HTTP using SSL and use Meterpreter\n']

# called from create_payload.py associated dictionary = ms_attacks
create_payloads_menu = [
    'SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)',
    'SET Custom Written Document UNC LM SMB Capture Attack',
    'MS15-100 Microsoft Windows Media Center MCL Vulnerability',
    'MS14-017 Microsoft Word RTF Object Confusion (2014-04-01)',
    'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow',
    'Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)',
    'Adobe Flash Player "Button" Remote Code Execution',
    'Adobe CoolType SING Table "uniqueName" Overflow',
    'Adobe Flash Player "newfunction" Invalid Pointer Use',
    'Adobe Collab.collectEmailInfo Buffer Overflow',
    'Adobe Collab.getIcon Buffer Overflow',
    'Adobe JBIG2Decode Memory Corruption Exploit',
    'Adobe PDF Embedded EXE Social Engineering',
    'Adobe util.printf() Buffer Overflow',
    'Custom EXE to VBA (sent via RAR) (RAR required)',
    'Adobe U3D CLODProgressiveMeshDeclaration Array Overrun',
    'Adobe PDF Embedded EXE Social Engineering (NOJS)',
    'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow',
    'Apple QuickTime PICT PnSize Buffer Overflow',
    'Nuance PDF Reader v6.0 Launch Stack Buffer Overflow',
    'Adobe Reader u3D Memory Corruption Vulnerability',
    'MSCOMCTL ActiveX Buffer Overflow (ms12-027)\n']

create_payloads_text = """
 Select the file format exploit you want.
 The default is the PDF embedded EXE.\n
           ********** PAYLOADS **********\n"""

browser_exploits_menu = [
    'Adobe Flash Player ByteArray Use After Free (2015-07-06)',
    'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow (2015-06-23)',
    'Adobe Flash Player Drawing Fill Shader Memory Corruption (2015-05-12)',
    'MS14-012 Microsoft Internet Explorer TextRange Use-After-Free (2014-03-11)',
    'MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free (2014-02-13)',
    'Internet Explorer CDisplayPointer Use-After-Free (10/13/2013)',
    'Micorosft Internet Explorer SetMouseCapture Use-After-Free (09/17/2013)',
    'Java Applet JMX Remote Code Execution (UPDATED 2013-01-19)',
    'Java Applet JMX Remote Code Execution (2013-01-10)',
    'MS13-009 Microsoft Internet Explorer SLayoutRun Use-AFter-Free (2013-02-13)',
    'Microsoft Internet Explorer CDwnBindInfo Object Use-After-Free (2012-12-27)',
    'Java 7 Applet Remote Code Execution (2012-08-26)',
    'Microsoft Internet Explorer execCommand Use-After-Free Vulnerability (2012-09-14)',
    'Java AtomicReferenceArray Type Violation Vulnerability (2012-02-14)',
    'Java Applet Field Bytecode Verifier Cache Remote Code Execution (2012-06-06)',
    'MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption (2012-06-12)',
    'Microsoft XML Core Services MSXML Uninitialized Memory Corruption (2012-06-12)',
    'Adobe Flash Player Object Type Confusion  (2012-05-04)',
    'Adobe Flash Player MP4 "cprt" Overflow (2012-02-15)',
    'MS12-004 midiOutPlayNextPolyEvent Heap Overflow (2012-01-10)',
    'Java Applet Rhino Script Engine Remote Code Execution (2011-10-18)',
    'MS11-050 IE mshtml!CObjectElement Use After Free  (2011-06-16)',
    'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability (2011-04-11)',
    'Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute (2011-06-01)',
    'Internet Explorer CSS Import Use After Free (2010-11-29)',
    'Microsoft WMI Administration Tools ActiveX Buffer Overflow (2010-12-21)',
    'Internet Explorer CSS Tags Memory Corruption (2010-11-03)',
    'Sun Java Applet2ClassLoader Remote Code Execution (2011-02-15)',
    'Sun Java Runtime New Plugin docbase Buffer Overflow (2010-10-12)',
    'Microsoft Windows WebDAV Application DLL Hijacker (2010-08-18)',
    'Adobe Flash Player AVM Bytecode Verification Vulnerability (2011-03-15)',
    'Adobe Shockwave rcsL Memory Corruption Exploit (2010-10-21)',
    'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow (2010-09-07)',
    'Apple QuickTime 7.6.7 Marshaled_pUnk Code Execution (2010-08-30)',
    'Microsoft Help Center XSS and Command Execution (2010-06-09)',
    'Microsoft Internet Explorer iepeers.dll Use After Free (2010-03-09)',
    'Microsoft Internet Explorer "Aurora" Memory Corruption (2010-01-14)',
    'Microsoft Internet Explorer Tabular Data Control Exploit (2010-03-0)',
    'Microsoft Internet Explorer 7 Uninitialized Memory Corruption (2009-02-10)',
    'Microsoft Internet Explorer Style getElementsbyTagName Corruption (2009-11-20)',
    'Microsoft Internet Explorer isComponentInstalled Overflow (2006-02-24)',
    'Microsoft Internet Explorer Explorer Data Binding Corruption (2008-12-07)',
    'Microsoft Internet Explorer Unsafe Scripting Misconfiguration (2010-09-20)',
    'FireFox 3.5 escape Return Value Memory Corruption (2009-07-13)',
    'FireFox 3.6.16 mChannel use after free vulnerability (2011-05-10)',
    'Metasploit Browser Autopwn (USE AT OWN RISK!)\n']

browser_exploits_text = """
 Enter the browser exploit you would like to use [8]:
"""

# this is for the powershell attack vectors
powershell_menu = ['Powershell Alphanumeric Shellcode Injector',
                   'Powershell Reverse Shell',
                   'Powershell Bind Shell',
                   'Powershell Dump SAM Database',
                   '0D']

powershell_text = ("""
The """ + bcolors.BOLD + """Powershell Attack Vector""" + bcolors.ENDC + """ module allows you to create PowerShell specific attacks. These attacks will allow you to use PowerShell which is available by default in all operating systems Windows Vista and above. PowerShell provides a fruitful  landscape for deploying payloads and performing functions that  do not get triggered by preventative technologies.\n""")


encoder_menu = ['shikata_ga_nai',
                'No Encoding',
                'Multi-Encoder',
                'Backdoored Executable\n']

encoder_text = """
Select one of the below, 'backdoored executable' is typically the best. However,
most still get picked up by AV. You may need to do additional packing/crypting
in order to get around basic AV detection.
"""

dll_hijacker_text = """
 The DLL Hijacker vulnerability will allow normal file extenstions to
 call local (or remote) .dll files that can then call your payload or
 executable. In this scenario it will compact the attack in a zip file
 and when the user opens the file extension, will trigger the dll then
 ultimately our payload. During the time of this release, all of these
 file extensions were tested and appear to work and are not patched. This
 will continiously be updated as time goes on.
"""

fakeap_dhcp_menu = ['10.0.0.100-254',
                    '192.168.10.100-254\n']

fakeap_dhcp_text = "Please choose which DHCP Config you would like to use: "
