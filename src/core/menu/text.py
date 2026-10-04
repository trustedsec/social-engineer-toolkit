#!/usr/bin/env python
########################################################################
#
# text menu for set menu stuff
#
########################################################################
from src.core.setcore import bcolors, get_version, check_os, meta_path
from src.core.i18n import translate as _

# grab version of SET
define_version = get_version()

# check operating system
operating_system = check_os()

# grab metasploit path
msf_path = meta_path()

PORT_NOT_ZERO = _("Port cannot be zero!")
PORT_TOO_HIGH = _("Let's stick with the LOWER 65,535 ports...")

main_text = _(" Select from the menu:\n")

main_menu = [_('Social-Engineering Attacks'),
             _('Penetration Testing (Fast-Track)'),
             _('Third Party Modules'),
             _('Update the Social-Engineer Toolkit'),
             _('Update SET configuration'),
             _('Help, Credits, and About')]

main = [_('Spear-Phishing Attack Vectors'),
        _('Website Attack Vectors'),
        _('Infectious Media Generator'),
        _('Create a Payload and Listener'),
        _('Mass Mailer Attack'),
        _('Arduino-Based Attack Vector'),
        _('Wireless Access Point Attack Vector'),
        _('QRCode Generator Attack Vector'),
        _('Powershell Attack Vectors'),
        _('Third Party Modules')]

spearphish_menu = [_('Perform a Mass Email Attack'),
                   _('Create a FileFormat Payload'),
                   _('Create a Social-Engineering Template'),
                   '0D']

spearphish_text = _("""
 The {bold}Spearphishing{endc} module allows you to specially craft email messages and send
 them to a large (or small) number of people with attached fileformat malicious
 payloads. If you want to spoof your email address, be sure "Sendmail" is in-
 stalled (apt-get install sendmail) and change the config/set_config SENDMAIL=OFF
 flag to SENDMAIL=ON.

 There are two options, one is getting your feet wet and letting SET do
 everything for you (option 1), the second is to create your own FileFormat
 payload and use it in your own attack. Either way, good luck and enjoy!
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

webattack_menu = [_('Java Applet Attack Method'),
                  _('Metasploit Browser Exploit Method'),
                  _('Credential Harvester Attack Method'),
                  _('Tabnabbing Attack Method'),
                  _('Web Jacking Attack Method'),
                  _('Multi-Attack Web Method'),
                  _('HTA Attack Method'),
                  '0D']

fasttrack_menu = [_('Microsoft SQL Bruter'),
                  _('Custom Exploits'),
                  _('SCCM Attack Vector'),
                  _('Dell DRAC/Chassis Default Checker'),
                  _('RID_ENUM - User Enumeration Attack'),
                  _('PSEXEC Powershell Injection'),
                  '0D']

fasttrack_text = _("""
Welcome to the Social-Engineer Toolkit - {bold}Fast-Track Penetration Testing platform{endc}. These attack vectors
have a series of exploits and automation aspects to assist in the art of penetration testing. SET
now incorporates the attack vectors leveraged in Fast-Track. All of these attack vectors have been
completely rewritten and customized from scratch as to improve functionality and capabilities.
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

fasttrack_exploits_menu1 = [_('MS08-067 (Win2000, Win2k3, WinXP)'),
                            _('Mozilla Firefox 3.6.16 mChannel Object Use After Free Exploit (Win7)'),
                            _('Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit'),
                            _('RDP | Use after Free - Denial of Service'),
                            _('MySQL Authentication Bypass Exploit'),
                            _('F5 Root Authentication Bypass Exploit'),
                            '0D']

fasttrack_exploits_text1 = _("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing {bold}Exploits Section{endc}. This
menu has obscure exploits and ones that are primarily python driven. This will continue to grow over time.
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

fasttrack_mssql_menu1 = [_('Scan and Attack MSSQL'),
                         _('Connect directly to MSSQL'),
                         '0D']

fasttrack_mssql_text1 = _("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing {bold}Microsoft SQL Brute Forcer{endc}. This
attack vector will attempt to identify live MSSQL servers and brute force the weak account passwords that
may be found. If that occurs, SET will then compromise the affected system by deploying a binary to
hexadecimal attack vector which will take a raw binary, convert it to hexadecimal and use a staged approach
in deploying the hexadecimal form of the binary onto the underlying system. At this point, a trigger will occur
to convert the payload back to a binary for us.
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

webattack_text = _("""
The Web Attack module is a unique way of utilizing multiple web-based attacks in order to compromise the intended victim.

The {bold}Java Applet Attack{endc} method will spoof a Java Certificate and deliver a Metasploit-based payload. Uses a customized java applet created by Thomas Werth to deliver the payload.

The {bold}Metasploit Browser Exploit{endc} method will utilize select Metasploit browser exploits through an iframe and deliver a Metasploit payload.

The {bold}Credential Harvester{endc} method will utilize web cloning of a web- site that has a username and password field and harvest all the information posted to the website.

The {bold}TabNabbing{endc} method will wait for a user to move to a different tab, then refresh the page to something different.

The {bold}Web-Jacking Attack{endc} method was introduced by white_sheep, emgent. This method utilizes iframe replacements to make the highlighted URL link to appear legitimate however when clicked a window pops up then is replaced with the malicious link. You can edit the link replacement settings in the set_config if it's too slow/fast.

The {bold}Multi-Attack{endc} method will add a combination of attacks through the web attack menu. For example, you can utilize the Java Applet, Metasploit Browser, Credential Harvester/Tabnabbing all at once to see which is successful.

The {bold}HTA Attack{endc} method will allow you to clone a site and perform PowerShell injection through HTA files which can be used for Windows-based PowerShell exploitation through the browser.
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

webattack_vectors_menu = [_('Web Templates'),
                          _('Site Cloner'),
                          _('Custom Import\n'),
                          ]

webattack_vectors_text = (_("""
 The first method will allow SET to import a list of pre-defined web
 applications that it can utilize within the attack.

 The second method will completely clone a website of your choosing
 and allow you to utilize the attack vectors within the completely
 same web application you were attempting to clone.

 The third method allows you to import your own website, note that you
 should only have an index.html when using the import website
 functionality.
   """))

teensy_menu = [_('PowerShell HTTP GET MSF Payload'),
               _('WSCRIPT HTTP GET MSF Payload'),
               _('PowerShell based Reverse Shell Payload'),
               _('Internet Explorer/FireFox Beef Jack Payload'),
               _('Go to malicious java site and accept applet Payload'),
               _('Gnome wget Download Payload'),
               _('Binary 2 Teensy Attack (Deploy MSF payloads)'),
               _('SDCard 2 Teensy Attack (Deploy Any EXE)'),
               _('SDCard 2 Teensy Attack (Deploy on OSX)'),
               _('X10 Arduino Sniffer PDE and Libraries'),
               _('X10 Arduino Jammer PDE and Libraries'),
               _('PowerShell Direct ShellCode Teensy Attack'),
               _('Peensy Multi Attack Dip Switch + SDCard Attack'),
	       _('HID Msbuild compile to memory Shellcode Attack'),
               '0D']

teensy_text = _("""
 The {bold}Arduino-Based Attack{endc} Vector utilizes the Arduin-based device to
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
 vectors range from PowerShell based downloaders, wscript attacks,
 and other methods.

 For more information on specifications and good tutorials visit:

 http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle

 To purchase a Teensy, visit: http://www.pjrc.com/store/teensy.html
 Special thanks to: IronGeek, WinFang, and Garland

 This attack vector also attacks X10 based controllers, be sure to be leveraging
 X10 based communication devices in order for this to work.

 Select a payload to create the pde file to import into Arduino:
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

wireless_attack_menu = [_('Start the SET Wireless Attack Vector Access Point'),
                        _('Stop the SET Wireless Attack Vector Access Point'),
                        '0D']


wireless_attack_text = _("""
 The {bold}Wireless Attack{endc} module will create an access point leveraging your
 wireless card and redirect all DNS queries to you. The concept is fairly
 simple, SET will create a wireless access point, DHCP server, and spoof
 DNS to redirect traffic to the attacker machine. It will then exit out
 of that menu with everything running as a child process.

 You can then launch any SET attack vector you want, for example the Java
 Applet attack and when a victim joins your access point and tries going to
 a website, will be redirected to your attacker machine.

 This attack vector requires AirBase-NG, AirMon-NG, DNSSpoof, and dhcpd3.

""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)

infectious_menu = [_('File-Format Exploits'),
                   _('Standard Metasploit Executable'),
                   '0D']


infectious_text = _("""
 The {bold}{green}Infectious {endc}USB/CD/DVD module will create an autorun.inf file and a
 Metasploit payload. When the DVD/USB/CD is inserted, it will automatically
 run if autorun is enabled.{endc}

 Pick the attack vector you wish to use: fileformat bugs or a straight executable.
""").format(bold=bcolors.BOLD, green=bcolors.GREEN, endc=bcolors.ENDC)

# used in create_payloads.py
if operating_system != "windows":
    if msf_path != False:
        payload_menu_1 = [
            _('Meterpreter Memory Injection (DEFAULT)  This will drop a Meterpreter payload through powershell injection'),
            _('Meterpreter Multi-Memory Injection      This will drop multiple Metasploit payloads via powershell injection'),
            _('SE Toolkit Interactive Shell            Custom interactive reverse toolkit designed for SET'),
            _('SE Toolkit HTTP Reverse Shell           Purely native HTTP shell with AES encryption support'),
            _('RATTE HTTP Tunneling Payload            Security bypass payload that will tunnel all comms over HTTP'),
            _('ShellCodeExec Alphanum Shellcode        This will drop a meterpreter payload through shellcodeexec'),
            _('Import your own executable              Specify a path for your own executable'),
            _('Import your own commands.txt            Specify payloads to be sent via command line\n')]

if operating_system == "windows" or msf_path == False:
    payload_menu_1 = [
        _('SE Toolkit Interactive Shell    Custom interactive reverse toolkit designed for SET'),
        _('SE Toolkit HTTP Reverse Shell   Purely native HTTP shell with AES encryption support'),
        _('RATTE HTTP Tunneling Payload    Security bypass payload that will tunnel all comms over HTTP\n')]

payload_menu_1_text = _("""
What payload would you like to generate:

  Name:                                       Description:
""")

# used in gen_payload.py
payload_menu_2 = [
    _('Windows Shell Reverse_TCP               Spawn a command shell on victim and send back to attacker'),
    _('Windows Reverse_TCP Meterpreter         Spawn a meterpreter shell on victim and send back to attacker'),
    _('Windows Reverse_TCP VNC DLL             Spawn a VNC server on victim and send back to attacker'),
    _('Windows Shell Reverse_TCP X64           Windows X64 Command Shell, Reverse TCP Inline'),
    _('Windows Meterpreter Reverse_TCP X64     Connect back to the attacker (Windows x64), Meterpreter'),
    _('Windows Meterpreter Egress Buster       Spawn a Meterpreter shell and find a port home via multiple ports'),
    _('Windows Meterpreter Reverse HTTPS       Tunnel communication over HTTP using SSL and use Meterpreter'),
    _('Windows Meterpreter Reverse DNS         Use a hostname instead of an IP address and use Reverse Meterpreter'),
    _('Download/Run your Own Executable        Downloads an executable and runs it\n')
]


payload_menu_2_text = """\n"""

payload_menu_3_text = ""
payload_menu_3 = [
    _('Windows Reverse TCP Shell              Spawn a command shell on victim and send back to attacker'),
    _('Windows Meterpreter Reverse_TCP        Spawn a Meterpreter shell on victim and send back to attacker'),
    _('Windows Reverse VNC DLL                Spawn a VNC server on victim and send back to attacker'),
    _('Windows Reverse TCP Shell (x64)        Windows X64 Command Shell, Reverse TCP Inline'),
    _('Windows Meterpreter Reverse_TCP (X64)  Connects back to the attacker (Windows x64), Meterpreter'),
    _('Windows Shell Bind_TCP (X64)           Execute payload and create an accepting port on remote system'),
    _('Windows Meterpreter Reverse HTTPS      Tunnel communication over HTTP using SSL and use Meterpreter\n')]

# called from create_payload.py associated dictionary = ms_attacks
create_payloads_menu = [
    _('SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)'),
    _('SET Custom Written Document UNC LM SMB Capture Attack'),
    _('MS15-100 Microsoft Windows Media Center MCL Vulnerability'),
    _('MS14-017 Microsoft Word RTF Object Confusion (2014-04-01)'),
    _('Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow'),
    _('Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)'),
    _('Adobe Flash Player "Button" Remote Code Execution'),
    _('Adobe CoolType SING Table "uniqueName" Overflow'),
    _('Adobe Flash Player "newfunction" Invalid Pointer Use'),
    _('Adobe Collab.collectEmailInfo Buffer Overflow'),
    _('Adobe Collab.getIcon Buffer Overflow'),
    _('Adobe JBIG2Decode Memory Corruption Exploit'),
    _('Adobe PDF Embedded EXE Social Engineering'),
    _('Adobe util.printf() Buffer Overflow'),
    _('Custom EXE to VBA (sent via RAR) (RAR required)'),
    _('Adobe U3D CLODProgressiveMeshDeclaration Array Overrun'),
    _('Adobe PDF Embedded EXE Social Engineering (NOJS)'),
    _('Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow'),
    _('Apple QuickTime PICT PnSize Buffer Overflow'),
    _('Nuance PDF Reader v6.0 Launch Stack Buffer Overflow'),
    _('Adobe Reader u3D Memory Corruption Vulnerability'),
    _('MSCOMCTL ActiveX Buffer Overflow (ms12-027)\n')]

create_payloads_text = _("""
 Select the file format exploit you want.
 The default is the PDF embedded EXE.\n
           ********** PAYLOADS **********\n""")

browser_exploits_menu = [
    _('Adobe Flash Player ByteArray Use After Free (2015-07-06)'),
    _('Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow (2015-06-23)'),
    _('Adobe Flash Player Drawing Fill Shader Memory Corruption (2015-05-12)'),
    _('MS14-012 Microsoft Internet Explorer TextRange Use-After-Free (2014-03-11)'),
    _('MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free (2014-02-13)'),
    _('Internet Explorer CDisplayPointer Use-After-Free (10/13/2013)'),
    _('Micorosft Internet Explorer SetMouseCapture Use-After-Free (09/17/2013)'),
    _('Java Applet JMX Remote Code Execution (UPDATED 2013-01-19)'),
    _('Java Applet JMX Remote Code Execution (2013-01-10)'),
    _('MS13-009 Microsoft Internet Explorer SLayoutRun Use-AFter-Free (2013-02-13)'),
    _('Microsoft Internet Explorer CDwnBindInfo Object Use-After-Free (2012-12-27)'),
    _('Java 7 Applet Remote Code Execution (2012-08-26)'),
    _('Microsoft Internet Explorer execCommand Use-After-Free Vulnerability (2012-09-14)'),
    _('Java AtomicReferenceArray Type Violation Vulnerability (2012-02-14)'),
    _('Java Applet Field Bytecode Verifier Cache Remote Code Execution (2012-06-06)'),
    _('MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption (2012-06-12)'),
    _('Microsoft XML Core Services MSXML Uninitialized Memory Corruption (2012-06-12)'),
    _('Adobe Flash Player Object Type Confusion  (2012-05-04)'),
    _('Adobe Flash Player MP4 "cprt" Overflow (2012-02-15)'),
    _('MS12-004 midiOutPlayNextPolyEvent Heap Overflow (2012-01-10)'),
    _('Java Applet Rhino Script Engine Remote Code Execution (2011-10-18)'),
    _('MS11-050 IE mshtml!CObjectElement Use After Free  (2011-06-16)'),
    _('Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability (2011-04-11)'),
    _('Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute (2011-06-01)'),
    _('Internet Explorer CSS Import Use After Free (2010-11-29)'),
    _('Microsoft WMI Administration Tools ActiveX Buffer Overflow (2010-12-21)'),
    _('Internet Explorer CSS Tags Memory Corruption (2010-11-03)'),
    _('Sun Java Applet2ClassLoader Remote Code Execution (2011-02-15)'),
    _('Sun Java Runtime New Plugin docbase Buffer Overflow (2010-10-12)'),
    _('Microsoft Windows WebDAV Application DLL Hijacker (2010-08-18)'),
    _('Adobe Flash Player AVM Bytecode Verification Vulnerability (2011-03-15)'),
    _('Adobe Shockwave rcsL Memory Corruption Exploit (2010-10-21)'),
    _('Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow (2010-09-07)'),
    _('Apple QuickTime 7.6.7 Marshaled_pUnk Code Execution (2010-08-30)'),
    _('Microsoft Help Center XSS and Command Execution (2010-06-09)'),
    _('Microsoft Internet Explorer iepeers.dll Use After Free (2010-03-09)'),
    _('Microsoft Internet Explorer "Aurora" Memory Corruption (2010-01-14)'),
    _('Microsoft Internet Explorer Tabular Data Control Exploit (2010-03-0)'),
    _('Microsoft Internet Explorer 7 Uninitialized Memory Corruption (2009-02-10)'),
    _('Microsoft Internet Explorer Style getElementsbyTagName Corruption (2009-11-20)'),
    _('Microsoft Internet Explorer isComponentInstalled Overflow (2006-02-24)'),
    _('Microsoft Internet Explorer Data Binding Corruption (2008-12-07)'),
    _('Microsoft Internet Explorer Unsafe Scripting Misconfiguration (2010-09-20)'),
    _('FireFox 3.5 escape Return Value Memory Corruption (2009-07-13)'),
    _('FireFox 3.6.16 mChannel use after free vulnerability (2011-05-10)'),
    _('Metasploit Browser Autopwn (USE AT OWN RISK!)\n')]

browser_exploits_text = _("""
 Enter the browser exploit you would like to use [8]:
""")

# this is for the powershell attack vectors
powershell_menu = [_('Powershell Alphanumeric Shellcode Injector'),
                   _('Powershell Reverse Shell'),
                   _('Powershell Bind Shell'),
                   _('Powershell Dump SAM Database'),
                   '0D']

powershell_text = _("""
The {bold}Powershell Attack Vector{endc} module allows you to create PowerShell specific attacks. These attacks will allow you to use PowerShell which is available by default in all operating systems Windows Vista and above. PowerShell provides a fruitful landscape for deploying payloads and performing functions that  do not get triggered by preventative technologies.
""").format(bold=bcolors.BOLD, endc=bcolors.ENDC)


encoder_menu = [_('shikata_ga_nai'),
                _('No Encoding'),
                _('Multi-Encoder'),
                _('Backdoored Executable\n')]

encoder_text = _("""
Select one of the below, 'backdoored executable' is typically the best. However,
most still get picked up by AV. You may need to do additional packing/crypting
in order to get around basic AV detection.
""")

dll_hijacker_text = _("""
 The DLL Hijacker vulnerability will allow normal file extensions to
 call local (or remote) .dll files that can then call your payload or
 executable. In this scenario it will compact the attack in a zip file
 and when the user opens the file extension, will trigger the dll then
 ultimately our payload. During the time of this release, all of these
 file extensions were tested and appear to work and are not patched. This
 will continuously be updated as time goes on.
""")

fakeap_dhcp_menu = ['10.0.0.100-254',
                    '192.168.10.100-254\n']

fakeap_dhcp_text = _("Please choose the DHCP configuration you would like to use: ")
