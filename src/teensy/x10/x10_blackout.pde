// Written by Rob Simon (kickenchicken57)
// include the X10 library files:
// Original library for sending
// http://www.arduino.cc/en/Tutorial/X10
 
// Send/Receive Library by creatrope
// https://docs.google.com/leaf?id=0B5Sg6E9g_zOXMzQxZmVkYjktNjQwZi00MjgxLTk4YzQtNGIwYzI0ZjA0Njg3&hl=en_US

#include <x10.h>
#include <x10constants.h>

#define zcPin 12         // the zero crossing detect pin
#define dataPin 13       // the X10 data out pin
#define repeatTimes 1

// set up a new x10  library instance:
x10 myHouse =  x10(zcPin, dataPin);

void setup() {
}

void loop() {
  myHouse.write(A, ALL_UNITS_OFF,repeatTimes);
}
