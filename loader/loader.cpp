#include <windows.h>
#include <iostream>

// g++ loader.cpp -o loader

int main(int argc, char** argv)
{
    LPCSTR lpcstrDll = "swr_reimpl.dll";
    LPCSTR targetPath = "SWEP1RCR.EXE";
    SIZE_T nLength;
    LPVOID lpLoadLibraryA = NULL;
    LPVOID lpRemoteString;
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInformation;
    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(STARTUPINFO);

    // https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
    char cmdArgs[8191] = { 0 };
    strcat(cmdArgs, "SWEP1RCR.EXE");
    for (int i = 1; i < argc; i++)
    {
        strcat(cmdArgs, " ");
        strcat(cmdArgs, argv[i]);
    }
    cmdArgs[8190] = '\0';

    if (!CreateProcessA(targetPath, cmdArgs, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation))
    {
        std::cerr << "Target process has failed to start\n";
        return FALSE;
    }
    lpLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!lpLoadLibraryA)
    {
        std::cerr << "GetProcAddress failed\n";

        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    nLength = strlen(lpcstrDll);

    lpRemoteString = VirtualAllocEx(processInformation.hProcess, NULL, nLength + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteString)
    {
        std::cerr << "VirtualAllocEx failed\n";
        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    if (!WriteProcessMemory(processInformation.hProcess, lpRemoteString, lpcstrDll, nLength, NULL))
    {
        std::cerr << "WriteProcessMemory failed\n";

        VirtualFreeEx(processInformation.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    HANDLE hThread_injection = CreateRemoteThread(processInformation.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpRemoteString, 0, NULL);
    if (!hThread_injection)
    {
        std::cerr << "CreateRemoteThread failed\n";
    }
    else
    {
        WaitForSingleObject(hThread_injection, INFINITE);
        ResumeThread(processInformation.hThread);
        CloseHandle(hThread_injection);
    }

    VirtualFreeEx(processInformation.hProcess, lpRemoteString, 0, MEM_RELEASE);
    CloseHandle(processInformation.hProcess);
    return TRUE;
}
