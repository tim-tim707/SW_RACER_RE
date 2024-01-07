#include <windows.h>
#include <iostream>

#include "md5.h"

// g++ loader.cpp -o loader

std::string GetLastErrorAsString()
{
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0) {
        return std::string();
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    return message;
}

int md5Match(uint8_t* reference, uint8_t* candidate)
{
    int res = 0;
    for (size_t i = 0; i < 16; i++)
    {
        if (reference[i] != candidate[i])
        {
            return 0;
        }
    }
    return 1;
}

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

    // Check md5 in order to work only on supported versions
    FILE* f = fopen(targetPath, "rb");

    uint8_t GOG_VERSION[16] = { 0xe1, 0xfc, 0xf5, 0x0c, 0x8d, 0xe2, 0xdb, 0xef, 0x70, 0xe6, 0xad, 0x8e, 0x09, 0x37, 0x13, 0x22 };
    uint8_t STEAM_VERSION[16] = { 0xad, 0xbe, 0xf6, 0xbc, 0x97, 0x47, 0xc0, 0x87, 0x48, 0x5f, 0xce, 0x8a, 0x48, 0xf5, 0xec, 0xa4 };
    uint8_t result[16];

    md5File(f, result);
    int matching_gog = md5Match(GOG_VERSION, result);
    int matching_steam = 0;
    
    if (!matching_gog)
    {
        matching_steam = md5Match(STEAM_VERSION, result);
    }
    
    if (!(matching_gog || matching_steam))
    {
        printf("Your version not supported yet for this loader. Only GOG and Steams Versions are supported at the moment.\n");
        printf("If you want your version to be supported in the future, please file an issue with your version and the attached md5 sum provided here:\n");
        printf("md5: ");
        for (size_t i = 0; i < 16; i++)
        {
            printf("%02x", result[i]);
        }
        printf("\n");

        return 1;
    }
    if (matching_gog)
    {
        printf("GOG version detected, md5 are matching\n");
    }
    if (matching_steam)
    {
        printf("Steam version detected, md5 are matching\n");
    }

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
        auto error = GetLastErrorAsString();
        std::cerr << error << std::endl;
        return FALSE;
    }
    lpLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!lpLoadLibraryA)
    {
        std::cerr << "GetProcAddress failed\n";
        auto error = GetLastErrorAsString();
        std::cerr << error << std::endl;

        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    nLength = strlen(lpcstrDll);

    lpRemoteString = VirtualAllocEx(processInformation.hProcess, NULL, nLength + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteString)
    {
        std::cerr << "VirtualAllocEx failed\n";
        auto error = GetLastErrorAsString();
        std::cerr << error << std::endl;
        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    if (!WriteProcessMemory(processInformation.hProcess, lpRemoteString, lpcstrDll, nLength, NULL))
    {
        std::cerr << "WriteProcessMemory failed\n";
        auto error = GetLastErrorAsString();
        std::cerr << error << std::endl;

        VirtualFreeEx(processInformation.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(processInformation.hProcess);
        return FALSE;
    }
    HANDLE hThread_injection = CreateRemoteThread(processInformation.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpRemoteString, 0, NULL);
    if (!hThread_injection)
    {
        std::cerr << "CreateRemoteThread failed\n";
        auto error = GetLastErrorAsString();
        std::cerr << error << std::endl;
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
