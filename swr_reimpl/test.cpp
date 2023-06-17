// g++ test.cpp

#include <Windows.h>
#include <string>

#include <libloaderapi.h> // GetProcAddress

std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

int main(void) {
    HINSTANCE hDLL = NULL;
    FARPROC lpGetNumber;
    hDLL = LoadLibraryA("swr_reimpl.dll");
    lpGetNumber = GetProcAddress((HMODULE)hDLL, "hook_init_win");
    printf("error: %s\n", GetLastErrorAsString());
    printf("result %p\n", lpGetNumber);
    // while(1){}
    return 0;
}
