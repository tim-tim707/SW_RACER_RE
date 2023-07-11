#include "stdConsole.h"

#include "globals.h"

// 0x00484820
int stdConsole_Printf(char* format, ...)
{
    va_list args;
    va_start(args, format);
    va_end(args);

    vsnprintf(std_output_buffer, sizeof(std_output_buffer), format, args);
    stdConsole_Puts(std_output_buffer);

    return sizeof(std_output_buffer);
}

// 0x0048d160
BOOL stdConsole_SetConsoleTextAttribute(WORD wAttributes)
{
    stdConsole_wAttributes = wAttributes;
    return SetConsoleTextAttribute(stdConsole_hConsoleOutput, wAttributes);
}

// 0x0048d180
BOOL stdConsole_Puts(char* buffer, DWORD wAttributes)
{
    uint buffer_len;
    if (stdConsole_wAttributes != (short)wAttributes)
    {
        stdConsole_SetConsoleTextAttribute(wAttributes);
    }

    buffer_len = strlen(buffer);
    WriteConsoleA(stdConsole_hConsoleOutput, buffer, buffer_len, &wAttributes, NULL);
    return;
}
