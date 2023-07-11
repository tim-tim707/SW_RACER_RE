#ifndef STD_CONSOLE_H
#define STD_CONSOLE_H

#include <windows.h>

#define stdConsole_Printf_ADDR (0x00484820)
#define stdConsole_SetConsoleTextAttribute_ADDR (0x0048d160)
#define stdConsole_Puts_ADDR (0x0048d180)

int stdConsole_Printf(char* buffer, ...);
BOOL stdConsole_SetConsoleTextAttribute(WORD wAttributes);
BOOL stdConsole_Puts(char* buffer, DWORD wAttributes);

#endif // STD_CONSOLE_H
