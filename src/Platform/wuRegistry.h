#ifndef WUREGISTRY_H
#define WUREGISTRY_H

#include "types.h"
#include "globals.h"

#define wuRegistry_Startup_ADDR (0x0049d060)
#define wuRegistry_Shutdown_ADDR (0x0049d0e0)
#define wuRegistry_SaveInt_ADDR (0x0049d100)
#define wuRegistry_GetInt_ADDR (0x0049d180)
#define wuRegistry_SaveInt2_ADDR (0x0049d210)
#define wuRegistry_GetInt2_ADDR (0x0049d230)
#define wuRegistry_SetString_ADDR (0x0049d250)
#define wuRegistry_GetString_ADDR (0x0049d2e0)

int wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey);
void wuRegistry_Shutdown();
int wuRegistry_SaveInt(LPCSTR lpValueName, int val);
int wuRegistry_GetInt(LPCSTR lpValueName, int val);
int wuRegistry_SaveInt2(LPCSTR lpValueName, int val);
int wuRegistry_GetInt2(LPCSTR lpValueName, int val);
int wuRegistry_SetString(LPCSTR lpValueName, char* lpData);
int wuRegistry_GetString(LPCSTR lpValueName, char* lpData, int outSize, char* outDefault);

#endif // WUREGISTRY_H
