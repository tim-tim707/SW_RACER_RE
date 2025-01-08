#include "wuRegistry.h"

// 0x0049d060
int wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey)
{
    LSTATUS status;
    HKEY phkResult;

    phkResult = NULL;

    wuRegistry_bInitted = 1;
    wuRegistry_lpSubKey = lpSubKey;
    wuRegistry_hKey = hKey;
    status = RegCreateKeyExA(hKey, lpSubKey, 0, wuRegistry_lpClass, 0, 0xf003f, NULL, &phkResult, (LPDWORD)&lpSubKey);
    if (status == 0)
    {
        status = RegCloseKey(phkResult);
        if (status == 0)
        {
            return 0;
        }
    }
    if (phkResult != NULL)
    {
        RegCloseKey(phkResult);
    }
    return 1;
}

// 0x0049d0e0
void wuRegistry_Shutdown()
{
    wuRegistry_lpSubKey = NULL;
    wuRegistry_hKey = NULL;
    wuRegistry_bInitted = 0;
}

// 0x0049d100
int wuRegistry_SaveInt(LPCSTR lpValueName, int val)
{
    LSTATUS status;
    HKEY phkResult;

    phkResult = NULL;
    status = RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xf003f, &phkResult);
    if (status == 0)
    {
        status = RegSetValueExA(phkResult, lpValueName, 0, REG_DWORD, (BYTE*)&val, 4);
        if (status == 0)
        {
            status = RegCloseKey(phkResult);
            if (status == 0)
            {
                return 0;
            }
        }
    }
    if (phkResult != NULL)
    {
        RegCloseKey(phkResult);
    }
    return 1;
}

// 0x0049d180
int wuRegistry_GetInt(LPCSTR lpValueName, int val)
{
    LSTATUS status;
    HKEY phkResult;
    DWORD cbData;
    BYTE Data[4];

    phkResult = NULL;
    status = RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xf003f, &phkResult);
    if (status == 0)
    {
        cbData = 4;
        status = RegQueryValueExA(phkResult, lpValueName, NULL, (LPDWORD)&lpValueName, Data, &cbData);
        if (status == 0)
        {
            RegCloseKey(phkResult);
            return *(int*)Data;
        }
        RegCloseKey(phkResult);
    }
    return val;
}

// 0x0049d210
int wuRegistry_SaveInt2(LPCSTR lpValueName, int val)
{
    return wuRegistry_SaveInt(lpValueName, val);
}

// 0x0049d230
int wuRegistry_GetInt2(LPCSTR lpValueName, int val)
{
    return wuRegistry_GetInt(lpValueName, val);
}

// 0x0049d250
int wuRegistry_SetString(LPCSTR lpValueName, char* lpData)
{
    LSTATUS status;
    HKEY phkResult;

    phkResult = NULL;
    status = RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xf003f, &phkResult);
    if (status == 0)
    {
        status = RegSetValueExA(phkResult, lpValueName, 0, 1, (BYTE*)lpData, strlen(lpData));
        if (status == 0)
        {
            status = RegCloseKey(phkResult);
            if (status == 0)
            {
                return 0;
            }
        }
    }
    if (phkResult != NULL)
    {
        RegCloseKey(phkResult);
    }
    return 1;
}

// 0x0049d2e0
int wuRegistry_GetString(LPCSTR lpValueName, char* lpData, int outSize, char* outDefault)
{
    LSTATUS status;
    HKEY phkResult;
    DWORD cbData;
    DWORD Type;

    phkResult = NULL;
    status = RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xf003f, &phkResult);
    if (status == 0)
    {
        cbData = outSize;
        status = RegQueryValueExA(phkResult, lpValueName, NULL, &Type, (LPBYTE)lpData, &cbData);
        if (status == 0)
        {
            status = RegCloseKey(phkResult);
            if (status == 0)
            {
                return 0;
            }
        }
    }
    if (outDefault != NULL)
    {
        strncpy(lpData, outDefault, outSize - 1);
        lpData[outSize + -1] = '\0';
    }
    if (phkResult != NULL)
    {
        RegCloseKey(phkResult);
    }
    return 1;
}
