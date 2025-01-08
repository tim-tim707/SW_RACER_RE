#include "a3d.h"

#include "Winreg.h"

#include "globals.h"

#include <macros.h>

// 0x0049e750
int a3d_RegisterAll(void)
{
    a3d_RegisterCLSID("A3d", (LPCSTR)&wuRegistry_lpClass, "A3d Object");
    a3d_RegisterCLSID("A3d\\CLSID", (LPCSTR)&wuRegistry_lpClass, "{d8f1eee0-f634-11cf-8700-00a0245d918b}");
    a3d_RegisterCLSID("CLSID\\{d8f1eee0-f634-11cf-8700-00a0245d918b}", (LPCSTR)&wuRegistry_lpClass, "A3d Object");
    a3d_RegisterCLSID("CLSID\\{d8f1eee0-f634-11cf-8700-00a0245d918b}\\InprocServer32", (LPCSTR)&wuRegistry_lpClass, "a3d.dll");
    a3d_RegisterCLSID("CLSID\\{d8f1eee0-f634-11cf-8700-00a0245d918b}\\InprocServer32", "ThreadingModel", "Apartment");

    a3d_RegisterCLSID("A3dApi", (LPCSTR)&wuRegistry_lpClass, "A3dApi_Object");
    a3d_RegisterCLSID("A3dApi\\CLSID", (LPCSTR)&wuRegistry_lpClass, "{92FA2C24-253C-11d2-90FB-006008A1F441}");
    a3d_RegisterCLSID("CLSID\\{92FA2C24-253C-11d2-90FB-006008A1F441}", (LPCSTR)&wuRegistry_lpClass, "A3dApi Object");
    a3d_RegisterCLSID("CLSID\\{92FA2C24-253C-11d2-90FB-006008A1F441}", "AppID", "{92FA2C24-253C-11D2-90FB-006008A1F441}");
    a3d_RegisterCLSID("CLSID\\{92FA2C24-253C-11d2-90FB-006008A1F441}\\InprocServer32", (LPCSTR)&wuRegistry_lpClass, "a3dapi.dll");
    a3d_RegisterCLSID("CLSID\\{92FA2C24-253C-11d2-90FB-006008A1F441}\\InprocServer32", "ThreadingModel", "Apartment");

    a3d_RegisterCLSID("A3dDAL", (LPCSTR)&wuRegistry_lpClass, "A3dDAL_Object");
    a3d_RegisterCLSID("A3dDAL\\CLSID", (LPCSTR)&wuRegistry_lpClass, "{442D12A1-2641-11d2-90FB-006008A1F441}");
    a3d_RegisterCLSID("CLSID\\{442D12A1-2641-11d2-90FB-006008A1F441}", (LPCSTR)&wuRegistry_lpClass, "A3dDAL_Object");
    a3d_RegisterCLSID("CLSID\\{442D12A1-2641-11d2-90FB-006008A1F441}", "AppID", "{442D12A1-2641-11D2-90FB-006008A1F441}");
    a3d_RegisterCLSID("CLSID\\{442D12A1-2641-11d2-90FB-006008A1F441}\\InprocServer32", (LPCSTR)&wuRegistry_lpClass, "a3d.dll");
    a3d_RegisterCLSID("CLSID\\{442D12A1-2641-11d2-90FB-006008A1F441}\\InprocServer32", "ThreadingModel", "Apartment");
    return 0;
}

// 0x0049e8e0
void a3d_RegisterCLSID(LPCSTR str1, LPCSTR str2, char* str3)
{
    DWORD tmp;
    HKEY key;
    RegCreateKeyExA((HKEY)0x80000000, str1, 0, "REG_SZ", 0, 0xf003f, NULL, &key, &tmp);
    RegSetValueExA(key, str2, 0, 1, (BYTE*)str3, strlen(str3));
    RegCloseKey(key);
}

// 0x0049e940
HRESULT a3d_CoInitialize(void)
{
    HRESULT res = CoInitialize(NULL);
    a3d_RegisterAll();
    return res;
}

// 0x0049e970
HRESULT a3d_CoCreateInstance(GUID* null, IA3d4** ia3d, LPUNKNOWN null2, DWORD features)
{
    HANG("TODO");
    return 0;
}
