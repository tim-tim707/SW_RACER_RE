#ifndef DIRECTX_H
#define DIRECTX_H

#include "types.h"

#define DirectPlay_EnumConnectionsCallback_ADDR (0x00487370)

#define DirectX_DirectDrawEnumerateA_ADDR (0x0049D390)
#define DirectX_DirectDrawCreate_ADDR (0x0049D396)
#define DirectX_DirectInputCreateA_ADDR (0x0049D39C)

BOOL DirectPlay_EnumConnectionsCallback(GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

HRESULT DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
HRESULT DirectX_DirectDrawCreate(GUID* lpGuid, LPDIRECTDRAW* lplpDD, IUnknown* pUnkOuter);
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* lplpDirectInput, LPUNKNOWN punkOuter);

#endif // DIRECTX_H
