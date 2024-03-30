#ifndef DIRECTX_H
#define DIRECTX_H

#include "types.h"

#define DirectDraw_InitProgressBar_ADDR (0x00408510)
#define DirectDraw_Shutdown_ADDR (0x00408620)
#define DirectDraw_BlitProgressBar_ADDR (0x00408640)

#define DirectDraw_LockZBuffer_ADDR (0x00431C40)
#define DirectDraw_UnlockZBuffer_ADDR (0x00431cd0)

#define DirectInput_EnumDevice_Callback_ADDR (0x00486a10)

#define DirectPlay_Startup_ADDR (0x00486ad0)

#define DirectPlay_Destroy_ADDR (0x00486b40)

#define DirectPlay_EnumConnectionsCallback_ADDR (0x00487370)

#define DirectDraw_GetSelectedDevice_ADDR (0x004880c0)

#define DirectDraw_GetAvailableVidMem_ADDR (0x00488880)

#define DirectDraw_GetZBuffer_ADDR (0x00488a80)

#define DirectDraw_FillMainSurface_ADDR (0x00488a90)

#define DirectDraw_EnumerateA_Callback_ADDR (0x00488d70)

#define DirectDraw_EnumDisplayModes_Callback_ADDR (0x00488f50)

#define Direct3d_SetFogMode_ADDR (0x0048a140)

#define Direct3d_IsLensflareCompatible_ADDR (0x0048a1a0)

#define Direct3d_ConfigFog_ADDR (0x0048b340)
#define Direct3d_CreateAndAttachViewport_ADDR (0x0048b3c0)

#define Direct3d_EnumDevices_Callback_ADDR (0x0048b540)
#define Direct3d_EnumTextureFormats_Callback_ADDR (0x0048b770)

#define DirectX_DirectDrawEnumerateA_ADDR (0x0049d390)
#define DirectX_DirectDrawCreate_ADDR (0x0049d396)
#define DirectX_DirectInputCreateA_ADDR (0x0049d39C)

void DirectDraw_InitProgressBar(void);
void DirectDraw_Shutdown(void);
void DirectDraw_BlitProgressBar(int progress);

void DirectDraw_LockZBuffer(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data, float *near, float *far);
void DirectDraw_UnlockZBuffer(void);

int DirectInput_EnumDevice_Callback(DIDEVICEINSTANCEA* deviceInstance);

BOOL DirectPlay_Startup(void);

void DirectPlay_Destroy(void);

BOOL __stdcall DirectPlay_EnumConnectionsCallback(const GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

int DirectDraw_GetSelectedDevice(swrDrawDevice* device);

bool DirectDraw_GetAvailableVidMem(LPDWORD total, LPDWORD free);

IDirectDrawSurface4* DirectDraw_GetZBuffer(void);

void DirectDraw_FillMainSurface(void);

WINBOOL DirectDraw_EnumerateA_Callback(GUID* directDraw_guid, LPSTR driver_name, LPSTR driver_desc, LPVOID swr_unk_struct);

HRESULT DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC* surfaceDesc, void* param_2);

int Direct3d_SetFogMode(void);

int Direct3d_IsLensflareCompatible(void);

void Direct3d_ConfigFog(DWORD renderstate, float p2, float p3, float p4);
bool Direct3d_CreateAndAttachViewport(void);

HRESULT Direct3d_EnumDevices_Callback(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx);
HRESULT Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx);

HRESULT DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
HRESULT DirectX_DirectDrawCreate(GUID* lpGuid, LPDIRECTDRAW* lplpDD, IUnknown* pUnkOuter);
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* lplpDirectInput, LPUNKNOWN punkOuter);

#endif // DIRECTX_H
