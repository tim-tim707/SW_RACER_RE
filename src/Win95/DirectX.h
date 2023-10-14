#ifndef DIRECTX_H
#define DIRECTX_H

#include "types.h"

#define DirectDraw_Shutdown_ADDR (0x00408620)

#define DirectDraw_UnlockMainSurface_ADDR (0x00431cd0)

#define DirectInput_Initialize_ADDR (0x00485360)

#define DirectPlay_EnumConnectionsCallback_ADDR (0x00487370)

#define DirectPlay_EnumPlayersCallback_ADDR (0x004874a0)

#define DirectDraw_GetAvailableVidMem_ADDR (0x00488880)

#define DirectDraw_GetMainSurface_ADDR (0x00488a80)

#define DirectDraw_EnumerateA_Callback_ADDR (0x00488d70)

#define DirectDraw_EnumDisplayModes_Callback_ADDR (0x00488f50)

#define DirectDraw_GetDirectDrawInterface_ADDR (0x00489260)

#define Direct3d_GetDevices_ADDR (0x00489eb0)

#define Direct3d_SetFogMode_ADDR (0x0048a140)

#define Direct3d_DrawIndexedTriangleList_ADDR (0x0048a350)

#define Direct3d_BeginScene_ADDR (0x0048a300)
#define Direct3d_EndScene_ADDR (0x0048a330)
#define Direct3d_ClearRenderState_ADDR (0x0048a3c0)

#define Direct3d_DrawLineStrip_ADDR (0x0048a3f0)

#define Direct3d_DrawPointList_ADDR (0x0048a420)

#define Direct3d_SetRenderState_ADDR (0x0048a450)

#define Direct3d_InitRenderState_ADDR (0x0048aeb0)
#define Direct3d_SetTextureStageState_ADDR (0x0048b1b0)
#define Direct3d_SetTransformProjection_ADDR (0x0048b260)
#define Direct3d_ConfigFog_ADDR (0x0048b340)
#define Direct3d_CreateAndAttachViewport_ADDR (0x0048b3c0)

#define Direct3d_EnumZBufferFormats_Callback_ADDR (0x0048b500)
#define Direct3d_EnumDevices_Callback_ADDR (0x0048b540)
#define Direct3d_EnumTextureFormats_Callback_ADDR (0x0048b770)

#define DirectX_DirectDrawEnumerateA_ADDR (0x0049D390)
#define DirectX_DirectDrawCreate_ADDR (0x0049D396)
#define DirectX_DirectInputCreateA_ADDR (0x0049D39C)

void DirectDraw_Shutdown(void);

void DirectDraw_UnlockMainSurface(void);

int DirectInput_Initialize(void);

BOOL DirectPlay_EnumConnectionsCallback(GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

int DirectPlay_EnumPlayersCallback(int a, int b, int c);

bool DirectDraw_GetAvailableVidMem(LPDWORD total, LPDWORD free);

IDirectDrawSurface* DirectDraw_GetMainSurface(void);

WINBOOL DirectDraw_EnumerateA_Callback(GUID* directDraw_guid, LPSTR driver_name, LPSTR driver_desc, LPVOID swr_unk_struct);

HRESULT DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC* surfaceDesc, void* param_2);

IDirectDraw* DirectDraw_GetDirectDrawInterface(void);
swr3DDevice* Direct3d_GetDevices(void);

int Direct3d_SetFogMode(void);

void Direct3d_DrawIndexedTriangleList(IDirect3DTexture2* texture, int renderstate, void* vertices, unsigned int NumVertices, WORD* indices, DWORD indexCount);

void Direct3d_BeginScene(void);
void Direct3d_EndScene(void);
void Direct3d_ClearRenderState(void);

void Direct3d_DrawLineStrip(void* vertices, unsigned int vertex_count);

void Direct3d_DrawPointList(void* vertices, unsigned int vertex_count);

void Direct3d_SetRenderState(unsigned int renderstate);

bool Direct3d_InitRenderState(void);
void Direct3d_SetTextureStageState(void);
HRESULT Direct3d_SetTransformProjection(float fov, float aspect_ratio, float clip_y, float clip_z);
void Direct3d_ConfigFog(DWORD renderstate, float p2, float p3, float p4);
bool Direct3d_CreateAndAttachViewport(void);

HRESULT Direct3d_EnumZBufferFormats_Callback(DDPIXELFORMAT* format, void* ctx);
HRESULT Direct3d_EnumDevices_Callback(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx);
HRESULT Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx);

HRESULT DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
HRESULT DirectX_DirectDrawCreate(GUID* lpGuid, LPDIRECTDRAW* lplpDD, IUnknown* pUnkOuter);
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* lplpDirectInput, LPUNKNOWN punkOuter);

#endif // DIRECTX_H
