#include "DirectX.h"

#include "Window.h"
#include "globals.h"
#include "stdDisplay.h"

#include <macros.h>

#if GLFW_BACKEND
#include <GLFW/glfw3.h>
#include <glad/glad.h>

extern void renderer_drawProgressBar(int progress);
extern void renderer_setLinearFogParameters(float color[4], float start, float end);
#endif

extern FILE* hook_log;

// 0x00408510 HOOK
void DirectDraw_InitProgressBar(void)
{
#if GLFW_BACKEND
    // nothing to do here
#else
    HANG("TODO");
#endif
}

// 0x00408620 HOOK
void DirectDraw_Shutdown(void)
{
#if GLFW_BACKEND
    // nothing to do here
#else
    if (iDirectDraw4_error == 0)
    {
        (*ddSurfaceForProgressBar->lpVtbl->Release)(ddSurfaceForProgressBar);
    }
#endif
}

// 0x00408640 HOOK
void DirectDraw_BlitProgressBar(int progress)
{
#if GLFW_BACKEND

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    renderer_drawProgressBar(progress);

    stdDisplay_Update();
#else
    HANG("TODO");
#endif
}

#if GLFW_BACKEND
uint16_t* depth_data = NULL;
#endif

// 0x00431C40 HOOK
void DirectDraw_LockZBuffer(uint32_t* bytes_per_depth_value, LONG* pitch, LPVOID* data, float* near_, float* far_)
{
#if GLFW_BACKEND
    int w = screen_width;
    int h = screen_height;
    depth_data = malloc(w * h * 2);

    glGetError();
    glReadPixels(0, 0, w, h, GL_DEPTH_COMPONENT, GL_UNSIGNED_SHORT, depth_data);
    if (glGetError())
        abort();

    *bytes_per_depth_value = 2;
    // hack to vertically flip the image: set pitch to a negative value
    *pitch = -w * 2;
    *data = depth_data + w * (h - 1);
    *near_ = rdCamera_pCurCamera->pClipFrustum->zNear;
    *far_ = rdCamera_pCurCamera->pClipFrustum->zFar;
#else
    HANG("TODO");
#endif
}

// 0x00431cd0 HOOK
void DirectDraw_UnlockZBuffer(void)
{
#if GLFW_BACKEND
    if (depth_data)
        free(depth_data);

    depth_data = NULL;
#else
    LPDIRECTDRAWSURFACE4 This = DirectDraw_GetZBuffer();
    (*This->lpVtbl->Unlock)(This, NULL);
#endif
}

// 0x00486a10
int DirectInput_EnumDevice_Callback(DIDEVICEINSTANCEA* deviceInstance)
{
    HANG("TODO");
    return 1;
}

// 0x00486ad0 HOOK
BOOL DirectPlay_Startup(void)
{
    IDirectPlay4Vtbl* pIVar1;
    GUID* guid;
    HRESULT HVar2;
    int iVar3;
    StdCommConnection* pSVar4;
    LPVOID null_;
    DWORD zero_;

    CoInitialize(NULL);
    CoCreateInstance((IID*)&DirectPlay_GUID, NULL, 1, &IID_IDirectPlay4_GUID, (void**)&stdComm_pDirectPlay);
    stdComm_numConnections = 0;
    pSVar4 = stdComm_Connections;
    for (iVar3 = 0x460; iVar3 != 0; iVar3 = iVar3 + -1)
    {
        *(uint32_t*)pSVar4->name = 0;
        pSVar4 = (StdCommConnection*)(pSVar4->name + 2);
    }
    stdComm_bGameActive = 0;
    stdComm_bIsServer = 0;
    zero_ = 0;
    null_ = NULL;
    pIVar1 = stdComm_pDirectPlay->lpVtbl;
    guid = Window_GetGUID();
    HVar2 = (*pIVar1->EnumConnections)(stdComm_pDirectPlay, guid, DirectPlay_EnumConnectionsCallback, null_, zero_);
    return HVar2 < 0;
}

// 0x00486b40 HOOK
void DirectPlay_Destroy(void)
{
    int iVar1;
    void** ppvVar2;
    unsigned int uVar3;
    StdCommConnection* pSVar4;

    if (stdComm_pDirectPlay != NULL)
    {
        (*stdComm_pDirectPlay->lpVtbl->Release)(stdComm_pDirectPlay);
        stdComm_pDirectPlay = NULL;
    }
    uVar3 = 0;
    if (stdComm_numConnections != 0)
    {
        ppvVar2 = &stdComm_Connections[0].lpConnection;
        do
        {
            if (*ppvVar2 != NULL)
            {
                (*stdPlatform_hostServices_ptr->free)(*ppvVar2);
            }
            uVar3 = uVar3 + 1;
            ppvVar2 = ppvVar2 + 0x46;
        } while (uVar3 < (unsigned int)stdComm_numConnections);
    }
    stdComm_numConnections = 0;
    pSVar4 = stdComm_Connections;
    for (iVar1 = 0x460; iVar1 != 0; iVar1 = iVar1 + -1)
    {
        *(uint32_t*)pSVar4->name = 0;
        pSVar4 = (StdCommConnection*)(pSVar4->name + 2);
    }
    stdComm_bGameActive = 0;
    stdComm_bIsServer = 0;
    CoUninitialize();
}

// 0x00487370
BOOL __stdcall DirectPlay_EnumConnectionsCallback(const GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    HANG("TODO. Argument count doesnt match documentation");
    return 1;
}

// 0x004880c0
int DirectDraw_GetSelectedDevice(StdDisplayDevice* device)
{
    HANG("TODO");
}

// 0x00488880 HOOK
bool DirectDraw_GetAvailableVidMem(LPDWORD total, LPDWORD free)
{
    HRESULT HVar1;
    DDSCAPS2 caps;

    caps.dwCaps2 = 0;
    caps.dwCaps3 = 0;
    caps.dwCaps4 = 0;
    caps.dwCaps = 0x1000;
    HVar1 = (*stdDisplay_lpDD->lpVtbl->GetAvailableVidMem)(stdDisplay_lpDD, &caps, total, free);
    return HVar1 != 0;
}

// 0x00488a80 HOOK
IDirectDrawSurface4* DirectDraw_GetZBuffer(void)
{
    return stdDisplay_zBuffer.pDDSurf;
}

// 0x00488a90
void DirectDraw_FillMainSurface(void)
{
    HANG("TODO");
}

// 0x00488d70
BOOL __stdcall DirectDraw_EnumerateA_Callback(GUID* directDraw_guid, LPSTR driver_name, LPSTR driver_desc, LPVOID swr_unk_struct)
{
    HANG("TODO");
    return 0;
}

// 0x00488f50
HRESULT __stdcall DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC2* surfaceDesc, void* param_2)
{
    HANG("TODO");
    return 0;
}

// 0x0048a140 HOOK
int Direct3d_SetFogMode(void)
{
#if GLFW_BACKEND
    return 2;
#else
    HRESULT hres;
    unsigned int light_result;
    unsigned int fog_result;

    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x100) != 0)
    {
        hres = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device, D3DRENDERSTATE_FOGTABLEMODE, 3);
        if (hres == 0)
        {
            return 2;
        }
    }
    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x80) != 0)
    {
        light_result = (*std3D_pD3Device->lpVtbl->SetLightState)(std3D_pD3Device, D3DLIGHTSTATE_FOGMODE, 0);
        fog_result = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device, D3DRENDERSTATE_FOGTABLEMODE, 0);
        if ((light_result | fog_result) == 0)
        {
            return 1;
        }
    }
    return 0;
#endif
}

// 0x0048a1a0 HOOK
int Direct3d_IsLensflareCompatible(void)
{
#if GLFW_BACKEND
    return true;
#else
    return (d3dDeviceDesc.dpcTriCaps.dwTextureBlendCaps & 0xff) >> 3 & 1;
#endif
}

// 0x0048b340 HOOK
void Direct3d_ConfigFog(float r, float g, float b, float near_, float far_)
{
#if GLFW_BACKEND
    float color[4] = { r, g, b, 1.0 };
    renderer_setLinearFogParameters(color, 0.999, 1);
#else
    HANG("TODO");
#endif
}

// 0x0048b3c0 HOOK
bool Direct3d_CreateAndAttachViewport(void)
{
    HRESULT hres;
    int iVar1;
    D3DVIEWPORT2 viewport_data;

    hres = (*std3D_pDirect3D->lpVtbl->CreateViewport)(std3D_pDirect3D, &std3D_lpD3DViewPort, NULL);
    if (hres != 0)
    {
        return false;
    }
    hres = (*std3D_pD3Device->lpVtbl->AddViewport)(std3D_pD3Device, std3D_lpD3DViewPort);
    if (hres != 0)
    {
        return false;
    }
    memset(&viewport_data, 0, sizeof(viewport_data));

    // TODO: members of stdDisplay_g_backBuffer are offset by 4 bytes?
    viewport_data.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    viewport_data.dvClipWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    viewport_data.dwHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    viewport_data.dvClipHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    viewport_data.dwSize = 0x2c;
    viewport_data.dwX = 0;
    viewport_data.dwY = 0;
    viewport_data.dvClipX = 0.0;
    viewport_data.dvClipY = 0.0;
    viewport_data.dvMinZ = 0.0;
    viewport_data.dvMaxZ = 1.0;
    hres = (*std3D_lpD3DViewPort->lpVtbl->SetViewport2)(std3D_lpD3DViewPort, &viewport_data);
    if (hres != 0)
    {
        return false;
    }
    hres = (*std3D_pD3Device->lpVtbl->SetCurrentViewport)(std3D_pD3Device, std3D_lpD3DViewPort);
    return hres == 0;
}

// 0x0048b540
HRESULT __stdcall Direct3d_EnumDevices_Callback(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx)
{
    HANG("TODO");
    return 0;
}

// 0x0048b770
HRESULT __stdcall Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx)
{
    HANG("TODO");
    return 0;
}
