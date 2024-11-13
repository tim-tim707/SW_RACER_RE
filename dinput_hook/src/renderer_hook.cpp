//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"

#include "hook_helper.h"

#include "hooks/DirectX_hook.h"
#include "hooks/rdMaterial_hook.h"
#include "hooks/std3D_hook.h"
#include "hooks/stdConsole_hook.h"
#include "hooks/stdControl_hook.h"
#include "hooks/stdDisplay_hook.h"
#include "hooks/swrDisplay_hook.h"
#include "hooks/swrModel_hook.h"
#include "hooks/swrViewport_hook.h"
#include "hooks/Window_hook.h"

extern "C" {
#include <stdPlatform.h>
#include <Swr/swrAssetBuffer.h>
#include <Engine/rdMaterial.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Swr/swrModel.h>
#include <Swr/swrRender.h>
#include <Swr/swrSprite.h>
#include <Swr/swrViewport.h>
#include <Swr/swrViewport.h>
#include <Swr/swrEvent.h>
#include <Swr/swrDisplay.h>
#include <Win95/stdConsole.h>
#include <Win95/stdDisplay.h>
#include <Main/swrMain2.h>
#include <Main/swrControl.h>
#include <Main/swrMain.h>
#include <Gui/swrGui.h>
#include <Win95/DirectX.h>
#include <Win95/Window.h>
#include <Swr/swrUI.h>
#include <swr.h>
}

extern "C" FILE *hook_log;

// static WNDPROC WndProcOrig;

// LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// LRESULT CALLBACK WndProc(HWND wnd, UINT code, WPARAM wparam, LPARAM lparam) {
//     if (ImGui_ImplWin32_WndProcHandler(wnd, code, wparam, lparam))
//         return 1;

//     return WndProcOrig(wnd, code, wparam, lparam);
// }

static void noop() {}

void init_renderer_hooks() {
    fprintf(hook_log, "[Renderer Hooks]\n");
    fflush(hook_log);

    // rdMaterial.c
    hook_replace((void *) rdMaterial_SaturateTextureR4G4B4A4_ADDR,
                 rdMaterial_SaturateTextureR4G4B4A4_hook);
    hook_replace(rdMaterial_InvertTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_InvertTextureColorR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR5G5B5A1, noop);

    // std3D.c
    hook_replace((void *) std3D_Startup_ADDR, std3D_Startup_hook);
    hook_replace((void *) std3D_Open_ADDR, std3D_Open_hook);
    hook_replace((void *) std3D_StartScene_ADDR, std3D_StartScene_hook);
    hook_replace((void *) std3D_EndScene_ADDR, std3D_EndScene_hook);
    hook_replace((void *) std3D_DrawRenderList_ADDR, std3D_DrawRenderList_hook);
    hook_replace((void *) std3D_SetRenderState_ADDR, std3D_SetRenderState_hook);
    hook_replace((void *) std3D_AllocSystemTexture_ADDR, std3D_AllocSystemTexture_hook);
    hook_replace((void *) std3D_ClearTexture_ADDR, std3D_ClearTexture_hook);
    hook_replace((void *) std3D_AddToTextureCache_ADDR, std3D_AddToTextureCache_hook);
    hook_replace((void *) std3D_ClearCacheList_ADDR, std3D_ClearCacheList_hook);
    hook_replace((void *) std3D_SetTexFilterMode_ADDR, std3D_SetTexFilterMode_hook);
    hook_replace((void *) std3D_SetProjection_ADDR, std3D_SetProjection_hook);
    hook_replace((void *) std3D_AddTextureToCacheList_ADDR, std3D_AddTextureToCacheList_hook);
    hook_replace((void *) std3D_RemoveTextureFromCacheList_ADDR,
                 std3D_RemoveTextureFromCacheList_hook);
    hook_replace((void *) std3D_PurgeTextureCache_ADDR, std3D_PurgeTextureCache_hook);

    // stdControl.c
    hook_replace((void *) stdControl_Startup_ADDR, stdControl_Startup_hook);
    hook_replace((void *) stdControl_ReadControls_ADDR, stdControl_ReadControls_hook);
    hook_replace((void *) stdControl_SetActivation_ADDR, stdControl_SetActivation_hook);

    // swrDisplay.c
    hook_replace((void *) swrDisplay_SetWindowSize_ADDR, swrDisplay_SetWindowSize_hook);

    // DirectX.c
    hook_replace((void *) DirectDraw_InitProgressBar_ADDR, DirectDraw_InitProgressBar_hook);
    hook_replace((void *) DirectDraw_Shutdown_ADDR, DirectDraw_Shutdown_hook);
    hook_replace((void *) DirectDraw_BlitProgressBar_ADDR, DirectDraw_BlitProgressBar_hook);
    hook_replace((void *) DirectDraw_LockZBuffer_ADDR, DirectDraw_LockZBuffer_hook);
    hook_replace((void *) DirectDraw_UnlockZBuffer_ADDR, DirectDraw_UnlockZBuffer_hook);
    hook_replace((void *) Direct3d_SetFogMode_ADDR, Direct3d_SetFogMode_hook);
    hook_replace((void *) Direct3d_IsLensflareCompatible_ADDR, Direct3d_IsLensflareCompatible_hook);
    hook_replace((void *) Direct3d_ConfigFog_ADDR, Direct3d_ConfigFog_hook);

    // stdDisplay.c
    hook_replace((void *) stdDisplay_Startup_ADDR, stdDisplay_Startup_hook);
    hook_replace((void *) stdDisplay_Open_ADDR, stdDisplay_Open_hook);
    hook_replace((void *) stdDisplay_Close_ADDR, stdDisplay_Close_hook);
    hook_replace((void *) stdDisplay_SetMode_ADDR, stdDisplay_SetMode_hook);
    hook_replace((void *) stdDisplay_Refresh_ADDR, stdDisplay_Refresh_hook);
    hook_replace((void *) stdDisplay_VBufferNew_ADDR, stdDisplay_VBufferNew_hook);
    hook_replace((void *) stdDisplay_SetWindowMode_ADDR, stdDisplay_SetWindowMode_hook);
    hook_replace((void *) stdDisplay_SetFullscreenMode_ADDR, stdDisplay_SetFullscreenMode_hook);
    hook_replace((void *) stdDisplay_VBufferFill_ADDR, stdDisplay_VBufferFill_hook);
    hook_replace((void *) stdDisplay_FillMainSurface_ADDR, stdDisplay_FillMainSurface_hook);
    hook_replace((void *) stdDisplay_ColorFillSurface_ADDR, stdDisplay_ColorFillSurface_hook);
    hook_replace((void *) stdDisplay_Update_ADDR, stdDisplay_Update_Hook);

    // Window.c
    hook_replace((void *) Window_SetActivated_ADDR, Window_SetActivated_hook);
    hook_replace((void *) Window_SmushPlayCallback_ADDR, Window_SmushPlayCallback_hook);
    hook_replace((void *) Window_Main_ADDR, Window_Main_hook);

    // stdConsole.c
    hook_replace((void *) stdConsole_GetCursorPos_ADDR, stdConsole_GetCursorPos_Hook);
    hook_replace((void *) stdConsole_SetCursorPos_ADDR, stdConsole_SetCursorPos_Hook);

    // swrViewport.c
    hook_replace((void *) swrViewport_Render_ADDR, swrViewport_Render_Hook);

    // swrModel.c
    hook_replace((void *) swrModel_LoadFromId_ADDR, swrModel_LoadFromId_Hook);
}
