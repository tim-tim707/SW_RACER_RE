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

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);
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

    hook_function("rdMaterial_SaturateTextureR4G4B4A4_hook",
                  (uint32_t) rdMaterial_SaturateTextureR4G4B4A4_ADDR,
                  (uint8_t *) rdMaterial_SaturateTextureR4G4B4A4_hook);
    // hook_replace(rdMaterial_InvertTextureAlphaR4G4B4A4, noop);
    // hook_replace(rdMaterial_InvertTextureColorR4G4B4A4, noop);
    // hook_replace(rdMaterial_RemoveTextureAlphaR4G4B4A4, noop);
    // hook_replace(rdMaterial_RemoveTextureAlphaR5G5B5A1, noop);

    // std3D.c
    hook_function("", (uint32_t) std3D_Startup_ADDR, (uint8_t *) std3D_Startup_hook);
    hook_function("", (uint32_t) std3D_Open_ADDR, (uint8_t *) std3D_Open_hook);
    hook_function("", (uint32_t) std3D_StartScene_ADDR, (uint8_t *) std3D_StartScene_hook);
    hook_function("", (uint32_t) std3D_EndScene_ADDR, (uint8_t *) std3D_EndScene_hook);
    hook_function("", (uint32_t) std3D_DrawRenderList_ADDR, (uint8_t *) std3D_DrawRenderList_hook);
    hook_function("", (uint32_t) std3D_SetRenderState_ADDR, (uint8_t *) std3D_SetRenderState_hook);
    hook_function("", (uint32_t) std3D_AllocSystemTexture_ADDR,
                  (uint8_t *) std3D_AllocSystemTexture_hook);
    hook_function("", (uint32_t) std3D_ClearTexture_ADDR, (uint8_t *) std3D_ClearTexture_hook);
    hook_function("", (uint32_t) std3D_AddToTextureCache_ADDR,
                  (uint8_t *) std3D_AddToTextureCache_hook);
    hook_function("", (uint32_t) std3D_ClearCacheList_ADDR, (uint8_t *) std3D_ClearCacheList_hook);
    hook_function("", (uint32_t) std3D_SetTexFilterMode_ADDR,
                  (uint8_t *) std3D_SetTexFilterMode_hook);
    hook_function("", (uint32_t) std3D_SetProjection_ADDR, (uint8_t *) std3D_SetProjection_hook);
    hook_function("", (uint32_t) std3D_AddTextureToCacheList_ADDR,
                  (uint8_t *) std3D_AddTextureToCacheList_hook);
    hook_function("", (uint32_t) std3D_RemoveTextureFromCacheList_ADDR,
                  (uint8_t *) std3D_RemoveTextureFromCacheList_hook);
    hook_function("", (uint32_t) std3D_PurgeTextureCache_ADDR,
                  (uint8_t *) std3D_PurgeTextureCache_hook);

    // stdControl.c
    hook_function("", (uint32_t) stdControl_Startup_ADDR, (uint8_t *) stdControl_Startup_hook);
    hook_function("", (uint32_t) stdControl_ReadControls_ADDR,
                  (uint8_t *) stdControl_ReadControls_hook);
    hook_function("", (uint32_t) stdControl_SetActivation_ADDR,
                  (uint8_t *) stdControl_SetActivation_hook);

    // swrDisplay.c
    hook_function("", (uint32_t) swrDisplay_SetWindowSize_ADDR,
                  (uint8_t *) swrDisplay_SetWindowSize_hook);

    // DirectX.c
    hook_function("", (uint32_t) DirectDraw_InitProgressBar_ADDR,
                  (uint8_t *) DirectDraw_InitProgressBar_hook);
    hook_function("", (uint32_t) DirectDraw_Shutdown_ADDR, (uint8_t *) DirectDraw_Shutdown_hook);
    hook_function("", (uint32_t) DirectDraw_BlitProgressBar_ADDR,
                  (uint8_t *) DirectDraw_BlitProgressBar_hook);
    hook_function("", (uint32_t) DirectDraw_LockZBuffer_ADDR,
                  (uint8_t *) DirectDraw_LockZBuffer_hook);
    hook_function("", (uint32_t) DirectDraw_UnlockZBuffer_ADDR,
                  (uint8_t *) DirectDraw_UnlockZBuffer_hook);
    hook_function("", (uint32_t) Direct3d_SetFogMode_ADDR, (uint8_t *) Direct3d_SetFogMode_hook);
    hook_function("", (uint32_t) Direct3d_IsLensflareCompatible_ADDR,
                  (uint8_t *) Direct3d_IsLensflareCompatible_hook);
    hook_function("", (uint32_t) Direct3d_ConfigFog_ADDR, (uint8_t *) Direct3d_ConfigFog_hook);

    // stdDisplay.c
    hook_function("", (uint32_t) stdDisplay_Startup_ADDR, (uint8_t *) stdDisplay_Startup_hook);
    hook_function("", (uint32_t) stdDisplay_Open_ADDR, (uint8_t *) stdDisplay_Open_hook);
    hook_function("", (uint32_t) stdDisplay_Close_ADDR, (uint8_t *) stdDisplay_Close_hook);
    hook_function("", (uint32_t) stdDisplay_SetMode_ADDR, (uint8_t *) stdDisplay_SetMode_hook);
    hook_function("", (uint32_t) stdDisplay_Refresh_ADDR, (uint8_t *) stdDisplay_Refresh_hook);
    hook_function("", (uint32_t) stdDisplay_VBufferNew_ADDR,
                  (uint8_t *) stdDisplay_VBufferNew_hook);
    hook_function("", (uint32_t) stdDisplay_SetWindowMode_ADDR,
                  (uint8_t *) stdDisplay_SetWindowMode_hook);
    hook_function("", (uint32_t) stdDisplay_SetFullscreenMode_ADDR,
                  (uint8_t *) stdDisplay_SetFullscreenMode_hook);
    hook_function("", (uint32_t) stdDisplay_VBufferFill_ADDR,
                  (uint8_t *) stdDisplay_VBufferFill_hook);
    hook_function("", (uint32_t) stdDisplay_FillMainSurface_ADDR,
                  (uint8_t *) stdDisplay_FillMainSurface_hook);
    hook_function("", (uint32_t) stdDisplay_ColorFillSurface_ADDR,
                  (uint8_t *) stdDisplay_ColorFillSurface_hook);
    // hook_replace((void *) stdDisplay_Update_ADDR, stdDisplay_Update_Hook);

    // Window.c
    hook_function("", (uint32_t) Window_SetActivated_ADDR, (uint8_t *) Window_SetActivated_hook);
    hook_function("", (uint32_t) Window_SmushPlayCallback_ADDR,
                  (uint8_t *) Window_SmushPlayCallback_hook);
    hook_function("", (uint32_t) Window_Main_ADDR, (uint8_t *) Window_Main_hook);

    // stdConsole.c
    // hook_replace((void *) stdConsole_GetCursorPos_ADDR, stdConsole_GetCursorPos_Hook);
    // hook_replace((void *) stdConsole_SetCursorPos_ADDR, stdConsole_SetCursorPos_Hook);

    // swrViewport.c
    // hook_replace((void *) swrViewport_Render_ADDR, swrViewport_Render_Hook);

    // swrModel.c
    // hook_replace((void *) swrModel_LoadFromId_ADDR, swrModel_LoadFromId_Hook);

    hook_function("", (uint32_t) rdMaterial_InvertTextureAlphaR4G4B4A4, (uint8_t *) noop);
    hook_function("", (uint32_t) rdMaterial_InvertTextureColorR4G4B4A4, (uint8_t *) noop);
    hook_function("", (uint32_t) rdMaterial_RemoveTextureAlphaR4G4B4A4, (uint8_t *) noop);
    hook_function("", (uint32_t) rdMaterial_RemoveTextureAlphaR5G5B5A1, (uint8_t *) noop);

    hook_function("", (uint32_t) stdDisplay_Update, (uint8_t *) stdDisplay_Update_Hook);
    hook_function("", (uint32_t) stdConsole_GetCursorPos, (uint8_t *) stdConsole_GetCursorPos_Hook);
    hook_function("", (uint32_t) stdConsole_SetCursorPos, (uint8_t *) stdConsole_SetCursorPos_Hook);
    hook_function("", (uint32_t) swrViewport_Render, (uint8_t *) swrViewport_Render_Hook);

    hook_function("", (uint32_t) swrModel_LoadFromId, (uint8_t *) swrModel_LoadFromId_Hook);
}
