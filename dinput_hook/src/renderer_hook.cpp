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
    fprintf(hook_log, "[Renderer Hooks]");
    fflush(hook_log);

    // rdMaterial.c
    hook_replace(rdMaterial_SaturateTextureR4G4B4A4, rdMaterial_SaturateTextureR4G4B4A4_hook);
    hook_replace(rdMaterial_InvertTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_InvertTextureColorR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR5G5B5A1, noop);

    // std3D.c
    hook_replace(std3D_Startup, std3D_Startup_hook);
    hook_replace(std3D_Open, std3D_Open_hook);
    hook_replace(std3D_StartScene, std3D_StartScene_hook);
    hook_replace(std3D_EndScene, std3D_EndScene_hook);
    hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_hook);
    hook_replace(std3D_SetRenderState, std3D_SetRenderState_hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_hook);
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_hook);
    hook_replace(std3D_AddToTextureCache, std3D_AddToTextureCache_hook);
    hook_replace(std3D_ClearCacheList, std3D_ClearCacheList_hook);
    hook_replace(std3D_SetTexFilterMode, std3D_SetTexFilterMode_hook);
    hook_replace(std3D_SetProjection, std3D_SetProjection_hook);
    hook_replace(std3D_AddTextureToCacheList, std3D_AddTextureToCacheList_hook);
    hook_replace(std3D_RemoveTextureFromCacheList, std3D_RemoveTextureFromCacheList_hook);
    hook_replace(std3D_PurgeTextureCache, std3D_PurgeTextureCache_hook);

    // stdControl.c
    hook_replace(stdControl_Startup, stdControl_Startup_hook);
    hook_replace(stdControl_ReadControls, stdControl_ReadControls_hook);
    hook_replace(stdControl_SetActivation, stdControl_SetActivation_hook);

    // swrDisplay.c
    hook_replace(swrDisplay_SetWindowSize, swrDisplay_SetWindowSize_hook);

    // DirectX.c
    hook_replace(DirectDraw_InitProgressBar, DirectDraw_InitProgressBar_hook);
    hook_replace(DirectDraw_Shutdown, DirectDraw_Shutdown_hook);
    hook_replace(DirectDraw_BlitProgressBar, DirectDraw_BlitProgressBar_hook);
    hook_replace(DirectDraw_LockZBuffer, DirectDraw_LockZBuffer_hook);
    hook_replace(DirectDraw_UnlockZBuffer, DirectDraw_UnlockZBuffer_hook);
    hook_replace(Direct3d_SetFogMode, Direct3d_SetFogMode_hook);
    hook_replace(Direct3d_IsLensflareCompatible, Direct3d_IsLensflareCompatible_hook);
    hook_replace(Direct3d_ConfigFog, Direct3d_ConfigFog_hook);

    // stdDisplay.c
    hook_replace(stdDisplay_Startup, stdDisplay_Startup_hook);
    hook_replace(stdDisplay_Open, stdDisplay_Open_hook);
    hook_replace(stdDisplay_Close, stdDisplay_Close_hook);
    hook_replace(stdDisplay_SetMode, stdDisplay_SetMode_hook);
    hook_replace(stdDisplay_Refresh, stdDisplay_Refresh_hook);
    hook_replace(stdDisplay_VBufferNew, stdDisplay_VBufferNew_hook);
    hook_replace(stdDisplay_SetWindowMode, stdDisplay_SetWindowMode_hook);
    hook_replace(stdDisplay_SetFullscreenMode, stdDisplay_SetFullscreenMode_hook);
    hook_replace(stdDisplay_VBufferFill, stdDisplay_VBufferFill_hook);
    hook_replace(stdDisplay_FillMainSurface, stdDisplay_FillMainSurface_hook);
    hook_replace(stdDisplay_ColorFillSurface, stdDisplay_ColorFillSurface_hook);
    hook_replace(stdDisplay_Update, stdDisplay_Update_Hook);

    // Window.c
    hook_replace(Window_SetActivated, Window_SetActivated_hook);
    hook_replace(Window_SmushPlayCallback, Window_SmushPlayCallback_hook);
    hook_replace(Window_Main, Window_Main_hook);

    // stdConsole.c
    hook_replace(stdConsole_GetCursorPos, stdConsole_GetCursorPos_Hook);
    hook_replace(stdConsole_SetCursorPos, stdConsole_SetCursorPos_Hook);

    // swrViewport.c
    hook_replace(swrViewport_Render, swrViewport_Render_Hook);

    // swrModel.c
    hook_replace(swrModel_LoadFromId, swrModel_LoadFromId_Hook);
}
