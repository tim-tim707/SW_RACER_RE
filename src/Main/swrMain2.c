#include "swrMain2.h"

#include "globals.h"
#include "engine_config.h"
#include "swrMain.h"
#include "swrControl.h"
#include "../swr.h"
#include "../Engine/rdCamera.h"
#include "../Raster/rdCache.h"
#include "../Swr/swrMultiplayer.h"
#include "../Swr/swrSprite.h"
#include "../Swr/swrUI.h"
#include "../Win95/stdDisplay.h"
#include "../Win95/Window.h"

#include <stdio.h>

// 0x00423580
void swrMain2_GuiAdvance(void)
{
    rdMatrix34 camMat;
    swrViewport* vp;
    float fov;
    DWORD elapsed;
    int frames;

    if (swrRender_sceneInitialized == 0)
        return;

    vp = &swrViewport_array[1];
    swrControl_ProcessInputs();
    swrMain_UpdateNetworkTick();
    swrSprite_DisplayCursor();
    swrUI_ProcessMouse();
    swrMain_RunFrame(swrMain2_firstFrame, 1);

    rdCamera_pCurCamera->pClipFrustum->bFarClip = 0;
    rdCamera_pCurCamera->pClipFrustum->zNear = vp->near_clipping;
    rdCamera_pCurCamera->pClipFrustum->zFar = vp->far_clipping;
    fov = SWR_GUI_CAMERA_FOV_MIN;
    if (SWR_GUI_CAMERA_FOV_MIN <= vp->fov_y_degrees) {
        fov = SWR_GUI_CAMERA_FOV_MAX;
        if (vp->fov_y_degrees <= SWR_GUI_CAMERA_FOV_MAX)
            fov = vp->fov_y_degrees;
    }
    rdCamera_pCurCamera->fov = fov;
    rdCamera_UpdateProject(rdCamera_pCurCamera, vp->aspect_ratio);

    camMat.rvec.x = vp->model_matrix.vA.x;
    camMat.rvec.y = vp->model_matrix.vA.y;
    camMat.rvec.z = vp->model_matrix.vA.z;
    camMat.lvec.x = vp->model_matrix.vB.x;
    camMat.lvec.y = vp->model_matrix.vB.y;
    camMat.lvec.z = vp->model_matrix.vB.z;
    camMat.uvec.x = vp->model_matrix.vC.x;
    camMat.uvec.y = vp->model_matrix.vC.y;
    camMat.uvec.z = vp->model_matrix.vC.z;
    camMat.scale.x = vp->model_matrix.vD.x;
    camMat.scale.y = vp->model_matrix.vD.y;
    camMat.scale.z = vp->model_matrix.vD.z;
    rdCamera_Update(&camMat);

    rdCache_AdvanceFrame();
    swrMultiplayer_PumpPackets();
    if (swrMainDisplaySettings_g.backbufferFill != 0)
        stdDisplay_BackBufferFill((uint8_t)backBufferClearColor[0], (uint8_t)backBufferClearColor[1], (uint8_t)backBufferClearColor[2], NULL);
    swrMain_RunFrame(swrMain2_firstFrame, 2);
    swrMain2_firstFrame = 0;
    swr_noop2();
    swrMain_ProcessDebugKeys();
    rdCache_Flush();
    rdCache_FlushAlpha();

    if (swrMain_showFpsHud != 0 && Main_settings_debug_hud != 0) {
        sprintf(std_output_buffer, "%02.3f  %d", (double)swrMain2_fpsHudFps, rdCache_GetDrawnFacesNum());
        stdDisplay_FlushText(std_output_buffer, 4, 4);
    }
    stdDisplay_Update();

    if (swrMain_introMoviesPending != 0) {
        if (Main_display_intro_scene != 0) {
            swrUI_UpdateProgressBar(98);
            Window_PlayCinematic(swrObjHang_cinematicFiles[SWR_CINEMATIC_GOLDIE]);
            Window_PlayCinematic(swrObjHang_cinematicFiles[SWR_CINEMATIC_TEXT_CRAWL]);
            Window_PlayCinematic(swrObjHang_cinematicFiles[SWR_CINEMATIC_INTRO_SCENE]);
        }
        swrMain_introMoviesPending = 0;
    }

    if (swrMain_showFpsHud != 0 && Main_settings_debug_hud != 0) {
        swrMain2_fpsFrameCount++;
        swrMain2_fpsNowMs = timeGetTime();
        elapsed = swrMain2_fpsNowMs - swrMain2_fpsSampleMs;
        if (elapsed > SWR_GUI_FPS_SAMPLE_MS) {
            frames = swrMain2_fpsFrameCount - swrMain2_fpsSampleFrameCount;
            swrMain2_fpsSampleFrameCount = swrMain2_fpsFrameCount;
            swrMain2_fpsHudFps = (float)((double)frames * 1000.0 / (double)elapsed);
            swrMain2_fpsSampleMs = swrMain2_fpsNowMs;
        }
    }
}
