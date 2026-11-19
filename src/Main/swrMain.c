#include "swrMain.h"

#include "globals.h"
#include "../macros.h"
#include "../swr.h"
#include "../Swr/swrObj.h"
#include "../Swr/swrRace.h"
#include "../Swr/swrSound.h"
#include "../Swr/swrUI.h"
#include "../Swr/swrText.h"
#include "../Swr/swrDisplay.h"
#include "../Swr/swrModel.h"
#include "../Swr/swrEvent.h"
#include "../Swr/swrViewport.h"
#include "../Swr/swrPlayerHUD.h"
#include "../Main/swrControl.h"
#include "../Engine/rdCamera.h"
#include "../Engine/rdroid.h"
#include "../Platform/wuRegistry.h"
#include "../Win95/DirectX.h"
#include "../Win95/stdDisplay.h"
#include "../Win95/Window.h"
#include "../stdPlatform.h"

#include <string.h>

// 0x004240d0
void Main_Shutdown(void)
{
    swrMain_initialized = 0;
    DirectDraw_Shutdown();
    swrRace_SaveCurrentProfile();
    swrSound_RewindChannels();
    swrUI_Shutdown();
    swr_noop2();
    rdCamera_Shutdown();
    swrSound_Teardown(1);
    swrControl_Shutdown();
    swrDisplay_Shutdown();
    (*stdPlatform_hostServices_ptr->debugPrint)("rdShutdown...");
    rdShutdown();
    wuRegistry_Shutdown();
    Window_set_msg_handler(NULL);
    swrText_Shutdown();
    stdPlatform_Shutdown();
}

// 0x00424140
void swrMain_GuiAdvance(void)
{
    ((void (*)(void))swrMain_GuiAdvanceFunction)();
}

// 0x00424150
void Main_ShutdownError(void)
{
    const char* err = unknownError_buffer;
    Main_Shutdown();
    MessageBoxA(NULL, "Unknown error", "Unable to continue Error", 0x2010);
    exit(1);
}

// 0x00423cc0
int Main_Startup(char* cmdline)
{
    HANG("TODO");
    return 0;
}

// 0x00424430
int Main_ParseCmdLine(char* cmdline)
{
    char* token;
    int cmp_res;
    double atof_res;

    token = strtok(cmdline, "\t\n\r");
    if (token == NULL)
    {
        return 0;
    }
    do
    {
        cmp_res = strcmpi(token, "-s");
        if (cmp_res == 0)
        {
            token = strtok(NULL, "\t\n\r");
            Main_sound = 0;
        }
        else
        {
            cmp_res = strcmpi(token, "-p");
            if (cmp_res == 0)
            {
                token = strtok(NULL, "\t\n\r");
                Main_sound_unk = 0;
            }
            else
            {
                cmp_res = strcmpi(token, "-r");
                if (cmp_res == 0)
                {
                    token = strtok(NULL, "\t\n\r");
                    if (token == NULL)
                    {
                        return 1;
                    }
                    atof_res = atof(token);
                    Main_sound_rolloff = atof_res;
                    if (Main_sound_rolloff < 0.0)
                    {
                        Main_sound_rolloff = 0.0;
                    }
                }
                else
                {
                    cmp_res = strcmpi(token, "-d");
                    if (cmp_res == 0)
                    {
                        token = strtok(NULL, "\t\n\r");
                        if (token == NULL)
                        {
                            return 1;
                        }
                        atof_res = atof(token);
                        Main_sound_doppler_scale = atof_res;
                        if (Main_sound_doppler_scale < 0.0)
                        {
                            Main_sound_doppler_scale = 0.0;
                        }
                    }
                    else
                    {
                        cmp_res = strcmpi(token, "-nut");
                        if (cmp_res != 0)
                        {
                            cmp_res = strcmpi(token, "-force");
                            if (cmp_res == 0)
                            {
                                token = strtok(NULL, "\t\n\r");
                                Main_force_feedback = 0;
                            }
                            else
                            {
                                cmp_res = strcmpi(token, "+3DImpacts");
                                if (cmp_res == 0)
                                {
                                    token = strtok(NULL, "\t\n\r");
                                    Main_sound_3dimpact = 0;
                                }
                                else
                                {
                                    cmp_res = strcmpi(token, "-v");
                                    if (cmp_res == 0)
                                    {
                                        token = strtok(NULL, "\t\n\r");
                                        Main_settings_menu_only = 1;
                                    }
                                    else
                                    {
                                        cmp_res = strcmpi(token, "-i");
                                        if (cmp_res == 0)
                                        {
                                            token = strtok(NULL, "\t\n\r");
                                            Main_display_intro_scene = 0;
                                        }
                                        else
                                        {
                                            cmp_res = strcmpi(token, "-f");
                                            if (cmp_res == 0)
                                            {
                                                token = strtok(NULL, "\t\n\r");
                                                Main_fullscreen_unk = 0;
                                            }
                                            else
                                            {
                                                cmp_res = strcmpi(token, "-snafu");
                                                if (cmp_res != 0)
                                                    goto next_token;
                                                token = strtok(NULL, "\t\n\r");
                                                Main_settings_debug_hud = 1;
                                            }
                                        }
                                    }
                                }
                            }
                            goto end_condition;
                        }
                        token = strtok(NULL, "\t\n\r");
                        if (token == NULL)
                        {
                            return 1;
                        }
                        Main_nut_delay_ms = atoi(token);
                    }
                }
            next_token:
                token = strtok(NULL, "\t\n\r");
            }
        }
    end_condition:
        if (token == NULL)
        {
            return 1;
        }
    } while (true);
}

// 0x00445980
void swrMain_RunFrame(short flags, short phase)
{
    if (phase == 1 || phase == 0) {
        swrMain_UpdateInRaceLoopSfx();
        swr_noop2();
        swr_noop4();
        swr_noop2();
        updateInRaceInputBitsets();
        swr_noop2();
        swrRace_IncrementFrameTimer();
        swr_noop4();
        swrSound_UpdateDelayedSfx();
        swrSound_UpdateMusic();
        swrObjJudge_PollPause();
        if (GetPauseState() == 0) {
            swrModel_UpdateAnimations();
            swrEvent_CallAllF0();
            swr_noop4();
            swrEvent_CallAllF1();
            swrEvent_CallAllF2();
            swr_noop4();
            swrEvent_CallAllF3();
        } else {
            updatePauseMenu();
        }
        swrViewport_UpdateCameras();
        swr_noop4();
    }
    if (phase == 2 || phase == 0) {
        swrPlayerHUD_SampleOcclusion();
        stdDisplay_FillMainSurface();
        swrPlayerHUD_RenderAllViewports();
        if (flags == 0) {
            swr_noop2();
            swrViewport_AdvanceFrameParity_Maybe();
        }
        swr_noop2();
        swr_noop2();
        swr_noop4();
        swrSound_UpdateIfEnabled();
    }
}

// 0x00426920
void swrMain_UpdateInRaceLoopSfx(void)
{
    int freq;

    if (swrMain_inRaceLoopSfxDisabled != 0 || swrMain_inRaceLoopSfxId < 0)
        return;
    freq = (int)((float)swrMain_inRaceLoopSfxBaseFreq * swrMain_inRaceLoopSfxFreqScale);
    if (GetPauseState() != 0)
        freq = (int)((float)freq / (GetPauseMenuScrollInOut() + 1.0f));
    playASound2(swrMain_inRaceLoopSfxId, 7, 0.25f, (float)freq, 1);
}
