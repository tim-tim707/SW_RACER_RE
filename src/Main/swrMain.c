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
#include "../Swr/swrConfig.h"
#include "../Swr/swrMultiplayer.h"
#include "../Platform/stdControl.h"
#include "../Engine/rdCamera.h"
#include "../Engine/rdroid.h"
#include "../Platform/wuRegistry.h"
#include "../Win95/DirectX.h"
#include "../Win95/stdDisplay.h"
#include "../Win95/Window.h"
#include "../stdPlatform.h"

#include <string.h>

// inlined strcat in the original
static void swrMain_AppendDebugNotice(const char* text)
{
    size_t len = strlen(swrMain_debugNotice);
    memcpy(swrMain_debugNotice + len, text, strlen(text) + 1);
}

// 0x004104f0
void swrMain_ProcessDebugKeys(void)
{
    int trugutsBefore = swrRace_truguts;
    swrObjJdge* jdge;
    swrUI_unk* page;
    int mirrorOn;
    int ev[3];

    if (swrMain_debugKeysUnkFlag != 0)
        swrMain_debugKeysUnkFlag = 0;
    if (stdControl_ReadKey(DIK_F12, NULL) != 0)
        swrRace_PollScreenshotKey();

    if (stdControl_ReadKey(DIK_LCONTROL, NULL) != 0 && stdControl_ReadKey(DIK_C, NULL) != 0 && stdControl_ReadKey(DIK_Y, NULL) != 0 && g_objHang2->menuScreen == swrObjHang_STATE_SELECT_VEHICLE) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_ReplaceBullseyeWithCyYunga();
        playUISound(-1);
    } else if (stdControl_ReadKey(DIK_RCONTROL, NULL) != 0 && stdControl_ReadKey(DIK_N, NULL) != 0 && stdControl_ReadKey(DIK_K, NULL) != 0 && g_objHang2->menuScreen == swrObjHang_STATE_SELECT_VEHICLE) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_ReplaceMarsGuoWithJinnReeso();
        playUISound(0x2d);
    } else if (stdControl_ReadKey(DIK_F1, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_pendingCameraEvent = 'ccf1';
    } else if (stdControl_ReadKey(DIK_F2, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_pendingCameraEvent = 'ccf2';
    } else if (stdControl_ReadKey(DIK_F3, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_pendingCameraEvent = 'ccf3';
    } else if (stdControl_ReadKey(DIK_F4, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrRace_pendingCameraEvent = 'ccf4';
        // SHIFT+4+F4 at Watto's shop: +1000 truguts (capped below)
        if (g_objHang2->menuScreen == swrObjHang_STATE_WATTO && (stdControl_ReadKey(DIK_LSHIFT, NULL) != 0 || stdControl_ReadKey(DIK_RSHIFT, NULL) != 0) && stdControl_ReadKey(DIK_4, NULL) != 0)
            swrRace_truguts += 1000;
    } else if (stdControl_ReadKey(DIK_CAPITAL, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        jdge = (swrObjJdge*)swrEvent_GetItem('Jdge', 0);
        if (jdge != NULL) {
            playUISound(0x46);
            if (numLocalPlayers < 2) {
                jdge->hud_mode++;
                if (jdge->hud_mode > swrObjJdge_HUDMODE_OFF)
                    jdge->hud_mode = swrObjJdge_HUDMODE_GAP_ARROWS;
            } else {
                jdge->hud_mode++;
                if (jdge->hud_mode > swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME)
                    jdge->hud_mode = swrObjJdge_HUDMODE_OFF;
            }
        }
    } else if ((stdControl_ReadKey(DIK_RMENU, NULL) != 0 || stdControl_ReadKey(DIK_LMENU, NULL) != 0) && stdControl_ReadKey(DIK_H, NULL) != 0) {
        if (swrMain_debugKeyHeld != 0)
            goto show_notice;
        swrMain_debugKeyHeld = 1;
        swrMain_moneyHintUnlocked = 1;
    } else {
        if (DebugMenuState == 2) {
            if (stdControl_ReadKey(DIK_LCONTROL, NULL) == 0 && stdControl_ReadKey(DIK_RCONTROL, NULL) == 0) {
                if (stdControl_ReadKey(DIK_MULTIPLY, NULL) != 0 && stdControl_ReadKey(DIK_T, NULL) != 0) {
                    if (multiplayer_enabled != 0)
                        goto unmodified_keys;
                    if (swrMain_debugKeyHeld != 0)
                        goto show_notice;
                    swr_FastMode ^= 1;
                    playUISound(0x2c);
                    swrMain_debugKeyHeld = 1;
                } else {
                    if (stdControl_ReadKey(DIK_I, NULL) == 0 || stdControl_ReadKey(DIK_F, NULL) == 0 || stdControl_ReadKey(DIK_L, NULL) == 0 || stdControl_ReadKey(DIK_Y, NULL) == 0 || multiplayer_enabled != 0)
                        goto unmodified_keys;
                    if (swrMain_debugKeyHeld != 0)
                        goto show_notice;
                    swrRace_DebugFlag ^= swrRace_DEBUGFLAG_IFLY;
                    playUISound(0x2b);
                    swrMain_debugKeyHeld = 1;
                }
            } else {
                if (stdControl_ReadKey(DIK_F10, NULL) == 0)
                    goto unmodified_keys;
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                if (multiplayer_enabled == 0) {
                    swrRace_DebugFlag ^= swrRace_DEBUGFLAG_INVINCIBILITY;
                    playUISound(0x28);
                }
                swrMain_debugKeyHeld = 1;
            }
        } else {
        unmodified_keys:
            if (stdControl_ReadKey(DIK_LCONTROL, NULL) == 0 && stdControl_ReadKey(DIK_RCONTROL, NULL) == 0) {
            no_ctrl_keys:
                if (stdControl_ReadKey(DIK_F7, NULL) != 0) {
                    if (swrMain_debugKeyHeld != 0)
                        goto show_notice;
                    playUISound(0x46);
                    swrMultiplayer_OpenChatInput();
                    swrMain_debugKeyHeld = 1;
                } else if (stdControl_ReadKey(DIK_F5, NULL) != 0 || stdControl_ReadKey(DIK_F6, NULL) != 0) {
                    if (swrMain_debugKeyHeld != 0)
                        goto show_notice;
                    swrRace_debugTauntRequest = 1;
                    swrMain_debugKeyHeld = 1;
                } else if (stdControl_ReadKey(DIK_SCROLL, NULL) != 0 && stdControl_ReadKey(DIK_HOME, NULL) != 0) {
                    if (swrMain_debugKeyHeld != 0)
                        goto show_notice;
                    swrMain_debugKeyHeld = 1;
                    if (g_objHang2->menuScreen == swrObjHang_STATE_SELECT_VEHICLE) {
                        swrRace_DebugFlag ^= swrRace_DEBUGFLAG_UNLOCK_ALL;
                        swrRace_CheatUnlockAll();
                    }
                } else {
                    swrMain_debugKeyHeld = 0;
                }
            } else if (stdControl_ReadKey(DIK_J, NULL) != 0) {
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                if (joystick_detected == 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0035/~nNO JOYSTICK DETECTED."));
                    goto done;
                }
                if (swrConfig_joystick_enabled == 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0363/Joystick ENABLED\n"));
                    swrConfig_FORCE_ENABLED = swrMain_savedForceEnabled;
                } else {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0364/Joystick DISABLED\n"));
                    swrMain_savedForceEnabled = swrConfig_FORCE_ENABLED;
                    if (swrConfig_FORCE_ENABLED != 0)
                        swrControl_StopAllForceEffects(1);
                    swrConfig_FORCE_ENABLED = 0;
                }
                playUISound(0x46);
                swrConfig_joystick_enabled = swrConfig_joystick_enabled == 0;
                if (swrControl_uiInputActive == 0)
                    swrConfig_RefreshMappingMenu(swrConfig_DEVICE_JOYSTICK, swrUI_GetById(NULL, swrUI_WINDOW_JOYSTICK_SETTINGS));
                page = swrUI_GetCurrentPage();
                // the settings page saves on exit; elsewhere save now
                if (swrControl_uiInputActive != 0 || page == NULL || page->id != swrUI_WINDOW_JOYSTICK_SETTINGS)
                    swrConfig_WriteMappings("current");
            } else if (stdControl_ReadKey(DIK_LMENU, NULL) != 0 && g_objHang2->menuScreen == swrObjHang_STATE_SELECT_TRACK && ((mirrorOn = stdControl_ReadKey(DIK_RMENU, NULL)) != 0 || stdControl_ReadKey(DIK_RCONTROL, NULL) != 0)) {
                // Ctrl+LAlt+RAlt sets mirror mode, Ctrl+LAlt+RCtrl clears it; both flip bMirror
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                if (multiplayer_enabled == 0) {
                    if (mirrorOn != 0) {
                        GameSettingFlags |= GAME_SETTING_MIRROR;
                        g_objHang2->bMirror = g_objHang2->bMirror == 0;
                        playUISound(0x2e);
                    } else {
                        GameSettingFlags &= ~GAME_SETTING_MIRROR;
                        g_objHang2->bMirror = g_objHang2->bMirror == 0;
                        playUISound(0x2f);
                    }
                }
            } else if (stdControl_ReadKey(DIK_M, NULL) != 0) {
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                if (mouse_detected == 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0036/~nNO MOUSE DETECTED."));
                    goto done;
                }
                swrMain_AppendDebugNotice(swrText_Translate(swrConfig_mouse_enabled == 0 ? "/MONDOTEXT_H_0365/Mouse ENABLED\n" : "/MONDOTEXT_H_0366/Mouse DISABLED\n"));
                playUISound(0x46);
                swrConfig_mouse_enabled = swrConfig_mouse_enabled == 0;
                if (swrControl_uiInputActive == 0)
                    swrConfig_RefreshMappingMenu(swrConfig_DEVICE_MOUSE, swrUI_GetById(NULL, swrUI_WINDOW_MOUSE_SETTINGS));
                page = swrUI_GetCurrentPage();
                if (swrControl_uiInputActive != 0 || page == NULL || page->id != swrUI_WINDOW_MOUSE_SETTINGS)
                    swrConfig_WriteMappings("current");
            } else if (stdControl_ReadKey(DIK_F, NULL) != 0) {
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                if (swrControl_forceFeedbackAvailable == 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0042/~nNo Force Feedback device detected."));
                    goto done;
                }
                if (swrControl_forceEffectsLoaded == 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0368/No force-effects loaded.\n"));
                    goto done;
                }
                if (swrConfig_FORCE_ENABLED == 0 && Main_force_feedback != 0) {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0369/Force Feedback ENABLED\n"));
                } else {
                    swrMain_AppendDebugNotice(swrText_Translate("/MONDOTEXT_H_0370/Force Feedback DISABLED\n"));
                    swrControl_StopAllForceEffects(1);
                }
                playUISound(0x46);
                if (swrConfig_FORCE_ENABLED != 0 || (swrConfig_FORCE_ENABLED = 1, Main_force_feedback == 0))
                    swrConfig_FORCE_ENABLED = 0;
                swrConfig_RefreshForceFeedbackMenu(swrUI_GetById(NULL, swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS));
                page = swrUI_GetCurrentPage();
                if (swrControl_uiInputActive != 0 || page == NULL || page->id != swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS)
                    swrConfig_WriteForceFeedbackConfig("current");
            } else if (stdControl_ReadKey(DIK_Q, NULL) != 0 && multiplayer_enabled != 0) {
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                ev[0] = 'Paws';
                ev[1] = -1;
                ev[2] = 1;
                swrEvent_CallF4('All!', ev);
            } else if (stdControl_ReadKey(DIK_F11, NULL) != 0) {
                if (swrMain_debugKeyHeld != 0)
                    goto show_notice;
                swrMain_debugKeyHeld = 1;
                swrMain_showFpsHud = swrMain_showFpsHud == 0;
            } else {
                goto no_ctrl_keys;
            }
        }
    }

done:
    if (swrMain_debugKeyHeld == 0)
        return;
show_notice:
    if (swrMain_debugNotice[0] != '\0') {
        swrText_ShowTimedMessage(swrMain_debugNotice, 2.0f);
        swrMain_debugNotice[0] = '\0';
        swrUI_noticeDurationUnused = 2.1f;
    }
    // the debug-key trugut bonus stops after 5000
    if (trugutsBefore != swrRace_truguts) {
        if (cheatedTrugutsAmount < 5000) {
            cheatedTrugutsAmount += 1000;
            return;
        }
        swrRace_truguts = trugutsBefore;
    }
}

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
