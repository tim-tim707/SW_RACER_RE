#include "swrControl.h"

#include "Win95/Window.h"
#include "Platform/cifr.h"
#include "Platform/stdControl.h"
#include "globals.h"
#include "engine_config.h"
#include "Swr/swrModel.h"
#include "Swr/swrConfig.h"
#include "Swr/swrSprite.h"
#include "Swr/swrText.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "Swr/swrUI.h"
#include "swr.h"
#include "Platform/wuRegistry.h"
#include "Main/swrMain.h"
#include "Swr/swrRender.h"
#include "Swr/swrObj.h"
#include "Swr/swrRace.h"

#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "macros.h"

// 0x00402250
int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4)
{
    HANG("TODO");
}

// 0x00404da0
int swrControl_Shutdown(void)
{
    swrControl_StopAllForceEffects(0);
    swrControl_LoadForceEffects(-1);
    stdControl_Close();
    stdControl_Shutdown();
    return 0;
}

// x87 clamp as compiled: NaN falls into the low branch
static float swrControl_ClampUnit(float value)
{
    if (!(value >= -1.0f)) {
        return -1.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

// 0x00404dd0
void swrControl_ProcessInputs(void)
{
    swrControlBinding* binding;
    swrUI_unk* page;
    float value;
    float right;
    float up;
    int axis;
    int key;
    int direction;
    int held;
    int suppress;
    int accept;
    int cancel;
    int i;
    short steerX;
    short steerY;

    stdControl_ReadControls();
    memset(JoystickButtonPressedInput, 0, swrControl_buttonInputBytes);
    swrControl_brakeIsAnalog = 0;
    memset(JoystickAxisInput, 0, swrControl_axisInputBytes);

    if (swrConfig_joystick_enabled == 0 && swrControl_bindingCaptureActive == 0) {
        swrControl_ClearDeviceState(swrConfig_DEVICE_JOYSTICK);
    } else {
        swr_noop2();
        if (swrControl_bindingCaptureActive != 0) {
            for (i = 0; i < STDCONTROL_AXES_PER_JOYSTICK; i++) {
                swrControl_axesPrev[i] = swrControl_joystickAxes[i];
            }
            for (i = 3; i < STDCONTROL_AXES_PER_JOYSTICK; i++) {
                swrControl_joystickAxes[i] = swrControl_ClampUnit(stdControl_ReadAxis(stdControl_joystickDeviceIndex * STDCONTROL_AXES_PER_JOYSTICK + i) * swrControl_joystickAxisScale[i]);
            }
        }
        for (i = 0; i < 3; i++) {
            swrControl_joystickAxes[i] = swrControl_ClampUnit(stdControl_ReadAxis(stdControl_joystickDeviceIndex * STDCONTROL_AXES_PER_JOYSTICK + i) * swrControl_joystickAxisScale[i]);
        }
        for (binding = swrControl_bindingsJoystick; binding < swrControl_bindingsJoystick + (SWR_CONTROL_BINDINGS_PER_DEVICE - 1) && binding->flags != SWR_CONTROL_BINDING_END; binding++) {
            if ((binding->flags & swrControlBinding_FLAG_BUTTON) != 0) {
                key = STDCONTROL_JOYSTICK_KEY_BASE + stdControl_joystickDeviceIndex * STDCONTROL_KEYS_PER_JOYSTICK + binding->input;
                if ((binding->flags & swrControlBinding_FLAG_ANALOG) != 0) {
                    value = stdControl_ReadKeyAsAxis(key);
                    if ((binding->flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                        JoystickAxisInput[binding->action] = value + JoystickAxisInput[binding->action];
                    } else if ((binding->flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                        JoystickAxisInput[binding->action] = JoystickAxisInput[binding->action] - value;
                    }
                } else if ((binding->flags & swrControlBinding_FLAG_DIGITAL) != 0) {
                    value = (float)stdControl_ReadKey(key, NULL);
                    JoystickButtonPressedInput[binding->action] = (value != 0.0f || JoystickButtonPressedInput[binding->action] != 0.0f) ? 1.0f : 0.0f;
                }
            } else if ((binding->flags & swrControlBinding_FLAG_AXIS) != 0) {
                axis = binding->input + stdControl_joystickDeviceIndex * STDCONTROL_AXES_PER_JOYSTICK;
                if ((binding->flags & swrControlBinding_FLAG_ANALOG) != 0) {
                    value = swrControl_ClampUnit(stdControl_ReadAxis(axis) * swrControl_joystickAxisScale[binding->input]);
                    JoystickAxisInput[binding->action] = value * (swrControl_joystickFlipAxis[binding->input] != 0 ? -1.0 : 1.0) + JoystickAxisInput[binding->action];
                } else if ((binding->flags & swrControlBinding_FLAG_DIGITAL) != 0) {
                    direction = swrControl_joystickFlipAxis[binding->input] != 0 ? -1 : 1;
                    if ((binding->flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                        value = (float)stdControl_isAxisAboveDeadzone(axis, -direction, 0.0f, SWR_CONTROL_AXIS_DIGITAL_THRESHOLD);
                    } else if ((binding->flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                        value = (float)stdControl_isAxisAboveDeadzone(axis, direction, 0.0f, SWR_CONTROL_AXIS_DIGITAL_THRESHOLD);
                    } else {
                        value = (float)stdControl_ReadAxisAsKeyEx(axis);
                        if (swrControl_joystickFlipAxis[binding->input] == 0) {
                            value = value != 0.0f ? 1.0f : 0.0f;
                        } else {
                            value = value == 0.0f ? 1.0f : 0.0f;
                        }
                    }
                    if (binding->action == SWR_CONTROL_ACTION_BRAKE && value != 0.0f) {
                        swrControl_brakeIsAnalog = 1;
                    }
                    JoystickButtonPressedInput[binding->action] = (value != 0.0f || JoystickButtonPressedInput[binding->action] != 0.0f) ? 1.0f : 0.0f;
                }
            }
        }
    }

    if (swrControl_mouseSuppressed == 0 && (swrConfig_mouse_enabled != 0 || swrControl_bindingCaptureActive != 0)) {
        if (swrControl_bindingCaptureActive != 0) {
            for (i = 0; i < STDCONTROL_MOUSE_NUM_AXES; i++) {
                swrControl_axesPrev[STDCONTROL_AXES_PER_JOYSTICK + i] = swrControl_mouseAxes[i];
            }
        }
        // flip_x/y/z_axis are consecutive: the mouse flip table
        for (i = 0; i < STDCONTROL_MOUSE_NUM_AXES; i++) {
            swrControl_mouseAxes[i] = stdControl_ReadAxis(STDCONTROL_MOUSE_AXIS_BASE + i) * ((&flip_x_axis)[i] != 0 ? -1.0 : 1.0);
        }
        if (swrControl_uiInputActive == 0 && swrControl_bindingCaptureActive == 0) {
            swrControl_mouseAxesAccum[2] = 0.0f;
            swrControl_mouseAxesAccum[1] = 0.0f;
            swrControl_mouseAxesAccum[0] = 0.0f;
        } else {
            for (i = 0; i < STDCONTROL_MOUSE_NUM_AXES; i++) {
                if (swrControl_mouseAxes[i] != 0.0f) {
                    swrControl_mouseAxesAccum[i] = swrControl_ClampUnit(swrControl_mouseAxes[i] + swrControl_mouseAxesAccum[i]);
                }
            }
            for (i = 0; i < STDCONTROL_MOUSE_NUM_AXES; i++) {
                swrControl_mouseAxes[i] = swrControl_mouseAxesAccum[i];
            }
        }
        for (binding = swrControl_bindingsMouse; binding < swrControl_bindingsMouse + (SWR_CONTROL_BINDINGS_PER_DEVICE - 1) && binding->flags != SWR_CONTROL_BINDING_END; binding++) {
            if ((binding->flags & swrControlBinding_FLAG_BUTTON) != 0) {
                value = (float)stdControl_ReadKey(STDCONTROL_MOUSE_KEY_BASE + binding->input, NULL);
                MouseButtonPressedInput[binding->action] = (value != 0.0f || MouseButtonPressedInput[binding->action] != 0.0f) ? 1.0f : 0.0f;
            } else if ((binding->flags & swrControlBinding_FLAG_AXIS) != 0) {
                axis = binding->input;
                if ((binding->flags & swrControlBinding_FLAG_ANALOG) != 0) {
                    if (axis == 0 || axis == 1 || axis == 2) {
                        MouseAxisInput[binding->action] = swrControl_mouseAxes[axis] + MouseAxisInput[binding->action];
                    } else {
                        // faithful: indexes the 3-entry mouse flip table with any axis
                        value = stdControl_ReadAxis(STDCONTROL_MOUSE_AXIS_BASE + axis);
                        MouseAxisInput[binding->action] = value * ((&flip_x_axis)[axis] != 0 ? -1.0 : 1.0) + MouseAxisInput[binding->action];
                    }
                } else if ((binding->flags & swrControlBinding_FLAG_DIGITAL) != 0) {
                    if ((binding->flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                        value = (float)stdControl_isAxisAboveDeadzone(-1, 1, swrControl_mouseAxes[axis], SWR_CONTROL_AXIS_DIGITAL_THRESHOLD);
                    } else if ((binding->flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                        value = (float)stdControl_isAxisAboveDeadzone(-1, -1, swrControl_mouseAxes[axis], SWR_CONTROL_AXIS_DIGITAL_THRESHOLD);
                    } else {
                        value = (float)stdControl_isAxisAboveDeadzone(STDCONTROL_MOUSE_AXIS_BASE + axis, 0, swrControl_mouseAxes[axis], SWR_CONTROL_MOUSE_AXIS_DIGITAL_THRESHOLD);
                    }
                    if (binding->action == SWR_CONTROL_ACTION_BRAKE && value != 0.0f) {
                        swrControl_brakeIsAnalog = 1;
                    }
                    MouseButtonPressedInput[binding->action] = (value != 0.0f || MouseButtonPressedInput[binding->action] != 0.0f) ? 1.0f : 0.0f;
                }
            }
        }
    } else {
        swrControl_ClearDeviceState(swrConfig_DEVICE_MOUSE);
    }

    if (swrConfig_keyboard_enabled == 0) {
        swrControl_ClearDeviceState(swrConfig_DEVICE_KEYBOARD);
    } else {
        swrControl_SnapshotKeyboard();
        right = stdControl_ReadKeyAsAxis(DIK_RIGHT) - stdControl_ReadKeyAsAxis(DIK_LEFT);
        swrControl_keyboardAxes[0] = (stdControl_ReadKeyAsAxis(DIK_NUMPAD6) - stdControl_ReadKeyAsAxis(DIK_NUMPAD4)) + right;
        up = stdControl_ReadKeyAsAxis(DIK_UP) - stdControl_ReadKeyAsAxis(DIK_DOWN);
        swrControl_keyboardAxes[1] = (stdControl_ReadKeyAsAxis(DIK_NUMPAD8) - stdControl_ReadKeyAsAxis(DIK_NUMPAD2)) + up;
        for (binding = swrControl_bindingsKeyboard; binding < swrControl_bindingsKeyboard + (SWR_CONTROL_BINDINGS_PER_DEVICE - 1) && binding->flags != SWR_CONTROL_BINDING_END; binding++) {
            if ((binding->flags & swrControlBinding_FLAG_BUTTON) == 0) {
                continue;
            }
            if ((binding->flags & swrControlBinding_FLAG_ANALOG) != 0) {
                value = stdControl_ReadKeyAsAxis(binding->input);
                if ((binding->flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                    KeyboardAxisInput[binding->action] = value + KeyboardAxisInput[binding->action];
                } else if ((binding->flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                    KeyboardAxisInput[binding->action] = KeyboardAxisInput[binding->action] - value;
                }
            } else if ((binding->flags & swrControlBinding_FLAG_DIGITAL) != 0) {
                value = (float)stdControl_ReadKey(binding->input, NULL);
                KeyboardButtonPressedInput[binding->action] = (value != 0.0f || KeyboardButtonPressedInput[binding->action] != 0.0f) ? 1.0f : 0.0f;
            }
        }
    }

    for (i = 0; i < SWR_CONTROL_NUM_ANALOG_ACTIONS; i++) {
        (&swrRace_ThrottleInput)[i] = swrControl_ClampUnit(JoystickAxisInput[i] + KeyboardAxisInput[i] + MouseAxisInput[i]);
    }
    for (i = 0; i < SWR_CONTROL_NUM_ACTIONS; i++) {
        if (JoystickButtonPressedInput[i] == 0.0f && MouseButtonPressedInput[i] == 0.0f && KeyboardButtonPressedInput[i] == 0.0f) {
            held = 0;
            (&swrControl_viewHoldTime)[i] = 0.0f;
        } else {
            held = 1;
            (&swrControl_viewHoldTime)[i] = (&swrControl_viewHoldTime)[i] + swrRace_deltaTimeSecs;
        }
        suppress = swrControl_buttonHeldPrev[i] != 0 && swrControl_actionEdgeOnly[i] != 0;
        // in race, action 0 (change view) repeats while held
        if (swrControl_uiInputActive == 0 && i == 0) {
            suppress = 0;
        }
        swrControl_buttonHeldPrev[i] = (char)held;
        (&swrControl_viewButton)[i] = (!suppress && held) ? 1.0f : 0.0f;
    }

    steerX = (short)(int)((swrControl_joystickAxes[0] + swrControl_mouseAxes[0] + swrControl_keyboardAxes[0]) * SWR_CONTROL_STEER_RECORD_SCALE);
    steerY = (short)(int)(((swrControl_mouseAxes[1] - swrControl_joystickAxes[1]) + swrControl_keyboardAxes[1]) * SWR_CONTROL_STEER_RECORD_SCALE);
    if (steerX < -SWR_CONTROL_STEER_RECORD_MAX) {
        steerX = -SWR_CONTROL_STEER_RECORD_MAX;
    } else if (steerX > SWR_CONTROL_STEER_RECORD_MAX) {
        steerX = SWR_CONTROL_STEER_RECORD_MAX;
    }
    if (steerY < -SWR_CONTROL_STEER_RECORD_MAX) {
        steerY = -SWR_CONTROL_STEER_RECORD_MAX;
    } else if (steerY > SWR_CONTROL_STEER_RECORD_MAX) {
        steerY = SWR_CONTROL_STEER_RECORD_MAX;
    }
    inRaceLocalPlayerInputRecord[0].axisX = steerX;
    inRaceLocalPlayerInputRecord[0].axisY = steerY;
    for (i = 0; i < SWR_CONTROL_NUM_RECORD_ACTIONS; i++) {
        if (swrControl_inputRecordActions[i] < 0) {
            inRaceLocalPlayerInputRecord[0].actions[i] = 0;
        } else {
            inRaceLocalPlayerInputRecord[0].actions[i] = (char)(int)(&swrControl_viewButton)[swrControl_inputRecordActions[i]];
        }
    }

    if (swrControl_uiInputActive != 0) {
        swrControl_mouseSuppressed = 0;
        swrControl_cancelHeldPrev = 0;
        swrControl_acceptHeldPrev = 0;
        swrControl_acceptReleasedEdge = 0;
        swrControl_cancelPressedEdge = 0;
        swrControl_acceptPressedEdge = 0;
        return;
    }

    accept = swrControl_PollAccept(-1);
    cancel = swrControl_PollCancel(-1);
    if (cancel != 0 && accept != 0) {
        accept = 0;
    }
    swrControl_acceptPressedEdge = (swrControl_acceptHeldPrev == 0 && accept != 0) ? 1 : 0;
    swrControl_cancelPressedEdge = (swrControl_cancelHeldPrev == 0 && cancel != 0) ? 1 : 0;
    swrControl_acceptReleasedEdge = (swrControl_acceptUpPrev == 0 && accept == 0) ? 1 : 0;
    swrControl_cancelReleasedEdge = (swrControl_cancelUpPrev == 0 && cancel == 0) ? 1 : 0;
    swrControl_acceptHeldPrev = accept;
    swrControl_cancelHeldPrev = cancel;
    swrControl_acceptUpPrev = accept == 0;
    swrControl_cancelUpPrev = cancel == 0;
    accept = swrControl_PollAccept(swrConfig_DEVICE_MOUSE);
    swrControl_menuAcceptPressedEdge = (swrControl_menuAcceptHeldPrev == 0 && accept != 0) ? 1 : 0;
    swrControl_menuAcceptHeldPrev = accept;
    if (swrControl_cancelPressedEdge != 0) {
        page = swrUI_GetCurrentPage();
        if (page == NULL || page->id != swrUI_WINDOW_SPLASH) {
            playUISound(0x4d);
        }
    }
    if (swrControl_menuAcceptGuard != 0 && g_objHang2->menuScreen != swrObjHang_STATE_MAIN_MENU && g_objHang2->menuScreen != swrObjHang_STATE_LOOK_AT_VEHICLE && g_objHang2->menuScreen != swrObjHang_STATE_POST_RACE_INFO) {
        swrControl_mouseSuppressed = 1;
    } else {
        swrControl_mouseSuppressed = 0;
    }
}

// 0x00407500
int swrControl_RemoveMapping(void* cid, char* mondo_text, int bAnalog, int whichone, int bRemove)
{
    swrControlBinding* table;
    swrControlBinding wanted;
    int matches;
    int found;
    int i;

    matches = 0;
    found = -1;
    memset(&wanted, 0, sizeof(wanted));
    // cid is a swrConfig_DEVICE, or a binding table pointer
    if (cid == (void*)swrConfig_DEVICE_JOYSTICK) {
        table = swrControl_bindingsJoystick;
    } else if (cid == (void*)swrConfig_DEVICE_MOUSE) {
        table = swrControl_bindingsMouse;
    } else if (cid == (void*)swrConfig_DEVICE_KEYBOARD) {
        table = swrControl_bindingsKeyboard;
    } else {
        table = (swrControlBinding*)cid;
    }
    if (swrControl_ParseFunctionName(&wanted, mondo_text, 1) == 0) {
        return -1;
    }
    wanted.flags |= bAnalog == 0 ? swrControlBinding_FLAG_BUTTON : swrControlBinding_FLAG_AXIS;
    for (i = 0; table[i].flags != SWR_CONTROL_BINDING_END; i++) {
        if (table[i].action == wanted.action && (wanted.flags & table[i].flags) == wanted.flags) {
            matches++;
            if (matches == whichone) {
                found = i;
                break;
            }
        }
    }
    if (found < 0) {
        return -1;
    }
    if (bRemove != 0) {
        // faithful: the count is indexed by cid even when cid is a table pointer
        for (i = found; i <= swrControl_bindingCounts[(int)cid] - 1; i++) {
            table[i] = table[i + 1];
        }
        swrControl_bindingCounts[(int)cid]--;
    }
    return found;
}

// 0x004078e0
int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int direction, int slot)
{
    swrControlBinding* table;
    swrControlBinding binding;
    int count;

    memset(&binding, 0, sizeof(binding));
    if (cid == (void*)swrConfig_DEVICE_JOYSTICK) {
        table = swrControl_bindingsJoystick;
    } else if (cid == (void*)swrConfig_DEVICE_MOUSE) {
        table = swrControl_bindingsMouse;
    } else if (cid == (void*)swrConfig_DEVICE_KEYBOARD) {
        table = swrControl_bindingsKeyboard;
    } else {
        table = (swrControlBinding*)cid;
    }
    binding.input = controllerBinding;
    if (swrControl_ParseFunctionName(&binding, fnStr, 1) == 0) {
        return 0;
    }
    if (bAnalogCapture == 0) {
        binding.flags |= swrControlBinding_FLAG_BUTTON;
    } else {
        binding.flags |= swrControlBinding_FLAG_AXIS;
        if (direction > 0) {
            binding.flags |= swrControlBinding_FLAG_POSITIVE;
        } else if (direction < 0) {
            binding.flags |= swrControlBinding_FLAG_NEGATIVE;
        }
    }
    if (slot < 0) {
        // faithful: the count is indexed by cid even when cid is a table pointer
        count = swrControl_bindingCounts[(int)cid];
        table[count] = binding;
        swrControl_bindingCounts[(int)cid] = count + 1;
        table[count + 1].flags = SWR_CONTROL_BINDING_END;
        return 1;
    }
    table[slot] = binding;
    return 1;
}

// 0x004078a0
void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int direction, int controllerBinding)
{
    int slot;

    slot = swrControl_RemoveMapping(cid, fnStr, bAnalogCapture, whichOne, 0);
    swrControl_AddMapping(cid, fnStr, controllerBinding, bAnalogCapture, direction, slot);
}

// 0x00423efd
int swrControl_Startup(void)
{
    int color;

    swrUI_UpdateProgressBar(20);
    if (swrControl_Initialize() != 0) {
        sprintf(unknownError_buffer, "ERROR: elfControl_Initialize failed.\n%s", std_output_buffer);
        Main_ShutdownError();
        return 0;
    }
    swrUI_UpdateProgressBar(25);
    wuRegistry_SaveInt2("FullScreen", swrMainDisplaySettings_g.RegFullScreen);
    wuRegistry_SaveInt2("Fix Flicker", swrMainDisplaySettings_g.RegFixFlicker);
    wuRegistry_SaveInt2("DevMode", swrMainDisplaySettings_g.RegDevMode);
    wuRegistry_SaveInt2("UseFett", swrMainDisplaySettings_g.RegUseFett);
    swrRender_InitScene(&swrMainDisplaySettings_g);
    swrUI_UpdateProgressBar(38);
    Window_set_msg_handler(Window_msg_default_handler);
    swrUI_UpdateProgressBar(40);
    enablePauseOverlay_Maybe();
    swrUI_UpdateProgressBar(45);
    swrScene_Startup();
    swrUI_UpdateProgressBar(50);
    swrUI_BuildMenuPages();
    swrUI_UpdateProgressBar(60);
    swrRace_InitGameData();
    swrUI_UpdateProgressBar(65);

    // RGB565 -> RGB555 table for the Smush cinematic frames (Window_SmushPlayCallback)
    Window_smushColorTable = NULL;
    if (stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddpfPixelFormat.dwRBitMask == SWR_RGB555_RED_MASK && stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddpfPixelFormat.dwGBitMask == SWR_RGB555_GREEN_MASK && stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddpfPixelFormat.dwBBitMask == SWR_RGB555_BLUE_MASK) {
        Window_smushColorTable = Window_smushRgb565To555;
        for (color = 0xffff; color >= 0; color--)
            Window_smushColorTable[color] = (color & SWR_RGB555_BLUE_MASK) | ((color >> 1) & (SWR_RGB555_RED_MASK | SWR_RGB555_GREEN_MASK));
    }

    memset(&ddSurfaceDescForVideo, 0, sizeof(ddSurfaceDescForVideo));
    ddSurfaceDescForVideo.dwSize = sizeof(ddSurfaceDescForVideo);
    ddSurfaceDescForVideo.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
    ddSurfaceDescForVideo.dwWidth = SWR_SMUSH_VIDEO_WIDTH;
    ddSurfaceDescForVideo.dwHeight = SWR_SMUSH_VIDEO_HEIGHT;
    ddSurfaceDescForVideo.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY;
    // the EXE calls ShowWindow through EBX, loaded from the import table in Main_Startup
    if (swrMainDisplaySettings_g.RegFullScreen == 0 && swrMainDisplaySettings_g.RegDevMode == 0)
        ShowWindow(Main_hWnd, SW_MAXIMIZE);
    swrUI_UpdateProgressBar(90);
    return 1;
}

// 0x00405cf0
void swrControl_ClearDeviceState(int deviceClass)
{
    if (deviceClass < 0) {
        // leaves unk14 alone (only resetInRaceInputBuffer clears it)
        memset(&inRaceLocalPlayerInputRecord[0], 0, offsetof(swrControl_InRaceInputRecord, unk14));
        memset(swrControl_buttonHeldPrev, 0, sizeof(swrControl_buttonHeldPrev));
        deviceClass = -deviceClass;
    }
    if (deviceClass == swrConfig_DEVICE_JOYSTICK) {
        swrControl_joystickAxes[2] = 0.0f;
        swrControl_joystickAxes[1] = 0.0f;
        swrControl_joystickAxes[0] = 0.0f;
    } else if (deviceClass == swrConfig_DEVICE_MOUSE) {
        swrControl_mouseAxes[2] = 0.0f;
        swrControl_mouseAxes[1] = 0.0f;
        swrControl_mouseAxes[0] = 0.0f;
        swrControl_mouseAxesAccum[2] = 0.0f;
        swrControl_mouseAxesAccum[1] = 0.0f;
        swrControl_mouseAxesAccum[0] = 0.0f;
    } else if (deviceClass == swrConfig_DEVICE_KEYBOARD) {
        swrControl_keyboardAxes[2] = 0.0f;
        swrControl_keyboardAxes[1] = 0.0f;
        swrControl_keyboardAxes[0] = 0.0f;
    }
}

// 0x00409d70
int swrControl_LoadForceEffects(int deviceType)
{
    char projectFile[20];
    const char* bundle;

    if ((swrControl_forceEffectsDeviceType & 0xff) == deviceType) {
        return 1;
    }
    if (deviceType >= SWR_FF_DEVICE_NONE) {
        return 0;
    }
    if ((unsigned char)swrControl_forceEffectsDeviceType < SWR_FF_DEVICE_NONE) {
        cifr_ReinitEffects_Maybe(&swrControl_forceEffects);
    }
    memset(swrControl_forceEffectValue, 0, sizeof(swrControl_forceEffectValue));
    memset(swrControl_forceEffectPlaying, 0, sizeof(swrControl_forceEffectPlaying));
    // the EXE only ever writes the low byte of swrControl_forceEffectsDeviceType
    if (deviceType < 0) {
        *(unsigned char*)&swrControl_forceEffectsDeviceType = SWR_FF_DEVICE_NONE;
        return 1;
    }
    cifr_Init(&swrControl_forceEffects);
    bundle = cifr_deviceIsWheel ? ".\\data\\bundle2.fcr" : ".\\data\\bundle.fcr";
    memcpy(projectFile, bundle, strlen(bundle) + 1);
    if (cifr_LoadProjectFile(&swrControl_forceEffects, projectFile, swrControl_forceEffectSlotLastIds, swrControl_forceEffectNames) < 0) {
        return 0;
    }
    if (cifr_LoadAllEffects(&swrControl_forceEffects) < 0) {
        (*stdPlatform_hostServices_ptr->errorPrint)("BIZARRO ALERT!  cifr_LoadAllEffectsSlots couldn't load any forces!\n");
        return 0;
    }
    *(unsigned char*)&swrControl_forceEffectsDeviceType = (unsigned char)deviceType;
    swrControl_forceEffectsLoaded = 1;
    return 1;
}

// 0x00409ee0
int swrControl_PlayForceEffect(int effectId, int magnitude, int direction, int duration)
{
    int slot;
    int prepared;
    float strength;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    strength = swrControl_forceStrength;
    // slot -1 (unknown id) yields a pointer one slot before the table; faithful
    effect = &swrControl_forceEffects.slots[slot];
    if (swrConfig_FORCE_ENABLED == 0) {
        return 1;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        // a disabled GForce falls back to the auto-center spring
        if (effectId != swrForceEffect_GFORCE) {
            return 1;
        }
        setting = &swrControl_forceEffectSettings[swrForceEffect_AUTO_CENTER];
        if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
            return 1;
        }
        effectId = swrForceEffect_AUTO_CENTER;
    }
    prepared = swrControl_PrepareForceEffect(effectId, 0);
    if (swrControl_forceEffectPlaying[effectId] != 0 && cifr_IsPlaying(effect) == 0) {
        cifr_StopEffect(effect);
        swrControl_forceEffectPlaying[effectId] = 0;
        swrControl_forceEffectValue[effectId] = 0;
    }
    if (prepared == 0) {
        return 0;
    }
    if (swrControl_forceEffectSettings[effectId].gain > 0.0f) {
        strength = strength * swrControl_forceEffectSettings[effectId].gain;
    }
    if (magnitude >= 0) {
        cifr_SetMagnitude(effect, (int)((double)magnitude * strength), 0);
    } else if (strength < 1.0f) {
        cifr_SetMagnitude(effect, (int)((double)strength * 100.0f), 0);
    }
    if (direction >= 0) {
        cifr_SetDirection(effect, direction, 1);
    }
    if (duration >= 0) {
        cifr_SetDuration(effect, duration, 0);
    }
    if (cifr_StartEffect(effect, 0) < 0) {
        return 0;
    }
    swrControl_forceEffectPlaying[effectId] = 1;
    return 1;
}

// 0x0040a0b0
int swrControl_StopForceEffect(int effectId)
{
    int slot;
    cifr_Effect* effect;

    slot = swrControl_FindForceEffectSlot(effectId);
    if (swrControl_forceEffectPlaying[effectId] != 0) {
        swrControl_forceEffectPlaying[effectId] = 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect != NULL && effect->interfaces != NULL && swrControl_CheckForceEffectType(slot, effectId) == 0) {
        cifr_StopEffect(effect);
        return 1;
    }
    return 0;
}

// 0x0040a120
void swrControl_StopAllForceEffects(int reInit)
{
    int i;

    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        swrControl_StopForceEffect(swrControl_forceEffects.slots[i].effectId);
    }
    if (reInit != 0) {
        swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
    }
}

// 0x0040a160
int swrControl_FindForceEffectSlot(unsigned int effectId)
{
    int slot;

    for (slot = 0; slot < SWR_FF_EFFECT_SLOTS; slot++) {
        if (effectId <= swrControl_forceEffects.slots[slot].lastEffectId) {
            break;
        }
    }
    if (slot >= SWR_FF_EFFECT_SLOTS) {
        slot = -1;
    }
    return slot;
}

// 0x0040a190
int swrControl_CheckForceEffectType(int slot, unsigned int type)
{
    unsigned int loaded;

    if (slot < 0) {
        return -1;
    }
    loaded = swrControl_forceEffects.slots[slot].effectId;
    if ((int)loaded < 0) {
        return 2;
    }
    if (loaded == type) {
        return 0;
    }
    if (strcmp(swrControl_forceEffects.slots[slot].name, swrControl_forceEffectNames[type]) == 0) {
        return 1;
    }
    if (loaded < type) {
        return 3;
    }
    return 4;
}

// 0x0040a240
int swrControl_PrepareForceEffect(int effectId, int force)
{
    int slot;
    int check;
    cifr_Effect* effect;
    const char* name;

    slot = swrControl_FindForceEffectSlot(effectId);
    check = swrControl_CheckForceEffectType(slot, effectId);
    if (check < 0) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (check > 3 && force == 0 && cifr_IsPlaying(effect) != 0) {
        return 0;
    }
    // an empty slot (effectId -1) clears index -1 of both arrays; faithful
    swrControl_forceEffectPlaying[effect->effectId] = 0;
    swrControl_forceEffectValue[effect->effectId] = 0;
    effect->effectId = effectId;
    swrControl_forceEffectValue[effectId] = 0;
    if (check > 1) {
        name = swrControl_forceEffectNames[effectId];
        memcpy(effect->name, name, strlen(name) + 1);
        if (cifr_CreateEffect(effect, swrControl_forceEffectNames[effectId], swrControl_forceEffects.project) == 0) {
            return 0;
        }
        swrControl_forceEffectPlaying[effectId] = 0;
    }
    return 1;
}

// 0x0040a330
int swrControl_ConfigureForceEffect(int effectId, int value)
{
    int slot;
    int restarted;
    int ok;
    int coeff;
    unsigned int size;
    int* params;
    char state;
    float scale;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    restarted = 0;
    if (slot < 0 || swrControl_forceEffects.slots[slot].effectId != effectId) {
        return 0;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect->interfaces == NULL) {
        return 0;
    }
    if (cifr_IsPlaying(effect) == 0) {
        restarted = 1;
    }
    if (restarted == 0 && swrControl_forceEffectValue[effectId] == value) {
        return 1;
    }
    if (cifr_GetForceFeedbackState_Maybe(effect, &state) == 0) {
        return 0;
    }
    size = effect->params.cbTypeSpecificParams;
    params = (*stdPlatform_hostServices_ptr->alloc)(size);
    memcpy(params, effect->typeSpecificBuffer, size);
    scale = 1.0f;
    if (setting->magnitudeScale != 0.0f) {
        scale = setting->magnitudeScale;
    }
    // DICONDITION pair: [1]/[2] = axis-0 coefficients, [7]/[8] = axis-1 coefficients
    coeff = (int)((double)value * scale);
    params[1] = coeff;
    params[2] = coeff;
    if (cifr_deviceIsWheel == 0) {
        params[7] = (params[7] / coeff) * value;
        params[8] = params[7];
    }
    swrControl_forceEffectValue[effectId] = value;
    ok = cifr_SetCustomForceData_Maybe(effect, size, params, restarted);
    (*stdPlatform_hostServices_ptr->free)(params);
    if (ok != 0 && restarted != 0) {
        swrControl_forceEffectPlaying[effectId] = 1;
    }
    return ok;
}

// 0x0040a500
int swrControl_UpdateForceEffect(int effectId, int period)
{
    int slot;
    int restarted;
    int ok;
    unsigned int size;
    int* params;
    char state;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    restarted = 0;
    if (slot < 0 || swrControl_forceEffects.slots[slot].effectId != effectId) {
        return 0;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect->interfaces == NULL) {
        return 0;
    }
    if (cifr_IsPlaying(effect) == 0) {
        restarted = 1;
    }
    if (restarted == 0 && swrControl_forceEffectValue[effectId] == period) {
        return 1;
    }
    if (cifr_GetForceFeedbackState_Maybe(effect, &state) == 0) {
        return 0;
    }
    size = effect->params.cbTypeSpecificParams;
    params = (*stdPlatform_hostServices_ptr->alloc)(size);
    memcpy(params, effect->typeSpecificBuffer, size);
    params[3] = period; // DIPERIODIC dwPeriod
    swrControl_forceEffectValue[effectId] = period;
    ok = cifr_SetCustomForceData_Maybe(effect, size, params, restarted);
    (*stdPlatform_hostServices_ptr->free)(params);
    if (ok != 0 && restarted != 0) {
        swrControl_forceEffectPlaying[effectId] = 1;
    }
    return ok;
}

// 0x0040b110
void swrControl_SetForceFeedbackPlayer(swrRace* player)
{
    currentPlayer_Test = player;
    swrControl_ffScore = player->score_ptr;
    swrControl_ffMaxSpeed = player->podStats.maxSpeed;
    swrControl_ffRestSpeedRatio = 0.0f;
    swrControl_ffGForceScale = 6500.0f;
    swrControl_ffPrevSpeedRatio = -65535.0f;
}

// 0x0040b150
void swrControl_UpdateForceFeedback(void)
{
    if (swrConfig_FORCE_ENABLED != 0 && swrControl_ffScore != NULL && swrControl_ffScore->obj_test_ptr != NULL && currentPlayer_Test != NULL && swrRace_resultsScreenActive != 0 && (currentPlayer_Test->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0) {
        swrControl_UpdateTractionForceEffect();
        swrControl_UpdateSpeedForceEffect();
        swrControl_UpdateImpactForceEffect();
    }
}

// 0x0040b1c0
void swrControl_UpdateTractionForceEffect(void)
{
    swrRace* player;
    swrModel_Behavior* behavior;
    int period;
    int delta;
    int i;
    int leftCount;
    int rightCount;
    unsigned int status;
    float maxHealth;

    player = currentPlayer_Test;
    maxHealth = -1.0f;
    status = 0;
    rightCount = 0;
    leftCount = 0;
    if ((player->flags1 & swrObjTest_FLAG1_EXPLODING) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_CRASHING, -1, -1, -1);
        swrControl_PlayForceEffect(swrForceEffect_SWAMP_MUCK, -1, -1, -1);
        return;
    }
    if (player->surfaceSpeedFactor < 1.0f) {
        period = (int)(200000.0f - (double)player->surfaceSpeedFactor * 150000.0f);
        delta = period - swrControl_ffLastTractionPeriod;
        if (delta < 0) {
            delta = swrControl_ffLastTractionPeriod - period;
        }
        if (delta >= 20000) {
            swrControl_UpdateForceEffect(swrForceEffect_ENGINE_RUMBLE, period);
            swrControl_ffLastTractionPeriod = period;
        }
        swrControl_ffTractionRumbleActive = 1;
    } else {
        swrControl_UpdateForceEffect(swrForceEffect_ENGINE_RUMBLE, 8000);
        swrControl_ffTractionRumbleActive = 0;
    }
    if ((currentPlayer_Test->flags1 & swrObjTest_FLAG1_ON_SWAMP) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_SWAMP_MUCK, -1, -1, -1);
    } else {
        swrControl_StopForceEffect(swrForceEffect_SWAMP_MUCK);
    }
    if ((currentPlayer_Test->flags1 & swrObjTest_FLAG1_AIRBORNE) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_AIR_SLIDE, -1, -1, -1);
    } else {
        swrControl_StopForceEffect(swrForceEffect_AIR_SLIDE);
        player = currentPlayer_Test;
        if (player->terrainModel != NULL && player->speedValue > 50.0f) {
            behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)player->terrainModel);
            if (behavior != NULL && (behavior->vehicle_reaction & swrVehicleReaction_Slip) != 0) {
                swrControl_PlayForceEffect(swrForceEffect_ICE_SLIDE, -1, -1, -1);
            }
        }
    }
    // only engines that raise the running max are counted (faithful)
    for (i = 0; i < 6; i++) {
        if (maxHealth < currentPlayer_Test->engineHealth[i]) {
            maxHealth = currentPlayer_Test->engineHealth[i];
            status |= currentPlayer_Test->engineStatus[i];
            if (i <= 2) {
                leftCount++;
            } else {
                rightCount++;
            }
        }
    }
    if ((status & swrRace_ENGINESTATUS_ON_FIRE) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_ENGINE_FIRE_LEFT, -1, (rightCount > leftCount) * 180 + 90, -1);
        return;
    }
    swrControl_StopForceEffect(swrForceEffect_ENGINE_FIRE_LEFT);
}

// 0x0040b3d0
void swrControl_UpdateSpeedForceEffect(void)
{
    float ratio;
    float diff;
    double scaled;
    double rounded;
    int coeff;
    int magnitude;
    int delta;

    ratio = currentPlayer_Test->speedValue / swrControl_ffMaxSpeed;
    if ((swrControl_ffPrevSpeedRatio == -65535.0f || swrControl_ffGForceStarted == 0 || swrControl_damageForceEffectPreempted != 0) && swrControl_PlayForceEffect(swrForceEffect_GFORCE, -1, -1, -1) != 0) {
        swrControl_ffGForceStarted = 1;
        swrControl_damageForceEffectPreempted = 0;
    }
    diff = swrControl_ffAppliedSpeedRatio - ratio;
    if (diff < 0.0f) {
        diff = -diff;
    }
    swrControl_ffSpeedEffectDirty = diff > 0.1f;
    if (swrControl_ffSpeedEffectDirty != 0) {
        swrControl_ffSpeedSettled = 0;
    } else if (swrControl_ffSpeedSettled == 0) {
        // compares the ratio against the absolute maxSpeed, not 1.0 (faithful)
        swrControl_ffSpeedEffectDirty = ratio >= swrControl_ffMaxSpeed || ratio == swrControl_ffRestSpeedRatio;
        swrControl_ffSpeedSettled = swrControl_ffSpeedEffectDirty;
    }
    if (swrControl_ffSpeedEffectDirty != 0) {
        // round away from zero, then offset by 500
        scaled = (double)ratio * swrControl_ffGForceScale;
        coeff = (int)scaled;
        rounded = scaled;
        if ((double)coeff != scaled) {
            if (scaled > 0.0) {
                coeff++;
            } else {
                coeff--;
            }
            rounded = coeff;
        }
        coeff = (int)(rounded - -500.0f);
        if ((currentPlayer_Test->flags0 & swrObjTest_FLAG0_BOOSTING) != 0) {
            coeff = 9500;
        } else if ((float)coeff < 500.0f) {
            coeff = 500;
        } else {
            delta = swrControl_ffLastGForceCoeff - coeff;
            if (delta < 0) {
                delta = coeff - swrControl_ffLastGForceCoeff;
            }
            if (delta < 500) {
                coeff = swrControl_ffLastGForceCoeff;
            }
        }
        swrControl_ConfigureForceEffect(swrForceEffect_GFORCE, coeff);
        swrControl_ffLastGForceCoeff = coeff;
        if (swrControl_ffTractionRumbleActive == 0) {
            magnitude = (int)(((double)ratio - -1.0f) * 50.0f);
            delta = swrControl_ffLastRumbleMagnitude - magnitude;
            if (delta < 0) {
                delta = magnitude - swrControl_ffLastRumbleMagnitude;
            }
            if (delta < 10) {
                magnitude = swrControl_ffLastRumbleMagnitude;
            } else {
                swrControl_ffLastRumbleMagnitude = magnitude;
            }
            swrControl_PlayForceEffect(swrForceEffect_ENGINE_RUMBLE, magnitude, -1, -1);
        }
        swrControl_ffAppliedSpeedRatio = ratio;
    }
    swrControl_ffPrevSpeedRatio = ratio;
}

// 0x0040b5e0
void swrControl_UpdateImpactForceEffect(void)
{
    swrRace* player;
    int boosting;

    player = currentPlayer_Test;
    if ((player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_TURBO_START, -1, -1, -1);
    } else {
        boosting = player->flags0 & swrObjTest_FLAG0_BOOSTING;
        if (boosting != 0 && swrControl_ffBoostActive == 0) {
            swrControl_PlayForceEffect(swrForceEffect_START_BOOST, -1, -1, -1);
            swrControl_ffBoostActive = 1;
        } else if (boosting == 0 && swrControl_ffBoostActive != 0) {
            swrControl_PlayForceEffect(swrForceEffect_END_BOOST, -1, -1, -1);
            swrControl_ffBoostActive = 0;
        }
    }
    player = currentPlayer_Test;
    if ((player->flags1 & swrObjTest_FLAG1_SLIDING) != 0 && swrControl_slideButton != 0.0f) {
        if ((player->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0) {
            swrControl_PlayForceEffect(swrForceEffect_HEAVY_SLIDE_SLIP, -1, -1, -1);
        }
    } else if (swrControl_StopForceEffect(swrForceEffect_HEAVY_SLIDE_SLIP) != 0) {
        swrControl_ffGForceStarted = 0;
    }
    player = currentPlayer_Test;
    // fires when tilt leaves neutral or its truncated sign flips
    if (player->tiltManualMult != 0.0 && (swrControl_ffPrevTilt == 0.0 || ((int)swrControl_ffPrevTilt ^ (int)player->tiltManualMult) < 0)) {
        swrControl_PlayForceEffect(swrForceEffect_ROLL_LEFT, -1, player->tiltManualMult < 0.0f ? 90 : 270, -1);
    }
    swrControl_ffPrevTilt = currentPlayer_Test->tiltManualMult;
}

// 0x00405ea0
void swrControl_SetDefaultMappings(int device)
{
    int buttonLimit;
    int numPOVs;
    unsigned int axisMask;
    swrControlBinding* bindings;
    swrControlBinding* defaults;

    if (device == swrConfig_DEVICE_JOYSTICK) {
        buttonLimit = swrConfig_joystickNbButtons;
        axisMask = swrControl_joystickAxisMask;
        numPOVs = swrConfig_joystickNbPOVs;
        bindings = swrControl_bindingsJoystick;
        memset(swrControl_bindingsJoystick, 0, sizeof(swrControl_bindingsJoystick));
        Deadzone = swrControl_defaultDeadzone;
        memcpy(swrControl_joystickFlipAxis, swrControl_defaultJoystickFlipAxis, sizeof(swrControl_joystickFlipAxis));
        defaults = swrControl_defaultBindingsJoystick;
        if (numPOVs != 0 && buttonLimit > 4) {
            buttonLimit = SWR_CONTROL_DEFAULT_BUTTONS_WITH_POV;
        }
    } else if (device == swrConfig_DEVICE_MOUSE) {
        numPOVs = 0;
        buttonLimit = swrConfig_mouseNbButtons;
        axisMask = swrControl_mouseAxisMask;
        bindings = swrControl_bindingsMouse;
        memset(swrControl_bindingsMouse, 0, sizeof(swrControl_bindingsMouse));
        flip_x_axis = swrControl_defaultMouseFlipAxis[0];
        flip_y_axis = swrControl_defaultMouseFlipAxis[1];
        flip_z_axis = swrControl_defaultMouseFlipAxis[2];
        defaults = swrControl_defaultBindingsMouse;
    } else if (device == swrConfig_DEVICE_KEYBOARD) {
        numPOVs = 0;
        axisMask = 0;
        bindings = swrControl_bindingsKeyboard;
        defaults = swrControl_defaultBindingsKeyboard;
        buttonLimit = STDCONTROL_NUM_KEYBOARD_KEYS;
        memset(swrControl_bindingsKeyboard, 0, sizeof(swrControl_bindingsKeyboard));
    } else {
        // the EXE walks `device` itself as the default table here and crashes; never reached
        return;
    }
    swrControl_bindingCounts[device] = 0;
    swrControl_axisSensitivity[device] = 1.0f;
    for (; defaults->flags != SWR_CONTROL_BINDING_END; defaults++) {
        if (((defaults->flags & swrControlBinding_FLAG_BUTTON) != 0 && defaults->input < buttonLimit) || ((defaults->flags & swrControlBinding_FLAG_BUTTON) != 0 && defaults->input >= STDCONTROL_JOYSTICK_POV_KEY_BASE && defaults->input <= numPOVs * STDCONTROL_KEYS_PER_POV + (STDCONTROL_JOYSTICK_POV_KEY_BASE - 1)) || ((defaults->flags & swrControlBinding_FLAG_AXIS) != 0 && (axisMask & (1 << defaults->input)) != 0)) {
            bindings[swrControl_bindingCounts[device]] = *defaults;
            swrControl_bindingCounts[device]++;
        }
    }
    bindings[swrControl_bindingCounts[device]].flags = SWR_CONTROL_BINDING_END;
}

// 0x00406470
int stdConfFile_readAndApplyConf(int deviceFilter, char* configName, int useDefaultDir)
{
    char fileName[32] = "control.map";
    char path[256];
    swrControlBinding binding;
    swrControlBinding* table;
    StdConffileArg* arg;
    int device;
    int enabled;
    unsigned int i;

    memset(&binding, 0, sizeof(binding));
    if (useDefaultDir != 0) {
        if (strcmp(configName, "wheel") == 0) {
            sprintf(fileName, "wheel.map");
        } else if (strlen(configName) != 0) {
            sprintf(fileName, "%s", configName);
        }
        sprintf(path, "%s%s%s", rootPathName, ".\\data\\config\\default\\", fileName);
    } else {
        sprintf(path, "%s%s\\%s_%s", ".\\data\\config\\", configName, configName, "control.map");
    }
    if (stdConffile_Open(path) == 0) {
        stdConffile_Close();
        return -1;
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_JOYSTICK) {
        memset(swrControl_joystickFlipAxis, 0, sizeof(swrControl_joystickFlipAxis));
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_MOUSE) {
        flip_x_axis = 0;
        flip_y_axis = 0;
        flip_z_axis = 0;
    }
    swrControl_ClearBindings(deviceFilter);
    // the EXE leaves the current device uninitialized until a line names one
    device = swrConfig_DEVICE_JOYSTICK;
    table = swrControl_bindingsJoystick;
    while (stdConffile_ReadArgs() != 0 && strcmp(stdConffile_g_entry.aArgs[0].argName, "end.") != 0) {
        binding.flags = 0;
        binding.input = 0;
        binding.action = -1;
        for (i = 0; i < (unsigned int)stdConffile_g_entry.numArgs; i++) {
            arg = &stdConffile_g_entry.aArgs[i];
            if (_strcmpi(arg->argName, "JOYSTICK") == 0) {
                device = swrConfig_DEVICE_JOYSTICK;
                table = swrControl_bindingsJoystick;
            } else if (_strcmpi(arg->argName, "MOUSE") == 0) {
                device = swrConfig_DEVICE_MOUSE;
                table = swrControl_bindingsMouse;
            } else if (_strcmpi(arg->argName, "KEYBOARD") == 0) {
                device = swrConfig_DEVICE_KEYBOARD;
                table = swrControl_bindingsKeyboard;
            } else if (_strcmpi(arg->argName, "AXIS") == 0) {
                binding.flags |= swrControlBinding_FLAG_AXIS;
                binding.input = stdConfig_getKeymap_id(arg->argValue, keyMapping0);
            } else if (_strcmpi(arg->argName, "BUTTON") == 0) {
                binding.flags |= swrControlBinding_FLAG_BUTTON;
                binding.input = stdConfig_getKeymap_id(arg->argValue, keyMapping1);
            } else if (_strcmpi(arg->argName, "KEY") == 0) {
                binding.flags |= swrControlBinding_FLAG_BUTTON;
                binding.input = stdConfig_getKeymap_id(arg->argValue, keyMapping2);
            } else if (_strcmpi(arg->argName, "FUNCTION") == 0) {
                if (swrControl_ParseFunctionName(&binding, arg->argValue, 0) == 0) {
                    goto fail;
                }
            } else if (_strcmpi(arg->argName, "AXIS_RANGE") == 0) {
                if (_strcmpi(arg->argValue, "POSITIVE") == 0) {
                    binding.flags |= swrControlBinding_FLAG_POSITIVE;
                } else if (_strcmpi(arg->argValue, "NEGATIVE") == 0) {
                    binding.flags |= swrControlBinding_FLAG_NEGATIVE;
                } else {
                    goto fail;
                }
            } else if ((deviceFilter < 0 || deviceFilter == device) && _strcmpi(arg->argName, "FLIP_AXIS") == 0) {
                if (device == swrConfig_DEVICE_JOYSTICK) {
                    swrControl_joystickFlipAxis[binding.input] = 1;
                } else if (device == swrConfig_DEVICE_MOUSE) {
                    // flip_x/y/z_axis are consecutive: the mouse flip table
                    (&flip_x_axis)[binding.input] = 1;
                } else {
                    goto fail;
                }
            } else if (_strcmpi(arg->argName, "SENSITIVITY") == 0) {
                swrControl_axisSensitivity[device] = (float)atof(arg->argValue);
            } else if (_strcmpi(arg->argName, "DEADZONE") == 0) {
                if (device == swrConfig_DEVICE_JOYSTICK) {
                    Deadzone = (float)atof(arg->argValue);
                }
            } else if (_strcmpi(arg->argName, "ENABLED") == 0) {
                enabled = _strcmpi(arg->argValue, "TRUE") == 0;
                if (device == swrConfig_DEVICE_JOYSTICK) {
                    swrConfig_joystick_enabled = (enabled && joystick_detected != 0) ? 1 : 0;
                } else if (device == swrConfig_DEVICE_MOUSE) {
                    swrConfig_mouse_enabled = (enabled && mouse_detected != 0) ? 1 : 0;
                }
            }
            if (binding.input < 0) {
                goto fail;
            }
        }
        if ((deviceFilter < 0 || deviceFilter == device) && binding.action > -1) {
            table[swrControl_bindingCounts[device]] = binding;
            swrControl_bindingCounts[device]++;
        }
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_KEYBOARD) {
        binding.flags = swrControlBinding_FLAG_BUTTON | swrControlBinding_FLAG_DIGITAL;
        binding.input = DIK_ESCAPE;
        binding.action = SWR_CONTROL_ACTION_ESCAPE;
        swrControl_bindingsKeyboard[swrControl_bindingCounts[swrConfig_DEVICE_KEYBOARD]] = binding;
        swrControl_bindingCounts[swrConfig_DEVICE_KEYBOARD]++;
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_JOYSTICK) {
        swrControl_bindingsJoystick[swrControl_bindingCounts[swrConfig_DEVICE_JOYSTICK]].flags = SWR_CONTROL_BINDING_END;
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_MOUSE) {
        swrControl_bindingsMouse[swrControl_bindingCounts[swrConfig_DEVICE_MOUSE]].flags = SWR_CONTROL_BINDING_END;
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_KEYBOARD) {
        swrControl_bindingsKeyboard[swrControl_bindingCounts[swrConfig_DEVICE_KEYBOARD]].flags = SWR_CONTROL_BINDING_END;
    }
    stdConffile_Close();
    return 1;

fail:
    swrControl_ClearBindings(deviceFilter);
    stdConffile_Close();
    return 0;
}

// 0x00407800
void swrControl_ClearBindings(int deviceFilter)
{
    swrRace_ThrottleInput = 0.0f;
    swrRace_UnkInput = 0.0f;
    swrRace_SteeringInput = 0.0f;
    memset(&swrControl_viewButton, 0, SWR_CONTROL_NUM_ACTIONS * sizeof(float));
    swrRace_PitchInput = 0.0f;
    memset(&swrControl_viewHoldTime, 0, SWR_CONTROL_NUM_ACTIONS * sizeof(float));
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_JOYSTICK) {
        memset(swrControl_bindingsJoystick, 0, sizeof(swrControl_bindingsJoystick));
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_MOUSE) {
        memset(swrControl_bindingsMouse, 0, sizeof(swrControl_bindingsMouse));
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_KEYBOARD) {
        memset(swrControl_bindingsKeyboard, 0, sizeof(swrControl_bindingsKeyboard));
    }
    if (deviceFilter < 0) {
        swrControl_bindingCounts[swrConfig_DEVICE_JOYSTICK] = 0;
        swrControl_bindingCounts[swrConfig_DEVICE_MOUSE] = 0;
        swrControl_bindingCounts[swrConfig_DEVICE_KEYBOARD] = 0;
        return;
    }
    swrControl_bindingCounts[deviceFilter] = 0;
}

// 0x00407d90
char* swrControl_FindKeyName(int id, char otherId)
{
    int i;

    for (i = 0; keyMapping2_0[i].id != -1; i++) {
        if (keyMapping2_0[i].id == id && (char)keyMapping2_0[i].otherId == otherId) {
            return keyMapping2_0[i].name;
        }
    }
    return NULL;
}

// 0x00407f80
int swrControl_PollCancel(int excludeDevice)
{
    int joystick;
    int mouse;
    int keyboard;
    float wheelButton;

    if (excludeDevice == swrConfig_DEVICE_JOYSTICK) {
        joystick = 0;
    } else {
        joystick = stdControl_ReadKey(STDCONTROL_JOYSTICK_KEY_BASE + stdControl_joystickDeviceIndex * STDCONTROL_KEYS_PER_JOYSTICK + 1, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_MOUSE) {
        mouse = 0;
    } else {
        mouse = stdControl_ReadKey(STDCONTROL_MOUSE_KEY_BASE + 1, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_KEYBOARD) {
        keyboard = 0;
    } else {
        keyboard = stdControl_ReadKey(DIK_ESCAPE, NULL);
    }
    // a wheel's brake button also cancels unless the joystick is excluded
    wheelButton = 0.0f;
    if (cifr_deviceIsWheel != 0 && excludeDevice != swrConfig_DEVICE_JOYSTICK) {
        wheelButton = JoystickButtonPressedInput[SWR_CONTROL_ACTION_BRAKE];
    }
    if (joystick == 0 && mouse == 0 && keyboard == 0 && (int)wheelButton == 0) {
        return 0;
    }
    return 1;
}

// 0x00405dd0
unsigned int swrControl_ScanPressedButtons(int device, int returnBitmask)
{
    unsigned int i;
    unsigned int pressed;

    pressed = 0;
    if (device == swrConfig_DEVICE_MOUSE) {
        for (i = 0; (int)i < STDCONTROL_MOUSE_NUM_KEYS; i++) {
            if (stdControl_ReadKey(STDCONTROL_MOUSE_KEY_BASE + i, NULL) != 0) {
                if (returnBitmask == 0) {
                    return i;
                }
                pressed |= 1 << i;
            }
        }
    } else if (device == swrConfig_DEVICE_JOYSTICK) {
        for (i = 0; (int)i < STDCONTROL_KEYS_PER_JOYSTICK; i++) {
            if (stdControl_ReadKey(STDCONTROL_JOYSTICK_KEY_BASE + stdControl_joystickDeviceIndex * STDCONTROL_KEYS_PER_JOYSTICK + i, NULL) != 0) {
                if (returnBitmask == 0) {
                    return i;
                }
                pressed |= 1 << i;
            }
        }
    } else if (device == swrConfig_DEVICE_KEYBOARD) {
        for (i = 0; (int)i < STDCONTROL_NUM_KEYBOARD_KEYS; i++) {
            if (stdControl_ReadKey(i, NULL) != 0 && swrControl_IsKeyStringControl(i) == 0) {
                return i;
            }
        }
    }
    if (returnBitmask == 0 || device == swrConfig_DEVICE_KEYBOARD) {
        pressed = SWR_CONTROL_SCAN_NONE;
    }
    return pressed;
}

// 0x00407700
int swrControl_FindMovedAxis(int device, int* outDirection)
{
    const float* axes;
    const float* axesPrev;
    int numAxes;
    int i;
    int found;
    float best;
    float delta;
    float magnitude;
    double threshold;

    found = -1;
    numAxes = (device != swrConfig_DEVICE_MOUSE ? 3 : 0) + 3;
    axes = swrControl_joystickAxes + device * STDCONTROL_AXES_PER_JOYSTICK;
    axesPrev = swrControl_axesPrev + device * STDCONTROL_AXES_PER_JOYSTICK;
    best = 0.0f;
    for (i = 0; i < numAxes; i++) {
        delta = axesPrev[i] - axes[i];
        if (delta < 0.0f) {
            delta = -delta;
        }
        magnitude = axes[i];
        if (magnitude < 0.0f) {
            magnitude = -magnitude;
        }
        threshold = (device == swrConfig_DEVICE_JOYSTICK) ? SWR_CONTROL_CAPTURE_JOYSTICK_AXIS_MIN : SWR_CONTROL_CAPTURE_AXIS_MIN;
        if (magnitude > threshold && delta > SWR_CONTROL_CAPTURE_AXIS_MIN_DELTA && delta > best) {
            if (axes[i] < 0.0f) {
                *outDirection = -1;
            } else if (axes[i] > 0.0f) {
                *outDirection = 1;
            } else {
                *outDirection = 0;
            }
            found = i;
            best = delta;
        }
    }
    return found;
}

// 0x004079f0
int swrControl_FindMapping(unsigned char* device, int a2, int a3, unsigned char* a4)
{
    swrControlBinding* table;
    unsigned char kindMask;
    unsigned char flags;
    int i;

    // device is a swrConfig_DEVICE, or a binding table pointer
    if (device == (unsigned char*)swrConfig_DEVICE_JOYSTICK) {
        table = swrControl_bindingsJoystick;
    } else if (device == (unsigned char*)swrConfig_DEVICE_MOUSE) {
        table = swrControl_bindingsMouse;
    } else if (device == (unsigned char*)swrConfig_DEVICE_KEYBOARD) {
        table = swrControl_bindingsKeyboard;
    } else {
        table = (swrControlBinding*)device;
    }
    kindMask = a3 != 0 ? swrControlBinding_FLAG_AXIS : swrControlBinding_FLAG_BUTTON;
    for (i = 0; table[i].flags != SWR_CONTROL_BINDING_END; i++) {
        if (table[i].input == a2 && (table[i].flags & kindMask) != 0) {
            flags = table[i].flags;
            *a4 = flags;
            if ((flags & swrControlBinding_FLAG_BUTTON) == 0) {
                *a4 = flags & ~(swrControlBinding_FLAG_POSITIVE | swrControlBinding_FLAG_NEGATIVE);
            }
            *a4 &= ~(swrControlBinding_FLAG_AXIS | swrControlBinding_FLAG_BUTTON);
            return table[i].action;
        }
    }
    return -1;
}

// 0x00407a90
int stdConfig_getKeymap_id(char* name, void* keyTable)
{
    keyMapping* entry;
    char* entryName;

    for (entry = (keyMapping*)keyTable; entry->id != -1; entry++) {
        entryName = stdString_RemoveTEXTTag(entry->name);
        if (_strcmpi(stdString_RemoveTEXTTag(name), entryName) == 0) {
            return entry->id;
        }
    }
    return -1;
}

// 0x00407cd0
int swrControl_ParseFunctionName(void* outEntry, char* name, int mode)
{
    swrControlBinding* binding;
    char* entryName;
    int i;

    binding = (swrControlBinding*)outEntry;
    for (i = 0; keyMapping2_0[i].id != -1; i++) {
        if (mode == 0) {
            entryName = stdString_RemoveTEXTTag(keyMapping2_0[i].name);
            if (strcmpi(swrText_Translate(name), entryName) == 0) {
                break;
            }
        }
        if (mode == 1) {
            entryName = swrText_Translate(keyMapping2_0[i].name);
            if (strcmpi(swrText_Translate(name), entryName) == 0) {
                break;
            }
        }
    }
    if (keyMapping2_0[i].id == -1) {
        return 0;
    }
    binding->action = keyMapping2_0[i].id;
    binding->flags |= (unsigned char)keyMapping2_0[i].otherId;
    return 1;
}

// 0x00407de0
void swrControl_SelectSavedJoystick(void)
{
    char savedGuid[256];
    OLECHAR wideGuid[128];
    char guid[256];
    const unsigned char* src;
    unsigned char c;
    size_t len;
    unsigned int i;

    stdControl_joystickDeviceIndex = 0;
    if (wuRegistry_GetString("JoystickGUID", savedGuid, sizeof(savedGuid), wuRegistry_lpClass) != 0) {
        return;
    }
    for (i = 0; i < (unsigned int)stdControl_numJoystickDevices; i++) {
        // faithful: cchMax is the buffer's byte size, not its OLECHAR count
        StringFromGUID2((GUID*)((char*)&DirectInputJoystickGUID + i * STDCONTROL_JOYSTICK_RECORD_SIZE), wideGuid, sizeof(wideGuid));
        // narrows by walking the UTF-16 bytes and dropping the zero ones; stops after '}'
        len = 0;
        src = (const unsigned char*)wideGuid;
        do {
            if (*src != '\0') {
                guid[len++] = (char)*src;
            }
            c = *src++;
        } while (c != '}');
        if (strncmp(savedGuid, guid, len) == 0) {
            stdControl_joystickDeviceIndex = i;
            return;
        }
    }
}

// 0x00407ea0
int swrControl_PollAccept(int excludeDevice)
{
    int joystick;
    int mouse;
    int keyboard;
    int wheel;

    if (excludeDevice == swrConfig_DEVICE_JOYSTICK) {
        joystick = 0;
    } else {
        joystick = stdControl_ReadKey(STDCONTROL_JOYSTICK_KEY_BASE + stdControl_joystickDeviceIndex * STDCONTROL_KEYS_PER_JOYSTICK, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_MOUSE) {
        mouse = 0;
    } else {
        mouse = stdControl_ReadKey(STDCONTROL_MOUSE_KEY_BASE, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_KEYBOARD) {
        keyboard = 0;
    } else if (stdControl_ReadKey(DIK_RETURN, NULL) != 0 || stdControl_ReadKey(DIK_NUMPADENTER, NULL) != 0) {
        keyboard = 1;
    } else if (swrUI_GetMenuRoot_Maybe() == 0 && stdControl_ReadKey(DIK_SPACE, NULL) != 0) {
        // Space only accepts while no text entry is active
        keyboard = 1;
    } else {
        keyboard = 0;
    }
    // a wheel's throttle axis also accepts unless the joystick is excluded
    if (cifr_deviceIsWheel != 0 && excludeDevice != swrConfig_DEVICE_JOYSTICK && JoystickAxisInput[0] > SWR_CONTROL_WHEEL_ACCEPT_AXIS_MIN) {
        wheel = 1;
    } else {
        wheel = 0;
    }
    if (joystick == 0 && mouse == 0 && keyboard == 0 && wheel == 0) {
        return 0;
    }
    return 1;
}

// 0x00408020
int swrControl_IsKeyStringControl(int controlId)
{
    int i;

    for (i = 0; i < SWR_CONTROL_NUM_RESERVED_KEYS; i++) {
        if (controlId == swrConfig_aControlKeyStrings[i]) {
            return 1;
        }
    }
    return 0;
}

// 0x00408040
int stdControl_isAxisAboveDeadzone(int axisId, int direction, float value, float threshold)
{
    if (axisId >= 0) {
        value = stdControl_ReadAxis(axisId);
    }
    if (direction != 0 && (value < 0.0f ? -1 : 1) != direction) {
        return 0;
    }
    if (value < 0.0f) {
        value = -value;
    }
    return value > threshold ? 1 : 0;
}

// 0x00408120
void swrControl_SnapshotKeyboard(void)
{
    int i;
    int count;

    for (i = 0; i < STDCONTROL_NUM_KEYBOARD_KEYS; i++) {
        stdControl_KeyPressed_unused[i] = (char)stdControl_ReadKey(i, NULL);
    }
    EnterCriticalSection(&WindowsInputCritSection);
    stdControlInputItemCount = WindowsInputStackSize;
    count = WindowsInputStackSize;
    for (i = 0; i < count; i++) {
        stdControlInputItems[i].virtualKeyCode = WindowsInputStack[i].virtualKeyCode;
        stdControlInputItems[i].keystrokeMessageFlags = WindowsInputStack[i].keystrokeMessageFlags | (WindowsInputStack[i].keydown != 0 ? stdControlInputItem_FLAG_KEYDOWN : 0);
    }
    WindowsInputStackSize = 0;
    LeaveCriticalSection(&WindowsInputCritSection);
}

// 0x004081c0
int swrControl_ClearPollState_Maybe(void)
{
    int* state;
    int i;

    state = &swrUI_inputChangeFlags;
    for (i = 0; i < SWR_UI_INPUT_STATE_DWORDS; i++) {
        state[i] = 0;
    }
    return 1;
}

// 0x00404b10
int swrControl_Initialize(void)
{
    int i;

    if (stdControl_Startup() != 0) {
        return 1;
    }
    if (stdControl_Open() != 0) {
        return 1;
    }
    swrControl_SelectSavedJoystick();
    swrConfig_joystickNbPOVs = 0;
    swrConfig_joystickNbButtons = 0;
    swrControl_joystickAxisMask = 0;
    swrConfig_joystickNbAxis = 0;
    for (i = 0; i < STDCONTROL_AXES_PER_JOYSTICK; i++) {
        if (stdControl_EnableAxis(stdControl_joystickDeviceIndex * STDCONTROL_AXES_PER_JOYSTICK + i) != 0) {
            swrControl_joystickAxisMask |= 1 << i;
            swrConfig_joystickNbAxis++;
        }
    }
    if (swrConfig_joystickNbAxis == 0) {
        joystick_detected = 0;
        swrConfig_joystick_enabled = 0;
    } else {
        swrConfig_joystickNbButtons = *(DWORD*)((char*)&stdControlJoystickCapsButtons + stdControl_joystickDeviceIndex * STDCONTROL_JOYSTICK_RECORD_SIZE);
        swrConfig_joystickNbPOVs = *(DWORD*)((char*)&stdControlJoystickCapsPOVs + stdControl_joystickDeviceIndex * STDCONTROL_JOYSTICK_RECORD_SIZE);
    }
    swrConfig_mouseNbButtons = 0;
    swrControl_mouseAxisMask = 0;
    swrConfig_mouseNbAxis = 0;
    for (i = 0; i < STDCONTROL_MOUSE_NUM_AXES; i++) {
        if (stdControl_EnableAxis(STDCONTROL_MOUSE_AXIS_BASE + i) != 0) {
            swrControl_mouseAxisMask |= 1 << i;
            swrConfig_mouseNbAxis++;
        }
    }
    if (swrConfig_mouseNbAxis == 0) {
        mouse_detected = 0;
        swrConfig_mouse_enabled = 0;
    } else {
        swrConfig_mouseNbButtons = stdControlMouseCapsButtons;
    }
    InitializeCriticalSection(&WindowsInputCritSection);
    memset(swrControl_buttonHeldPrev, 0, SWR_CONTROL_NUM_ACTIONS);
    WindowsInputStackSize = 0;
    // faithful: byte store into the int flag
    *(unsigned char*)&enableWindowInput = 1;
    swrControl_cancelHeldPrev = 0;
    swrControl_acceptHeldPrev = 0;
    swrControl_cancelUpPrev = 1;
    swrControl_acceptUpPrev = 1;
    swrControl_menuAcceptHeldPrev = 0;
    swrControl_ClearBindings(-1);
    swrControl_StopAllForceEffects(0);
    swrControl_LoadForceEffects(0);
    swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
    if (swrConfig_ReadForceFeedbackConfig("current") < 0) {
        swrConfig_SetDefaultForce();
        swrConfig_WriteForceFeedbackConfig("current");
    }
    if (stdConfFile_readAndApplyConf(-1, wuRegistry_lpClass, 1) < 0) {
        swrControl_SetDefaultMappings(swrConfig_DEVICE_JOYSTICK);
        swrControl_SetDefaultMappings(swrConfig_DEVICE_MOUSE);
        swrControl_SetDefaultMappings(swrConfig_DEVICE_KEYBOARD);
    }
    if (cifr_deviceIsWheel != 0) {
        stdConfFile_readAndApplyConf(swrConfig_DEVICE_JOYSTICK, "wheel", 1);
        swrControl_defaultDeadzone = 0.0f;
        Deadzone = 0.0f;
    }
    if (stdConfFile_readAndApplyConf(-1, "current", 0) < 0) {
        swrConfig_WriteMappings("current");
    }
    swrControl_ApplyAxisConfig(swrConfig_DEVICE_JOYSTICK);
    swrControl_ApplyAxisConfig(swrConfig_DEVICE_MOUSE);
    return 0;
}

// 0x00406a50
int swrControl_FormatBinding(int device, int action, int flagsMask, unsigned char direction, int index, char* out, unsigned int* outControl)
{
    swrControlBinding* table;
    int numButtons;
    int numPOVs;
    unsigned int axisMask;
    int count;
    char sign[5];
    unsigned char mask;
    unsigned char flags;
    int input;
    int isButton;
    int valid;

    sign[0] = wuRegistry_lpClass[0];
    count = 0;
    memset(&sign[1], 0, 4);
    if (index < 0) {
        index = -index;
    }
    *outControl = (unsigned int)-1;
    sprintf(out, "---");
    if (device == swrConfig_DEVICE_JOYSTICK) {
        numButtons = swrConfig_joystickNbButtons;
        numPOVs = swrConfig_joystickNbPOVs;
        axisMask = swrControl_joystickAxisMask;
        table = swrControl_bindingsJoystick;
    } else if (device == swrConfig_DEVICE_MOUSE) {
        numButtons = swrConfig_mouseNbButtons;
        numPOVs = 0;
        axisMask = swrControl_mouseAxisMask;
        table = swrControl_bindingsMouse;
    } else if (device == swrConfig_DEVICE_KEYBOARD) {
        numButtons = STDCONTROL_NUM_KEYBOARD_KEYS;
        numPOVs = 0;
        axisMask = 0;
        table = swrControl_bindingsKeyboard;
    } else {
        // faithful: a custom table comes in through flagsMask, whose low byte is then also the mask.
        // The original leaves the limits uninitialized here; zero them.
        numButtons = 0;
        numPOVs = 0;
        axisMask = 0;
        table = (swrControlBinding*)flagsMask;
    }
    mask = (unsigned char)flagsMask;
    isButton = mask & swrControlBinding_FLAG_BUTTON;
    for (; table->flags != SWR_CONTROL_BINDING_END; table++) {
        flags = table->flags;
        input = table->input;
        if (table->action != action || (flags & mask) != mask) {
            continue;
        }
        if (isButton && (flags & SWR_CONTROL_BINDING_DIRECTION_MASK) != direction) {
            continue;
        }
        if ((flags & swrControlBinding_FLAG_BUTTON) != 0 && input < numButtons) {
            valid = 1;
        } else if ((flags & swrControlBinding_FLAG_BUTTON) != 0 && input >= STDCONTROL_JOYSTICK_POV_KEY_BASE && input <= numPOVs * STDCONTROL_KEYS_PER_POV + STDCONTROL_JOYSTICK_POV_KEY_BASE - 1) {
            valid = 1;
        } else if ((flags & swrControlBinding_FLAG_AXIS) != 0 && (axisMask & (1 << (input & 0x1f))) != 0) { // x86 SHL count wraps at 32
            valid = 1;
        } else {
            valid = 0;
        }
        if (!valid) {
            continue;
        }
        count++;
        if (index != count) {
            continue;
        }
        *outControl = input;
        if (device == swrConfig_DEVICE_KEYBOARD) {
            sprintf(out, "%s", swrText_Translate(swrConfig_ControlToString(input, NULL)));
        } else if (isButton) {
            if (input < STDCONTROL_JOYSTICK_POV_KEY_BASE) {
                char* name = swrText_Translate(swrConfig_ControlToString(input, keyMapping1));
                sprintf(out, swrText_Translate("/MONDOTEXT_H_0213/BUTTON %s"), name);
            } else {
                sprintf(out, "%s", swrText_Translate(swrConfig_ControlToString(input, keyMapping1)));
            }
        } else {
            char* name;
            if ((flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                sprintf(sign, "+");
            } else if ((flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                sprintf(sign, "-");
            }
            name = swrText_Translate(swrConfig_ControlToString(input, keyMapping0));
            sprintf(out, swrText_Translate("/MONDOTEXT_H_0216/%s%s AXIS"), sign, name);
        }
    }
    return count;
}

// 0x00407630
void swrControl_ApplyAxisConfig(int axis)
{
    char text[64];
    unsigned int steerAxis;

    if (swrControl_FormatBinding(axis, SWR_CONTROL_AXIS_STEER, swrControlBinding_FLAG_ANALOG | swrControlBinding_FLAG_AXIS, 0, 1, text, &steerAxis) == 0) {
        return;
    }
    // axis is the device here: joystick or mouse
    if (axis == swrConfig_DEVICE_MOUSE) {
        if (steerAxis == 0) {
            stdControl_SetMouseRange(1.0f / swrControl_axisSensitivity[swrConfig_DEVICE_MOUSE], 1.0f);
        } else if (steerAxis == 1) {
            stdControl_SetMouseRange(1.0f, 1.0f / swrControl_axisSensitivity[swrConfig_DEVICE_MOUSE]);
        }
        return;
    }
    stdControl_SetAxisDeadzone(Deadzone, stdControl_joystickDeviceIndex, steerAxis);
    {
        float sensitivity = swrControl_axisSensitivity[axis];
        int i;
        for (i = 0; i < STDCONTROL_AXES_PER_JOYSTICK; i++) {
            swrControl_joystickAxisScale[i] = 1.0f;
        }
        swrControl_joystickAxisScale[steerAxis] = sensitivity;
    }
}
