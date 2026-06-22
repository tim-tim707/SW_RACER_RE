#include "stdControl_delta.h"

#include "globals.h"

#include <macros.h>

#if ENABLE_GLFW_INPUT_HANDLING
#include <GLFW/glfw3.h>

// 0x00485360
int stdControl_Startup_delta(void) {
    stdControl_g_bStartup = 1;
    return 0;
}

// 0x00485630
void stdControl_ReadControls_delta(void) {
    if (!stdControl_bControlsActive)
        return;

    memset(stdControl_aKeyIdleTimes, 0, sizeof(stdControl_aKeyIdleTimes));
    memset(stdControl_g_aKeyPressCounter, 0, sizeof(stdControl_g_aKeyPressCounter));
    stdControl_bControlsIdle = 1;
    stdControl_curReadTime = timeGetTime();
    stdControl_readDeltaTime = stdControl_curReadTime - stdControl_lastReadTime;
    memset(stdControl_aAxisPos, 0, 0xF0u);
    sithControl_secFPS = 1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime);
    sithControl_msecFPS =
        1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime) * 1000.0;
    glfwPollEvents();
    stdControl_lastReadTime = stdControl_curReadTime;
}

// 0x00485a30
int stdControl_SetActivation_delta(int bActive) {
    stdControl_bControlsActive = bActive;

    return 0;
}
#else
#include <Win95/DirectX.h>
#include <Win95/Window.h>
#include <Platform/stdControl.h>

#include <stdio.h>

extern FILE *hook_log;

// DIAGNOSTIC (G502 repro build, remove before any PR): log every device DirectInput hands
// us per class (name + dwDevType), then delegate to the original game callback that stores
// it. If startup faults, the last logged device is the offender.
static WINBOOL __stdcall diag_enum_cb(LPCDIDEVICEINSTANCEA inst, LPVOID ref) {
    fprintf(hook_log, "[input]   enum dev: dwDevType=0x%08lx name='%s' product='%s'\n",
            (unsigned long) inst->dwDevType, inst->tszInstanceName, inst->tszProductName);
    fflush(hook_log);
    return ((LPDIENUMDEVICESCALLBACKA) DirectInput_EnumDevice_Callback_ADDR)(inst, ref);
}

// 0x00485360
// The original passes dwDevType=0 to EnumDevices, so DirectInput walks every attached
// device -- including non-game HID devices (e.g. some USB headsets). Enumerating one of
// those crashes the game on launch (a long-standing vanilla bug; this path was never
// reimplemented). Enumerate only the device classes the game actually uses
// (keyboard/mouse/joystick) so unrelated HID devices are never touched. The sub-steps
// are HANG stubs in src, so they call the original game functions via their _ADDR.
int stdControl_Startup_delta(void) {
    if (stdControl_g_bStartup)
        return 1;

    HINSTANCE hinst = ((HINSTANCE(*)(void)) Window_GetHINSTANCE_ADDR)();
    // DirectInputCreateA is __stdcall (callee cleans the stack); the cast must match or
    // the stack is corrupted on return.
    HRESULT hr = ((HRESULT(__stdcall *)(HINSTANCE, DWORD, LPDIRECTINPUTA *, LPUNKNOWN))
                      DirectX_DirectInputCreateA_ADDR)(hinst, 0x0500 /* DInput v5 */,
                                                       &iDirectInputA_ptr, NULL);
    if (hr != S_OK)
        return 1;

    DirectInputNbKeyboard = 0;
    DirectInputNbMouses = 0;
    stdControl_numJoystickDevices = 0;

    IDirectInputA *di = iDirectInputA_ptr;
    LPDIENUMDEVICESCALLBACKA cb = diag_enum_cb;
    fprintf(hook_log, "[input] enum KEYBOARD\n");
    fflush(hook_log);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_KEYBOARD, cb, NULL, DIEDFL_ATTACHEDONLY);
    fprintf(hook_log, "[input] enum MOUSE\n");
    fflush(hook_log);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_MOUSE, cb, NULL, DIEDFL_ATTACHEDONLY);
    fprintf(hook_log, "[input] enum JOYSTICK\n");
    fflush(hook_log);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_JOYSTICK, cb, NULL, DIEDFL_ATTACHEDONLY);
    fprintf(hook_log, "[input] enum done: kbd=%d mouse=%d joy=%d\n", DirectInputNbKeyboard,
            DirectInputNbMouses, stdControl_numJoystickDevices);
    fflush(hook_log);

    fprintf(hook_log, "[input] InitKeyboard\n");
    fflush(hook_log);
    ((void (*)(void)) stdControl_InitKeyboard_ADDR)();
    fprintf(hook_log, "[input] InitJoysticks\n");
    fflush(hook_log);
    ((void (*)(void)) stdControl_InitJoysticks_ADDR)();
    fprintf(hook_log, "[input] InitMouse\n");
    fflush(hook_log);
    ((void (*)(void)) stdControl_InitMouse_ADDR)();
    fprintf(hook_log, "[input] Reset\n");
    fflush(hook_log);
    ((void (*)(void)) stdControl_Reset_ADDR)();
    fprintf(hook_log, "[input] stdControl_Startup done\n");
    fflush(hook_log);

    stdControl_g_bStartup = 1;
    return 0;
}
#endif
