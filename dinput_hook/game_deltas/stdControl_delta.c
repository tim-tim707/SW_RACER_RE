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

#include <GLFW/glfw3.h>
#include <stdio.h>

#include <Main/swrControl.h>

extern FILE *hook_log;

// After a rescan creates the device, swrControl still has the joystick latched off:
// swrControl_Initialize set joystick_detected / swrConfig_joystick_enabled = 0 at startup
// because no pad was present. Re-run its joystick detect/enable block so the new device is
// actually read -- select the saved device, enable its 6 axes, and (per the hot-plug UX)
// force the pad on -- without re-running all of swrControl_Initialize (which would reset
// bindings and bails early once stdControl is already started).
static void stdControl_RefreshJoystickConfig(void) {
    ((void (*) (void)) swrControl_SelectSavedJoystick_ADDR)();
    swrConfig_joystickNbAxis = 0;
    for (int i = 0; i < 6; i++) {
        if (((int (*) (int)) stdControl_EnableAxis_ADDR)(i + stdControl_joystickDeviceIndex * 6))
            swrConfig_joystickNbAxis++;
    }
    if (swrConfig_joystickNbAxis > 0) {
        joystick_detected = 1;
        swrConfig_joystick_enabled = 1;
    }
    ((void (*) (int)) swrControl_ApplyAxisConfig_ADDR)(0);
    ((void (*) (int)) swrControl_ApplyAxisConfig_ADDR)(1);
}

// Re-enumerate + re-init the DirectInput joysticks so a controller plugged in after startup
// becomes usable. Known limitation: this rebuilds all joysticks (re-creating existing ones,
// leaking the old device objects per event); hot-plug events are rare, so a follow-up should
// dedupe by guidInstance and init only the newly-arrived device so an active pad isn't disrupted.
static void stdControl_RescanJoysticks(void) {
    if (iDirectInputA_ptr == NULL)
        return;
    const int before = stdControl_numJoystickDevices;
    stdControl_numJoystickDevices = 0;
    IDirectInputA *di = iDirectInputA_ptr;
    HRESULT hr = di->lpVtbl->EnumDevices(di, DIDEVTYPE_JOYSTICK,
                                         (LPDIENUMDEVICESCALLBACKA) DirectInput_EnumDevice_Callback_ADDR,
                                         NULL, DIEDFL_ATTACHEDONLY);
    const int enumerated = stdControl_numJoystickDevices;
    ((void (*)(void)) stdControl_InitJoysticks_ADDR)();
    stdControl_RefreshJoystickConfig();
    fprintf(hook_log,
            "[hotplug] rescan: enum hr=0x%08lx joysticks before=%d after=%d; nbAxis=%d enabled=%d\n",
            (unsigned long) hr, before, enumerated, swrConfig_joystickNbAxis,
            swrConfig_joystick_enabled);
    fflush(hook_log);
}

// GLFW fires this on the main thread during glfwPollEvents (called every frame in the
// master loop, Window_delta.c) on a joystick connect/disconnect.
static void stdControl_JoystickHotplug(int jid, int event) {
    fprintf(hook_log, "[hotplug] glfw joystick jid=%d event=0x%x\n", jid, event);
    fflush(hook_log);
    stdControl_RescanJoysticks();
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
    LPDIENUMDEVICESCALLBACKA cb =
        (LPDIENUMDEVICESCALLBACKA) DirectInput_EnumDevice_Callback_ADDR;
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_KEYBOARD, cb, NULL, DIEDFL_ATTACHEDONLY);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_MOUSE, cb, NULL, DIEDFL_ATTACHEDONLY);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_JOYSTICK, cb, NULL, DIEDFL_ATTACHEDONLY);

    ((void (*)(void)) stdControl_InitKeyboard_ADDR)();
    ((void (*)(void)) stdControl_InitJoysticks_ADDR)();
    ((void (*)(void)) stdControl_InitMouse_ADDR)();
    ((void (*)(void)) stdControl_Reset_ADDR)();

    // Pick up controllers hot-plugged after startup.
    glfwSetJoystickCallback(stdControl_JoystickHotplug);

    stdControl_g_bStartup = 1;
    return 0;
}
#endif
