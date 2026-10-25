#include "stdControl_delta.h"

#include "globals.h"

#include <engine_config.h>
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
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <Main/swrControl.h>

extern FILE *hook_log;

// Per-index product names of the enumerated joysticks, captured during enumeration for
// the input-diagnostics device picker (the game stores device records but no readily
// readable name table). Parallel to the game's joystick device array.
#define STDCONTROL_MAX_DIAG_JOY 8
static char g_joyDiagNames[STDCONTROL_MAX_DIAG_JOY][64];

// DualShock 4 / DualSense pads enumerate as raw HID with Sony's own button and axis order
// (Square=0, Cross=1, triggers on Rx/Ry resting at their minimum), but the game's default
// bindings and the shipped control map assume an Xbox 360 pad's DirectInput layout. On a Sony
// pad that turns Square into confirm/thrust and pins the RX roll binding on while L2 rests.
// When enabled, their polled state is rewritten into the Xbox layout before the game sees it.
#define SONY_USB_VID (0x054C)
static const WORD sony_pad_pids[] = {
    0x05C4, // DualShock 4 (v1)
    0x09CC, // DualShock 4 (v2)
    0x0BA0, // DualShock 4 USB wireless adapter
    0x0CE6, // DualSense
    0x0DF2, // DualSense Edge
};
#define DI_DEFAULT_AXIS_MAX (0xFFFF)// DirectInput's axis range when a device reports none
static int g_joyIsSony[STDCONTROL_MAX_DIAG_JOY];
static WORD g_joyPid[STDCONTROL_MAX_DIAG_JOY];
int stdControl_sonyLayoutEnabled = 1;

// Product name of enumerated joystick `index` ("" if out of range). For the overlay UI.
const char *stdControl_GetJoystickName(int index) {
    if (index < 0 || index >= STDCONTROL_MAX_DIAG_JOY)
        return "";
    return g_joyDiagNames[index];
}

int stdControl_IsSonyJoystick(int index) {
    if (index < 0 || index >= STDCONTROL_MAX_DIAG_JOY)
        return 0;
    return g_joyIsSony[index];
}

// USB product id of the active joystick if it is a Sony pad, else 0. For the HID rumble path.
int stdControl_GetActiveSonyPid(void) {
    const int active = stdControl_joystickDeviceIndex;
    if (active >= stdControl_numJoystickDevices || !stdControl_IsSonyJoystick(active))
        return 0;
    return g_joyPid[active];
}

// For HID devices DirectInput packs the USB ids into guidProduct.Data1 as MAKELONG(vid, pid).
static int stdControl_IsSonyProduct(const GUID *guidProduct) {
    if (LOWORD(guidProduct->Data1) != SONY_USB_VID)
        return 0;
    for (size_t i = 0; i < sizeof(sony_pad_pids) / sizeof(sony_pad_pids[0]); i++) {
        if (HIWORD(guidProduct->Data1) == sony_pad_pids[i])
            return 1;
    }
    return 0;
}

// EnumDevices callback that records each joystick's product name, then chains to the
// game's own callback. The original appends the device and bumps the count, so the
// current count is the slot this device will take -- capture before chaining.
static BOOL CALLBACK stdControl_EnumJoystickName_cb(LPCDIDEVICEINSTANCEA lpddi, LPVOID pvRef) {
    const int idx = stdControl_numJoystickDevices;
    if (idx >= 0 && idx < STDCONTROL_MAX_DIAG_JOY) {
        strncpy(g_joyDiagNames[idx], lpddi->tszProductName, sizeof(g_joyDiagNames[idx]) - 1);
        g_joyDiagNames[idx][sizeof(g_joyDiagNames[idx]) - 1] = '\0';
        g_joyIsSony[idx] = stdControl_IsSonyProduct(&lpddi->guidProduct);
        g_joyPid[idx] = HIWORD(lpddi->guidProduct.Data1);
    }
    return ((LPDIENUMDEVICESCALLBACKA) DirectInput_EnumDevice_Callback_ADDR)(lpddi, pvRef);
}

static LPDIRECTINPUTDEVICEA stdControl_GetJoystickDevice(int index) {
    return (&stdControlJoystickDevice)[index * STDCONTROL_JOYSTICK_RECORD_DWORDS];
}

// Xbox 360 button slot <- Sony button index. Face buttons by position (Cross where A sits),
// Create/Options where Back/Start sit, and the digital L2/R2 clicks moved past the Xbox range.
static const BYTE sony_to_xbox_button[16] = {1, 2, 0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 6, 7, 14, 15};

// lZ, lRx, lRy, lRz; queried lazily per pad since a device can report any range.
typedef struct SonyAxisRanges {
    int valid;
    LONG min[4];
    LONG max[4];
} SonyAxisRanges;
static SonyAxisRanges g_sonyRanges[STDCONTROL_MAX_DIAG_JOY];

static HRESULT(__stdcall *g_origGetDeviceState)(IDirectInputDeviceA *This, DWORD cbData,
                                                LPVOID lpvData);

static void stdControl_QuerySonyRanges(IDirectInputDeviceA *dev, SonyAxisRanges *r) {
    for (int i = 0; i < 4; i++) {
        DIPROPRANGE range;
        range.diph.dwSize = sizeof(range);
        range.diph.dwHeaderSize = sizeof(range.diph);
        range.diph.dwObj = offsetof(DIJOYSTATE, lZ) + i * sizeof(LONG);
        range.diph.dwHow = DIPH_BYOFFSET;
        if (dev->lpVtbl->GetProperty(dev, DIPROP_RANGE, &range.diph) == S_OK &&
            range.lMax > range.lMin) {
            r->min[i] = range.lMin;
            r->max[i] = range.lMax;
        } else {
            r->min[i] = 0;
            r->max[i] = DI_DEFAULT_AXIS_MAX;
        }
    }
    r->valid = 1;
}

static LONG stdControl_RemapAxis(LONG v, LONG srcMin, LONG srcMax, LONG dstMin, LONG dstMax) {
    return dstMin + (LONG) ((double) (v - srcMin) * (dstMax - dstMin) / (srcMax - srcMin));
}

static void stdControl_SonyToXboxLayout(IDirectInputDeviceA *dev, int index, DIJOYSTATE *s) {
    SonyAxisRanges *r = &g_sonyRanges[index];
    if (!r->valid)
        stdControl_QuerySonyRanges(dev, r);
    enum { Z, RX, RY, RZ };

    BYTE sonyButtons[16];
    memcpy(sonyButtons, s->rgbButtons, sizeof(sonyButtons));
    for (int i = 0; i < 16; i++)
        s->rgbButtons[i] = sonyButtons[sony_to_xbox_button[i]];

    // Xbox 360 over DirectInput: right stick on Rx/Ry, both triggers sharing Z
    // (LT pushes above centre, RT below, centred at rest).
    const LONG rightX = s->lZ;
    const LONG rightY = s->lRz;
    const double lt = (double) (s->lRx - r->min[RX]) / (r->max[RX] - r->min[RX]);
    const double rt = (double) (s->lRy - r->min[RY]) / (r->max[RY] - r->min[RY]);
    const double zHalf = (r->max[Z] - r->min[Z]) / 2.0;
    s->lZ = (LONG) (r->min[Z] + zHalf + (lt - rt) * zHalf);
    s->lRx = stdControl_RemapAxis(rightX, r->min[Z], r->max[Z], r->min[RX], r->max[RX]);
    s->lRy = stdControl_RemapAxis(rightY, r->min[RZ], r->max[RZ], r->min[RY], r->max[RY]);
    s->lRz = r->min[RZ] + (r->max[RZ] - r->min[RZ]) / 2;
}

// Joysticks whose GetDeviceState goes through the hook below, and which of them delivered a
// state during the current stdControl_ReadControls (cleared by stdControl_NeutralizeLostJoysticks).
static int g_joyHooked[STDCONTROL_MAX_DIAG_JOY];
static int g_joyReadThisFrame[STDCONTROL_MAX_DIAG_JOY];

// Last Xbox-layout buttons + hat of the active Sony pad, for the gamepad-nav bridge (which
// otherwise only sees XInput pads, so START/BACK/D-pad do nothing on a DualShock/DualSense).
static BYTE g_sonyNavButtons[16];
static DWORD g_sonyNavPov;
static int g_sonyNavValid;

int stdControl_GetSonyNavState(unsigned char buttons[16], unsigned long *pov) {
    const int active = stdControl_joystickDeviceIndex;
    if (!g_sonyNavValid || !stdControl_sonyLayoutEnabled || !stdControl_IsSonyJoystick(active))
        return 0;
    memcpy(buttons, g_sonyNavButtons, sizeof(g_sonyNavButtons));
    *pov = g_sonyNavPov;
    return 1;
}

// Shared by every DirectInput device (they share one vtable), so match `This` to a joystick.
static HRESULT __stdcall stdControl_GetDeviceState_hook(IDirectInputDeviceA *This, DWORD cbData,
                                                        LPVOID lpvData) {
    const HRESULT hr = g_origGetDeviceState(This, cbData, lpvData);
    if (hr < 0 || cbData < sizeof(DIJOYSTATE))
        return hr;
    for (int i = 0; i < stdControl_numJoystickDevices && i < STDCONTROL_MAX_DIAG_JOY; i++) {
        if (stdControl_GetJoystickDevice(i) != This)
            continue;
        g_joyReadThisFrame[i] = 1;
        if (g_joyIsSony[i] && stdControl_sonyLayoutEnabled) {
            DIJOYSTATE *state = (DIJOYSTATE *) lpvData;
            stdControl_SonyToXboxLayout(This, i, state);
            if (i == stdControl_joystickDeviceIndex) {
                memcpy(g_sonyNavButtons, state->rgbButtons, sizeof(g_sonyNavButtons));
                g_sonyNavPov = state->rgdwPOV[0];
                g_sonyNavValid = 1;
            }
        }
        break;
    }
    return hr;
}

// Route the joysticks' GetDeviceState through the hook. Run after the joysticks are (re)created;
// the vtable slot is patched once and later calls only refresh the per-index bookkeeping.
static void stdControl_InstallJoystickStateHook(void) {
    memset(g_sonyRanges, 0, sizeof(g_sonyRanges));
    memset(g_joyHooked, 0, sizeof(g_joyHooked));
    memset(g_joyReadThisFrame, 0, sizeof(g_joyReadThisFrame));
    g_sonyNavValid = 0;
    for (int i = 0; i < stdControl_numJoystickDevices && i < STDCONTROL_MAX_DIAG_JOY; i++) {
        IDirectInputDeviceA *dev = stdControl_GetJoystickDevice(i);
        if (dev == NULL)
            continue;
        IDirectInputDeviceAVtbl *vtbl = dev->lpVtbl;
        if (vtbl->GetDeviceState != stdControl_GetDeviceState_hook) {
            if (g_origGetDeviceState != NULL && g_origGetDeviceState != vtbl->GetDeviceState) {
                fprintf(hook_log, "[joystick] %d has an unexpected vtable; state hook skipped\n", i);
                continue;
            }
            DWORD oldProtect;
            if (!VirtualProtect(&vtbl->GetDeviceState, sizeof(vtbl->GetDeviceState),
                                PAGE_READWRITE, &oldProtect))
                continue;
            g_origGetDeviceState = vtbl->GetDeviceState;
            vtbl->GetDeviceState = stdControl_GetDeviceState_hook;
            VirtualProtect(&vtbl->GetDeviceState, sizeof(vtbl->GetDeviceState), oldProtect,
                           &oldProtect);
        }
        g_joyHooked[i] = 1;
        if (g_joyIsSony[i])
            fprintf(hook_log, "[sony] joystick %d (%s): Xbox layout rewrite installed\n", i,
                    g_joyDiagNames[i]);
    }
    fflush(hook_log);
}

// stdControl_ReadControls zeroes stdControl_aAxisPos every frame and only a successful device read
// refills it; raw 0 is the bottom of the range, so an unplugged pad reads as every axis at full
// deflection (full analog throttle, roll, pitch) with its last-held buttons stuck down. Called
// right after ReadControls: park every joystick slot not read this frame at centre, all released.
void stdControl_NeutralizeLostJoysticks(void) {
    const int nbSlots = STDCONTROL_NUM_AXIS_SLOTS / STDCONTROL_AXES_PER_JOYSTICK;
    for (int i = 0; i < nbSlots && i < STDCONTROL_MAX_DIAG_JOY; i++) {
        const int present = i < stdControl_numJoystickDevices;
        const int lost = present ? g_joyHooked[i] && !g_joyReadThisFrame[i] : 1;
        g_joyReadThisFrame[i] = 0;
        if (!lost)
            continue;
        if (i == stdControl_joystickDeviceIndex)
            g_sonyNavValid = 0;
        for (int k = 0; k < STDCONTROL_AXES_PER_JOYSTICK; k++) {
            const int axis = i * STDCONTROL_AXES_PER_JOYSTICK + k;
            stdControl_aAxisPos[axis] = stdControl_aAxes[axis].xOffset;
        }
        memset(&stdControl_aKeyInfos[STDCONTROL_JOYSTICK_KEY_BASE + i * STDCONTROL_KEYS_PER_JOYSTICK],
               0, STDCONTROL_KEYS_PER_JOYSTICK * sizeof(stdControl_aKeyInfos[0]));
    }
}

// Make joystick `index` the active device: point the device index at it, enable its 6
// axes, force the pad on, and push axis config. Every step keys off
// stdControl_joystickDeviceIndex (the EnableAxis offset, SetAxisDeadzone, and the
// FormatBinding axis resolution in swrControl_ApplyAxisConfig), so setting it first
// retargets both binding and read to the chosen pad -- and since every device is already
// polled into its own slots, the previously-bound pad simply stops being read. Drives the
// input-diagnostics device picker. Not persisted; startup still selects the saved GUID.
void stdControl_SelectJoystickByIndex(int index) {
    if (index < 0 || index >= stdControl_numJoystickDevices)
        return;
    stdControl_joystickDeviceIndex = index;
    swrConfig_joystickNbAxis = 0;
    for (int i = 0; i < STDCONTROL_AXES_PER_JOYSTICK; i++) {
        if (((int (*) (int)) stdControl_EnableAxis_ADDR)(i + index * STDCONTROL_AXES_PER_JOYSTICK))
            swrConfig_joystickNbAxis++;
    }
    if (swrConfig_joystickNbAxis > 0) {
        joystick_detected = 1;
        swrConfig_joystick_enabled = 1;
    }
    ((void (*) (int)) swrControl_ApplyAxisConfig_ADDR)(0);
    ((void (*) (int)) swrControl_ApplyAxisConfig_ADDR)(1);
}

// After a rescan creates the device, swrControl still has the joystick latched off:
// swrControl_Initialize set joystick_detected / swrConfig_joystick_enabled = 0 at startup
// because no pad was present. Re-run its joystick detect/enable block so the new device is
// actually read -- select the saved device, then run the shared enable block -- without
// re-running all of swrControl_Initialize (which would reset bindings and bails early once
// stdControl is already started).
static void stdControl_RefreshJoystickConfig(void) {
    ((void (*) (void)) swrControl_SelectSavedJoystick_ADDR)();
    stdControl_SelectJoystickByIndex(stdControl_joystickDeviceIndex);
}

// Re-enumerate + re-init the DirectInput joysticks so a controller plugged in after startup
// becomes usable. Known limitation: this rebuilds all joysticks (re-creating existing ones,
// leaking the old device objects per event); hot-plug events are rare, so a follow-up should
// dedupe by guidInstance and init only the newly-arrived device so an active pad isn't disrupted.
// Non-static: also driven manually by the input-diagnostics overlay's "Re-scan devices" button.
void stdControl_RescanJoysticks(void) {
    if (iDirectInputA_ptr == NULL)
        return;
    const int before = stdControl_numJoystickDevices;
    stdControl_numJoystickDevices = 0;
    memset(g_joyDiagNames, 0, sizeof(g_joyDiagNames));
    memset(g_joyIsSony, 0, sizeof(g_joyIsSony));
    IDirectInputA *di = iDirectInputA_ptr;
    HRESULT hr = di->lpVtbl->EnumDevices(di, DIDEVTYPE_JOYSTICK, stdControl_EnumJoystickName_cb,
                                         NULL, DIEDFL_ATTACHEDONLY);
    const int enumerated = stdControl_numJoystickDevices;
    ((void (*)(void)) stdControl_InitJoysticks_ADDR)();
    stdControl_InstallJoystickStateHook();
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
    memset(g_joyDiagNames, 0, sizeof(g_joyDiagNames));
    memset(g_joyIsSony, 0, sizeof(g_joyIsSony));

    IDirectInputA *di = iDirectInputA_ptr;
    LPDIENUMDEVICESCALLBACKA cb =
        (LPDIENUMDEVICESCALLBACKA) DirectInput_EnumDevice_Callback_ADDR;
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_KEYBOARD, cb, NULL, DIEDFL_ATTACHEDONLY);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_MOUSE, cb, NULL, DIEDFL_ATTACHEDONLY);
    di->lpVtbl->EnumDevices(di, DIDEVTYPE_JOYSTICK, stdControl_EnumJoystickName_cb, NULL,
                            DIEDFL_ATTACHEDONLY);

    ((void (*)(void)) stdControl_InitKeyboard_ADDR)();
    ((void (*)(void)) stdControl_InitJoysticks_ADDR)();
    stdControl_InstallJoystickStateHook();
    ((void (*)(void)) stdControl_InitMouse_ADDR)();
    ((void (*)(void)) stdControl_Reset_ADDR)();

    // Pick up controllers hot-plugged after startup.
    glfwSetJoystickCallback(stdControl_JoystickHotplug);

    stdControl_g_bStartup = 1;
    return 0;
}
#endif
