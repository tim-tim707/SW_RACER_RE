#include "stdControl_delta.h"

#include "globals.h"

#include <engine_config.h>
#include <macros.h>

#include <Main/swrControl.h>
#include <General/stdConffile.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// The keyMapping2_0 name table: 22 entries, id == -1 terminated, each mapping an
// (id, otherId) pair to a display-name string pointer. The generated globals.h macro
// `keyMapping2_0` is unusable here -- globals.h also defines an object macro named
// `keyMapping2` that shadows the struct type, poisoning the macro's own expansion -- so
// reach it through the raw address with a local layout mirror. Layout matches
// types.h keyMapping2 {int id; char name[4] /* holds a char* */; int otherId;}.
#define keyMapping2_0_ADDR (0x004b29e8)
typedef struct {
    int id;
    const char *name;
    int otherId;
} swrKeyNameEntry;

// Return addresses of the two swrControl_CaptureBinding call sites (the binding menu's
// conflict check) and of the swrConfig_WriteMappings site (the profile writer). Used to
// scope the null-safety override below to exactly the crash sites without disturbing the
// writer -- see the hook comment.
#define FINDKEYNAME_RET_CAPTUREBINDING_1 (0x00406ede)
#define FINDKEYNAME_RET_CAPTUREBINDING_2 (0x00407204)

// 0x00407d90 HOOK
// Vanilla swrControl_FindKeyName returns NULL when the (id, otherId) pair has no entry
// in the name table. Two very different callers depend on that:
//   * swrControl_CaptureBinding (binding menu) feeds it through swrText_Translate (which
//     passes NULL through) into _stricmp, which dereferences it -- so re-binding a button
//     already mapped to a control with no name entry crashes (read @0). That state is
//     reachable after a hot-plug rescan shifts the joystick axis/button id space.
//   * swrConfig_WriteMappings RELIES on NULL to SKIP an unnamed binding. If it instead
//     got "", it would write a blank "FUNCTION=" line; swrControl_LoadMappings then fails
//     to parse it and ClearBindings-wipes the ENTIRE device -- i.e. bindings vanish on the
//     next load. So "" is safe for the menu but catastrophic for the writer.
// Keep the exact vanilla NULL for every caller and hand back "" ONLY at the two binding-
// menu sites, so the conflict check sees a harmless non-match and the bind proceeds.
// Active in both input modes because the binding menu is shared.
const char *swrControl_FindKeyName_delta(int id, char otherId) {
    const swrKeyNameEntry *table = (const swrKeyNameEntry *) keyMapping2_0_ADDR;
    for (int i = 0; table[i].id != -1; i++) {
        if (table[i].id == id && (char) table[i].otherId == otherId)
            return table[i].name;
    }
    const void *ret = __builtin_return_address(0);
    if (ret == (const void *) FINDKEYNAME_RET_CAPTUREBINDING_1 ||
        ret == (const void *) FINDKEYNAME_RET_CAPTUREBINDING_2)
        return "";
    return (const char *) 0;
}

// One parsed binding: {input code, action} + type flags. 0xff in the flags byte terminates
// a device's table. Matches the 0xc-byte on-disk-into-memory layout the game uses.
typedef struct {
    unsigned int flags; // low byte: 0x04 axis, 0x08 button/key, 0x10/0x20 axis range +/-, 0xff term
    int input;          // key/button/axis code (stdConfig_getKeymap_id); -1 = unresolved
    int action;         // control action id (swrControl_ParseFunctionName); -1 = none
} swrControlBinding;

// Game globals the loader touches that are not yet in the generated header. Addressed here
// with the same _ADDR convention the function hooks use (no raw hex in the body below).
#define swrControl_bindingCounts_ADDR (0x004d5e20)  // int[3]: [0]=joystick [1]=mouse [2]=keyboard
#define swrControl_bindingsJoystick_ADDR (0x004d5fc0)
#define swrControl_bindingsMouse_ADDR (0x004d6518)
#define swrControl_bindingsKeyboard_ADDR (0x004d6828)
#define swrControl_joystickFlipAxis_ADDR (0x00ec8880)  // int[6]
#define swrControl_mouseFlipAxis_ADDR (0x00ec8790)     // int[3] (flip_x/y/z)
#define swrControl_axisSensitivity_ADDR (0x00ec8780)   // float[2] (joystick, mouse)
#define swrControl_mousePresentGate_ADDR (0x004b2950)  // nonzero when a mouse is usable
#define keyMapping_axis_ADDR (0x004b2af0)              // keyMapping0 (AXIS names)
#define keyMapping_button_ADDR (0x004b2b28)            // keyMapping1 (BUTTON names)
#define keyMapping_key_ADDR (0x004b2bd0)               // keyMapping2 (KEY names)
#define swrControl_inputAccumA_ADDR (0x00ec8840)       // per-action input accumulator, 15 dwords
#define swrControl_inputAccumB_ADDR (0x00ec88a0)       // per-action input accumulator, 15 dwords

// Per-device binding table capacity. swrControl_ClearBindings / swrControl_SetDefaultMappings
// zero 0xc3 dwords = 65 entries per table; reserve the last slot for the 0xff terminator, so
// at most 64 real bindings fit. The loader must cap adds here or a pathological config would
// overflow one device's table into the next.
#define swrControl_bindingsPerDevice_MAX (64)

// 0x00406470 HOOK  (stdConfFile_readAndApplyConf / swrControl_LoadMappings)
// Faithful reimplementation of the config-mapping loader, with ONE behavioral change: the
// vanilla parser jumps to a shared error label on any unparseable entry (a FUNCTION name it
// can't resolve, a malformed AXIS_RANGE, a FLIP_AXIS on the wrong device, or a KEY/BUTTON
// name that stdConfig_getKeymap_id rejects with -1), and that label does
// swrControl_ClearBindings(device) + returns 0 -- so a SINGLE bad line wipes the device's
// ENTIRE binding set. A controller whose button ids shift between sessions then loses all its
// bindings on load ("bindings keep getting wiped"). Here a bad entry is SKIPPED (the line is
// abandoned and parsing continues), so every good binding is kept and the table is still
// terminated normally. Everything else mirrors the original.
int stdConfFile_readAndApplyConf_delta(int deviceFilter, char *configName, int useDefaultDir) {
    swrControlBinding *const tables[3] = {
        (swrControlBinding *) swrControl_bindingsJoystick_ADDR,
        (swrControlBinding *) swrControl_bindingsMouse_ADDR,
        (swrControlBinding *) swrControl_bindingsKeyboard_ADDR,
    };
    int *const counts = (int *) swrControl_bindingCounts_ADDR;
    int *const joyFlip = (int *) swrControl_joystickFlipAxis_ADDR;
    int *const mouseFlip = (int *) swrControl_mouseFlipAxis_ADDR;
    float *const sensitivity = (float *) swrControl_axisSensitivity_ADDR;

    char path[256];
    if (useDefaultDir == 0) {
        sprintf(path, "%s%s\\%s_%s", ".\\data\\config\\", configName, configName, "control.map");
    } else {
        char name[32];
        strcpy(name, "control.map");
        if (strcmp(configName, "wheel") == 0)
            strcpy(name, "wheel.map");
        else if (configName[0] != '\0')
            sprintf(name, "%s", configName);
        sprintf(path, "%s%s%s", (char *) rootPathName, ".\\data\\config\\default\\", name);
    }

    if (!((int (*) (const char *)) stdConffile_Open_ADDR)(path)) {
        ((void (*) (void)) stdConffile_Close_ADDR)();
        return -1;
    }

    if (deviceFilter < 0 || deviceFilter == 0)
        for (int i = 0; i < 6; i++)
            joyFlip[i] = 0;
    if (deviceFilter < 0 || deviceFilter == 1)
        mouseFlip[0] = mouseFlip[1] = mouseFlip[2] = 0;
    ((void (*) (int)) swrControl_ClearBindings_ADDR)(deviceFilter);

    int curDevice = 0;
    if (((int (*) (void)) stdConffile_ReadArgs_ADDR)()) {
        do {
            if (_stricmp(stdConffile_g_entry.aArgs[0].argName, "end.") == 0)
                break;

            swrControlBinding line = {0, 0, -1};
            int skip = 0;
            for (int i = 0; i < stdConffile_g_entry.numArgs; i++) {
                char *name = stdConffile_g_entry.aArgs[i].argName;
                char *value = stdConffile_g_entry.aArgs[i].argValue;
                if (_stricmp(name, "JOYSTICK") == 0) {
                    curDevice = 0;
                } else if (_stricmp(name, "MOUSE") == 0) {
                    curDevice = 1;
                } else if (_stricmp(name, "KEYBOARD") == 0) {
                    curDevice = 2;
                } else if (_stricmp(name, "AXIS") == 0) {
                    line.flags |= 4;
                    line.input = ((int (*) (char *, void *)) stdConfig_getKeymap_id_ADDR)(
                        value, (void *) keyMapping_axis_ADDR);
                } else if (_stricmp(name, "BUTTON") == 0) {
                    line.flags |= 8;
                    line.input = ((int (*) (char *, void *)) stdConfig_getKeymap_id_ADDR)(
                        value, (void *) keyMapping_button_ADDR);
                } else if (_stricmp(name, "KEY") == 0) {
                    line.flags |= 8;
                    line.input = ((int (*) (char *, void *)) stdConfig_getKeymap_id_ADDR)(
                        value, (void *) keyMapping_key_ADDR);
                } else if (_stricmp(name, "FUNCTION") == 0) {
                    if (((int (*) (void *, char *, int)) swrControl_ParseFunctionName_ADDR)(
                            &line, value, 0) == 0) {
                        skip = 1; // was: ClearBindings + abort the whole load
                        break;
                    }
                } else if (_stricmp(name, "AXIS_RANGE") == 0) {
                    if (_stricmp(value, "POSITIVE") == 0) {
                        line.flags |= 0x10;
                    } else if (_stricmp(value, "NEGATIVE") == 0) {
                        line.flags |= 0x20;
                    } else {
                        skip = 1;
                        break;
                    }
                } else if ((deviceFilter < 0 || deviceFilter == curDevice) &&
                           _stricmp(name, "FLIP_AXIS") == 0) {
                    if (curDevice == 0) {
                        joyFlip[line.input] = 1;
                    } else if (curDevice == 1) {
                        mouseFlip[line.input] = 1;
                    } else {
                        skip = 1;
                        break;
                    }
                } else if (_stricmp(name, "SENSITIVITY") == 0) {
                    sensitivity[curDevice] = (float) atof(value);
                } else if (_stricmp(name, "DEADZONE") == 0) {
                    if (curDevice == 0)
                        Deadzone = (float) atof(value);
                } else if (_stricmp(name, "ENABLED") == 0) {
                    int isTrue = _stricmp(value, "TRUE") == 0;
                    if (curDevice == 0) {
                        swrConfig_joystick_enabled = (isTrue && joystick_detected) ? 1 : 0;
                    } else if (curDevice == 1) {
                        swrConfig_mouse_enabled =
                            (isTrue && *(int *) swrControl_mousePresentGate_ADDR) ? 1 : 0;
                    }
                }

                if (line.input < 0) {
                    skip = 1; // unresolvable KEY/BUTTON name -- was: wipe the whole device
                    break;
                }
            }
            if (skip)
                continue; // skip just this line; keep the bindings parsed so far

            if ((deviceFilter < 0 || deviceFilter == curDevice) && line.action > -1 &&
                counts[curDevice] < swrControl_bindingsPerDevice_MAX) {
                int idx = counts[curDevice];
                tables[curDevice][idx] = line;
                counts[curDevice] = idx + 1;
            }
        } while (((int (*) (void)) stdConffile_ReadArgs_ADDR)());
    }

    // A device whose config has no SENSITIVITY line leaves sensitivity[] at 0, and
    // swrControl_ApplyAxisConfig then computes 1.0f / sensitivity[mouse] = INF for the mouse
    // range (no zero guard at 0x40766f). Clamp to the neutral 1.0 default so a missing/zero
    // sensitivity can't produce an INF/NaN axis scale.
    if (sensitivity[0] <= 0.0f)
        sensitivity[0] = 1.0f;
    if (sensitivity[1] <= 0.0f)
        sensitivity[1] = 1.0f;

    // Vanilla appends a fixed keyboard entry (pause) and 0xff-terminates each device table.
    if ((deviceFilter < 0 || deviceFilter == 2) && counts[2] < swrControl_bindingsPerDevice_MAX) {
        int idx = counts[2];
        swrControlBinding pause = {0xa, 1, 0xa};
        tables[2][idx] = pause;
        counts[2] = idx + 1;
    }
    if (deviceFilter < 0 || deviceFilter == 0)
        *(unsigned char *) &tables[0][counts[0]].flags = 0xff;
    if (deviceFilter < 0 || deviceFilter == 1)
        *(unsigned char *) &tables[1][counts[1]].flags = 0xff;
    if (deviceFilter < 0 || deviceFilter == 2)
        *(unsigned char *) &tables[2][counts[2]].flags = 0xff;
    ((void (*) (void)) stdConffile_Close_ADDR)();
    return 1;
}

// 0x00407800 HOOK  (swrControl_ClearBindings)
// Faithful reimplementation with ONE addition: after zeroing a device's binding table the
// vanilla routine leaves every slot's flags byte at 0 and does NOT write the 0xff list
// terminator, so a cleared-but-not-repopulated table is malformed. swrConfig_WriteMappings
// (and the binding walkers) scan until a 0xff flags byte, so serializing such a table runs
// off the end into adjacent memory and emits thousands of junk "(null)" entries -- which then
// get saved to the profile. Terminating here makes "empty table" a valid table for every
// caller, closing that whole class of corruption at the source.
void swrControl_ClearBindings_delta(int deviceFilter) {
    swrControlBinding *const tables[3] = {
        (swrControlBinding *) swrControl_bindingsJoystick_ADDR,
        (swrControlBinding *) swrControl_bindingsMouse_ADDR,
        (swrControlBinding *) swrControl_bindingsKeyboard_ADDR,
    };
    int *const counts = (int *) swrControl_bindingCounts_ADDR;

    // Reset the accumulated per-frame input state (unchanged from vanilla).
    swrRace_ThrottleInput = 0.0f;
    swrRace_UnkInput = 0.0f;
    swrRace_SteeringInput = 0.0f;
    swrRace_PitchInput = 0.0f;
    memset((void *) swrControl_inputAccumA_ADDR, 0, 15 * sizeof(int));
    memset((void *) swrControl_inputAccumB_ADDR, 0, 15 * sizeof(int));

    for (int dev = 0; dev < 3; dev++) {
        if (deviceFilter >= 0 && deviceFilter != dev)
            continue;
        memset((void *) tables[dev], 0, 0xc3 * sizeof(int)); // 195 dwords, as vanilla
        counts[dev] = 0;
        *(unsigned char *) &tables[dev][0].flags = 0xff; // the terminator vanilla omits
    }
}

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
    } else {
        // No axes came up (device not acquired yet, or a stale/empty slot). Keep the
        // detect/enable flags honest so the diagnostics overlay and the Ctrl+J toggle
        // don't report a phantom "ready" controller that yields no input -- the exact
        // contradiction users hit when a rescan enumerates a pad but nbAxis stays 0.
        joystick_detected = 0;
        swrConfig_joystick_enabled = 0;
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
    // A pad hot-plugged after launch usually gets a fresh DirectInput instance GUID, so
    // the saved-GUID match in swrControl_SelectSavedJoystick misses and no axes come up.
    // If a joystick did enumerate, fall back to the first device so the reconnected pad
    // becomes usable immediately instead of the user having to re-scan until it happens
    // to land (the "won't detect until it randomly does" symptom).
    if (swrConfig_joystickNbAxis == 0 && stdControl_numJoystickDevices > 0)
        stdControl_SelectJoystickByIndex(0);
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
