// PROTOTYPE -- friendlier gamepad button names in the controls menu.
//
// Two display-only tweaks to how a joystick BUTTON row is labelled:
//   * when an XInput pad is connected, show the Xbox label (A/B/X/Y/LB/RB/...) instead of the
//     vanilla numeric "1".."16", so a rebind row reads "BUTTON A" rather than "BUTTON 1";
//   * a button id past the name table (>=20, beyond the HAT entries) resolves to NULL and the
//     menu prints "(null)" -- show the 1-based number instead so it stays readable (audit #7).
//
// DISPLAY ONLY: swrConfig_ControlToString is overridden for every caller EXCEPT the save routine
// swrConfig_WriteMappings (.text 0x00406080..0x00406470), so the on-disk config keeps its numeric
// BUTTON=<n> form. No binding tables are modified.
//
// DEVICE GATE: the joystick and MOUSE pages share the one keyMapping1 name table, and
// swrConfig_ControlToString takes no device argument -- so the active device index is published by
// the two callers that know it (swrControl_FormatBinding's param 1, and swrControl_CaptureBinding
// via gamepad_button_names_set_device) and the Xbox label only substitutes on the joystick page.
// The numeric "(null)" fallback stays device-agnostic.
//
// Installs its own Detours trampolines via gamepad_button_names_install().

#if ENABLE_GAMEPAD_NAV

#include <windows.h>
#include <detours.h>
#include <cstdio>

#include "swrGamepadNav_delta.h" // swrGamepadNav_GetDiagState -> XInput pad presence

// Vanilla addresses (see the RE notes in stdControl_delta.c for the surrounding parser).
#define swrConfig_ControlToString_ADDR (0x00407b00)
#define swrControl_FormatBinding_ADDR (0x00406a50) // menu-row formatter; param 1 = device index
#define keyMapping1_ADDR (0x004b2b28) // joystick/mouse BUTTON name table ("1".."16" + HAT_* 16-19)
// Exactly one SAVE caller (swrConfig_WriteMappings, .text 0x00406080..0x00406470); every other is
// display, including the post-rebind text, which vanilla formats through CaptureBinding rather than
// FormatBinding.
#define WRITEMAPPINGS_LO (0x00406080)
#define WRITEMAPPINGS_HI (0x00406470)

// Device index published by the callers below (matches FormatBinding's param 1: 0=joystick,
// 1=mouse, 2=keyboard). -1 = unknown. Friendly Xbox labels apply only to the joystick page.
#define DEVICE_JOYSTICK (0)
static int g_activeControlDevice = -1;

// swrConfig_ControlToString returns the name string pointer in EAX (the menu formatter
// pushes the result straight into swrText_Translate).
typedef char *(__cdecl *ControlToString_t)(unsigned int controlId, char *pDest);
static ControlToString_t orig_ControlToString = (ControlToString_t) swrConfig_ControlToString_ADDR;

// swrControl_FormatBinding(device, action, flags, rangeFlag, slot, out, outId) -> int.
typedef int(__cdecl *FormatBinding_t)(int device, int action, unsigned char *flags,
                                      unsigned char rangeFlag, int slot, char *out,
                                      unsigned int *outId);
static FormatBinding_t orig_FormatBinding = (FormatBinding_t) swrControl_FormatBinding_ADDR;

// DirectInput button index -> Xbox label for an XInput pad seen through DirectInput
// (index 0 == the button vanilla labels "1"). Buttons past this fall through to numeric.
static const char *const kXboxButtonNames[] = {
    "A", "B", "X", "Y", "LB", "RB", "BACK", "START", "LS", "RS",
};

static char g_fallbackName[16]; // for the numeric fallback below (menu is single-threaded)

static bool xinput_pad_connected() {
    GamepadDiagState s;
    return swrGamepadNav_GetDiagState(&s) && s.padIndex >= 0;
}

static char *__cdecl ControlToString_friendly(unsigned int controlId, char *pDest) {
    const bool fromSave = __builtin_return_address(0) >= (void *) WRITEMAPPINGS_LO &&
                          __builtin_return_address(0) < (void *) WRITEMAPPINGS_HI;

    // Friendly Xbox label for a face/shoulder button on a connected XInput pad (display only).
    // Only on the joystick page: the mouse page shares keyMapping1 but must keep numeric labels.
    if (!fromSave && g_activeControlDevice == DEVICE_JOYSTICK && pDest == (char *) keyMapping1_ADDR &&
        controlId < sizeof(kXboxButtonNames) / sizeof(kXboxButtonNames[0]) && xinput_pad_connected())
        return (char *) kXboxButtonNames[controlId];

    char *name = orig_ControlToString(controlId, pDest);

    // A button id past the name table (>=20, beyond the HAT entries) resolves to NULL and the menu
    // prints "(null)". The save path (fromSave) keeps NULL so it never persists an unparseable
    // BUTTON= line.
    if (name == nullptr && !fromSave && pDest == (char *) keyMapping1_ADDR) {
        snprintf(g_fallbackName, sizeof(g_fallbackName), "%u", controlId + 1);
        return g_fallbackName;
    }
    return name;
}

// Publish the device index while the menu formats a row, so ControlToString_friendly knows which
// page (joystick vs mouse) is being drawn. FormatBinding calls ControlToString internally.
static int __cdecl FormatBinding_setDevice(int device, int action, unsigned char *flags,
                                           unsigned char rangeFlag, int slot, char *out,
                                           unsigned int *outId) {
    g_activeControlDevice = device;
    return orig_FormatBinding(device, action, flags, rangeFlag, slot, out, outId);
}

// swrControl_CaptureBinding (game_deltas/capture_binding_delta.cpp) formats the post-rebind row
// text itself, outside FormatBinding, so it publishes the device here before naming a button.
extern "C" void gamepad_button_names_set_device(int device) {
    g_activeControlDevice = device;
}

extern "C" void gamepad_button_names_install() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void **) &orig_ControlToString, (void *) ControlToString_friendly);
    DetourAttach((void **) &orig_FormatBinding, (void *) FormatBinding_setDevice);
    DetourTransactionCommit();
}

#endif // ENABLE_GAMEPAD_NAV
