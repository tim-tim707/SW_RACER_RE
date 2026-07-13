#pragma once

// Modern-gamepad UI/system navigation for SW Racer.
//
// The game's input layer reads DirectInput, where an XInput pad's analog stick,
// face buttons and triggers are visible (the stick navigates menus and the bound
// buttons work in a race) on the pads DirectInput enumerates -- but that path does
// not reach every controller, and the D-pad (a POV hat), START and BACK/SELECT are
// never mapped to anything. Rather than touch the binding tables, this bridge reads
// the pad directly via XInput and drives the game's *own* mechanisms:
//   * D-pad -> the game's menu navigation. The left stick is left alone: the game
//     already navigates menus with it via DirectInput, so bridging it too would
//     move two entries per push.
//   * START -> in-race pause (and resume), and cutscene skip;
//   * BACK/SELECT -> cycle the HUD mode (the keyboard Caps-Lock function).
//
// Pure XInput reads + writes into the game's input state, independent of the
// legacy DirectInput path, so it works on any XInput controller. Compile-time
// gated by ENABLE_GAMEPAD_NAV (see dinput_hook/CMakeLists.txt).

#if ENABLE_GAMEPAD_NAV

#ifdef __cplusplus
extern "C" {
#endif

// Game-function hooks the bridge installs (menu nav + in-race actions).
// Registered inline in init_renderer_hooks().
void __cdecl swrUI_ProcessMouse_delta(void);
void __cdecl swrUI_UpdatePlayerMenuInput_delta(int player);
void __cdecl updateInRaceInputBitsets_delta(void);
void __cdecl swrObjHang_UpdateTauntScene_delta(void *hang);

// Per-frame poll: read the controller and latch its held / just-pressed state.
// Safe to call every frame, in or out of a race (also runs in the cutscene loop).
void swrGamepadNav_Poll(void);

// Non-zero on the frame START is pressed -- used by the cutscene-skip path.
int swrGamepadNav_SkipPressed(void);

// Live XInput pad snapshot for the input-diagnostics overlay. Reuses the bridge's
// dynamically-loaded XInput entry point and the pad index the per-frame poll latched.
typedef struct GamepadDiagState {
    int padIndex;          // connected XInput slot 0..3, -1 if none
    unsigned int buttons;  // XINPUT_GAMEPAD wButtons bitfield
    short thumbLX, thumbLY;// left stick, -32768..32767
    short thumbRX, thumbRY;// right stick
    unsigned char leftTrigger, rightTrigger;// 0..255
} GamepadDiagState;

// Fill *out with a fresh read of the connected pad. Returns 1 if XInput is loaded at
// all (out->padIndex still tells whether a pad is connected), 0 if no XInput runtime.
int swrGamepadNav_GetDiagState(GamepadDiagState *out);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_GAMEPAD_NAV
