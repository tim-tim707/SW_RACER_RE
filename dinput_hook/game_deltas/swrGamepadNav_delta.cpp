//
// Modern-gamepad UI/system navigation. See swrGamepadNav_delta.h for the why.
//
// SW Racer reads DirectInput, where an XInput pad's stick and face buttons are
// usable (the stick navigates menus; bound buttons work in a race) on the pads
// DirectInput enumerates -- but not every controller -- while the D-pad (a POV
// hat), START and BACK are never mapped. This bridge reads those via XInput and
// feeds the game's own input paths:
//   * D-pad, and the left stick (folded into the D-pad bits in swrGamepadNav_Poll),
//               -> the held in-race input bitset (inRaceLocalPlayerInputBitset3) the
//               front-end menu builder (swrUI_UpdatePlayerMenuInput) consumes (plus
//               the swrUI focus path), so both navigate every menu like the analog
//               stick does on a DirectInput-enumerated pad;
//   * START  -> in-race pause / resume, and cutscene (FMV) skip;
//   * BACK   -> swrObjJdge_CycleHudMode (the keyboard Caps-Lock HUD function).
//
// Menu nav rides the game's own per-player builder: it edge-detects the held bits
// into swrUI_localPlayersInputPressedBitset (one step per press) and auto-repeats
// list nav, and it applies the game's own input-enable gate -- so injecting the
// D-pad as held bits gives behaviour identical to the stick. In-race pause/HUD are
// OR'd into inRaceLocalPlayerInputBitset1 (the "just pressed" set), firing once per
// press like a keyboard key. Pure XInput reads + writes into game state.
//

#if ENABLE_GAMEPAD_NAV

#include "swrGamepadNav_delta.h"

#include <windows.h>
#include <xinput.h>

extern "C" {
#include <types.h>
#include <globals.h>            // pauseState, inRaceLocalPlayerInputBitset1/3
#include <Swr/swrObj.h>         // swrUI_UpdatePlayerMenuInput_ADDR, updateInRaceInputBitsets_ADDR
#include <Swr/swrUI.h>          // swrUI_ProcessMouse_ADDR, swrUI_HandleKeyEvent_ADDR
#include <Swr/swrEvent.h>       // swrEvent_GetItem_ADDR (in-race detection)

extern FILE *hook_log;
}

#include "../imgui_utils.h"     // imgui_state.enable_gamepad_nav (toggle)
#include "../hook_helper.h"     // hook_call_original

typedef void *(__cdecl *swrEvent_GetItemFn)(int, int);
typedef void(__cdecl *swrUI_UpdatePlayerMenuInputFn)(int);
typedef void(__cdecl *updateInRaceInputBitsetsFn)(void);
typedef void(__cdecl *swrUI_ProcessMouseFn)(void);
typedef int(__cdecl *swrUI_HandleKeyEventFn)(int, int);
typedef void(__cdecl *swrObjHang_UpdateTauntSceneFn)(void *);

// 'Jdge' race-manager event id: swrEvent_GetItem('Jdge', 0) is non-null only while
// a race is running (null in menus). The game's own in-race test.
#define JDGE_EVENT 0x4a646765

// In-race action bits (read via KeyDownForPlayer1Or2 from the rising-edge bitset).
#define INPUT_BIT_CYCLE_HUD 0x40 // swrObjJdge_CycleHudMode <- KeyDownForPlayer1Or2(0x40)
#define INPUT_BIT_PAUSE 0x200    // swrObjJdge_CheckIfPauseRequested <- KeyDownForPlayer1Or2(0x200)

// Menu directional bits in the in-race input bitset (the front-end menus read these:
// vertical menus use up/down, horizontal lists use left/right). Matches the analog
// axis thresholds in updateInRaceInputBitsets.
#define MENU_BIT_UP 0x4000
#define MENU_BIT_DOWN 0x8000
#define MENU_BIT_LEFT 0x10000
#define MENU_BIT_RIGHT 0x20000

// In-race pause menu (swrRace_UpdateInRaceMenu) reads these rising-edge bits:
// up = 0x4000, down = 0x8000 (shared with MENU_BIT_*), accept/activate = 0x1.
#define PAUSE_MENU_ACCEPT 0x1

// pauseState values (written by requestPause / the pause-menu scroll): 0 = none,
// 2 = scrolling in, 1 = fully paused, 3 = scrolling out -> endPause (resume).
#define PAUSE_STATE_NONE 0
#define PAUSE_STATE_PAUSED 1
#define PAUSE_STATE_RESUMING 3

// swrUI page/widget screens (splash, mode-select, options) navigate via the focus
// system, not the menu bitset -- they read arrow-key events through swrUI_HandleKeyEvent.
// The keyboard drives that as Window_msg_default_handler -> swrUI_HandleKeyEvent(vk, 1)
// on key-down. So map the D-pad to the VK arrow codes and call HandleKeyEvent exactly
// like a key-down, with keyboard-style hold-to-repeat (OS key-repeat = repeated down).
static const int NAV_VK[4] = {0x26, 0x28, 0x25, 0x27};// VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT
static const WORD NAV_BIT[4] = {XINPUT_GAMEPAD_DPAD_UP, XINPUT_GAMEPAD_DPAD_DOWN,
                                XINPUT_GAMEPAD_DPAD_LEFT, XINPUT_GAMEPAD_DPAD_RIGHT};
static const uint32_t NAV_REPEAT_DELAY_MS = 400;// hold-to-repeat: delay before first repeat
static const uint32_t NAV_REPEAT_RATE_MS = 110; // hold-to-repeat: interval between repeats
static uint32_t g_navNextFire[4] = {0, 0, 0, 0};
static WORD g_navPrevHeld = 0;// d-pad directions we have an outstanding key-down for

// --- XInput, loaded dynamically (no hard link dependency, mirrors the renderer) -
typedef DWORD(WINAPI *XInputGetState_t)(DWORD, XINPUT_STATE *);
static XInputGetState_t p_XInputGetState = nullptr;
static bool g_xinputTried = false;
static int g_padIndex = -1;       // currently connected pad (0..3), -1 = none
static uint32_t g_lastScanMs = 0; // last time we scanned for a pad

// Latched controller state, refreshed once per present by swrGamepadNav_Poll.
static WORD g_held = 0;   // buttons currently down
static WORD g_pressed = 0;// buttons that went down this poll (rising edge)
static WORD g_prevButtons = 0;

static void nav_load_xinput() {
    g_xinputTried = true;
    const char *dlls[] = {"xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"};
    for (const char *name: dlls) {
        HMODULE mod = LoadLibraryA(name);
        if (!mod)
            continue;
        p_XInputGetState = (XInputGetState_t) GetProcAddress(mod, "XInputGetState");
        if (p_XInputGetState) {
            fprintf(hook_log, "[gamepad-nav] using %s for XInput.\n", name);
            fflush(hook_log);
            return;
        }
    }
    fprintf(hook_log, "[gamepad-nav] no XInput DLL found; gamepad navigation disabled.\n");
    fflush(hook_log);
}

// Find the first connected pad. Rescans at most once a second so an unplugged /
// late-plugged controller is picked up without polling every slot every frame.
static void nav_refresh_pad(uint32_t now) {
    if (g_padIndex >= 0 && (now - g_lastScanMs) < 1000)
        return;
    g_lastScanMs = now;
    for (DWORD i = 0; i < XUSER_MAX_COUNT; i++) {
        XINPUT_STATE st;
        if (p_XInputGetState(i, &st) == ERROR_SUCCESS) {
            g_padIndex = (int) i;
            return;
        }
    }
    g_padIndex = -1;
}

// Map the left analog stick to virtual D-pad bits so the stick drives the very same menu
// navigation as the D-pad. The game already reads the stick through DirectInput on the pads
// it enumerates, but that path does not reach every controller; folding the stick into the
// D-pad bits here makes stick menu-nav work on any XInput pad. Because these bits only feed the
// D-pad's menu paths (front-end + pause), in-race steering -- read straight off the analog axes
// via DirectInput -- is unaffected. Per-axis past the standard deadzone; the two axes are
// independent (a vertical menu ignores the horizontal bit and vice versa).
static WORD nav_stick_to_dpad(const XINPUT_GAMEPAD &pad) {
    const SHORT dz = XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE;
    WORD bits = 0;
    if (pad.sThumbLY > dz)
        bits |= XINPUT_GAMEPAD_DPAD_UP;
    else if (pad.sThumbLY < -dz)
        bits |= XINPUT_GAMEPAD_DPAD_DOWN;
    if (pad.sThumbLX > dz)
        bits |= XINPUT_GAMEPAD_DPAD_RIGHT;
    else if (pad.sThumbLX < -dz)
        bits |= XINPUT_GAMEPAD_DPAD_LEFT;
    return bits;
}

void swrGamepadNav_Poll(void) {
    if (!g_xinputTried)
        nav_load_xinput();
    if (!p_XInputGetState)
        return;

    const uint32_t now = GetTickCount();
    nav_refresh_pad(now);

    WORD buttons = 0;
    if (g_padIndex >= 0) {
        XINPUT_STATE st;
        if (p_XInputGetState((DWORD) g_padIndex, &st) == ERROR_SUCCESS) {
            // Treat the left stick as a D-pad so it shares every menu-nav path (and the
            // hold-to-repeat) below; the directional bits are inert in-race except when paused.
            buttons = st.Gamepad.wButtons | nav_stick_to_dpad(st.Gamepad);
        } else {
            g_padIndex = -1;// likely unplugged; rescan next frame
        }
    }
    g_pressed = buttons & ~g_prevButtons;
    g_held = buttons;
    g_prevButtons = buttons;
}

int swrGamepadNav_SkipPressed(void) {
    return (imgui_state.enable_gamepad_nav && (g_pressed & XINPUT_GAMEPAD_START)) ? 1 : 0;
}

// Snapshot the connected pad for the input-diagnostics overlay. Reads through the
// XInput entry point the bridge already loaded, off the pad index swrGamepadNav_Poll
// latches every present, so it stays in step with the navigation path.
int swrGamepadNav_GetDiagState(GamepadDiagState *out) {
    if (!out)
        return 0;
    *out = GamepadDiagState{};
    out->padIndex = -1;
    if (!g_xinputTried)
        nav_load_xinput();
    if (!p_XInputGetState)
        return 0;

    out->padIndex = g_padIndex;
    if (g_padIndex >= 0) {
        XINPUT_STATE st;
        if (p_XInputGetState((DWORD) g_padIndex, &st) == ERROR_SUCCESS) {
            const XINPUT_GAMEPAD &p = st.Gamepad;
            out->buttons = p.wButtons;
            out->thumbLX = p.sThumbLX;
            out->thumbLY = p.sThumbLY;
            out->thumbRX = p.sThumbRX;
            out->thumbRY = p.sThumbRY;
            out->leftTrigger = p.bLeftTrigger;
            out->rightTrigger = p.bRightTrigger;
        } else {
            out->padIndex = -1;// dropped since the last poll
        }
    }
    return 1;
}

// swrUI page/widget screens (splash, mode-select, options) navigate by focus, driven by
// the keyboard as Window_msg_default_handler -> swrUI_HandleKeyEvent(vk, 1/0). Replicate
// that for the D-pad here. swrUI_ProcessMouse renders the UI tree so it runs every frame a
// menu is up; HandleKeyEvent self-gates on UI visibility, so this is inert outside menus
// (and harmless on the hangar bitset screens, which don't navigate by focus).
void __cdecl swrUI_ProcessMouse_delta(void) {
    hook_call_original((swrUI_ProcessMouseFn) swrUI_ProcessMouse_ADDR);
    if (!imgui_state.enable_gamepad_nav)
        return;

    const uint32_t now = GetTickCount();
    for (int i = 0; i < 4; i++) {
        const bool held = (g_held & NAV_BIT[i]) != 0;
        const bool wasHeld = (g_navPrevHeld & NAV_BIT[i]) != 0;
        if (held) {
            bool fire = false;
            if (!wasHeld) {
                fire = true;// initial key-down
                g_navNextFire[i] = now + NAV_REPEAT_DELAY_MS;
            } else if ((int32_t) (now - g_navNextFire[i]) >= 0) {
                fire = true;// OS-style key-repeat while held
                g_navNextFire[i] = now + NAV_REPEAT_RATE_MS;
            }
            if (fire)
                ((swrUI_HandleKeyEventFn) swrUI_HandleKeyEvent_ADDR)(NAV_VK[i], 1);// key-down
            g_navPrevHeld |= NAV_BIT[i];
        } else if (wasHeld) {
            ((swrUI_HandleKeyEventFn) swrUI_HandleKeyEvent_ADDR)(NAV_VK[i], 0);// key-up
            g_navPrevHeld &= ~NAV_BIT[i];
        }
    }
}

// Menu navigation: temporarily fold the D-pad into the local player's held in-race
// input before the front-end menu builder reads it, then restore. The original then
// edge-detects + auto-repeats it into the menu bitsets (and its own input-enable
// gate decides whether to act), so the D-pad behaves exactly like the analog stick.
void __cdecl swrUI_UpdatePlayerMenuInput_delta(int player) {
    int augment = 0;
    if (imgui_state.enable_gamepad_nav && player == 0) {
        if (g_held & XINPUT_GAMEPAD_DPAD_UP)
            augment |= MENU_BIT_UP;
        if (g_held & XINPUT_GAMEPAD_DPAD_DOWN)
            augment |= MENU_BIT_DOWN;
        if (g_held & XINPUT_GAMEPAD_DPAD_LEFT)
            augment |= MENU_BIT_LEFT;
        if (g_held & XINPUT_GAMEPAD_DPAD_RIGHT)
            augment |= MENU_BIT_RIGHT;
    }
    if (augment == 0) {
        hook_call_original((swrUI_UpdatePlayerMenuInputFn) swrUI_UpdatePlayerMenuInput_ADDR, player);
        return;
    }
    const int saved = inRaceLocalPlayerInputBitset3[player];
    inRaceLocalPlayerInputBitset3[player] = saved | augment;
    hook_call_original((swrUI_UpdatePlayerMenuInputFn) swrUI_UpdatePlayerMenuInput_ADDR, player);
    inRaceLocalPlayerInputBitset3[player] = saved;// don't disturb the in-race edge calc
}

// In-race system buttons: feed START / BACK into the game's rising-edge input set
// after the original computes it, so the game's own pause / HUD-cycle logic runs
// exactly as if the keyboard keys were pressed. Also handles START-to-resume.
void __cdecl updateInRaceInputBitsets_delta(void) {
    hook_call_original((updateInRaceInputBitsetsFn) updateInRaceInputBitsets_ADDR);
    if (!imgui_state.enable_gamepad_nav)
        return;
    if (((swrEvent_GetItemFn) swrEvent_GetItem_ADDR)(JDGE_EVENT, 0) == nullptr)
        return;// not in a race

    if (g_pressed & XINPUT_GAMEPAD_START) {
        if (pauseState == PAUSE_STATE_NONE)
            inRaceLocalPlayerInputBitset1[0] |= INPUT_BIT_PAUSE;// -> requestPause
        else if (pauseState == PAUSE_STATE_PAUSED)
            pauseState = PAUSE_STATE_RESUMING;// scroll out -> endPause (resume)
    }
    if (g_pressed & XINPUT_GAMEPAD_BACK)
        inRaceLocalPlayerInputBitset1[0] |= INPUT_BIT_CYCLE_HUD;// -> swrObjJdge_CycleHudMode

    // While paused, the pause menu (swrRace_UpdateInRaceMenu) navigates from this same
    // rising-edge bitset: D-pad up/down move the cursor, A activates the entry.
    if (pauseState != PAUSE_STATE_NONE) {
        if (g_pressed & XINPUT_GAMEPAD_DPAD_UP)
            inRaceLocalPlayerInputBitset1[0] |= MENU_BIT_UP;
        if (g_pressed & XINPUT_GAMEPAD_DPAD_DOWN)
            inRaceLocalPlayerInputBitset1[0] |= MENU_BIT_DOWN;
        if (g_pressed & XINPUT_GAMEPAD_A)
            inRaceLocalPlayerInputBitset1[0] |= PAUSE_MENU_ACCEPT;
    }
}

// Cantina taunt cutscene: it advances/skips as soon as the accept or cancel edge is set
// (the same edges Enter/Esc set). Set the cancel edge on START so START skips it. Scoped
// to this scene, so START stays inert in normal menus.
void __cdecl swrObjHang_UpdateTauntScene_delta(void *hang) {
    if (imgui_state.enable_gamepad_nav && (g_pressed & XINPUT_GAMEPAD_START))
        swrControl_cancelPressedEdge = 1;
    hook_call_original((swrObjHang_UpdateTauntSceneFn) swrObjHang_UpdateTauntScene_ADDR, hang);
}

#endif // ENABLE_GAMEPAD_NAV
