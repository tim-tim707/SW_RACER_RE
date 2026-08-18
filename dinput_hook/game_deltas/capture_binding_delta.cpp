// Axis-as-button binding (controls-menu wishlist #2).
//
// The binding data model already supports "axis direction acts as a digital trigger"
// (AddMapping produces flag 0x14 / 0x24 for a positive / negative axis range), and the stock
// config uses it (e.g. AXIS=RY FUNCTION=BOOST AXIS_RANGE=POSITIVE). But the vanilla controls
// menu only offers it for the few actions that have a dedicated "axis" row: a normal *button*
// action captures with swrControl_CaptureBinding(bAnalogCapture=0), whose "press a button"
// prompt only scans buttons (swrControl_ScanPressedButtons), never axes.
//
// This hooks swrControl_CaptureBinding and reimplements ONLY the button-action path
// (bAnalogCapture==0) so the prompt also watches for a moved axis: push a stick/trigger and it
// binds that axis + direction as a range trigger, exactly like the config allows. Axis-action
// captures (bAnalogCapture!=0: TURN/PITCH/analog-throttle/roll) delegate to the original
// unchanged, so all their nuance (roll pairing, analog handling) is untouched.
//
// Conflicts are accepted silently (matching the binding-conflict-modal skip elsewhere -- the
// re-entrant confirm dialog hangs, so we trust the user). The row text is set here because the
// vanilla menu does not refresh a row after capture.

#include <windows.h>
#include <detours.h>
#include <cstdio>
#include <cstring>

// --- vanilla entry points / data (image base 0x400000) ---
#define swrControl_CaptureBinding_ADDR (0x00406cc0)
#define swrUI_GetValueText_ADDR (0x00414af0)
#define swrUI_SetValueText_ADDR (0x00414ab0)
#define rdCache_AdvanceFrame_ADDR (0x0048db60)
#define stdDisplay_FillMainSurface_ADDR (0x00489bc0)
#define swrControl_ProcessInputs_ADDR (0x00404dd0)
#define swrMain_RunFrame_ADDR (0x00445980)
#define swrUI_RenderTree_ADDR (0x00415020)
#define swr_noop2_ADDR (0x00426910)
#define rdCache_Flush_ADDR (0x0048dce0)
#define rdCache_FlushAlpha_ADDR (0x0048dd80)
#define stdDisplay_Update_ADDR (0x00489ab0)
#define swrControl_PollCancel_ADDR (0x00407f80)
#define swrControl_ScanPressedButtons_ADDR (0x00405dd0)
#define swrControl_FindMovedAxis_ADDR (0x00407700)
#define swrControl_ReplaceMapping_ADDR (0x004078a0)
#define swrConfig_ControlToString_ADDR (0x00407b00)
#define swrText_Translate_ADDR (0x00421360)
#define swrText_ShowTimedMessage_ADDR (0x0044fce0)
#define swrControl_RemoveMapping_ADDR (0x00407500)
#define stdControl_ReadKey_ADDR (0x00485880)
#define keyMapping_axis_ADDR (0x004b2af0)     // keyMapping0
#define keyMapping_button_ADDR (0x004b2b28)   // keyMapping1
#define STR_placeholder_ADDR (0x004b4270)     // "..." row placeholder
#define STR_unbound_ADDR (0x004b3eec)         // "---" unbound marker
#define STR_cancelled_ADDR (0x004b3ef0)       // "Cancelled"
#define STR_button_fmt_ADDR (0x004b3ed0)      // "BUTTON %s"
#define STR_percent_s_ADDR (0x004b2304)       // "%s"
#define DIK_DELETE (0xd3)                     // DirectInput scancode for the Delete key

typedef unsigned char(__cdecl *CaptureBinding_t)(int, void *, void *, char *, int);
static CaptureBinding_t orig_CaptureBinding = (CaptureBinding_t) swrControl_CaptureBinding_ADDR;

#if ENABLE_GAMEPAD_NAV
// The friendly-names override (game_deltas/gamepad_button_names_delta.cpp) needs to know which
// device page is active to decide whether to show Xbox labels. We name the row below outside
// FormatBinding, so publish the device here too (0=joystick, 1=mouse, 2=keyboard).
extern "C" void gamepad_button_names_set_device(int device);
#endif

static char *xlate(const char *s) {
    return ((char *(__cdecl *) (const char *) ) swrText_Translate_ADDR)(s);
}
static void toast(const char *msg, float secs) {
    ((void(__cdecl *)(const char *, float)) swrText_ShowTimedMessage_ADDR)(msg, secs);
}
static void set_row_text(void *row, const char *text) {
    ((void(__cdecl *)(void *, const char *, int)) swrUI_SetValueText_ADDR)(row, text, 0);
}
// swrConfig_ControlToString returns the name pointer in EAX.
static char *control_name(unsigned int id, void *table) {
    return ((char *(__cdecl *) (unsigned int, void *) ) swrConfig_ControlToString_ADDR)(id, table);
}

static void advance_frame_head() {
    ((void(__cdecl *)(void)) rdCache_AdvanceFrame_ADDR)();
    ((void(__cdecl *)(void)) stdDisplay_FillMainSurface_ADDR)();
    ((void(__cdecl *)(void)) swrControl_ProcessInputs_ADDR)();
    ((void(__cdecl *)(int, int)) swrMain_RunFrame_ADDR)(0, 2);
    ((void(__cdecl *)(void *)) swrUI_RenderTree_ADDR)(nullptr);
}
static void advance_frame_tail() {
    ((void(__cdecl *)(void)) swr_noop2_ADDR)();
    ((void(__cdecl *)(void)) rdCache_Flush_ADDR)();
    ((void(__cdecl *)(void)) rdCache_FlushAlpha_ADDR)();
    ((void(__cdecl *)(void)) stdDisplay_Update_ADDR)();
}

static unsigned char __cdecl CaptureBinding_delta(int bAnalogCapture, void *device, void *row,
                                                  char *fnStr, int slot) {
#if ENABLE_GAMEPAD_NAV
    // Tell the friendly-names override which page this capture is on, so a mouse-button rebind
    // keeps its numeric label while a joystick rebind can show the Xbox name.
    gamepad_button_names_set_device((int) device);
#endif
    // Axis-type actions (steering / pitch / analog throttle / roll) keep the vanilla flow. The
    // keyboard page (device 2) has no axes, so the axis-as-button watch is meaningless there --
    // delegate it too, so a key rebind keeps the stock prompt and can still bind the Delete key
    // (this reimpl reserves DEL as a clear shortcut). Only the joystick/mouse button path is ours.
    if (bAnalogCapture != 0 || device == (void *) 2)
        return orig_CaptureBinding(bAnalogCapture, device, row, fnStr, slot);

    char origText[64];
    ((void(__cdecl *)(void *, char *, int)) swrUI_GetValueText_ADDR)(row, origText, 0x40);
    set_row_text(row, (const char *) STR_placeholder_ADDR);
    toast(xlate("Press a button or move an axis  (DEL clears, ESC cancels)"), 4.0f);

    bool primed = false; // require an all-released frame first, so the accept press that
                         // started the capture doesn't immediately bind itself.
    for (;;) {
        advance_frame_head();

        const unsigned int btn =
            ((unsigned int(__cdecl *)(int, int)) swrControl_ScanPressedButtons_ADDR)((int) device, 0);
        int dir = 0;
        const int axis =
            ((int(__cdecl *)(int, int *)) swrControl_FindMovedAxis_ADDR)((int) device, &dir);
        const int cancel = ((int(__cdecl *)(int)) swrControl_PollCancel_ADDR)((int) device);
        const bool anythingHeld = btn != 0xffff || (axis >= 0 && dir != 0) || cancel != 0;

        unsigned char result = 0;
        bool done = false;
        if (cancel != 0) {
            // ESC always escapes, even before prime -- otherwise a resting/deflected axis or a
            // stuck button (anythingHeld never clears) would spin the capture loop forever with
            // no way out. The accept input that opened the capture is a click/button, never ESC.
            set_row_text(row, origText);
            toast(xlate((const char *) STR_cancelled_ADDR), 2.0f);
            result = 3;
            done = true;
        } else if (!primed) {
            if (!anythingHeld)
                primed = true;
        } else if (((int(__cdecl *)(int, int *)) stdControl_ReadKey_ADDR)(DIK_DELETE, nullptr)) {
            // Clear this row's binding. RemoveMapping matches by type (button vs axis), so remove
            // both to cover a normal button AND an axis bound to a button action (feature #2).
            ((int(__cdecl *)(void *, char *, int, int, int)) swrControl_RemoveMapping_ADDR)(
                device, fnStr, 0, slot, 1); // button binding
            ((int(__cdecl *)(void *, char *, int, int, int)) swrControl_RemoveMapping_ADDR)(
                device, fnStr, 1, slot, 1); // axis binding
            set_row_text(row, (const char *) STR_unbound_ADDR);
            toast(xlate("Cleared"), 2.0f);
            result = 6;
            done = true;
        } else if (btn != 0xffff) {
            // Bind the pressed button (accept any conflict silently).
            ((void(__cdecl *)(void *, char *, int, int, int, unsigned int)) swrControl_ReplaceMapping_ADDR)(
                device, fnStr, slot, 0, 0, btn);
            char buf[256];
            if (device == (void *) 2) { // keyboard: name via GetKeyNameTextA path (table = NULL)
                char *nm = xlate(control_name(btn, nullptr));
                snprintf(buf, sizeof(buf), (const char *) STR_percent_s_ADDR, nm);
            } else if (btn < 0x10) { // joystick / mouse face button
                char *nm = xlate(control_name(btn, (void *) keyMapping_button_ADDR));
                snprintf(buf, sizeof(buf), xlate((const char *) STR_button_fmt_ADDR), nm);
            } else { // HAT / high-index button
                char *nm = xlate(control_name(btn, (void *) keyMapping_button_ADDR));
                snprintf(buf, sizeof(buf), (const char *) STR_percent_s_ADDR, nm);
            }
            set_row_text(row, buf);
            result = 6;
            done = true;
        } else if (axis >= 0 && dir != 0) {
            // Bind the moved axis + direction as a digital range trigger.
            ((void(__cdecl *)(void *, char *, int, int, int, unsigned int)) swrControl_ReplaceMapping_ADDR)(
                device, fnStr, slot, 1, dir, axis);
            char buf[256];
            char *nm = xlate(control_name(axis, (void *) keyMapping_axis_ADDR));
            snprintf(buf, sizeof(buf), "%s%s AXIS", dir > 0 ? "+" : "-", nm);
            set_row_text(row, buf);
            result = 6;
            done = true;
        }

        advance_frame_tail();
        if (done) {
            // Drain: keep advancing frames until every input is released before returning. Without
            // this, the button just pressed (e.g. B) is still held when control returns to the menu
            // and gets consumed a second time as a nav action ("back"). Same idea as the initial
            // prime, applied on the way out.
            for (;;) {
                advance_frame_head();
                const unsigned int b2 =
                    ((unsigned int(__cdecl *)(int, int)) swrControl_ScanPressedButtons_ADDR)(
                        (int) device, 0);
                int d2 = 0;
                const int a2 =
                    ((int(__cdecl *)(int, int *)) swrControl_FindMovedAxis_ADDR)((int) device, &d2);
                const int c2 = ((int(__cdecl *)(int)) swrControl_PollCancel_ADDR)((int) device);
                const int del2 =
                    ((int(__cdecl *)(int, int *)) stdControl_ReadKey_ADDR)(DIK_DELETE, nullptr);
                advance_frame_tail();
                if (b2 == 0xffff && !(a2 >= 0 && d2 != 0) && c2 == 0 && del2 == 0)
                    break;
            }
            return result;
        }
    }
}

// Drop the "BUTTON " prefix from displayed joystick bindings (so a row reads "A" not "BUTTON A").
// The prefix comes from swrText_Translate of the "BUTTON %s" key (0x4b3ed0), used by both the
// menu formatter (swrControl_FormatBinding) and the post-capture text above. Returning "%s" for
// just that key strips the word everywhere it's displayed. The config-file format ("BUTTON: %s",
// a different string) and every other translation are untouched.
typedef char *(__cdecl *Translate_t)(const char *);
static Translate_t orig_Translate = (Translate_t) swrText_Translate_ADDR;

static char *__cdecl Translate_dropButtonWord(const char *key) {
    if (key == (const char *) STR_button_fmt_ADDR)
        return (char *) "%s";
    return orig_Translate(key);
}

extern FILE *hook_log;

// An axis DIRECTION bound to a button action must trigger on the SAME physical direction that was
// pressed to bind it, regardless of the axis's invert/flip setting -- flip should only affect
// full-axis (analog steering) mappings. Two things are entangled in swrControl_ProcessInputs:
//   * capture stores a physical-positive push as flag 0x10, physical-negative as 0x20
//     (swrControl_FindMovedAxis -> +1/-1 -> swrControl_AddMapping);
//   * race-eval reads a per-axis "direction" from the flip and feeds it to isAxisAboveDeadzone as
//     -direction for a 0x10 binding and +direction for a 0x20 binding:
//       00405bd9  MOV EAX,[ESI*4 + 0x00ec8880]   ; EAX = flip[axis]
//       00405be0  NEG EAX ; SBB EAX,EAX ; AND AL,0xFE ; INC EAX   ; EAX = flip ? -1 : +1
//     isAxisAboveDeadzone(axis, D) fires when sign(rawAxis) == D. So a 0x10 (captured-positive)
//     binding fires on positive only when -direction == +1, i.e. direction == -1; a 0x20 binding
//     fires on negative only when +direction == -1, again direction == -1.
// Patch those 14 bytes to force direction = -1 (MOV EAX,-1 + NOPs): capture direction now equals
// race direction for both signs, independent of flip. The full-axis flip (@0x00405c34) is untouched.
static void patch_axis_button_ignore_flip() {
    unsigned char *p = (unsigned char *) 0x00405bd9;
    // Guard: only patch if the bytes are exactly the expected MOV EAX,[ESI*4+0xec8880] + ±1 seq.
    static const unsigned char expect[14] = {0x8b, 0x04, 0xb5, 0x80, 0x88, 0xec, 0x00,
                                             0xf7, 0xd8, 0x1b, 0xc0, 0x24, 0xfe, 0x40};
    for (int i = 0; i < 14; ++i) {
        if (p[i] != expect[i]) {
            if (hook_log) {
                fprintf(hook_log, "[axis-flip-fix] unexpected bytes @0x405bd9, skipping patch\n");
                fflush(hook_log);
            }
            return;
        }
    }
    unsigned char patch[14] = {0xb8, 0xff, 0xff, 0xff, 0xff, // MOV EAX,-1
                               0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}; // NOP x9
    DWORD oldProtect = 0;
    if (VirtualProtect(p, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(p, patch, sizeof(patch));
        VirtualProtect(p, sizeof(patch), oldProtect, &oldProtect);
        if (hook_log) {
            fprintf(hook_log, "[axis-flip-fix] axis-as-button direction now ignores flip\n");
            fflush(hook_log);
        }
    }
}

extern "C" void capture_binding_install() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void **) &orig_CaptureBinding, (void *) CaptureBinding_delta);
    DetourAttach((void **) &orig_Translate, (void *) Translate_dropButtonWord);
    DetourTransactionCommit();
    patch_axis_button_ignore_flip();
}
