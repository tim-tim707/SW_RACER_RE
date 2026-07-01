//
// Input-edge debounce: one accept/cancel transition per physical button press.
//
// swrControl_ProcessInputs computes the rising-edge flags swrControl_acceptPressedEdge /
// swrControl_cancelPressedEdge from per-device "was-down-last-frame" trackers. But every screen
// transition routes through swrObjHang_LoadScreen, which sets swrControl_uiInputActive = 1; on the
// next frame ProcessInputs takes its uiInputActive-active branch and RESETS those trackers to 0. A
// still-held Enter/Escape then looks freshly pressed a frame or two later, so the edge fires AGAIN
// and the next screen / cutscene is skipped too -- the "holding advances more than one screen" bug.
// (INT_004d6b48, the other accept edge, is not affected: its tracker is never reset here.)
//
// Fix: after the original runs, re-gate both edges against a rising edge of the *physical* button
// state. swrControl_PollAccept / swrControl_PollCancel read the raw keys across all devices,
// independent of uiInputActive, and we keep our own prev-down trackers that a screen transition
// never touches. An edge the game raised is cleared unless the button genuinely went down since the
// last frame. This only ever SUPPRESSES a spurious re-fire -- it never raises an edge -- so the
// cutscene-skip toggles and the gamepad START skip (which set the edge later, inside the scene
// handlers) and the separate held-to-repeat menu-nav path are all unaffected.
//

extern "C" {
#include <Main/swrControl.h>// swrControl_ProcessInputs (reimpl symbol), PollAccept/PollCancel
#include <globals.h>        // swrControl_acceptPressedEdge / swrControl_cancelPressedEdge
}

#include "../hook_helper.h"

typedef int(__cdecl *swrControl_PollFn)(int);

// Shared "skip" edge for the cutscene deltas: 1 for exactly one frame on a fresh accept/cancel
// press (release-latched), 0 otherwise. Computed here because ProcessInputs runs in every context
// the cutscenes span -- menus, the Smush FMV callback, and the in-race loop -- so a key held from a
// previous screen (e.g. the Enter that started the race) never re-registers as a fresh press and
// can't cascade through the pre-race stages. Consumers: the FMV callback + the pre-race / circuit-
// winner scene deltas.
extern "C" int g_cutscene_skip_edge = 0;

void swrControl_ProcessInputs_delta(void) {
    hook_call_original(swrControl_ProcessInputs);

    // Poll device -1 (all sources) for the raw physical accept/cancel state, same as ProcessInputs.
    const int acceptDown = ((swrControl_PollFn) swrControl_PollAccept_ADDR)(-1);
    const int cancelDown = ((swrControl_PollFn) swrControl_PollCancel_ADDR)(-1);

    // Our own prev-down state; unlike the game's trackers a screen transition never clears it.
    static int prevAcceptDown = 0;
    static int prevCancelDown = 0;

    // Keep an edge only when it lines up with a genuine physical down-transition.
    if (swrControl_acceptPressedEdge && !(acceptDown && !prevAcceptDown))
        swrControl_acceptPressedEdge = 0;
    if (swrControl_cancelPressedEdge && !(cancelDown && !prevCancelDown))
        swrControl_cancelPressedEdge = 0;

    // Fresh press of either action = one skip; a held key yields no edge (so it can't cascade).
    g_cutscene_skip_edge =
            ((acceptDown && !prevAcceptDown) || (cancelDown && !prevCancelDown)) ? 1 : 0;

    prevAcceptDown = acceptDown;
    prevCancelDown = cancelDown;
}
