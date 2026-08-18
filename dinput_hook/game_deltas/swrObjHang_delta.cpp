#include "swrObjHang_delta.h"

extern "C" {
#include <macros.h>
#include <Swr/swrObj.h>
#include <globals.h>
}

#include "../hook_helper.h"
#include "../imgui_utils.h"// imgui_state cutscene-skip toggles ("Game" settings panel)

// Fresh accept/cancel skip edge (defined in swrControl_delta.cpp): 1 for one frame on a genuine
// press, never for a held key. Lets the Circuit Winner podium be skipped with a key/button press.
extern "C" int g_cutscene_skip_edge;

// Fix for the multiplayer "can't change racer after a race" bug (affects BOTH the host and
// clients; the racer cursor freezes, the non-host typically stuck on Anakin / racer 0).
//
// In an MP race the hangar is left with num_local_players (swrObjHang+0x70) == 2, so the
// vehicle-select screen (swrRace_SelectVehicle, 0x435700) walks the local-player index
// current_player_for_vehicle_selection (swrObjHang+0x6f) hotseat-style from 0..num_local_players-1,
// reading that player's controls via FUN_00469c30(swrUI_localPlayersInputDownBitset[player]). But on
// every machine the local controller's input is funneled into input slot 0 only (swrObjHang_F0:
// swrUI_localPlayersInputDownBitset[0] = DAT_004d8bdc). Once the menu advances to player 1 -- a
// remote player whose input slot is never populated on this machine -- the racer cursor can no
// longer move, and it re-seeds to that remote player's racer (0/Anakin if it never picked).
//
// In multiplayer each machine drives exactly one local racer, so pin vehicle selection to the
// single local player (slot 0): with num_local_players forced to 1 the confirm path
// (`if (num_local_players-1 <= current) -> next screen`) exits cleanly without ever stepping to a
// remote player, and the cursor input always reads the populated slot. Single-player / split-screen
// is untouched (guarded by multiplayer_enabled).
void swrObjHang_F0_delta(swrObjHang *hang) {
    if (multiplayer_enabled != 0 && hang->menuScreen == swrObjHang_STATE_SELECT_VEHICLE) {
        hang->current_player_for_vehicle_selection = 0;
        hang->num_local_players = 1;
    }

    hook_call_original(swrObjHang_F0, hang);
}

// --- cutscene auto-skip ----------------------------------------------------------------------
// The hangar's camera-intro scenes (states 16-18) and the room-pan transition each advance
// themselves once a particular signal is set; the deltas below set that signal every frame the
// matching "Game" panel toggle is on, so the scene completes via the game's own clean path
// (camera/holo teardown, state advance) instead of being torn out. All default off.
typedef void(__cdecl *swrObjHang_UpdatePlanetSelectIntroFn)(swrObjHang *);
typedef void(__cdecl *swrObjHang_UpdateVehicleSelectIntroFn)(swrObjHang *);

// The "Pod Unlock Scene" (state 17, RESULTS_INTRO) is skipped upstream in swrRace_ResultsMenu_delta
// (swrRace_delta.cpp): it stops the results flow from ever entering the scene, so there's nothing to
// suppress here. The dev "Trigger" for it still plays it normally (it's no longer hooked).

// State 18: the "Cantina Intro" -- the holo-planet + camera fly-through into vehicle select. Like
// the taunt it honors the cancel edge directly, snapping to STATE_SELECT_VEHICLE.
void __cdecl swrObjHang_UpdateVehicleSelectIntro_delta(swrObjHang *hang) {
    if (imgui_state.skip_cantina_intro)
        swrControl_cancelPressedEdge = 1;
    hook_call_original((swrObjHang_UpdateVehicleSelectIntroFn) swrObjHang_UpdateVehicleSelectIntro_ADDR,
                       hang);
}

// State 16: the "Circuit Winner Scene" -- the podium of winning characters shown after completing a
// circuit (it then leads into planet select for the next leg). Its cancel-edge skip is gated behind
// the debug build, so instead drive its own countdown timer to the end threshold; the original then
// runs its normal completion (advance to STATE_SELECT_PLANET). On the scene's first frame the
// original re-seeds the timer, so the skip lands a frame later -- imperceptible. Skipped either by
// the "Circuit Winner Scene" toggle or by a fresh accept/cancel press (the scene has no release-
// build skip key of its own -- the game gates that behind the debug build).
void __cdecl swrObjHang_UpdatePlanetSelectIntro_delta(swrObjHang *hang) {
    if (imgui_state.skip_circuit_winner || g_cutscene_skip_edge)
        swrObjHang_planetIntroTimer = swrObjHang_cutsceneTimerEnd;
    hook_call_original((swrObjHang_UpdatePlanetSelectIntroFn) swrObjHang_UpdatePlanetSelectIntro_ADDR,
                       hang);
}

// Pre-race camera sweep skip lives in swrObjJdge_F0_delta (swrObjJdge_delta.cpp): the race manager
// owns the sweep state machine, so the skip is driven from there rather than from the camera.
