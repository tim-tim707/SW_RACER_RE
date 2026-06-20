#include "swrObjHang_delta.h"

extern "C" {
#include <macros.h>
#include <Swr/swrObj.h>
#include <globals.h>
}

#include "../hook_helper.h"

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
