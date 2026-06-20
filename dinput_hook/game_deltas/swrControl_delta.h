#pragma once

// Splitscreen Player 2 input.
//
// The stock swrControl_ProcessInputs reads a single device set into raw in-race input slot 0 (its
// src reimplementation is a HANG stub, so it must not be hooked). Everything downstream is already
// 4-wide: updateInRaceInputBitsets (0x00440df0) translates all four raw slots into the per-player
// bitsets and steer/pitch float arrays, indexed by each pod's control index -- only device
// acquisition was single-player. So we simply write a 2nd XInput gamepad into raw slot 1 once per
// frame (from the render hook) and let the game's own translation pick it up. Gated on
// numLocalPlayers, so single-player is untouched.
void swrControl_FeedPlayer2Input(void);

// P2's boost button state (XInput A), 1.0 pressed / 0.0 released. Sampled in swrControl_FeedPlayer2Input
// and swapped into swrRace_BoostInput for the 2nd local player by swrRace_UpdatePlayerControl_delta.
extern float swrControl_player2BoostInput;
