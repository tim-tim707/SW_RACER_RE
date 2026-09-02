#pragma once

// Splitscreen Player 2 input. Everything downstream of swrControl_ProcessInputs is already 4-wide:
// updateInRaceInputBitsets (0x00440df0) translates all four raw slots into the per-player bitsets
// and steer/pitch arrays, indexed by each pod's control index -- only device ACQUISITION was
// single-player. So a 2nd XInput pad is written into raw slot 1 once per frame and the game's own
// translation picks it up. (ProcessInputs itself must NOT be hooked: its src reimpl is a HANG stub.)
void swrControl_FeedPlayer2Input(void);

// P2's boost button (XInput A), swapped into swrRace_BoostInput for the 2nd local player by
// swrRace_UpdatePlayerControl_delta.
extern float swrControl_player2BoostInput;
