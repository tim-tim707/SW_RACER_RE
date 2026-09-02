#pragma once

// Input-edge debounce (see swrControl_delta.cpp). Reverse-hooks swrControl_ProcessInputs so a held
// accept/cancel button produces exactly one transition per physical press.
void swrControl_ProcessInputs_delta(void);

// XInput rumble bridge for modern gamepads.
//
// The game's force-feedback subsystem is gated on a legacy DirectInput FF device being detected
// at startup (swrConfig_FORCE_ENABLED + DAT_004d789c), which an XInput pad never trips, so its
// FF drivers stay dormant. This reads the same swrRace fields those drivers read and
// synthesizes XInput vibration instead -- pure reads plus an XInputSetState write.
//
// Compile-time gated by ENABLE_XINPUT_RUMBLE. The in-game Force Feedback "Strength" scales it.

#if ENABLE_XINPUT_RUMBLE

struct swrRace;

// Detour on swrRace_UpdateScrapeSparks: snapshots the wall-scrape spark flags before the original
// consumes them.
void __cdecl swrRace_UpdateScrapeSparks_delta(struct swrRace *player);

// NOT a detour: swrRace_TriggerHandler is already hooked by swrObjJdge_delta (fast restart) and
// two detours on one address collide, so that handler calls this directly.
void __cdecl swrControl_RumbleOnTrigger(int trigObj, int racer, char flags);

// Per-frame mixer. Safe to call every frame, in or out of a race.
void swrControl_RumbleUpdate(void);

#else // !ENABLE_XINPUT_RUMBLE

// Rumble compiled out: the shared trigger dispatcher calls this unconditionally.
static inline void swrControl_RumbleOnTrigger(int, int, char) {}

#endif // ENABLE_XINPUT_RUMBLE
