#pragma once

// XInput rumble bridge for modern gamepads.
//
// SW Racer's force-feedback subsystem is gated on a legacy DirectInput
// force-feedback device being detected at startup, which a modern XInput pad
// never trips -- so its FF drivers stay dormant. Rather than ride that subsystem,
// this bridge reads the player's pod state every frame (speed, collisions, boost,
// surface contact, tilt -- the same swrRace fields the game's FF drivers read)
// and synthesizes XInput vibration from it. It is pure reads + an XInputSetState
// write, independent of the legacy FF path, so it works on any XInput controller.
//
// Compile-time gated by ENABLE_XINPUT_RUMBLE (see dinput_hook/CMakeLists.txt).
// The in-game Force Feedback "Strength" setting still scales the intensity.

#if ENABLE_XINPUT_RUMBLE

struct swrRace;

// Detour on swrRace_UpdateScrapeSparks: snapshots the wall-scrape spark flags for
// the local player before the original consumes them, feeding the rumble bridge.
// Registered in init_renderer_hooks().
void __cdecl swrRace_UpdateScrapeSparks_delta(struct swrRace *player);

// When the local player is inside a camera-shake (earthquake) trigger, arms the
// earthquake rumble. NOT a detour: the trigger dispatcher swrRace_TriggerHandler is
// already hooked by swrObjJdge_delta (fast restart), and two detours on one address
// collide, so that single handler calls this directly.
void __cdecl swrControl_RumbleOnTrigger(int trigObj, int racer, char flags);

// Per-frame mixer: derive rumble from the player's pod state and push it to the
// connected pad. Safe to call every frame, in or out of a race.
void swrControl_RumbleUpdate(void);

#else // !ENABLE_XINPUT_RUMBLE

// Rumble compiled out: the shared trigger dispatcher calls this unconditionally.
static inline void swrControl_RumbleOnTrigger(int, int, char) {}

#endif // ENABLE_XINPUT_RUMBLE
