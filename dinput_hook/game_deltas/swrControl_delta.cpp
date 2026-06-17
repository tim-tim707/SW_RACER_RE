//
// XInput rumble bridge for modern gamepads. See swrControl_delta.h for the why.
//
// SW Racer ships a full force-feedback runtime (swrControl_UpdateForceFeedback +
// the speed/traction/impact drivers), but the whole subsystem is gated on a
// legacy DirectInput force-feedback device being detected at startup
// (swrConfig_FORCE_ENABLED + DAT_004d789c). A modern XInput pad never trips that
// detection, so those drivers stay dormant and never emit any effects -- which is
// the real reason rumble is dead on modern controllers, on top of XInput pads not
// supporting DirectInput effects at all.
//
// So instead of riding the game's FF subsystem, this bridge reads the player's
// pod state every frame and drives XInput vibration directly, from the same fields
// the game's own FF drivers use:
//   * collision / terrain shake -- the physics "vibrator" float (swrRace+0x2B8),
//     zero during a clean lap, so no constant-driving rumble;
//   * death -- the explosion state (flags0 0x4000), a strong fading jolt;
//   * engine fire / damage / repair -- a sustained rumble on the damaged engine
//     side (engineStatus[i] & 0x14; first trio = left motor, last trio = right);
//   * boost engage (flags0 0x800000).
// Mirrors the long-running Cheat Engine prototype. Pure reads + an XInputSetState
// write, independent of the legacy FF path, so it works on any XInput controller
// and cannot disturb the game.

#if ENABLE_XINPUT_RUMBLE

#include "swrControl_delta.h"

#include <windows.h>
#include <xinput.h>

extern "C" {
#include <types.h>
#include <globals.h>
#include <Swr/swrEvent.h>// swrEvent_GetItem (in-race detection)
#include <Swr/swrRace.h> // swrRace_UpdateScrapeSparks_ADDR

extern FILE *hook_log;
}

#include "../imgui_utils.h"// imgui_state.enable_rumble (debug toggle)
#include "../hook_helper.h"// hook_call_original (capture the scrape sparks mid-frame)

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

typedef void *(__cdecl *swrEvent_GetItemFn)(int, int);
typedef void(__cdecl *swrRace_UpdateScrapeSparksFn)(swrRace *);

// --- XInput, loaded dynamically (no hard link dependency, mirrors glfw) -------
typedef DWORD(WINAPI *XInputGetState_t)(DWORD, XINPUT_STATE *);
typedef DWORD(WINAPI *XInputSetState_t)(DWORD, XINPUT_VIBRATION *);

static XInputGetState_t p_XInputGetState = nullptr;
static XInputSetState_t p_XInputSetState = nullptr;
static bool g_xinputTried = false;
static int g_padIndex = -1;      // currently connected pad (0..3), -1 = none
static uint32_t g_lastScanMs = 0;// last time we scanned for a pad

static void rumble_load_xinput() {
    g_xinputTried = true;
    const char *dlls[] = {"xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"};
    for (const char *name: dlls) {
        HMODULE mod = LoadLibraryA(name);
        if (!mod)
            continue;
        p_XInputGetState = (XInputGetState_t) GetProcAddress(mod, "XInputGetState");
        p_XInputSetState = (XInputSetState_t) GetProcAddress(mod, "XInputSetState");
        if (p_XInputGetState && p_XInputSetState) {
            fprintf(hook_log, "[rumble] using %s for XInput vibration.\n", name);
            fflush(hook_log);
            return;
        }
        p_XInputGetState = nullptr;
        p_XInputSetState = nullptr;
    }
    fprintf(hook_log, "[rumble] no XInput DLL found; gamepad rumble disabled.\n");
    fflush(hook_log);
}

// Find the first connected pad. Rescans at most once a second so an unplugged /
// late-plugged controller is picked up without polling every frame.
static void rumble_refresh_pad(uint32_t now) {
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

static void rumble_set(float left, float right) {
    if (g_padIndex < 0)
        return;
    if (left < 0.0f)
        left = 0.0f;
    if (left > 1.0f)
        left = 1.0f;
    if (right < 0.0f)
        right = 0.0f;
    if (right > 1.0f)
        right = 1.0f;
    XINPUT_VIBRATION vib = {(WORD) (left * 65535.0f), (WORD) (right * 65535.0f)};
    if (p_XInputSetState((DWORD) g_padIndex, &vib) != ERROR_SUCCESS)
        g_padIndex = -1;// likely unplugged; rescan next frame
}

// --- Game state used to gate / drive rumble -----------------------------------
// swrRace+0x2B8: float "vibrator" the physics writes for collision/terrain shake
// (the unk2b8 slot in types.h). Tiny but non-zero only during events.
#define RACE_VIBRATOR_OFFSET 0x2B8
#define RACE_F0_BOOST 0x00800000// flags0: mid-race charge boost / overthrust active
#define RACE_F1_AFTERBURNER 0x2000// flags1: afterburner / boost flame lit (big-flame condition in UpdateEngineExhaust)
#define RACE_F0_DEAD 0x00004000 // flags0: set by swrRace_HandleDeathExplosion during death
#define ENGINE_FIRE_BIT 0x08    // engineStatus: engine damaged / on fire (drives smoke FX in UpdateEngineDamageFX)
#define ENGINE_REPAIR_BIT 0x04  // engineStatus: actively repairing (swrRace_Repair sets this only after the ~1s hold)
// flags0 scrape-spark bits, set by the wall-scrape detection and consumed (cleared) by
// swrRace_UpdateScrapeSparks each frame -- so they must be captured from a hook on that
// function, not at present-time. One bit per engine side (spark nodes 0x41 / 0x42).
#define RACE_F0_SCRAPE_L 0x10000000
#define RACE_F0_SCRAPE_R 0x20000000
// pauseState (read by GetPauseState 0x00445690, written by requestPause/Unpause):
// non-zero while the pause menu is up.
#define PAUSE_STATE_ADDR 0x0050C5F0
// 'Jdge' race-manager event id. swrEvent_GetItem('Jdge', 0) is non-null only while
// a race is running (null in menus / after leaving) -- the game's own in-race test
// (see pollPauseInput). currentPlayer_Test alone is unreliable: it is set at race
// init and never cleared, so it stays stale in menus.
#define JDGE_EVENT 0x4a646765

// Tuning knobs. The collision curve is the original's: motor = clamp(vibrator^2 * gain),
// which saturates on real hits but falls off fast so the tail is short (note #2).
static const float RUMBLE_HIT_GAIN_DIR = 65535.0f; // single-motor (biased) collision gain
static const float RUMBLE_HIT_GAIN_BOTH = 22674.0f;// both-motor (unbiased) collision gain (orig /1.7)
static const float RUMBLE_DAMAGE_GAIN = 0.7f;      // engine-trouble rumble per side = engineHealth (0..1 damage) * this
static const float RUMBLE_DEATH_PEAK = 1.0f;       // death jolt strength
static const float RUMBLE_DEATH_DECAY_S = 0.6f;    // death jolt fade time
static const float RUMBLE_BOOST_KICK = 1.0f;       // strong initial pulse when boost engages (countdown + regular)
static const float RUMBLE_BOOST_KICK_DECAY_S = 0.50f;
static const float RUMBLE_BOOST_SUSTAIN = 0.40f;   // steady rumble while boost is held
static const float RUMBLE_REPAIR_PULSE = 1.0f;     // repair-engage pulse strength (delivered as a double tap)
static const float RUMBLE_SCRAPE_LEVEL = 0.20f;    // light rumble while a wall-scrape spark is active (per side)
static const float RUMBLE_FLAMEJET_LEVEL = 0.55f;  // right-side rumble while Sebulba's flame plume is active
static const float RUMBLE_FLAMEJET_WINDOW_S = 5.0f;// flamejet rumble length (matches the extended flame plume)
static const float RUMBLE_LEFT_GAIN = 1.5f;        // boost the low-frequency (left) motor so it feels balanced with the right
static const float UNPAUSE_MUTE_S = 0.25f;         // silence just after unpausing (kills the quit->menu blip)

static bool g_prevDead = false;      // rising-edge detect for the death jolt
static bool g_prevBoost = false;     // rising-edge detect for the boost kick
static bool g_prevRepairing = false; // rising-edge detect for the repair pulse
static bool g_prevPaused = false;    // unpause-transition detect for the mute
static bool g_repairArmed = false;   // repair double-tap in progress
static float g_deathBurst = 0.0f;
static float g_boostBurst = 0.0f;
static float g_repairPulseT = 0.0f;  // seconds since the repair double-tap armed
static float g_unpauseMute = 0.0f;
static volatile uint32_t g_scrapeFlags = 0;// scrape-spark bits captured by the UpdateScrapeSparks hook
static volatile bool g_boostActive = false;// afterburner lit (boost flag / flags1 0x2000), captured by that hook
static bool g_prevFlame = false;     // flame plume active last frame (unk31c), for the rising edge
static float g_flamejetTimer = 0.0f; // remaining flamejet rumble window
static uint32_t g_lastTickMs = 0;

static float clamp01(float v) {
    if (v < 0.0f)
        return 0.0f;
    if (v > 1.0f)
        return 1.0f;
    return v;
}

void swrControl_RumbleUpdate(void) {
    if (!g_xinputTried)
        rumble_load_xinput();
    if (!p_XInputSetState)
        return;

    const uint32_t now = GetTickCount();
    rumble_refresh_pad(now);

    float dt = g_lastTickMs == 0 ? 0.016f : (float) (now - g_lastTickMs) / 1000.0f;
    g_lastTickMs = now;
    if (dt < 0.0f)
        dt = 0.0f;
    if (dt > 0.1f)
        dt = 0.1f;

    swrRace *player = currentPlayer_Test;
    const bool inRace = ((swrEvent_GetItemFn) swrEvent_GetItem_ADDR)(JDGE_EVENT, 0) != nullptr;
    const bool paused = *(int *) PAUSE_STATE_ADDR != 0;

    // Mute briefly after any unpause. Quitting a race from the pause menu unpauses and
    // then tears the race down over a few frames; without this the stale pod state
    // rumbles during that hand-off to the menu (note #3). Harmless on a normal resume.
    if (!paused && g_prevPaused)
        g_unpauseMute = UNPAUSE_MUTE_S;
    g_prevPaused = paused;
    if (g_unpauseMute > 0.0f)
        g_unpauseMute -= dt;

    // currentPlayer_Test is never cleared, so after a race it can point at freed /
    // garbage memory while the Jdge entity still briefly exists during teardown --
    // that garbage drove rumble in the menu. Sanity-check it: engineStatus entries are
    // small bitfields (<= 0x1f); anything larger means the pointer is stale.
    bool podSane = player != nullptr;
    for (int i = 0; podSane && i < 6; i++) {
        if (player->engineStatus[i] & 0xffffffe0u)
            podSane = false;
    }
    const bool active = imgui_state.enable_rumble && inRace && podSane && !paused &&
                        g_unpauseMute <= 0.0f;
    if (!active) {
        if (!inRace || !podSane) {
            // Left the race / stale pod / in menus: drop all state so nothing carries over.
            g_prevDead = false;
            g_prevBoost = false;
            g_prevRepairing = false;
            g_repairArmed = false;
            g_deathBurst = 0.0f;
            g_boostBurst = 0.0f;
            g_scrapeFlags = 0;
            g_boostActive = false;
            g_prevFlame = false;
            g_flamejetTimer = 0.0f;
        }
        rumble_set(0.0f, 0.0f);
        return;
    }

    // Edge-triggered bursts (death jolt, boost kick), decayed each frame.
    const bool dead = (player->flags0 & RACE_F0_DEAD) != 0;
    if (dead && !g_prevDead)
        g_deathBurst = RUMBLE_DEATH_PEAK;
    g_prevDead = dead;
    // Boost / afterburner: kick when the afterburner lights, sustained rumble while it
    // burns (the sustain is applied below). The boost start lights and *extends* the
    // afterburner, so this matches that visual cue and fires right at the launch.
    // g_boostActive is the afterburner state captured mid-frame in the scrape hook.
    const bool boosting = g_boostActive;
    if (boosting && !g_prevBoost)
        g_boostBurst = RUMBLE_BOOST_KICK;
    g_prevBoost = boosting;
    g_deathBurst -= dt / RUMBLE_DEATH_DECAY_S;
    if (g_deathBurst < 0.0f)
        g_deathBurst = 0.0f;
    g_boostBurst -= dt / RUMBLE_BOOST_KICK_DECAY_S;
    if (g_boostBurst < 0.0f)
        g_boostBurst = 0.0f;

    // Boost start: a successful start boost briefly sets flags0 0x200000 right after GO
    // (found by diffing a boost-start vs a normal start). That bit also toggles mid-race
    // (charge mechanic), so only accept its rising edge within a short window after the GO
    // transition (race phase, flags0 low nibble, becomes 2). One-shot per start.
    // Flamejet: rumble for a fixed window from the plume spawn (unk31c rising edge); the
    // plume handle itself lingers ~2s, longer than the visible flame.
    const bool flameActive = player->unk31c != 0;
    if (flameActive && !g_prevFlame)
        g_flamejetTimer = RUMBLE_FLAMEJET_WINDOW_S;
    g_prevFlame = flameActive;
    if (g_flamejetTimer > 0.0f)
        g_flamejetTimer -= dt;


    float left = 0.0f, right = 0.0f;

    if (g_deathBurst > 0.0f) {
        left = right = g_deathBurst;// the death jolt owns both motors while it lasts
    } else if (!dead) {
        // Collision / terrain shake -- zero during a clean lap. Bias to one motor by
        // the current turn direction (matches the original).
        const float vibrator = *(float *) ((char *) player + RACE_VIBRATOR_OFFSET);
        if (vibrator > 0.0f) {
            const float v2 = vibrator * vibrator;
            const float bias = player->turnModifier;// +0x1F4, signed L/R
            if (bias > 0.0f)
                right = clamp01(v2 * RUMBLE_HIT_GAIN_DIR);
            else if (bias < 0.0f)
                left = clamp01(v2 * RUMBLE_HIT_GAIN_DIR);
            else
                left = right = clamp01(v2 * RUMBLE_HIT_GAIN_BOTH);
        } else if (boosting) {
            left = right = RUMBLE_BOOST_SUSTAIN;// steady rumble while boost is held
        }

        // Wall scrape: light rumble on the side whose scrape spark is active, captured
        // from the UpdateScrapeSparks hook (the game clears these flags each frame, so
        // they can't be read at present-time). Layered over the base so it reads while
        // coasting along a wall even without a hard hit.
        const uint32_t scrape = g_scrapeFlags;
        if (scrape & RACE_F0_SCRAPE_L)
            left = left > RUMBLE_SCRAPE_LEVEL ? left : RUMBLE_SCRAPE_LEVEL;
        if (scrape & RACE_F0_SCRAPE_R)
            right = right > RUMBLE_SCRAPE_LEVEL ? right : RUMBLE_SCRAPE_LEVEL;

        // Sebulba flamejet: right-side rumble for a fixed window from when the plume spawns.
        // The plume handle (unk31c) is set only on a real plume (a "no flame already"
        // cooldown gates it), but it lingers longer than the visible flame, so we use a
        // capped window off its rising edge rather than its full lifetime.
        if (g_flamejetTimer > 0.0f)
            right = right > RUMBLE_FLAMEJET_LEVEL ? right : RUMBLE_FLAMEJET_LEVEL;

        // Engine trouble: rumble the side whose engine segment is burning (0x8) or being
        // repaired (0x4) -- segments 0-2 = left motor, 3-5 = right. Intensity scales with
        // the damage remaining on that segment (engineHealth is a 0..1 damage accumulator),
        // and we take the worst segment per side. Repair cycles most-to-least damaged, so
        // the active segment is the worst one -> its rumble fades as it heals, then the next
        // segment takes over. Using both bits keeps it going through the repair (the fire
        // bit cools but the repair bit stays set while held).
        float leftDmg = 0.0f, rightDmg = 0.0f;
        bool repairing = false;
        for (int i = 0; i < 6; i++) {
            const unsigned int st = player->engineStatus[i];
            if (st & (ENGINE_FIRE_BIT | ENGINE_REPAIR_BIT)) {
                float dmg = player->engineHealth[i] * RUMBLE_DAMAGE_GAIN;
                if (dmg > 1.0f)
                    dmg = 1.0f;
                if (i < 3) {
                    if (dmg > leftDmg)
                        leftDmg = dmg;
                } else if (dmg > rightDmg) {
                    rightDmg = dmg;
                }
            }
            if (st & ENGINE_REPAIR_BIT)
                repairing = true;
        }
        if (leftDmg > left)
            left = leftDmg;
        if (rightDmg > right)
            right = rightDmg;

        // Repair: a distinct double-tap the moment repair engages (the game only sets
        // the repair bit after the input has been held ~1s). It rides above the
        // sustained trouble rumble so it reads as a clear, separate event.
        if (repairing && !g_prevRepairing) {
            g_repairArmed = true;
            g_repairPulseT = 0.0f;
        }
        g_prevRepairing = repairing;
        if (g_repairArmed) {
            g_repairPulseT += dt;
            float pulse = 0.0f;
            if (g_repairPulseT < 0.15f || (g_repairPulseT >= 0.23f && g_repairPulseT < 0.38f))
                pulse = RUMBLE_REPAIR_PULSE;// two ~150ms taps separated by an ~80ms gap
            if (g_repairPulseT >= 0.38f)
                g_repairArmed = false;
            left = left > pulse ? left : pulse;
            right = right > pulse ? right : pulse;
        }

        // Boost engage kick / boost-start pulse -- layered on top (an event), so it
        // reads even mid-turn.
        if (g_boostBurst > 0.0f) {
            left = left > g_boostBurst ? left : g_boostBurst;
            right = right > g_boostBurst ? right : g_boostBurst;
        }
    }

    // The left (low-frequency) motor feels much softer than the right (high-frequency)
    // at the same value, so scale it up to balance the two sides; then apply the master
    // intensity from the debug slider (rumble_set clamps the result).
    const float intensity = imgui_state.rumble_intensity;
    rumble_set(left * RUMBLE_LEFT_GAIN * intensity, right * intensity);
}

// The scrape-spark flags (flags0 0x10000000 / 0x20000000) are set by the wall-scrape
// detection and cleared by swrRace_UpdateScrapeSparks every frame, so snapshot them here
// (for the local player only) before the original consumes them.
static void __cdecl swrRace_UpdateScrapeSparks_delta(swrRace *player) {
    if (player == currentPlayer_Test) {
        const uint32_t f0 = player->flags0;
        g_scrapeFlags = f0 & (RACE_F0_SCRAPE_L | RACE_F0_SCRAPE_R);
        // Afterburner = the big-flame condition from UpdateEngineExhaust. The boost start
        // lights and extends the afterburner, so this is the visual cue to match.
        g_boostActive = (f0 & RACE_F0_BOOST) != 0 || (player->flags1 & RACE_F1_AFTERBURNER) != 0;
    }
    hook_call_original((swrRace_UpdateScrapeSparksFn) swrRace_UpdateScrapeSparks_ADDR, player);
}

void swrControl_RegisterRumbleHooks(void) {
    hook_function("swrRace_UpdateScrapeSparks", (uint32_t) swrRace_UpdateScrapeSparks_ADDR,
                  (uint8_t *) swrRace_UpdateScrapeSparks_delta);
}

#endif // ENABLE_XINPUT_RUMBLE
