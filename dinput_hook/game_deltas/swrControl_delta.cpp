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
extern "C" {
int g_cutscene_skip_edge = 0;
}

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

// XInput rumble bridge. See swrControl_delta.h for why the game's own FF path is unusable.
//
// Drives XInput vibration from the same swrRace fields the game's FF drivers read:
//   * collision / terrain shake -- the physics "vibrator" float (swrRace+0x2B8), zero on a
//     clean lap
//   * rough terrain -- grounded on a slip/loose surface (the game's own FF effect 0xc)
//   * death -- the explosion state (flags0 0x4000)
//   * engine fire / damage / repair -- engineStatus[i] & 0x14; first trio = left, last = right
//   * boost engage (flags0 0x800000)
//   * earthquake -- the camera-shake trigger (cMan shake vector at +0x38c)

#if ENABLE_XINPUT_RUMBLE

#include "swrControl_delta.h"

#include <windows.h>
#include <xinput.h>

extern "C" {
#include <types.h>
#include <globals.h>
#include <Swr/swrEvent.h>// swrEvent_GetItem (in-race detection)
#include <Swr/swrRace.h> // swrRace_UpdateScrapeSparks_ADDR
#include <Swr/swrModel.h>// swrModel_MeshGetBehavior_ADDR (terrain surface-reaction tag)

extern FILE *hook_log;
}

#include "../imgui_utils.h"// imgui_state.enable_rumble (debug toggle)
#include "../hook_helper.h"// hook_call_original (capture the scrape sparks mid-frame)

typedef void *(__cdecl *swrEvent_GetItemFn)(int, int);
typedef void(__cdecl *swrRace_UpdateScrapeSparksFn)(swrRace *);
typedef swrModel_Behavior *(__cdecl *swrModel_MeshGetBehaviorFn)(swrModel_Mesh *);

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

// Rescans at most once a second. The throttle must apply whether or not a pad is bound: with
// none connected, probing all four slots is the slow absent-slot path, every frame.
static void rumble_refresh_pad(uint32_t now) {
    if (g_lastScanMs != 0 && (now - g_lastScanMs) < 1000)
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
    const WORD l = (WORD) (left * 65535.0f);
    const WORD r = (WORD) (right * 65535.0f);
    // Skip the driver round-trip when nothing changed -- a clean lap pushes 0,0 every frame.
    static WORD s_lastLeft = 0, s_lastRight = 0;
    static int s_lastPad = -1;
    if (g_padIndex == s_lastPad && l == s_lastLeft && r == s_lastRight)
        return;
    XINPUT_VIBRATION vib = {l, r};
    if (p_XInputSetState((DWORD) g_padIndex, &vib) != ERROR_SUCCESS) {
        g_padIndex = -1;// likely unplugged; rescan shortly
        s_lastPad = -1; // force a fresh write once a pad is reacquired
        return;
    }
    s_lastPad = g_padIndex;
    s_lastLeft = l;
    s_lastRight = r;
}

// The physics "vibrator" float is swrRace.vibrationMagnitude: non-zero only during events.
// flags0/flags1 gates reuse the canonical swrObjTest_FLAG0/FLAG1 names from types_enums.h:
//   swrObjTest_FLAG0_BOOSTING          -- mid-race charge boost / overthrust active
//   swrObjTest_FLAG1_BOOST_START 0x2000 -- afterburner / boost flame lit (big-flame condition in UpdateEngineExhaust)
//   swrObjTest_FLAG1_AIRBORNE          -- pod is >30 units off the ground (rough terrain only rumbles while grounded)
//   swrObjTest_FLAG0_DEAD              -- set by swrRace_HandleDeathExplosion during death
// The pause state is the named `pauseState` global (globals.h): non-zero while the pause menu is up.
// swrRace_UpdateEnergyBinder parks the hidden binder (player->binderXfL) at translation
// z = -100000 until it lights in the pre-race sweep, so a rising edge on z marks ignition.
#define ENGINE_FIRE_BIT 0x08    // engineStatus: engine damaged / on fire (drives smoke FX in UpdateEngineDamageFX)
#define ENGINE_REPAIR_BIT 0x04  // engineStatus: actively repairing (swrRace_Repair sets this only after the ~1s hold)
// flags0 scrape-spark bits, set by the wall-scrape detection and consumed (cleared) by
// swrRace_UpdateScrapeSparks each frame -- so they must be captured from a hook on that
// function, not at present-time. One bit per engine side (spark nodes 0x41 / 0x42).
#define RACE_F0_SCRAPE_L 0x10000000
#define RACE_F0_SCRAPE_R 0x20000000
// swrEvent_GetItem('Jdge', 0) is non-null only while a race runs -- the game's own in-race test
// (see pollPauseInput). currentPlayer_Test is set at race init and NEVER cleared, so it goes stale.
#define JDGE_EVENT 0x4a646765
// The earthquake is a track trigger whose handler sends a 'Shak' camera-shake to the cMan.
// Reading the resulting cMan shake state proved unreliable, so drive off the trigger id.
#define TRIGGER_QUAKE_SOFT 105 // trigger id 0x69:  light camera shake ('Shak' amplitude ~0.05)
#define TRIGGER_QUAKE_HARD1 213// trigger id 0xd5:  strong camera shake ('Shak' amplitude ~0.25)
#define TRIGGER_QUAKE_HARD2 306// trigger id 0x132: strong camera shake ('Shak' amplitude ~0.25)
// Offsets read in swrRace_TriggerHandler: the swrObjTrig holds its trigger description at
// +0x4c, and the description's trigger id is the short at +0x24.
#define TRIG_DESC_OFFSET 0x4c
#define TRIG_DESC_ID 0x24

// Collision curve is the original's: motor = clamp(vibrator^2 * gain).
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
static const float RUMBLE_TERRAIN_RUFF = 0.45f;    // harder steady rumble on a Ruff (rough) surface, both motors
static const float RUMBLE_TERRAIN_SLOW = 0.20f;    // lighter steady rumble on a Slow surface, both motors
static const float RUMBLE_TERRAIN_MIN_SPEED = 20.0f;// speed floor before the terrain rumble kicks in (game gates on _DAT_004ac3ac; tune in-game)
static const float RUMBLE_FLAMEJET_LEVEL = 0.55f;  // right-side rumble while Sebulba's flame plume is active
static const float RUMBLE_FLAMEJET_WINDOW_S = 5.0f;// flamejet rumble length (matches the extended flame plume)
static const float RUMBLE_QUAKE_SOFT = 0.30f;      // light earthquake rumble (trigger 105), both motors
static const float RUMBLE_QUAKE_HARD = 0.60f;      // strong earthquake rumble (triggers 213/306), both motors
static const float RUMBLE_QUAKE_DURATION_S = 3.5f; // earthquake rumble length from the one-shot trigger (matches the camera shake)
static const float RUMBLE_BINDER_PULSE = 0.30f;    // subtle one-shot pulse when the engine binder lights during the pre-race sweep
static const float RUMBLE_BINDER_DECAY_S = 0.25f;  // binder pulse length
static const float RUMBLE_LEFT_GAIN = 1.5f;        // boost the low-frequency (left) motor so it feels balanced with the right
static const float UNPAUSE_MUTE_S = 0.25f;         // silence just after unpausing (kills the quit->menu blip)

static bool g_prevDead = false;      // rising-edge detect for the death jolt
static bool g_prevBoost = false;     // rising-edge detect for the boost kick
static bool g_prevRepairing = false; // rising-edge detect for the repair pulse
static bool g_prevPaused = false;    // unpause-transition detect for the mute
static bool g_repairArmed = false;   // repair double-tap in progress
static bool g_prevBinderHidden = false;// rising-edge detect for the engine-binder ignition
static float g_binderPulse = 0.0f;
static float g_deathBurst = 0.0f;
static float g_boostBurst = 0.0f;
static float g_repairPulseT = 0.0f;  // seconds since the repair double-tap armed
static float g_unpauseMute = 0.0f;
static volatile uint32_t g_scrapeFlags = 0;// scrape-spark bits captured by the UpdateScrapeSparks hook
static volatile bool g_boostActive = false;// afterburner lit (boost flag / flags1 0x2000), captured by that hook
// The trigger is one-shot but the shake plays for seconds, so arm a fixed timer at the id's level.
static volatile float g_quakeTimer = 0.0f;// seconds of earthquake rumble remaining
static volatile float g_quakeLevel = 0.0f;// its intensity (soft vs strong, by trigger id)
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
    const bool paused = pauseState != 0;

    // Quitting from the pause menu unpauses and THEN tears the race down over a few frames, so
    // the stale pod state would rumble through that hand-off.
    if (!paused && g_prevPaused)
        g_unpauseMute = UNPAUSE_MUTE_S;
    g_prevPaused = paused;
    if (g_unpauseMute > 0.0f)
        g_unpauseMute -= dt;

    // currentPlayer_Test is never cleared, so during teardown it can point at freed memory while
    // Jdge still exists. engineStatus entries are small bitfields (<= 0x1f), so anything larger
    // means the pointer is stale.
    bool podSane = player != nullptr;
    for (int i = 0; podSane && i < 6; i++) {
        if (player->engineStatus[i] & 0xffffffe0u)
            podSane = false;
    }
    // At the finish line the pod goes to autopilot, so whichever effect was live would otherwise
    // keep firing through the victory lap with the motor stuck on.
    const bool finished = podSane && (player->flags1 & swrObjTest_FLAG1_FINISHED) != 0;
    const bool active = imgui_state.enable_rumble && inRace && podSane && !paused && !finished &&
                        g_unpauseMute <= 0.0f;
    if (!active) {
        if (!inRace || !podSane || finished) {
            // Drop all state so nothing carries over.
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
            g_quakeTimer = 0.0f;
            g_prevBinderHidden = false;
            g_binderPulse = 0.0f;
        }
        rumble_set(0.0f, 0.0f);
        return;
    }

    // Edge-triggered bursts (death jolt, boost kick), decayed each frame.
    const bool dead = (player->flags0 & swrObjTest_FLAG0_DEAD) != 0;
    if (dead && !g_prevDead)
        g_deathBurst = RUMBLE_DEATH_PEAK;
    g_prevDead = dead;
    // The boost start lights and EXTENDS the afterburner, so keying on it matches the visual cue.
    // g_boostActive is captured mid-frame in the scrape hook.
    const bool boosting = g_boostActive;
    if (boosting && !g_prevBoost)
        g_boostBurst = RUMBLE_BOOST_KICK;
    g_prevBoost = boosting;
    // Rising edge off the parked z = -100000 binder transform (see above) -> one pulse.
    const bool binderHidden = player->binderXfL.vD.z <= -99999.0f;
    if (g_prevBinderHidden && !binderHidden)
        g_binderPulse = RUMBLE_BINDER_PULSE;
    g_prevBinderHidden = binderHidden;
    g_deathBurst -= dt / RUMBLE_DEATH_DECAY_S;
    if (g_deathBurst < 0.0f)
        g_deathBurst = 0.0f;
    g_boostBurst -= dt / RUMBLE_BOOST_KICK_DECAY_S;
    if (g_boostBurst < 0.0f)
        g_boostBurst = 0.0f;
    g_binderPulse -= dt / RUMBLE_BINDER_DECAY_S;
    if (g_binderPulse < 0.0f)
        g_binderPulse = 0.0f;
    // Armed for a fixed duration by the TriggerHandler hook, counted down here.
    g_quakeTimer -= dt;
    if (g_quakeTimer < 0.0f)
        g_quakeTimer = 0.0f;

    // Fixed window off the flameSmokeHandle rising edge: the handle lingers ~2s, longer than the
    // visible flame.
    const bool flameActive = player->flameSmokeHandle != NULL;
    if (flameActive && !g_prevFlame)
        g_flamejetTimer = RUMBLE_FLAMEJET_WINDOW_S;
    g_prevFlame = flameActive;
    if (g_flamejetTimer > 0.0f)
        g_flamejetTimer -= dt;


    float left = 0.0f, right = 0.0f;

    if (g_deathBurst > 0.0f) {
        left = right = g_deathBurst;// the death jolt owns both motors while it lasts
    } else if (!dead) {
        // Biased to one motor by turn direction, matching the original.
        const float vibrator = player->vibrationMagnitude;
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

        // Captured from the UpdateScrapeSparks hook -- the game clears these flags each frame, so
        // they cannot be read at present-time. Layered over the base.
        const uint32_t scrape = g_scrapeFlags;
        if (scrape & RACE_F0_SCRAPE_L)
            left = left > RUMBLE_SCRAPE_LEVEL ? left : RUMBLE_SCRAPE_LEVEL;
        if (scrape & RACE_F0_SCRAPE_R)
            right = right > RUMBLE_SCRAPE_LEVEL ? right : RUMBLE_SCRAPE_LEVEL;

        // Scaled by surface tag: harder on Ruff, lighter on Slow, Ruff winning if both are set.
        // (The game's FF effect 0xc keyed on Slip instead.) Grounded only -- flags1 0x200 is
        // airborne. terrainModel is the collided ground node.
        if ((player->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0 && player->terrainModel != nullptr &&
            player->speedValue > RUMBLE_TERRAIN_MIN_SPEED) {
            swrModel_Behavior *behavior =
                    ((swrModel_MeshGetBehaviorFn) swrModel_MeshGetBehavior_ADDR)(
                            (swrModel_Mesh *) player->terrainModel);
            if (behavior != nullptr) {
                float terrain = 0.0f;
                if ((behavior->vehicle_reaction & swrVehicleReaction_Ruff) != 0)
                    terrain = RUMBLE_TERRAIN_RUFF;
                else if ((behavior->vehicle_reaction & swrVehicleReaction_Slow) != 0)
                    terrain = RUMBLE_TERRAIN_SLOW;
                if (terrain > 0.0f) {
                    left = left > terrain ? left : terrain;
                    right = right > terrain ? right : terrain;
                }
            }
        }

        // The plume handle (unk31c) is set only on a real plume but lingers past the visible
        // flame, hence a capped window off its rising edge rather than its lifetime.
        if (g_flamejetTimer > 0.0f)
            right = right > RUMBLE_FLAMEJET_LEVEL ? right : RUMBLE_FLAMEJET_LEVEL;

        // Level set off the trigger id by the TriggerHandler hook (the cMan shake state read zero).
        if (g_quakeTimer > 0.0f) {
            left = left > g_quakeLevel ? left : g_quakeLevel;
            right = right > g_quakeLevel ? right : g_quakeLevel;
        }

        // Burning (0x8) or repairing (0x4); segments 0-2 = left motor, 3-5 = right. Intensity
        // from engineHealth (a 0..1 damage accumulator), worst segment per side. Both bits are
        // needed to carry through a repair: the fire bit cools but the repair bit stays set.
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

        // The game only sets the repair bit after the input is held ~1s.
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

        // Layered on top as an event, so it reads even mid-turn.
        if (g_boostBurst > 0.0f) {
            left = left > g_boostBurst ? left : g_boostBurst;
            right = right > g_boostBurst ? right : g_boostBurst;
        }

        // Engine-binder ignition pulse (a subtle one-shot at race start).
        if (g_binderPulse > 0.0f) {
            left = left > g_binderPulse ? left : g_binderPulse;
            right = right > g_binderPulse ? right : g_binderPulse;
        }
    }

    // The left (low-frequency) motor feels much softer than the right at the same value, so it is
    // scaled up to balance the two sides.
    const float intensity = imgui_state.rumble_intensity;
    rumble_set(left * RUMBLE_LEFT_GAIN * intensity, right * intensity);
}

// The scrape-spark flags (flags0 0x10000000 / 0x20000000) are cleared by
// swrRace_UpdateScrapeSparks every frame, so they must be snapshotted before the original runs.
void __cdecl swrRace_UpdateScrapeSparks_delta(swrRace *player) {
    if (player == currentPlayer_Test) {
        const uint32_t f0 = player->flags0;
        g_scrapeFlags = f0 & (RACE_F0_SCRAPE_L | RACE_F0_SCRAPE_R);
        // The big-flame condition from UpdateEngineExhaust.
        g_boostActive = (f0 & swrObjTest_FLAG0_BOOSTING) != 0 ||
                        (player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0;
    }
    hook_call_original((swrRace_UpdateScrapeSparksFn) swrRace_UpdateScrapeSparks_ADDR, player);
}

// The dispatcher fires every frame the pod overlaps the trigger hitbox, so the pulse holds while
// inside and decays in the mixer after. Called, NOT detoured, from the single
// swrRace_TriggerHandler hook in swrObjJdge_delta -- one address can only carry one detour.
void __cdecl swrControl_RumbleOnTrigger(int trigObj, int racer, char flags) {
    (void) flags;
    char *trig = (char *) (uintptr_t) trigObj;
    if ((swrRace *) (uintptr_t) racer == currentPlayer_Test && trig != nullptr) {
        const int desc = *(int *) (trig + TRIG_DESC_OFFSET);
        if (desc != 0) {
            const short id = *(short *) ((char *) (uintptr_t) desc + TRIG_DESC_ID);
            float level = 0.0f;
            if (id == TRIGGER_QUAKE_SOFT)
                level = RUMBLE_QUAKE_SOFT;
            else if (id == TRIGGER_QUAKE_HARD1 || id == TRIGGER_QUAKE_HARD2)
                level = RUMBLE_QUAKE_HARD;
            if (level > 0.0f) {
                g_quakeTimer = RUMBLE_QUAKE_DURATION_S;
                g_quakeLevel = level;
            }
        }
    }
}

#endif // ENABLE_XINPUT_RUMBLE
