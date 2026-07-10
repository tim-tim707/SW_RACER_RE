//
// Randomizer game-side integration: the thin hooks that arm the per-profile
// randomizer and apply its effects to the running game. The seed/config/sidecar
// logic lives in ../randomizer.{h,cpp}; this file only bridges to the engine.
// See RANDOMIZER_ROADMAP.md.
//

#include "randomizer_game_delta.h"

extern "C" {
#include <macros.h>
#include <globals.h>
#include <Swr/swrRace.h>
#include <Swr/swrObj.h>
#include "tracks_delta.h"
}

#include "../hook_helper.h"
#include "../randomizer.h"

// The live working profile: a 0x50-byte struct at 0x00e364b4 whose first field is the
// profile name (this is exactly what swrRace_SaveProfile serializes). Reading the name
// here is how we know which profile to arm at race time -- there is no named
// current-profile-name global yet (promote 0x00e364b4 in the DB at pre-PR time).
static const char *live_profile_name() {
    return (const char *) 0x00e364b4;
}

// Value envelope for randomized AI, matching the range the game itself uses across
// tracks: base level (post *0.1) spans ~0.82..1.15, spread ~20..40.
static const float AI_LEVEL_MIN = 0.82f;
static const float AI_LEVEL_MAX = 1.15f;
static const float AI_SPREAD_MIN = 20.0f;
static const float AI_SPREAD_MAX = 40.0f;

// swrRace_SaveProfile(playerName) serializes the live working profile to
// ./data/player/<name>.sav. It runs when a new profile is created and on every
// autosave (via swrRace_SaveCurrentProfile), always with the current profile's name.
// We arm the randomizer here: for a brand-new profile this freezes the staged config
// (matched by name via the creation intent); for an existing one it just loads the
// already-frozen config. Address-only (not reimplemented).
typedef bool(swrRace_SaveProfile_t)(char *playerName);

bool swrRace_SaveProfile_delta(char *playerName) {
    randomizer_ensure_armed(playerName);
    return hook_call_original((swrRace_SaveProfile_t *) swrRace_SaveProfile_ADDR, playerName);
}

// AI-difficulty applier. InitAISettingsForTrack sets swrRace_AILevel / ai_spread for the
// current track; we run the original, then (if this profile randomizes AI) overwrite them
// with per-(profile, track) deterministic values from the AI sub-stream. Keying on the
// track index makes each track's difficulty fixed for a given profile but varied across
// tracks. We re-apply the AI Speed menu scale so that setting still has effect.
// Reimplemented function -> hook_replace (mirrors swrObjHang_F0).
void InitAISettingsForTrack_delta(swrObjJdge *judge) {
    hook_call_original(InitAISettingsForTrack, judge);

    randomizer_ensure_armed(live_profile_name());
    if (!randomizer_category_active(RANDOMIZER_CAT_AI_DIFFICULTY))
        return;

    uint32_t trackIndex = (uint32_t) (judge->planet_track_number + judge->planetId * 4);
    RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_AI_DIFFICULTY, trackIndex);

    float level = AI_LEVEL_MIN + randomizer_next_unit(&rng) * (AI_LEVEL_MAX - AI_LEVEL_MIN);
    float spread = AI_SPREAD_MIN + randomizer_next_unit(&rng) * (AI_SPREAD_MAX - AI_SPREAD_MIN);

    // Respect the AI Speed menu setting the same way the original does.
    if (judge->aiSpeedSetting == -1)
        level *= 0.9f;
    else if (judge->aiSpeedSetting == 1)
        level *= 1.1f;

    swrRace_AILevel = level;
    ai_spread = spread;
}

// Track order: shuffle each circuit's track slots deterministically per profile. The
// course-selection menu maps slot -> track via g_aTrackIDs[circuit*7 + slot] and rebuilds
// its names/sprites from it, while unlock gating keys off the slot index -- so permuting
// within a circuit reorders the tracks safely. Called every frame we're on the track-select
// screen (before the menu handler reads g_aTrackIDs); idempotent because it always rebuilds
// from a one-time snapshot of the vanilla order.
extern "C" void randomizer_apply_track_order(void) {
    static bool captured = false;
    static int original[DEFAULT_NB_TRACKS];
    if (!captured) {
        for (int i = 0; i < DEFAULT_NB_TRACKS; i++)
            original[i] = g_aTrackIDs[i];
        captured = true;
    }

    randomizer_ensure_armed(live_profile_name());
    bool active = randomizer_category_active(RANDOMIZER_CAT_TRACK_ORDER);

    for (int c = 0; c < DEFAULT_NB_CIRCUIT_PER_TRACK; c++) {
        int base = c * DEFAULT_NB_CIRCUIT;
        int count = g_aTracksInCircuits[c];
        if (count < 0)
            count = 0;
        if (count > DEFAULT_NB_CIRCUIT)
            count = DEFAULT_NB_CIRCUIT;

        int slice[DEFAULT_NB_CIRCUIT];
        for (int i = 0; i < DEFAULT_NB_CIRCUIT; i++)
            slice[i] = original[base + i];

        if (active && count > 1) {
            // Fisher-Yates over the circuit's real tracks, keyed by circuit so each
            // circuit shuffles independently but stably.
            RandomizerRng rng =
                randomizer_active_stream_keyed(RANDOMIZER_CAT_TRACK_ORDER, (uint32_t) c);
            for (int i = count - 1; i > 0; i--) {
                uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
                int tmp = slice[i];
                slice[i] = slice[j];
                slice[j] = tmp;
            }
        }

        for (int i = 0; i < DEFAULT_NB_CIRCUIT; i++)
            g_aTrackIDs[base + i] = slice[i];
    }
}

// Pod handling: permute which pod gets which handling stats. swrRacer_PodHandlingData[podId]
// is the per-pod stat block that swrRace_Init copies into each pod at race start, so permuting
// this table before the roster builds makes each pod drive like a different one (and the menu
// stat bars, which read the same table, match). Idempotent from a one-time snapshot; identity
// (vanilla) when inactive.
static const int NUM_PODS = 23;

void randomizer_apply_pod_handling(void) {
    static bool captured = false;
    static PodHandlingData original[NUM_PODS];
    if (!captured) {
        for (int i = 0; i < NUM_PODS; i++)
            original[i] = swrRacer_PodHandlingData[i];
        captured = true;
    }

    randomizer_ensure_armed(live_profile_name());
    bool active = randomizer_category_active(RANDOMIZER_CAT_POD_HANDLING);

    int perm[NUM_PODS];
    for (int i = 0; i < NUM_PODS; i++)
        perm[i] = i;
    if (active) {
        RandomizerRng rng = randomizer_active_stream(RANDOMIZER_CAT_POD_HANDLING);
        for (int i = NUM_PODS - 1; i > 0; i--) {
            uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
            int tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
    }

    // Pod i takes pod perm[i]'s handling (identity restores vanilla when inactive).
    for (int i = 0; i < NUM_PODS; i++)
        swrRacer_PodHandlingData[i] = original[perm[i]];
}

// Single-player roster build: apply the pod-handling permutation just before the roster
// (and thus each pod's stats) is built. Address-only (not reimplemented).
typedef void *(swrObjHang_BuildRosterSinglePlayer_t)(swrObjHang *hang, int *out);

void *swrObjHang_BuildRosterSinglePlayer_delta(swrObjHang *hang, int *out) {
    randomizer_apply_pod_handling();
    return hook_call_original(
        (swrObjHang_BuildRosterSinglePlayer_t *) swrObjHang_BuildRosterSinglePlayer_ADDR, hang, out);
}
