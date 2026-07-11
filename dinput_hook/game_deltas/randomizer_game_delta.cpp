//
// Randomizer game-side integration: the thin hooks that arm the per-profile
// randomizer and apply its effects to the running game. The seed/config/sidecar
// logic lives in ../randomizer.{h,cpp}; this file only bridges to the engine.
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
#include "../patch.h"
#include "../randomizer.h"

// The pods unlocked by default in a vanilla profile -- swrRace_BuildPartMenuList's base-pod OR mask
// 0x22e01 (pods 0, 9, 10, 11, 13, 17). Track Favorites' "exclude starter pods" sub-option drops
// these from the reward deck so a win only ever unlocks a pod you did not already start with.
static const uint32_t STARTER_POD_MASK = 0x22e01;

// Distinct RNG key for the cross-circuit track shuffle so its single global permutation never
// collides with the per-circuit within-circuit shuffles (which key by circuit index 0..3).
static const uint32_t TRACK_ORDER_CROSS_KEY = 0x100;

// swrRace_ResultsMenu hardcodes Sebulba (pod 2) to only unlock on physical track 1:
//   if (FavoritePilot == 2 && track_index != 1) FavoritePilot = 0;   // XOR ECX,ECX @ 0x0043a2b9
// so winning any OTHER track whose favorite is Sebulba grants nothing. That silently swallows the
// reward wherever the randomizer deals pod 2. While Track Favorites is active we NOP the XOR so
// every track unlocks whatever pod it was dealt; the byte is restored (via the patch journal) when
// the category is inactive, preserving vanilla behavior for normal profiles.
static const uint32_t SEBULBA_GUARD_XOR_ADDR = 0x0043a2b9;
static const char *const SEBULBA_GUARD_OWNER = "randomizer_track_favorite";

static void randomizer_set_sebulba_guard_patched(bool patched) {
    static bool current = false;
    if (patched == current)
        return;// edge-triggered: never re-journal the same state (avoids unbounded journal growth)
    if (patched) {
        static const uint8_t nops[2] = {0x90, 0x90};
        WriteMemory(SEBULBA_GUARD_OWNER, (void *) SEBULBA_GUARD_XOR_ADDR, nops, sizeof(nops));
    } else {
        UndoOwner(SEBULBA_GUARD_OWNER);
    }
    current = patched;
}

// The name of the profile currently in play. Uses the WORKING profile slot (the
// authoritative in-memory profile the menus/shop read), not the save-image slot: the
// menu-time appliers below (track order, favorites, winnings, mirror/laps, shop, AI) run
// in the hangar BEFORE any race, and the save image is only synced from the working
// profile at save/race time -- so keying off it there would arm a stale/previous profile
// after a profile switch. The working slot is current on every screen.
static const char *live_profile_name() {
    return swrRace_workingProfileName;
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

    // Never in multiplayer: these are shared globals and the randomizer is single-player
    // only. Since disarm is never called, an SP-armed profile would otherwise randomize
    // AI in a subsequent MP race. The original call above already set vanilla values.
    if (multiplayer_enabled)
        return;

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

    // Preserve the original's reverse-track / special-event fixed-spread override
    // (InitAISettingsForTrack forces ai_spread = 2.0 when flag & 0x20), the same way we
    // re-apply the AI Speed scale above -- otherwise reverse/special races get the wrong
    // AI field spacing.
    if ((judge->flag & 0x20) != 0)
        ai_spread = 2.0f;
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
    bool cross = active && randomizer_active_config().track_cross_circuit;

    // Rebuild from the vanilla snapshot every call: idempotent, and restores vanilla when inactive.
    for (int i = 0; i < DEFAULT_NB_TRACKS; i++)
        g_aTrackIDs[i] = original[i];
    if (!active)
        return;

    // Per-circuit real-track counts; the trailing (empty / -1) slots are left untouched so a
    // circuit never gains or loses a slot -- only which track sits in each real slot changes.
    int count[DEFAULT_NB_CIRCUIT_PER_TRACK];
    for (int c = 0; c < DEFAULT_NB_CIRCUIT_PER_TRACK; c++) {
        int n = g_aTracksInCircuits[c];
        count[c] = (n < 0) ? 0 : (n > DEFAULT_NB_CIRCUIT) ? DEFAULT_NB_CIRCUIT : n;
    }

    if (cross) {
        // Pool every circuit's real tracks, shuffle the whole pool once, then deal it back into the
        // same-shaped real slots -- per-circuit sizes are preserved, but a track can land in any
        // circuit (progression still keys off slot position, not track id, so it stays sound).
        int pool[DEFAULT_NB_TRACKS];
        int poolN = 0;
        for (int c = 0; c < DEFAULT_NB_CIRCUIT_PER_TRACK; c++)
            for (int i = 0; i < count[c]; i++)
                pool[poolN++] = original[c * DEFAULT_NB_CIRCUIT + i];

        RandomizerRng rng =
            randomizer_active_stream_keyed(RANDOMIZER_CAT_TRACK_ORDER, TRACK_ORDER_CROSS_KEY);
        for (int i = poolN - 1; i > 0; i--) {
            uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
            int tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
        }

        int p = 0;
        for (int c = 0; c < DEFAULT_NB_CIRCUIT_PER_TRACK; c++)
            for (int i = 0; i < count[c]; i++)
                g_aTrackIDs[c * DEFAULT_NB_CIRCUIT + i] = pool[p++];
        return;
    }

    // Within-circuit shuffle: Fisher-Yates over each circuit's real tracks, keyed by circuit so each
    // circuit shuffles independently but stably.
    for (int c = 0; c < DEFAULT_NB_CIRCUIT_PER_TRACK; c++) {
        if (count[c] <= 1)
            continue;
        RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_TRACK_ORDER, (uint32_t) c);
        int base = c * DEFAULT_NB_CIRCUIT;
        for (int i = count[c] - 1; i > 0; i--) {
            uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
            int tmp = g_aTrackIDs[base + i];
            g_aTrackIDs[base + i] = g_aTrackIDs[base + j];
            g_aTrackIDs[base + j] = tmp;
        }
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
    // Never in multiplayer: this table is shared and read by the MP roster builder, so an
    // SP-armed profile (disarm is never called) would otherwise leak its permutation into a
    // later MP race and desync clients. Treat as inactive -> the identity restore below
    // returns the table to vanilla.
    bool active = !multiplayer_enabled && randomizer_category_active(RANDOMIZER_CAT_POD_HANDLING);

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

// Vehicle-select stat bars read swrRacer_PodHandlingData via swrObjHang_ComputeUpgradedStats.
// Permute the table before it computes so the previewed bars match how the pod will actually drive
// (BuildRosterSinglePlayer alone only fixed the race, not the menu). Idempotent. Address-only.
typedef void(swrObjHang_ComputeUpgradedStats_t)(int, int, char, char);

void swrObjHang_ComputeUpgradedStats_delta(int podIndex, int upgradeSlot, char upgradeType,
                                           char upgradeLevel) {
    randomizer_apply_pod_handling();
    hook_call_original((swrObjHang_ComputeUpgradedStats_t *) swrObjHang_ComputeUpgradedStats_ADDR,
                       podIndex, upgradeSlot, upgradeType, upgradeLevel);
}

// The working (live) profile, slot 0: the authoritative in-memory profile the menus/shop read
// and that SaveCurrentProfile copies into the save image + tgfd.dat.
static const char *working_profile_name(void) {
    return swrRace_workingProfileName;
}
static uint32_t *working_pod_unlock_mask(void) {
    return &swrRace_workingPodUnlockMask;
}

static const uint32_t START_TRUGUTS_MIN = 0;
static const uint32_t START_TRUGUTS_MAX = 5000;

// Class-A: randomize the new profile's starting money and/or which pods start unlocked
// (independent toggles, independent sub-streams), writing them into the working profile. Track
// unlocks are deliberately left at their defaults so race progression can never be soft-locked.
// Called once at creation; each write is a no-op unless its category is active.
//
// Starting Pods unlocks EXACTLY N randomly-chosen pods (N from the profile's slider, 1..23). The
// game's swrRace_BuildPartMenuList normally force-ORs 6 base pods (0x22e01), which would floor the
// count at 6; that OR is neutralized once at hook install (see renderer_hook.cpp) so the mask alone
// controls the roster. N >= 1 guarantees at least one drivable pod.
void randomizer_apply_starting_state(void) {
    if (randomizer_category_active(RANDOMIZER_CAT_STARTING_MONEY)) {
        RandomizerRng rng = randomizer_active_stream(RANDOMIZER_CAT_STARTING_MONEY);
        uint32_t truguts = START_TRUGUTS_MIN +
                           randomizer_next_below(&rng, START_TRUGUTS_MAX - START_TRUGUTS_MIN + 1);
        swrRace_truguts = (int) truguts;
    }

    if (randomizer_category_active(RANDOMIZER_CAT_STARTING_UNLOCKS)) {
        int n = randomizer_active_config().starting_pod_count;
        if (n < 1)
            n = 1;
        if (n > NUM_PODS)
            n = NUM_PODS;

        // Shuffle a deck of all pods and take the first N -> exactly N distinct unlocked pods.
        uint8_t deck[NUM_PODS];
        for (int i = 0; i < NUM_PODS; i++)
            deck[i] = (uint8_t) i;
        RandomizerRng rng = randomizer_active_stream(RANDOMIZER_CAT_STARTING_UNLOCKS);
        for (int i = NUM_PODS - 1; i > 0; i--) {
            uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
            uint8_t t = deck[i];
            deck[i] = deck[j];
            deck[j] = t;
        }
        uint32_t mask = 0;
        for (int k = 0; k < n; k++)
            mask |= (1u << deck[k]);
        *working_pod_unlock_mask() = mask;
    }
}

// Autosave. We arm from the working profile name (authoritative and already current here,
// unlike the save image which this function is about to sync), and apply the Class-A starting
// state exactly once at creation -- before the original copies the profile to the save image
// and writes tgfd.dat, so the randomized start persists. Address-only (not reimplemented).
typedef void(swrRace_SaveCurrentProfile_t)(void);

void swrRace_SaveCurrentProfile_delta(void) {
    randomizer_ensure_armed(working_profile_name());
    if (randomizer_consume_just_created()) {
        randomizer_apply_starting_state();// no-op unless a starting-* category is active
    }
    hook_call_original((swrRace_SaveCurrentProfile_t *) swrRace_SaveCurrentProfile_ADDR);
}

// Track pod rewards: randomize each track's FavoritePilot. Winning a tournament track unlocks
// that track's FavoritePilot's pod (swrRace_ResultsMenu: podracers_unlocked |= 1 << FavoritePilot),
// so this randomizes which pod each track rewards. Rewards are dealt from a shuffled deck of all
// 23 pods without replacement -- every pod appears once before any repeats (with 25 tracks, only
// the last 2 can duplicate). Uses one sequential stream so the deal is a stable permutation per
// profile; idempotent (rebuilt each call); vanilla when inactive.
static const int NUM_TRACK_INFOS = 25;

static void fisher_yates_u8(uint8_t *deck, int n, RandomizerRng *rng) {
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = randomizer_next_below(rng, (uint32_t) (i + 1));
        uint8_t t = deck[i];
        deck[i] = deck[j];
        deck[j] = t;
    }
}

extern "C" void randomizer_apply_track_favorite(void) {
    static bool captured = false;
    static uint8_t original[NUM_TRACK_INFOS];
    if (!captured) {
        for (int t = 0; t < NUM_TRACK_INFOS; t++)
            original[t] = g_aTrackInfos[t].FavoritePilot;
        captured = true;
    }

    randomizer_ensure_armed(live_profile_name());
    bool active = randomizer_category_active(RANDOMIZER_CAT_TRACK_FAVORITE);

    // Sebulba (pod 2) is gated to physical track 1 by a hardcode in swrRace_ResultsMenu; neutralize
    // that guard while this category is active so a track can actually reward the pod it was dealt.
    randomizer_set_sebulba_guard_patched(active);

    if (!active) {
        for (int t = 0; t < NUM_TRACK_INFOS; t++) {
            g_aTrackInfos[t].FavoritePilot = original[t];
            g_aNewTrackInfos[t].FavoritePilot = original[t];
        }
        return;
    }

    // Build the reward deck: all 23 pods, or the non-default pods only when "exclude starter pods"
    // is on (so wins never re-hand a pod the profile already starts with).
    bool exclude = randomizer_active_config().favorite_exclude_starters;
    uint8_t deck[NUM_PODS];
    int deckN = 0;
    for (int i = 0; i < NUM_PODS; i++) {
        if (exclude && ((STARTER_POD_MASK >> i) & 1u))
            continue;
        deck[deckN++] = (uint8_t) i;
    }

    // Deal from the shuffled deck; reshuffle only once exhausted so every pod in the deck is used
    // before any duplicate.
    RandomizerRng rng = randomizer_active_stream(RANDOMIZER_CAT_TRACK_FAVORITE);
    int pos = deckN;// force an initial shuffle

    for (int t = 0; t < NUM_TRACK_INFOS; t++) {
        if (pos >= deckN) {
            fisher_yates_u8(deck, deckN, &rng);
            pos = 0;
        }
        uint8_t val = deck[pos++];
        // Write BOTH the vanilla table (read by the original swrRace_ResultsMenu unlock code) and
        // the custom-tracks inflated table (read by the menu display + reimplemented flow).
        g_aTrackInfos[t].FavoritePilot = val;
        g_aNewTrackInfos[t].FavoritePilot = val;
    }
}

// Per-track race settings (free play): seed a randomized mirror flag and/or lap count for the
// selected track. Seeded only when the selected track (or profile) changes, so the free-play
// menu's own mirror/laps controls remain free to override for the current visit; re-visiting a
// track restores its deterministic default. numLaps clamped 1-5. No-op unless a category is on.
extern "C" void randomizer_apply_track_race_settings(swrObjHang *hang) {
    if (!hang)
        return;

    randomizer_ensure_armed(live_profile_name());
    bool mirror = randomizer_category_active(RANDOMIZER_CAT_MIRROR);
    bool laps = randomizer_category_active(RANDOMIZER_CAT_LAPS);
    if (!mirror && !laps)
        return;

    // Key by the track's planet-slot (planetTrackNumber + PlanetIdx*4) -- the SAME key the
    // tournament override (swrObjJdge_F4_delta) uses -- so a given physical track gets identical
    // mirror/laps in both free play and tournament, regardless of track-order shuffling.
    int tid = (int) hang->track_index;
    int track = (tid >= 0 && tid < 25)
                    ? (g_aTrackInfos[tid].planetTrackNumber + g_aTrackInfos[tid].PlanetIdx * 4)
                    : tid;

    // Re-seed only on a track/profile change (not every frame), so the player owns any manual
    // adjustment until they move to another track.
    static uint32_t lastSeed = 0;
    static int lastTrack = -1;
    uint32_t seed = randomizer_active_seed();
    if (track == lastTrack && seed == lastSeed)
        return;
    lastTrack = track;
    lastSeed = seed;

    if (mirror) {
        RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_MIRROR, (uint32_t) track);
        hang->bMirror = (char) randomizer_next_below(&rng, 2);
    }
    if (laps) {
        RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_LAPS, (uint32_t) track);
        hang->numLaps = (char) (1 + randomizer_next_below(&rng, 5));
    }
}

// Tournament laps/mirror override. Tournament forces 3 laps / no mirror into the race config,
// and it doesn't go through the free-play course-select seed. swrObjJdge_F4's 'Begn' sub-event
// latches num_laps from subEvents[9] and the mirror flag from subEvents[0xd] (then InitTrack builds
// the track), so we rewrite those in tournament BEFORE the original runs. Free play is left alone
// (it uses the player-adjustable hang->numLaps seeded on the course-select screen).
int swrObjJdge_F4_delta(swrObjJdge *jdge, int *subEvents, int p3) {
    if (*subEvents == 'Begn' && g_objHang2 && g_objHang2->isTournamentMode) {
        randomizer_ensure_armed(live_profile_name());
        uint32_t track = (uint32_t) (subEvents[7] + subEvents[3] * 4);// planet_track_number + planetId*4
        if (randomizer_category_active(RANDOMIZER_CAT_LAPS)) {
            RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_LAPS, track);
            subEvents[9] = 1 + (int) randomizer_next_below(&rng, 5);
        }
        if (randomizer_category_active(RANDOMIZER_CAT_MIRROR)) {
            RandomizerRng rng = randomizer_active_stream_keyed(RANDOMIZER_CAT_MIRROR, track);
            subEvents[0xd] = (int) randomizer_next_below(&rng, 2);
        }
    }
    return hook_call_original(swrObjJdge_F4, jdge, subEvents, p3);
}

// Race winnings: shuffle the 12-value prize table (3 payout modes x 4 places). The values are a
// constant base set written once by swrObjHang_Init into hang->winnings (@ +0x92); the ONLY
// per-circuit difference vanilla applies is a read-time linear scale (K1 - circuitIdx*K2), so a
// single profile-wide shuffle leaves every circuit with the same relative prize pattern (just
// scaled). Keying the shuffle by the currently-viewed circuit (hang->circuitIdx, which the payout
// read also scales by) gives each circuit its own distinct permutation. Idempotent from a one-time
// snapshot -- it reshuffles for whatever circuit is showing; vanilla when inactive.
static const int WINNINGS_COUNT = 12;// 3 modes x 4 places

extern "C" void randomizer_apply_winnings(swrObjHang *hang) {
    if (!hang)
        return;

    static bool captured = false;
    static int16_t original[WINNINGS_COUNT];
    int16_t *w = &hang->winnings.truguts[0][0];
    if (!captured) {
        for (int i = 0; i < WINNINGS_COUNT; i++)
            original[i] = w[i];
        captured = true;
    }

    randomizer_ensure_armed(live_profile_name());
    if (!randomizer_category_active(RANDOMIZER_CAT_WINNINGS)) {
        for (int i = 0; i < WINNINGS_COUNT; i++)
            w[i] = original[i];
        return;
    }

    int16_t vals[WINNINGS_COUNT];
    for (int i = 0; i < WINNINGS_COUNT; i++)
        vals[i] = original[i];
    RandomizerRng rng =
        randomizer_active_stream_keyed(RANDOMIZER_CAT_WINNINGS, (uint32_t) hang->circuitIdx);
    for (int i = WINNINGS_COUNT - 1; i > 0; i--) {
        uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
        int16_t t = vals[i];
        vals[i] = vals[j];
        vals[j] = t;
    }
    for (int i = 0; i < WINNINGS_COUNT; i++)
        w[i] = vals[i];
}

// Shop prices: shuffle the pod-part upgrade costs among the upgrade slots. upgradeInfos[42]
// (swrUpgradeInfo, 16B) is 7 categories x 6 slots; slot 0 of each (index % 6 == 0) is the base
// part (kept vanilla), slots 1-5 are the buyable upgrades. `.cost` is read by
// swrRace_ComputeUpgradePrices. Idempotent from a one-time snapshot; vanilla when inactive.
static const int SHOP_NUM_ENTRIES = 42;
static const int SHOP_SLOTS_PER_CATEGORY = 6;

void randomizer_apply_shop_prices(void) {
    static bool captured = false;
    static uint32_t original[SHOP_NUM_ENTRIES];
    if (!captured) {
        for (int i = 0; i < SHOP_NUM_ENTRIES; i++)
            original[i] = upgradeInfos[i].cost;
        captured = true;
    }

    randomizer_ensure_armed(live_profile_name());
    if (!randomizer_category_active(RANDOMIZER_CAT_SHOP_PRICES)) {
        for (int i = 0; i < SHOP_NUM_ENTRIES; i++)
            upgradeInfos[i].cost = original[i];
        return;
    }

    // Collect the upgrade-slot costs (skip each category's base slot), shuffle, deal back.
    uint32_t costs[SHOP_NUM_ENTRIES];
    int idxs[SHOP_NUM_ENTRIES];
    int n = 0;
    for (int i = 0; i < SHOP_NUM_ENTRIES; i++) {
        if (i % SHOP_SLOTS_PER_CATEGORY == 0)
            continue;// base slot -> keep vanilla
        costs[n] = original[i];
        idxs[n] = i;
        n++;
    }

    RandomizerRng rng = randomizer_active_stream(RANDOMIZER_CAT_SHOP_PRICES);
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = randomizer_next_below(&rng, (uint32_t) (i + 1));
        uint32_t t = costs[i];
        costs[i] = costs[j];
        costs[j] = t;
    }

    for (int i = 0; i < SHOP_NUM_ENTRIES; i++)
        upgradeInfos[i].cost = original[i];// base slots (and a clean baseline)
    for (int k = 0; k < n; k++)
        upgradeInfos[idxs[k]].cost = costs[k];
}

// Prices are read/computed here when the shop is shown; apply the shuffle first. Address-only.
typedef void(swrRace_ComputeUpgradePrices_t)(void);

void swrRace_ComputeUpgradePrices_delta(void) {
    randomizer_apply_shop_prices();
    hook_call_original((swrRace_ComputeUpgradePrices_t *) swrRace_ComputeUpgradePrices_ADDR);
}
