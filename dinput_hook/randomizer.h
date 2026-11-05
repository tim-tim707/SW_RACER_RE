// Per-profile randomizer core: seed derivation, per-category RNG streams, the frozen per-profile
// config, and its sidecar persistence. Pure logic + INI IO -- no game hooks, no ImGui.
//
// The profile NAME is the seed (so tgfd.dat's format is untouched), the category choices are frozen
// at profile creation into a sidecar INI, and each category draws from its own RNG sub-stream.
//
#pragma once

#include <cstdint>

// Categories that can be independently randomized. Each has its own RNG sub-stream,
// so enabling/disabling one leaves every other category's result byte-identical.
enum RandomizerCategory {
    RANDOMIZER_CAT_AI_DIFFICULTY = 0,
    RANDOMIZER_CAT_STARTING_MONEY,
    RANDOMIZER_CAT_STARTING_UNLOCKS,
    RANDOMIZER_CAT_TRACK_ORDER,
    RANDOMIZER_CAT_POD_HANDLING,
    RANDOMIZER_CAT_TRACK_FAVORITE,
    RANDOMIZER_CAT_MIRROR,
    RANDOMIZER_CAT_LAPS,
    RANDOMIZER_CAT_SHOP_PRICES,
    RANDOMIZER_CAT_WINNINGS,
    RANDOMIZER_CAT_COUNT
};

// The frozen ruleset for one profile: the opt-in master plus which categories are on.
// master == false is a completely vanilla profile (no sidecar written, no effect).
struct RandomizerConfig {
    bool master;
    bool categories[RANDOMIZER_CAT_COUNT];
    int starting_pod_count;         // how many pods start unlocked (1-23); used when STARTING_UNLOCKS is on
    bool track_cross_circuit;       // TRACK_ORDER sub-option: shuffle tracks across circuits, not just within
    bool favorite_exclude_starters; // TRACK_FAVORITE sub-option: never deal a default-unlocked pod as a reward
};

// Deterministic PCG32. Independent of swrUtils_Rand, which effects consume every frame -- sharing
// it would desync them and break reproducibility.
struct RandomizerRng {
    uint64_t state;
    uint64_t inc;
};


// FNV-1a over the normalized profile name. The normalization (trailing-whitespace trim, at most
// 32 bytes) is FROZEN: changing it silently changes everyone's seed.
uint32_t randomizer_seed_from_name(const char *profile_name);

// A fresh RNG stream for `cat`, seeded from (profile seed, category). Orthogonal
// across categories.
RandomizerRng randomizer_stream(uint32_t seed, RandomizerCategory cat);

// Like randomizer_stream but also folds `key` in, so results are stable per key yet
// distinct (e.g. key = track index for stable-but-varied per-track values).
// randomizer_stream(s, c) == randomizer_stream_keyed(s, c, 0).
RandomizerRng randomizer_stream_keyed(uint32_t seed, RandomizerCategory cat, uint32_t key);

uint32_t randomizer_next_u32(RandomizerRng *rng);
uint32_t randomizer_next_below(RandomizerRng *rng, uint32_t bound);// unbiased [0, bound)
float randomizer_next_unit(RandomizerRng *rng);                    // [0, 1)


// ensure_armed() freezes this config only when a not-yet-configured profile of the SAME name is
// armed, so it can never leak onto a pre-existing or already-configured profile.
void randomizer_set_creation_intent(const char *profile_name, const RandomizerConfig *cfg);

// Drop any pending creation intent, bounding it to the dialog that staged it (see the .cpp).
void randomizer_clear_creation_intent(void);


// Idempotent for the same name. Loads the frozen sidecar config if present, else freezes either
// the pending creation intent (on a name match) or an all-off vanilla config, once.
void randomizer_ensure_armed(const char *profile_name);

// Clear the armed state (no profile active, e.g. back at the profile-select menu).
void randomizer_disarm();

// True once a profile has been armed (a profile is in the working set).
bool randomizer_is_armed();

// Returns (and clears) whether the last ensure_armed() froze a brand-new profile.
// The Class-A starting-state applier uses this to run exactly once, at creation.
bool randomizer_consume_just_created();

// True only when a profile is armed, its master is on, and `cat` is enabled.
// The game-side appliers gate on this.
bool randomizer_category_active(RandomizerCategory cat);

// The armed profile's seed (0 when nothing is armed).
uint32_t randomizer_active_seed();

// True when the armed profile randomizes anything -> lets a caller flag the run as
// non-canonical (e.g. for run/record verification).
bool randomizer_active_is_randomized();

// A fresh stream for `cat` from the armed profile's seed (zeroed stream if none armed).
RandomizerRng randomizer_active_stream(RandomizerCategory cat);

// Keyed variant of randomizer_active_stream (e.g. key = track index).
RandomizerRng randomizer_active_stream_keyed(RandomizerCategory cat, uint32_t key);

// The armed config, for the UI to display read-only (all-off when nothing armed).
RandomizerConfig randomizer_active_config();


// Staged for the NEXT newly-created profile; the creation hook passes it to
// randomizer_arm_profile() as `pending`. Persisted so the choice survives restarts.
RandomizerConfig randomizer_pending_config();
void randomizer_set_pending_config(const RandomizerConfig *cfg);


// Called every frame from imgui_Update, independent of the F5 overlay; draws itself only on the
// new-profile name-entry screen.
void randomizer_render_overlay();
