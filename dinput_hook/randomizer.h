//
// Per-profile randomizer core: seed derivation, per-category RNG streams, the
// frozen per-profile config, and its sidecar persistence. Pure logic + INI IO --
// no game hooks and no ImGui live here (the UI panel and the game-side appliers
// consume this module). See RANDOMIZER_ROADMAP.md.
//
// Design in one line: the profile *name* is the seed (no tgfd.dat format change),
// the player's category choices are frozen at profile creation into a sidecar INI,
// and each category draws from its own independent RNG sub-stream so the categories
// are orthogonal.
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
    RANDOMIZER_CAT_COUNT
};

// The frozen ruleset for one profile: the opt-in master plus which categories are on.
// master == false is a completely vanilla profile (no sidecar written, no effect).
struct RandomizerConfig {
    bool master;
    bool categories[RANDOMIZER_CAT_COUNT];
};

// A deterministic PCG32 stream. Independent of the game's swrUtils_Rand (which is
// consumed every frame by effects, so borrowing it would desync effects and break
// reproducibility).
struct RandomizerRng {
    uint64_t state;
    uint64_t inc;
};

// ---- Seed + RNG (pure, no state) --------------------------------------------

// FNV-1a over the normalized profile name -> the profile's 32-bit seed. Public so
// the UI can preview the seed live while the name is being typed. Normalization
// (trailing-whitespace trim, at most 32 bytes) is frozen: changing it silently
// changes everyone's seed.
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

// ---- Creation intent (overlay -> arming) ------------------------------------

// Called by the overlay each frame the new-profile dialog is up: the name being
// typed plus the staged config. ensure_armed() freezes this config into the profile
// only when a not-yet-configured profile of the SAME name is armed -- so it can never
// leak onto a pre-existing or already-configured profile.
void randomizer_set_creation_intent(const char *profile_name, const RandomizerConfig *cfg);

// ---- Active-profile state (driven by the game-side hooks) -------------------

// Arm the randomizer for `profile_name` (idempotent for the same name). Loads the
// profile's frozen sidecar config if present; otherwise freezes either the pending
// creation intent (if it matches this name) or an all-off vanilla config, once.
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

// True when the armed profile randomizes anything -> the race must be flagged
// non-canonical for run verification (VERIFICATION_ROADMAP.md).
bool randomizer_active_is_randomized();

// A fresh stream for `cat` from the armed profile's seed (zeroed stream if none armed).
RandomizerRng randomizer_active_stream(RandomizerCategory cat);

// Keyed variant of randomizer_active_stream (e.g. key = track index).
RandomizerRng randomizer_active_stream_keyed(RandomizerCategory cat, uint32_t key);

// The armed config, for the UI to display read-only (all-off when nothing armed).
RandomizerConfig randomizer_active_config();

// ---- Pending config (UI -> creation hook) -----------------------------------

// The config the UI has staged for the *next* newly-created profile. The creation
// hook passes this to randomizer_arm_profile() as `pending`. Persisted in the
// sidecar so the choice survives restarts.
RandomizerConfig randomizer_pending_config();
void randomizer_set_pending_config(const RandomizerConfig *cfg);

// ---- UI (defined in randomizer_overlay.cpp) ---------------------------------

// Draw the contextual "Randomizer" dialog. Called every frame from imgui_Update
// (independent of the F5 debug overlay); it draws itself only while the player is
// on the new-profile name-entry screen and is a no-op otherwise.
void randomizer_render_overlay();
