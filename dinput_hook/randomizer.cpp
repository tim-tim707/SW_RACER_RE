//
// Per-profile randomizer core. See randomizer.h.
//

#include "randomizer.h"

#include <cstring>
#include <string>
#include <filesystem>

#include <windows.h>

// ---- Hash + PRNG constants (standard algorithm constants, named for clarity) ----

static constexpr uint32_t FNV1A_OFFSET_BASIS = 2166136261u;
static constexpr uint32_t FNV1A_PRIME = 16777619u;

// PCG32 (O'Neill) multiplier for the LCG step.
static constexpr uint64_t PCG_MULTIPLIER = 6364136223846793005ull;

// Per-category stream tags, hashed into the stream seed so the categories are
// orthogonal. Fixed strings -> fixed tags; do not reorder or rename.
static const char *const CATEGORY_STREAM_NAMES[RANDOMIZER_CAT_COUNT] = {
    "ai",       "money",  "unlocks", "tracks",   "pods",
    "favorite", "mirror", "laps",    "shop",     "winnings"};

// ---- FNV-1a ----------------------------------------------------------------

static uint32_t fnv1a(const char *data, size_t len) {
    uint32_t h = FNV1A_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t) data[i];
        h *= FNV1A_PRIME;
    }
    return h;
}

// ---- Seed ------------------------------------------------------------------

uint32_t randomizer_seed_from_name(const char *profile_name) {
    if (!profile_name)
        return 0;

    // Frozen normalization: at most 32 bytes (the profile-name field width), stop at
    // the null terminator, and drop trailing spaces so "WATTO" and "WATTO   " hash
    // identically. Case is preserved (the game's name entry is fixed-case already).
    char buf[32];
    size_t len = 0;
    while (len < sizeof(buf) && profile_name[len] != '\0') {
        buf[len] = profile_name[len];
        len++;
    }
    while (len > 0 && buf[len - 1] == ' ')
        len--;

    return fnv1a(buf, len);
}

// ---- PCG32 -----------------------------------------------------------------

uint32_t randomizer_next_u32(RandomizerRng *rng) {
    uint64_t old = rng->state;
    rng->state = old * PCG_MULTIPLIER + rng->inc;
    uint32_t xorshifted = (uint32_t) (((old >> 18u) ^ old) >> 27u);
    uint32_t rot = (uint32_t) (old >> 59u);
    return (xorshifted >> rot) | (xorshifted << ((-(int32_t) rot) & 31));
}

static void pcg_seed(RandomizerRng *rng, uint64_t init_state, uint64_t init_seq) {
    rng->state = 0;
    rng->inc = (init_seq << 1u) | 1u;
    randomizer_next_u32(rng);
    rng->state += init_state;
    randomizer_next_u32(rng);
}

// Golden-ratio odd constant, for folding an extra key into the stream (Fibonacci hashing).
static constexpr uint32_t KEY_MIX = 0x9e3779b9u;

RandomizerRng randomizer_stream_keyed(uint32_t seed, RandomizerCategory cat, uint32_t key) {
    RandomizerRng rng{};
    if (cat < 0 || cat >= RANDOMIZER_CAT_COUNT)
        return rng;

    const char *tag_name = CATEGORY_STREAM_NAMES[cat];
    uint32_t tag = fnv1a(tag_name, strlen(tag_name)) ^ (key * KEY_MIX);

    // Fold the profile seed and the (category, key) tag into the two PCG init words so
    // both the sequence and the starting point differ per category and per key.
    uint64_t init_state = ((uint64_t) seed << 32) | tag;
    uint64_t init_seq = ((uint64_t) tag << 32) | seed;
    pcg_seed(&rng, init_state, init_seq);
    return rng;
}

RandomizerRng randomizer_stream(uint32_t seed, RandomizerCategory cat) {
    return randomizer_stream_keyed(seed, cat, 0);
}

uint32_t randomizer_next_below(RandomizerRng *rng, uint32_t bound) {
    if (bound == 0)
        return 0;

    // Rejection sampling for an unbiased result in [0, bound).
    uint32_t threshold = (uint32_t) (-(int32_t) bound) % bound;// == 2^32 % bound
    for (;;) {
        uint32_t r = randomizer_next_u32(rng);
        if (r >= threshold)
            return r % bound;
    }
}

float randomizer_next_unit(RandomizerRng *rng) {
    // Top 24 bits -> [0, 1) with full float mantissa precision.
    return (float) (randomizer_next_u32(rng) >> 8) * (1.0f / 16777216.0f);
}

// ---- Sidecar persistence (INI, one section per profile) --------------------

// Co-located with tgfd.dat under .\data\player, keyed by profile name. Kept out of
// the CRC-protected save so the vanilla tgfd.dat format is never touched.
static std::wstring sidecar_path() {
    wchar_t buff[1024];
    GetModuleFileNameW(nullptr, buff, (DWORD) std::size(buff));
    return (std::filesystem::path(buff).parent_path() / "data" / "player" / "randomizer.ini")
        .wstring();
}

static std::wstring widen(const char *s) {
    if (!s)
        return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 0)
        return L"";
    std::wstring w(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
    return w;
}

// Per-category INI key. Order-independent of the enum value (keyed by name), so
// reordering the enum never remaps a saved profile's categories.
static const wchar_t *const CATEGORY_INI_KEYS[RANDOMIZER_CAT_COUNT] = {
    L"cat_ai",       L"cat_money",  L"cat_unlocks", L"cat_tracks", L"cat_pods",
    L"cat_favorite", L"cat_mirror", L"cat_laps",    L"cat_shop",   L"cat_winnings"};

// Sentinel that distinguishes "profile has a frozen config" from "never created".
static const wchar_t *const KEY_WRITTEN = L"written";
static const wchar_t *const KEY_MASTER = L"master";

static bool sidecar_has_config(const std::wstring &section, const std::wstring &path) {
    return GetPrivateProfileIntW(section.c_str(), KEY_WRITTEN, 0, path.c_str()) != 0;
}

static RandomizerConfig sidecar_read(const std::wstring &section, const std::wstring &path) {
    RandomizerConfig cfg{};
    cfg.master = GetPrivateProfileIntW(section.c_str(), KEY_MASTER, 0, path.c_str()) != 0;
    for (int i = 0; i < RANDOMIZER_CAT_COUNT; i++)
        cfg.categories[i] =
            GetPrivateProfileIntW(section.c_str(), CATEGORY_INI_KEYS[i], 0, path.c_str()) != 0;
    int pods = GetPrivateProfileIntW(section.c_str(), L"pod_count", 6, path.c_str());
    cfg.starting_pod_count = (pods < 1) ? 1 : (pods > 23) ? 23 : pods;
    return cfg;
}

static void sidecar_write(const std::wstring &section, const std::wstring &path,
                          const RandomizerConfig &cfg) {
    WritePrivateProfileStringW(section.c_str(), KEY_MASTER, cfg.master ? L"1" : L"0", path.c_str());
    for (int i = 0; i < RANDOMIZER_CAT_COUNT; i++)
        WritePrivateProfileStringW(section.c_str(), CATEGORY_INI_KEYS[i],
                                   cfg.categories[i] ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(section.c_str(), L"pod_count",
                               std::to_wstring(cfg.starting_pod_count).c_str(), path.c_str());
    // Written last so a partial write is never mistaken for a frozen config.
    WritePrivateProfileStringW(section.c_str(), KEY_WRITTEN, L"1", path.c_str());
}

// ---- Creation intent -------------------------------------------------------

// Set by the overlay each frame the new-profile dialog is up: the name being typed
// plus the staged config. ensure_armed consumes it only for a matching, not-yet-seen
// name -- so the staged config is frozen into the profile being created and never
// leaks onto a pre-existing profile (name mismatch) or an already-configured one
// (sidecar already exists).
static bool g_intent_active = false;
static char g_intent_name[32] = {0};
static RandomizerConfig g_intent_config{};

// Set once when ensure_armed freezes a brand-new profile (intent consumed). Lets the
// Class-A applier (starting unlocks/money) run exactly once, at creation.
static bool g_just_created = false;

static bool names_equal(const char *a, const char *b) {
    // Same normalization as the seed: compare up to 32 bytes, ignore trailing spaces.
    char na[32], nb[32];
    auto norm = [](const char *s, char *out) {
        size_t n = 0;
        while (n < 32 && s && s[n])
            out[n] = s[n], n++;
        while (n > 0 && out[n - 1] == ' ')
            n--;
        return n;
    };
    size_t la = norm(a, na), lb = norm(b, nb);
    return la == lb && memcmp(na, nb, la) == 0;
}

void randomizer_set_creation_intent(const char *profile_name, const RandomizerConfig *cfg) {
    if (!profile_name || !cfg)
        return;
    g_intent_active = true;
    g_intent_config = *cfg;
    size_t n = 0;
    for (; n + 1 < sizeof(g_intent_name) && profile_name[n]; n++)
        g_intent_name[n] = profile_name[n];
    g_intent_name[n] = '\0';
}

// ---- Active-profile state --------------------------------------------------

static bool g_armed = false;
static uint32_t g_active_seed = 0;
static RandomizerConfig g_active_config{};
static char g_active_name[32] = {0};

void randomizer_ensure_armed(const char *profile_name) {
    if (!profile_name || !profile_name[0])
        return;
    if (g_armed && names_equal(g_active_name, profile_name))
        return;// already armed for this profile

    std::wstring path = sidecar_path();
    std::wstring section = widen(profile_name);

    if (sidecar_has_config(section, path)) {
        // A frozen config already exists for this profile -- honor it.
        g_active_config = sidecar_read(section, path);
    } else if (g_intent_active && names_equal(g_intent_name, profile_name)) {
        // This is the profile currently being created via the dialog: freeze the
        // staged config into it, once.
        g_active_config = g_intent_config;
        sidecar_write(section, path, g_active_config);
        g_intent_active = false;
        g_just_created = true;
    } else {
        // A profile with no config and no creation intent -- a pre-existing / vanilla
        // profile. Freeze it as all-off so it is recorded and never randomized.
        g_active_config = RandomizerConfig{};
        sidecar_write(section, path, g_active_config);
    }

    g_active_seed = randomizer_seed_from_name(profile_name);
    size_t n = 0;
    for (; n + 1 < sizeof(g_active_name) && profile_name[n]; n++)
        g_active_name[n] = profile_name[n];
    g_active_name[n] = '\0';
    g_armed = true;
}

void randomizer_disarm() {
    g_armed = false;
    g_active_seed = 0;
    g_active_config = RandomizerConfig{};
    g_active_name[0] = '\0';
}

bool randomizer_is_armed() {
    return g_armed;
}

bool randomizer_consume_just_created() {
    bool v = g_just_created;
    g_just_created = false;
    return v;
}

bool randomizer_category_active(RandomizerCategory cat) {
    if (!g_armed || !g_active_config.master)
        return false;
    if (cat < 0 || cat >= RANDOMIZER_CAT_COUNT)
        return false;
    return g_active_config.categories[cat];
}

uint32_t randomizer_active_seed() {
    return g_armed ? g_active_seed : 0;
}

bool randomizer_active_is_randomized() {
    if (!g_armed || !g_active_config.master)
        return false;
    for (int i = 0; i < RANDOMIZER_CAT_COUNT; i++)
        if (g_active_config.categories[i])
            return true;
    return false;
}

RandomizerRng randomizer_active_stream(RandomizerCategory cat) {
    if (!g_armed)
        return RandomizerRng{};
    return randomizer_stream(g_active_seed, cat);
}

RandomizerRng randomizer_active_stream_keyed(RandomizerCategory cat, uint32_t key) {
    if (!g_armed)
        return RandomizerRng{};
    return randomizer_stream_keyed(g_active_seed, cat, key);
}

RandomizerConfig randomizer_active_config() {
    return g_armed ? g_active_config : RandomizerConfig{};
}

// ---- Pending config --------------------------------------------------------

// Section name for the staged "next new profile" config. The '*' cannot be entered
// on the in-game name screen, so it can never collide with a real profile section.
static const wchar_t *const PENDING_SECTION = L"*pending";

static bool g_pending_loaded = false;
static RandomizerConfig g_pending{};

RandomizerConfig randomizer_pending_config() {
    if (!g_pending_loaded) {
        g_pending = sidecar_read(PENDING_SECTION, sidecar_path());
        g_pending_loaded = true;
    }
    return g_pending;
}

void randomizer_set_pending_config(const RandomizerConfig *cfg) {
    if (!cfg)
        return;
    g_pending = *cfg;
    g_pending_loaded = true;
    sidecar_write(PENDING_SECTION, sidecar_path(), g_pending);
}
