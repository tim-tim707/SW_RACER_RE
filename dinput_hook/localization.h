#pragma once

// Language selection for the game's built-in racer.tab translation system: swrText_Translate
// ("/KEY/english" -> a value in the racer.tab loaded by swrText_ParseRacerTab). Main_Startup loads
// a fixed "data\racer.tab" and the Steam build ships none, so English runs on inline fallbacks.
// This layer loads "data/lang/<code>/racer.tab" instead; English selects no tab.

struct LanguageEntry {
    const char *code;// racer.tab folder + ini value (e.g. "fr")
    const char *name;// ImGui display label (ASCII)
};

extern const LanguageEntry g_languages[];
extern const int g_language_count;

// Load the table for lang_index, freeing the current one. 0 = English -> no tab (inline
// fallbacks), as does a missing file. Safe to call at runtime to switch language.
void localization_apply(int lang_index);

// One-time boot init (called from the mod's startup hook, after Main_Startup's own
// ParseRacerTab): resolve the language from the ini (else the OS default) and apply it.
void init_localization();
