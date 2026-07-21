#pragma once

// Language selection for the game's built-in racer.tab translation system.
//
// The vanilla game localizes UI/dialogue via swrText_Translate ("/KEY/english" -> localized
// value looked up in a racer.tab loaded by swrText_ParseRacerTab). Main_Startup loads a fixed
// "data\racer.tab"; the Steam build ships none, so English runs on the inline fallbacks. This
// layer picks a language at boot (persisted setting, else the OS UI language) and (re)loads
// "data/lang/<code>/racer.tab" -- English selects no tab (inline fallbacks).

struct LanguageEntry {
    const char *code;// racer.tab folder + ini value (e.g. "fr")
    const char *name;// ImGui display label (ASCII)
};

extern const LanguageEntry g_languages[];
extern const int g_language_count;

// Free the currently loaded translation table and load the one for lang_index
// (0 = English -> no tab, inline fallbacks; a missing file also falls back to English).
// Safe to call at runtime to switch language.
void localization_apply(int lang_index);

// One-time boot init (called from the mod's startup hook, after Main_Startup's own
// ParseRacerTab): resolve the language from the ini (else the OS default) and apply it.
void init_localization();
