#include "localization.h"

#include <windows.h>
#include <filesystem>
#include <cstdio>
#include <cstring>
#include <cctype>

#include <detours.h>// Window_PlayCinematic detour (cutscene overlay)

#include "imgui_utils.h"// imgui_state (selected index), settings_ini_path()

extern "C" {
#include <globals.h>// swrText_racerTab_buffer / _array / _nbLinesRacerTab
#include <Swr/swrText.h>// swrText_ParseRacerTab_ADDR / swrText_Shutdown_ADDR
#include <Win95/Window.h>// Window_PlayCinematic_ADDR
}

extern FILE *hook_log;

// EFIGS + JA. Order is the persisted index and the ImGui combo order; index 0 must stay English.
// JA is present but needs the SDF+CJK path (Tier 2) to render; listed so the wiring is exercised.
const LanguageEntry g_languages[] = {
    {"en", "English"}, {"fr", "Francais"}, {"de", "Deutsch"},
    {"es", "Espanol"}, {"it", "Italiano"}, {"ja", "Japanese"},
};
const int g_language_count = (int) (sizeof(g_languages) / sizeof(g_languages[0]));

// Call the game's originals by address. real_ParseRacerTab starts at the address and becomes the
// Detours trampoline after we hook swrText_ParseRacerTab, so runtime language switches invoke the
// real original (not our detour). Reverse-hooked reimpls are dormant, so 0x00421120 is un-hooked.
typedef int(__cdecl *swrText_ParseRacerTab_fn)(char *filepath);
typedef void(__cdecl *swrText_Shutdown_fn)(void);
static swrText_ParseRacerTab_fn real_ParseRacerTab =
    (swrText_ParseRacerTab_fn) swrText_ParseRacerTab_ADDR;
static const swrText_Shutdown_fn orig_Shutdown = (swrText_Shutdown_fn) swrText_Shutdown_ADDR;

void localization_apply(int idx) {
    if (idx < 0 || idx >= g_language_count)
        idx = 0;

    // Drop the current table, then null the globals so a missing file cleanly falls back to the
    // inline English (swrText_Translate returns the fallback when the buffer is NULL).
    orig_Shutdown();
    swrText_racerTab_buffer = nullptr;
    swrText_racerTab_array = nullptr;
    swrText_nbLinesRacerTab = 0;

    if (idx == 0) {
        fprintf(hook_log, "[localization] en: inline English fallbacks (no tab)\n");
        fflush(hook_log);
        return;
    }

    char path[64];
    snprintf(path, sizeof(path), "./data/lang/%s/racer.tab", g_languages[idx].code);
    if (!std::filesystem::exists(path)) {
        fprintf(hook_log, "[localization] %s: '%s' not found -> English fallbacks\n",
                g_languages[idx].code, path);
        fflush(hook_log);
        return;
    }
    real_ParseRacerTab(path);
    fprintf(hook_log, "[localization] loaded '%s' (%d lines)\n", path, swrText_nbLinesRacerTab);
    fflush(hook_log);
}

// Map the OS UI language to our index; anything unsupported -> English.
static int detect_os_language() {
    switch (PRIMARYLANGID(GetUserDefaultUILanguage())) {
        case LANG_FRENCH: return 1;
        case LANG_GERMAN: return 2;
        case LANG_SPANISH: return 3;
        case LANG_ITALIAN: return 4;
        case LANG_JAPANESE: return 5;
        default: return 0;
    }
}

// Persisted index; -1 (unset) -> auto-detect from the OS once. Clamped to a valid language.
static int resolve_language() {
    int idx = GetPrivateProfileIntW(L"settings", L"language", -1, settings_ini_path());
    if (idx < 0)
        idx = detect_os_language();
    if (idx < 0 || idx >= g_language_count)
        idx = 0;
    return idx;
}

// ---- Localized audio/video overlay ----------------------------------------------------------
// The game opens voice/cutscene assets through stdPlatform_hostServices.fileOpen with fixed paths
// (".\data\wavs\{22K|11K}\Voice\X.WAV", ".\data\anims\*.znm"). We wrap that pointer and, when a
// non-English language is selected, transparently redirect the open to a per-file overlay under
// "data\lang\<code>\wavs|anims\..." IF that file exists. Voice ships as a small delta (most lines
// are shared alien speech and stay stock English via fallthrough); missing files fall back too.

static const char *stristr_ascii(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && tolower((unsigned char) p[i]) == tolower((unsigned char) needle[i]))
            i++;
        if (i == nl)
            return p;
    }
    return nullptr;
}

// Splice "lang\<code>\" in after the "data\" of a "data\wavs\" / "data\anims\" path.
static bool make_overlay_path(const char *path, const char *code, char *out, size_t outsz) {
    const char *anchor = stristr_ascii(path, "data\\wavs\\");
    if (!anchor)
        anchor = stristr_ascii(path, "data\\anims\\");
    if (!anchor)
        return false;
    size_t keep = (size_t) (anchor - path) + 5;// through "data\"
    int n = snprintf(out, outsz, "%.*slang\\%s\\%s", (int) keep, path, code, anchor + 5);
    return n > 0 && (size_t) n < outsz;
}

typedef stdFile_t (*fileOpen_fn)(const char *, const char *);
static fileOpen_fn orig_fileOpen = nullptr;

static stdFile_t overlay_fileOpen(const char *path, const char *mode) {
    const int idx = imgui_state.language;
    if (idx > 0 && idx < g_language_count && path) {
        char overlay[260];
        if (make_overlay_path(path, g_languages[idx].code, overlay, sizeof(overlay)) &&
            std::filesystem::exists(overlay))
            return orig_fileOpen(overlay, mode);
    }
    return orig_fileOpen(path, mode);
}

static void install_av_overlay() {
    if (orig_fileOpen)
        return;// install once
    orig_fileOpen = (fileOpen_fn) stdPlatform_hostServices_ptr->fileOpen;
    stdPlatform_hostServices_ptr->fileOpen = (stdFile_t(*)(const char *, const char *)) overlay_fileOpen;
    fprintf(hook_log, "[localization] AV file-overlay installed (data/lang/<code>/{wavs,anims})\n");
    fflush(hook_log);
}

// ---- Cutscene overlay --------------------------------------------------------------------------
// Cutscenes (.znm) are played by the statically-linked SMUSH lib (SmushPlay), which opens the file
// itself and bypasses hostServices.fileOpen, so the file-overlay above misses them. Instead we hook
// Window_PlayCinematic @0x004252a0 (it builds "<rootPathName>.\data\anims\<name>" and hands it to
// SmushPlay) and, when a localized cutscene exists, inject a "..\lang\<code>\anims\" prefix into the
// name -- the game's own "data\anims\" + our ".." resolves to "data\lang\<code>\anims\<name>".
typedef int(__cdecl *PlayCinematic_fn)(const char *znmFile);
static PlayCinematic_fn orig_PlayCinematic = (PlayCinematic_fn) Window_PlayCinematic_ADDR;

static int __cdecl Window_PlayCinematic_delta(const char *znmFile) {
    const int idx = imgui_state.language;
    if (idx > 0 && idx < g_language_count && znmFile) {
        char probe[260];
        snprintf(probe, sizeof(probe), "./data/lang/%s/anims/%s", g_languages[idx].code, znmFile);
        if (std::filesystem::exists(probe)) {
            char redir[128];
            snprintf(redir, sizeof(redir), "..\\lang\\%s\\anims\\%s", g_languages[idx].code, znmFile);
            return orig_PlayCinematic(redir);
        }
    }
    return orig_PlayCinematic(znmFile);
}

// Detour on the game's swrText_ParseRacerTab. init_localization (LoadIconHook) runs BEFORE
// stdPlatform is initialized, so hostServices is still NULL there -- calling ParseRacerTab or
// reading hostServices.fileOpen at that point crashes. Instead we hook ParseRacerTab and do the
// real work on its first call, which happens from Main_Startup once hostServices IS ready.
static bool g_loc_started = false;
static int __cdecl ParseRacerTab_detour(char *filepath) {
    if (!g_loc_started) {
        g_loc_started = true;
        imgui_state.language = resolve_language();
        install_av_overlay();// hostServices is valid now (ParseRacerTab itself uses it)
        fprintf(hook_log, "[localization] startup: language index=%d (%s)\n", imgui_state.language,
                g_languages[imgui_state.language].code);
        fflush(hook_log);
    }
    const int idx = imgui_state.language;
    if (idx > 0 && idx < g_language_count) {
        char path[64];
        snprintf(path, sizeof(path), "./data/lang/%s/racer.tab", g_languages[idx].code);
        if (std::filesystem::exists(path))
            return real_ParseRacerTab(path);
    }
    return real_ParseRacerTab(filepath);
}

void init_localization() {
    // Runs from LoadIconHook, where stdPlatform_hostServices is NOT ready yet -- so we ONLY install
    // Detours here (they don't touch hostServices). The ParseRacerTab detour resolves the language,
    // installs the voice overlay, and redirects the tab later, once hostServices is initialized.
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void **) &real_ParseRacerTab, (void *) ParseRacerTab_detour);
    DetourAttach((void **) &orig_PlayCinematic, (void *) Window_PlayCinematic_delta);
    DetourTransactionCommit();
    fprintf(hook_log, "[localization] hooks installed (ParseRacerTab + Window_PlayCinematic)\n");
    fflush(hook_log);
}
