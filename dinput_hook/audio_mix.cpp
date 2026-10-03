//
// Per-category volume mixer -- see audio_mix.h.
//
#include "audio_mix.h"
#include "hook_helper.h"
#include "config.h"

#include <imgui.h>

#include <cctype>
#include <cstring>

extern "C" {
#include <swr.h>          // playASoundImpl_ADDR
#include <Swr/swrObj.h>   // swrObjJdge_UpdateCountdownLights_ADDR, GetLocalPlayerNumberFromScore
#include <Swr/swrRace.h>  // swrRace_InRaceEngineUI_ADDR, swrRace_UpdateEngineSound_ADDR, ...
#include <Swr/swrSound.h> // swrSound_GetEntry, swrSound_IsLoopingSfxId_Maybe
#include <Swr/swrUI.h>    // playUISound_ADDR
}

// Defined in hook_helper.cpp (registers a raw game-address detour); not prototyped there.
extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

struct CategoryInfo {
    const char *key;  // SW_RACER_RE.ini [audio_mix] key
    const char *label;
    const char *tip;
};

static const CategoryInfo g_categories[AUDIO_MIX_COUNT] = {
    {"voices", "Voices", "Announcer, pilot taunts, Watto and pit-droid chatter."},
    {"alerts", "Cockpit alerts",
     "Overheat alarm, repair beep, engine-fire roar and coolant hiss from the damage readout."},
    {"countdown", "Countdown beeps", "The start-light beeps."},
    {"player_engine", "Player engine",
     "Your own pod: engine loop, gear shifts, boost ignition, airbrakes."},
    {"opponent_engines", "Opponent engines", "Every other pod's engine."},
    {"ambience", "Ambience", "Track ambient cues and environment loops (wind, crowds, machinery)."},
    {"crashes", "Crashes & explosions", "Wall impacts, crash debris and pod explosions."},
    {"menu", "Menu sounds", "Front-end and pause-menu clicks and confirms."},
};

static float g_volume[AUDIO_MIX_COUNT] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};

// Category of the game function currently emitting sounds, set around the original call by the
// context hooks below. Everything runs on the game thread.
static AudioMixCategory g_context = AUDIO_MIX_NONE;

static bool starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

// Voice lines are named <4-letter speaker+set><3-digit line>, e.g. absp001 / wtui045 / rali012.
static bool is_voice_name(const char *name) {
    for (int i = 0; i < 4; i++)
        if (!isalpha((unsigned char) name[i]))
            return false;
    for (int i = 4; i < 7; i++)
        if (!isdigit((unsigned char) name[i]))
            return false;
    return true;
}

static AudioMixCategory classify(int sound_id) {
    const swrSoundDescriptor *entry = (const swrSoundDescriptor *) swrSound_GetEntry(sound_id);
    const char *name = entry ? entry->name : "";

    if (is_voice_name(name) || starts_with(name, "sfx_vox_pdroid"))
        return AUDIO_MIX_VOICES;
    if (g_context != AUDIO_MIX_NONE)
        return g_context;
    if (starts_with(name, "sfx_amb_"))
        return AUDIO_MIX_AMBIENCE;
    if (starts_with(name, "sfx_crash_") || starts_with(name, "sfx_explo_") ||
        starts_with(name, "sfx_impact_"))
        return AUDIO_MIX_CRASHES;
    return AUDIO_MIX_NONE;
}

// Runs a context hook's original with g_context set. The deltas return the original's EAX even
// though the game functions are void in Ghidra: a void delta would clobber it on the way out.
template<typename Fn, typename... Args>
static int with_context(AudioMixCategory category, uint32_t addr, Args... args) {
    const AudioMixCategory prev = g_context;
    g_context = category;
    const int ret = hook_call_original((Fn) addr, args...);
    g_context = prev;
    return ret;
}

typedef int(__cdecl *playASoundImpl_t)(int, short, float, float, short, int, int, int *);
typedef int(__cdecl *InRaceEngineUI_t)(void *, int);
typedef int(__cdecl *UpdateCountdownLights_t)(swrObjJdge *);
typedef int(__cdecl *UpdateEngineSound_t)(swrRace *);
typedef int(__cdecl *PlayEngineSounds_t)(swrRace *, float);
typedef int(__cdecl *UpdateEngineAudio_t)(int, int, float *);
typedef int(__cdecl *playUISound_t)(int);

extern "C" int __cdecl playASoundImpl_delta(int sound_id, short priority, float pitch, float gain,
                                            short pan, int looping, int track_pos, int *pos) {
    if (!swrSound_IsLoopingSfxId_Maybe(sound_id)) {// music ids ride the music byte; leave them
        const AudioMixCategory category = classify(sound_id);
        if (category != AUDIO_MIX_NONE)
            gain *= g_volume[category];
    }
    return hook_call_original((playASoundImpl_t) playASoundImpl_ADDR, sound_id, priority, pitch,
                              gain, pan, looping, track_pos, pos);
}

extern "C" int __cdecl swrRace_InRaceEngineUI_delta(void *param_1, int player_index) {
    return with_context<InRaceEngineUI_t>(AUDIO_MIX_ALERTS, swrRace_InRaceEngineUI_ADDR, param_1,
                                          player_index);
}

extern "C" int __cdecl swrObjJdge_UpdateCountdownLights_delta(swrObjJdge *jdge) {
    return with_context<UpdateCountdownLights_t>(AUDIO_MIX_COUNTDOWN,
                                                 swrObjJdge_UpdateCountdownLights_ADDR, jdge);
}

// Matched against the local-player roster rather than flags0 LOCAL: once a pod crosses the line
// the autopilot drives the victory lap, and the roster is the one thing that stays put.
static AudioMixCategory engine_category(const swrRace *player) {
    const bool local = player != nullptr && player->score_ptr != nullptr &&
                       GetLocalPlayerNumberFromScore(player->score_ptr) >= 0;
    return local ? AUDIO_MIX_PLAYER_ENGINE : AUDIO_MIX_OPPONENT_ENGINES;
}

// Plays the distant-pod hum directly, or hands the pod on to swrRace_PlayEngineSounds.
extern "C" int __cdecl swrRace_UpdateEngineSound_delta(swrRace *player) {
    return with_context<UpdateEngineSound_t>(engine_category(player),
                                             swrRace_UpdateEngineSound_ADDR, player);
}

extern "C" int __cdecl swrRace_PlayEngineSounds_delta(swrRace *player, float gain) {
    return with_context<PlayEngineSounds_t>(engine_category(player),
                                            swrRace_PlayEngineSounds_ADDR, player, gain);
}

// Despite the name, this plays the per-track ambient cues keyed on lap progress; it is called
// from inside swrRace_PlayEngineSounds, so it overrides the engine tag.
extern "C" int __cdecl swrSound_UpdateEngineAudio_delta(int planet, int track, float *progress) {
    return with_context<UpdateEngineAudio_t>(AUDIO_MIX_AMBIENCE, swrSound_UpdateEngineAudio_ADDR,
                                             planet, track, progress);
}

extern "C" int __cdecl playUISound_delta(int sound_id) {
    return with_context<playUISound_t>(AUDIO_MIX_MENU, playUISound_ADDR, sound_id);
}

void audio_mix_RegisterHooks() {
    hook_function("playASoundImpl", (uint32_t) playASoundImpl_ADDR,
                  (uint8_t *) playASoundImpl_delta);
    hook_function("swrRace_InRaceEngineUI", (uint32_t) swrRace_InRaceEngineUI_ADDR,
                  (uint8_t *) swrRace_InRaceEngineUI_delta);
    hook_function("swrObjJdge_UpdateCountdownLights",
                  (uint32_t) swrObjJdge_UpdateCountdownLights_ADDR,
                  (uint8_t *) swrObjJdge_UpdateCountdownLights_delta);
    hook_function("swrRace_UpdateEngineSound", (uint32_t) swrRace_UpdateEngineSound_ADDR,
                  (uint8_t *) swrRace_UpdateEngineSound_delta);
    hook_function("swrRace_PlayEngineSounds", (uint32_t) swrRace_PlayEngineSounds_ADDR,
                  (uint8_t *) swrRace_PlayEngineSounds_delta);
    hook_function("swrSound_UpdateEngineAudio", (uint32_t) swrSound_UpdateEngineAudio_ADDR,
                  (uint8_t *) swrSound_UpdateEngineAudio_delta);
    hook_function("playUISound", (uint32_t) playUISound_ADDR, (uint8_t *) playUISound_delta);
}

void audio_mix_LoadSettings() {
    for (int i = 0; i < AUDIO_MIX_COUNT; i++) {
        const float v = config::get_float("audio_mix", g_categories[i].key, 1.0f);
        g_volume[i] = (v >= 0.0f && v <= 1.0f) ? v : 1.0f;
    }
}

void audio_mix_SaveSettings() {
    for (int i = 0; i < AUDIO_MIX_COUNT; i++)
        config::set_float("audio_mix", g_categories[i].key, g_volume[i]);
}

bool audio_mix_DrawSliders() {
    bool changed = false;
    for (int i = 0; i < AUDIO_MIX_COUNT; i++) {
        int pct = (int) (g_volume[i] * 100.0f + 0.5f);
        if (ImGui::SliderInt(g_categories[i].label, &pct, 0, 100, "%d%%")) {
            g_volume[i] = pct / 100.0f;
            changed = true;
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", g_categories[i].tip);
    }
    return changed;
}
