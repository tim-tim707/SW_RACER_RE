//
// Per-category volume mixer -- see audio_mix.h.
//
#include "audio_mix.h"
#include "hook_helper.h"
#include "config.h"
#include "custom_engine_sound.h"
#include "shadows.h"// camera_get
#include "game_deltas/pod_wreck.h"// pod_wreck_side_gone

#include <imgui.h>

#include <cctype>
#include <chrono>
#include <cmath>
#include <unordered_map>
#include <cstring>

extern "C" {
#include <swr.h>          // playASoundImpl_ADDR
#include <Swr/swrObj.h>   // swrObjJdge_UpdateCountdownLights_ADDR, GetLocalPlayerNumberFromScore
#include <Swr/swrRace.h>  // swrRace_InRaceEngineUI_ADDR, swrRace_UpdateEngineSound_ADDR, ...
#include <Swr/swrSound.h> // swrSound_GetEntry, swrSound_IsLoopingSfxId_Maybe
#include <Swr/swrUI.h>    // playUISound_ADDR
#include <Swr/swrViewport.h>
#include <globals.h>       // swrRace_voices_enabled, firstLocalPlayer
#include <types_enums.h>   // swrObjTest_FLAG*
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

// The film's Sebulba engine loop, played through custom_engine_sound on his pod.
struct FilmEngineSettings {
    bool on = true;
    float volume = 0.8f;
    float range = 600.0f;    // your Sebulba: distance from the camera at which it fades to silence
    float ai_range = 1500.0f;// an AI Sebulba: same, longer so you hear him approach
    float doppler = 1.0f;    // AI Sebulba Doppler strength (0 = off)
};
static FilmEngineSettings g_film;
static float g_film_debug_dist = -1.0f, g_film_debug_gain = 0.0f;// your Sebulba, last tick
static float g_film_ai_dist = -1.0f, g_film_ai_gain = 0.0f;      // an AI Sebulba, last tick
static float g_film_ai_doppler = 1.0f;

// AI pods using the player-style geared engine loops instead of the stock flat hum.
struct AiEngineSettings {
    bool on = true;
    float volume = 0.6f;
    float range = 900.0f; // distance from the camera at which an AI engine fades out
    float doppler = 1.0f; // 0 = off
    int max_voices = 6;   // loudest N AI engines get voices
};
static AiEngineSettings g_ai_engine;
static std::chrono::steady_clock::time_point g_film_ai_time{};

// The energy binder's hum on your pod while idling / in the lowest gear. Stock, the binder loop is
// only baked into the gear-0 engine loop (sfx_pod_chop_a_combo_loop), which the game pitches per
// racer, so it is only heard near its own pitch on Sebulba's deep engine. This plays the binder
// loop at its recorded pitch on every other racer's pod, fading out as the engine leaves gear 0.
struct BinderHumSettings {
    bool on = true;
    float volume = 0.7f;
    float fade_start = 0.12f;// speed (x the pod's top speed) where it starts fading
    float fade_end = 0.25f;  // ... and is gone (the game's gear 0 ends at 0.25)
};
static BinderHumSettings g_binder;
static float g_binder_debug_gain = -1.0f;
// The binder's start-up sound (sfx_pod_binder_start_b, 4.28 s) as it lights at the start of a
// race: the hum comes in just before it ends.
constexpr int kBinderStartSfx = 116;
constexpr float kBinderStartLen = 4.28f, kBinderHumLead = 1.0f;
static std::chrono::steady_clock::time_point g_binder_start_heard{};
static bool g_binder_start_seen = false;
static const swrRace *g_engine_racer = nullptr;// the pod whose engine sounds are being issued

static bool is_sebulba(const swrRace *r) {
    return r != nullptr && r->score_ptr != nullptr && r->score_ptr->pilotId != nullptr &&
           *r->score_ptr->pilotId == 2;
}

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
    if (sound_id == kBinderStartSfx) {
        g_binder_start_heard = std::chrono::steady_clock::now();
        g_binder_start_seen = true;
    }
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

// Film engine loop for Sebulba. Called once per pod per tick. There is one output voice, so each
// Sebulba pod proposes how loud it would be (from distance to your pod, throttle, speed) and the
// loudest proposal from the last ~0.1 s wins -- normally your own pod if you are flying him, else
// the nearest AI Sebulba.
// ---- shared helpers for positional pod engine sounds ----------------------------------------

// Per-pod smoothed velocity, updated once per pod per tick (from swrRace_UpdateEngineSound_delta).
static std::unordered_map<const swrRace *, std::pair<rdVector3, rdVector3>> g_pod_track;// last pos, vel
static const swrRace *g_local_pod = nullptr;// local player's pod (listener velocity for Doppler)
static void track_pod_velocity(const swrRace *player) {
    if (engine_category(player) == AUDIO_MIX_PLAYER_ENGINE)
        g_local_pod = player;
    const rdVector3 pos = {player->transform.vD.x, player->transform.vD.y, player->transform.vD.z};
    auto &tr = g_pod_track[player];
    const float dt = (float) swrRace_deltaTimeSecs;
    if (dt > 1e-5f) {
        rdVector3 v = {(pos.x - tr.first.x) / dt, (pos.y - tr.first.y) / dt, (pos.z - tr.first.z) / dt};
        if (v.x * v.x + v.y * v.y + v.z * v.z > 3000.0f * 3000.0f)
            v = {0, 0, 0};// respawn / first tick
        const float k = 1.0f - std::exp(-dt / 0.1f);
        tr.second = {tr.second.x + (v.x - tr.second.x) * k, tr.second.y + (v.y - tr.second.y) * k,
                     tr.second.z + (v.z - tr.second.z) * k};
    }
    tr.first = pos;
}

// Doppler factor for a pod heard from the camera: f' = f * c / (c - v), v = how fast the pod
// approaches the camera along the line between them (its velocity minus the camera's), c = the
// speed of sound in game units/s (2200, divided by `strength`). Clamped to 0.7 .. 1.45.
static float doppler_shift(const swrRace *player, const rdVector3 &cam, float strength) {
    rdVector3 cam_vel{};
    if (strength <= 0.0f || !camera_get_velocity(&cam_vel))
        return 1.0f;
    const rdVector3 pos = {player->transform.vD.x, player->transform.vD.y, player->transform.vD.z};
    const float dx = cam.x - pos.x, dy = cam.y - pos.y, dz = cam.z - pos.z;
    const float d = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (d < 1.0f)
        return 1.0f;
    const rdVector3 &vel = g_pod_track[player].second;
    // Listener velocity: when the camera rides with your pod (chase / cockpit), use your pod's
    // velocity -- measured per game tick exactly like the source pod's -- so pods flying at your
    // speed get no shift. The render camera's own velocity (wall-clock, per frame) doesn't match
    // the per-tick pod velocities and gave a constant false drop. Free/cutscene cameras keep it.
    if (g_local_pod != nullptr && g_local_pod != player) {
        auto it = g_pod_track.find(g_local_pod);
        if (it != g_pod_track.end()) {
            const float lx = cam.x - it->second.first.x, ly = cam.y - it->second.first.y,
                        lz = cam.z - it->second.first.z;
            if (lx * lx + ly * ly + lz * lz < 250.0f * 250.0f)
                cam_vel = it->second.second;
        }
    }
    const float v_rel = ((vel.x - cam_vel.x) * dx + (vel.y - cam_vel.y) * dy + (vel.z - cam_vel.z) * dz) / d;
    const float c = 2200.0f / strength;
    const float shift = c / std::max(c - v_rel, c * 0.3f);
    return shift < 0.7f ? 0.7f : (shift > 1.45f ? 1.45f : shift);
}

static void update_film_engine(const swrRace *player) {
    struct Proposal {
        float gain, rate, pan;
        std::chrono::steady_clock::time_point t;
    };
    static std::unordered_map<const swrRace *, Proposal> proposals;
    if (!g_film.on || !is_sebulba(player))
        return;
    const auto now = std::chrono::steady_clock::now();
    const bool local = engine_category(player) == AUDIO_MIX_PLAYER_ENGINE;
    // The sound lives AT the pod: heard from the camera (rdVector_model_translation, the active
    // 3D camera position) with distance falloff and panning -- for your own Sebulba too, so a
    // cutscene camera far away from the pod (the opening track sweep) barely hears it, while the
    // usual chase camera right behind the pod hears it at near full volume.
    // Camera = the one the renderer actually drew the last race frame with. If there is none
    // (no race frame drawn recently), fall back to: your own pod at full volume, others silent.
    rdVector3 cam{}, cam_right{};
    const bool have_cam = camera_get(&cam, &cam_right);
    float gain, pan = 0.0f, d = 0.0f;
    if (have_cam) {
        const float dx = player->transform.vD.x - cam.x;
        const float dy = player->transform.vD.y - cam.y;
        const float dz = player->transform.vD.z - cam.z;
        d = std::sqrt(dx * dx + dy * dy + dz * dz);
        // Your own pod: fades over `range`. An AI Sebulba: a longer, gentler fade over `ai_range`, so
        // you hear him coming up behind you and roaring past, not only when he's right on top of you.
        const float range = local ? g_film.range : g_film.ai_range;
        const float near_ = 1.0f - d / range;
        gain = near_ > 0.0f ? (local ? near_ * near_ : std::pow(near_, 1.3f)) : 0.0f;
        // Pan from which side of the camera the pod is on.
        const float rl = std::sqrt(cam_right.x * cam_right.x + cam_right.y * cam_right.y + cam_right.z * cam_right.z);
        if (d > 1e-3f && rl > 1e-6f)
            pan = 0.7f * (dx * cam_right.x + dy * cam_right.y + dz * cam_right.z) / (d * rl);
    } else {
        gain = local ? 1.0f : 0.0f;
    }
    if (local) {
        g_film_debug_dist = have_cam ? d : -1.0f;
        g_film_debug_gain = gain;
    } else {
        g_film_ai_dist = have_cam ? d : -1.0f;
        g_film_ai_gain = gain;
        g_film_ai_time = std::chrono::steady_clock::now();
    }
    if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        gain = 0.0f;
    // Throttle: full roar under power, quieter off it. Speed raises the pitch (boost a touch more).
    const bool boosting = (player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0;
    const bool powered = boosting || ((player->flags1 & swrObjTest_FLAG1_NOT_ACCEL) == 0 && player->throttle > 0.3f);
    gain *= powered ? 1.0f : 0.55f;
    gain *= g_film.volume * g_volume[local ? AUDIO_MIX_PLAYER_ENGINE : AUDIO_MIX_OPPONENT_ENGINES];
    const float f = player->speedValue / 600.0f;
    const float sf = f < 0.0f ? 0.0f : (f > 1.0f ? 1.0f : f);
    // Playback rate: 0.68x at a crawl up to 0.96x at top speed (+boost) -- 20% slower than the
    // recording's own tempo across the board -- and 10% faster on top of that while the throttle
    // is held (the audio thread glides between the two, so it revs up/down smoothly).
    float rate = 0.8f * (0.85f + 0.35f * sf + (boosting ? 0.08f : 0.0f)) * (powered ? 1.1f : 1.0f);

    if (!local) {
        // AI Sebulba: 20% louder than the other engine levels.
        gain *= 1.2f;
        // Doppler: pitch rises as he closes on the camera and drops as he pulls away. Classic
        // f' = f * c / (c - v), v = how fast he approaches the listener along the line between
        // them (his velocity minus the camera's), c = the speed of sound in game units/s.
        if (have_cam) {
            const float shift = doppler_shift(player, cam, g_film.doppler);
            rate *= shift;
            g_film_ai_doppler = shift;
        }
    }
    proposals[player] = {gain, rate, pan, now};

    const Proposal *best = nullptr;
    for (auto it = proposals.begin(); it != proposals.end();) {
        if (now - it->second.t > std::chrono::milliseconds(100)) {
            it = proposals.erase(it);// that pod stopped updating (gone / not racing)
            continue;
        }
        if (best == nullptr || it->second.gain > best->gain)
            best = &it->second;
        ++it;
    }
    if (best != nullptr)
        custom_engine_sound_set(best->gain, best->rate, best->pan);
}

// AI pods with the player's engine sound. Stock, an AI pod within 500 units plays one flat hum
// (sfx_pod_steady_hi_a/b, bank 166/167) while your pod plays a geared set of loops that change
// with RPM (bank 170-174: chop_a_combo, chop_b_combo, maw_slow, varispeed_comb, + jet). The
// game's player-engine code keeps per-local-player state and bails for AI, so instead each nearby
// AI pod gets that geared set through our mixer: the loop for its current "gear" (from its speed),
// crossfading into the next as it revs, pitched within the gear, positioned from the camera with
// Doppler. Returns true when it handled the pod (the stock hum is then skipped).
static bool update_ai_engine(const swrRace *player) {
    if (!g_ai_engine.on || engine_category(player) == AUDIO_MIX_PLAYER_ENGINE)
        return false;
    // Demo / attract mode pods take the game's player path; leave them alone.
    if ((player->flags0 & 0x20) != 0 || (player->flags1 & 0x4000000) != 0)
        return false;
    static int loops[5] = {-2, -2, -2, -2, -2};
    if (loops[0] == -2) {
        const char *names[5] = {"data\\wavs\\22K\\sfx_pod_chop_a_combo_loop.wav",
                                "data\\wavs\\22K\\sfx_pod_chop_b_combo_loop.wav",
                                "data\\wavs\\22K\\sfx_pod_maw_slow_loop.wav",
                                "data\\wavs\\22K\\sfx_pod_varispeed_comb_loop.wav",
                                "data\\wavs\\22K\\sfx_pod_jet_steady_loop.wav"};
        for (int i = 0; i < 5; i++)
            loops[i] = custom_sound_load(names[i]);
    }
    if (loops[0] < 0 || loops[3] < 0)
        return false;// files missing: keep the stock hum

    rdVector3 cam{}, cam_right{};
    if (!camera_get(&cam, &cam_right))
        return true;// no race camera yet: stay silent rather than hum
    // Sebulba with his film loop already has his own engine voice.
    if (g_film.on && is_sebulba(player))
        return true;
    if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        return true;

    const float dx = player->transform.vD.x - cam.x, dy = player->transform.vD.y - cam.y,
                dz = player->transform.vD.z - cam.z;
    const float d = std::sqrt(dx * dx + dy * dy + dz * dz);
    const float near_ = 1.0f - d / g_ai_engine.range;
    if (near_ <= 0.0f)
        return true;
    float gain = std::pow(near_, 1.4f) * g_ai_engine.volume * g_volume[AUDIO_MIX_OPPONENT_ENGINES];

    // Only the loudest few AI engines get voices (keeps a full grid from turning into mush).
    struct Entry {
        float gain;
        std::chrono::steady_clock::time_point t;
    };
    static std::unordered_map<const swrRace *, Entry> loudness;
    const auto now = std::chrono::steady_clock::now();
    loudness[player] = {gain, now};
    int louder = 0;
    for (auto it = loudness.begin(); it != loudness.end();) {
        if (now - it->second.t > std::chrono::milliseconds(100)) {
            it = loudness.erase(it);
            continue;
        }
        if (it->first != player && it->second.gain > gain)
            louder++;
        ++it;
    }
    if (louder >= g_ai_engine.max_voices)
        return true;

    float pan = 0.0f;
    const float rl = std::sqrt(cam_right.x * cam_right.x + cam_right.y * cam_right.y + cam_right.z * cam_right.z);
    if (d > 1e-3f && rl > 1e-6f)
        pan = 0.7f * (dx * cam_right.x + dy * cam_right.y + dz * cam_right.z) / (d * rl);
    const float doppler = doppler_shift(player, cam, g_ai_engine.doppler);

    // "Gears": 4 bands of speed, each played by its loop, pitch rising across the band; the top
    // of a band crossfades into the next loop. Off the throttle a bit quieter and lower.
    const bool boosting = (player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0;
    const bool powered = boosting || ((player->flags1 & swrObjTest_FLAG1_NOT_ACCEL) == 0 && player->throttle > 0.3f);
    const float f = player->speedValue / 600.0f;
    const float sf = f < 0.0f ? 0.0f : (f > 0.999f ? 0.999f : f);
    const int gear = (int) (sf * 4.0f);
    const float u = sf * 4.0f - (float) gear;// position within the gear
    const float xf = gear < 3 ? std::max(0.0f, (u - 0.8f) / 0.2f) : 0.0f;// crossfade to the next gear
    gain *= powered ? 1.0f : 0.7f;
    const float pitch = (0.78f + 0.5f * u) * (powered ? 1.0f : 0.92f) * doppler;
    const uint64_t base = ((uint64_t) (uintptr_t) player) << 4;
    custom_sound_voice(base | (uint64_t) gear, loops[gear], gain * (1.0f - xf), pitch, pan);
    if (xf > 0.0f)
        custom_sound_voice(base | (uint64_t) (gear + 1), loops[gear + 1], gain * xf, 0.78f * doppler, pan);
    if (boosting && loops[4] >= 0)
        custom_sound_voice(base | 8u, loops[4], gain * 0.7f, (0.9f + 0.2f * sf) * doppler, pan);
    return true;
}

static void update_binder_hum(const swrRace *player) {
    if (!g_binder.on || engine_category(player) != AUDIO_MIX_PLAYER_ENGINE)
        return;
    // Sebulba's own gear-0 loop already carries it near its recorded pitch.
    if (is_sebulba(player) || (player->flags0 & swrObjTest_FLAG0_DEAD) != 0 ||
        (player->flags1 & swrObjTest_FLAG1_EXPLODING) != 0)
        return;
    // Repairing: the game plays its own binder sound then (the voice fades out by itself).
    if ((player->flags0 & swrObjTest_FLAG0_REPAIRING) != 0) {
        g_binder_debug_gain = 0.0f;
        return;
    }
    // No binder once an engine has come off (the beam goes with it), and none on Neva Kee's pod.
    if (pod_wreck_side_gone(player, 0) || pod_wreck_side_gone(player, 1))
        return;
    if (player->score_ptr && player->score_ptr->pilotId && *player->score_ptr->pilotId == 14)
        return;
    // Only once the binder has lit: until then (the pre-race sweep) the game parks the hidden
    // beam at z = -100000 (swrRace_UpdateEnergyBinder).
    if (player->binderXfL.vD.z < -50000.0f && player->binderXfR.vD.z < -50000.0f) {
        g_binder_debug_gain = 0.0f;
        return;
    }
    // Before the race starts (pod state 0 = pre-race) the hum waits for this race's binder
    // start-up sound and comes in just before it ends -- silent until then. Once racing it plays
    // straight away.
    const bool pre_race = (player->flags0 & swrObjTest_FLAG0_STATE_MASK) == 0;
    static bool was_pre_race = false;
    if (pre_race && !was_pre_race)
        g_binder_start_seen = false;// a new race: wait for its start-up sound
    was_pre_race = pre_race;
    if (pre_race) {
        const auto wait = std::chrono::duration<float>(kBinderStartLen - kBinderHumLead);
        if (!g_binder_start_seen || std::chrono::steady_clock::now() - g_binder_start_heard < wait) {
            g_binder_debug_gain = 0.0f;
            return;
        }
    }
    static int loop = -2;
    if (loop == -2)
        loop = custom_sound_load("data\\wavs\\22K\\sfx_pod_binder_steady_loop.wav");
    if (loop < 0)
        return;
    // Gear 0 = under a quarter of the pod's top speed (the game's own gear table).
    const float top = player->podStats.maxSpeed > 1.0f ? player->podStats.maxSpeed : 600.0f;
    const float sf = player->speedValue / top;
    const float span = g_binder.fade_end - g_binder.fade_start;
    float k = span > 1e-3f ? (g_binder.fade_end - sf) / span : (sf < g_binder.fade_end ? 1.0f : 0.0f);
    k = k < 0.0f ? 0.0f : (k > 1.0f ? 1.0f : k);
    if (k <= 0.0f) {
        g_binder_debug_gain = 0.0f;
        return;
    }
    // Heard at the pod from the camera (a far-off cutscene camera barely hears it).
    float gain = 1.0f, pan = 0.0f;
    rdVector3 cam{}, cam_right{};
    if (camera_get(&cam, &cam_right)) {
        const float dx = player->transform.vD.x - cam.x, dy = player->transform.vD.y - cam.y,
                    dz = player->transform.vD.z - cam.z;
        const float d = std::sqrt(dx * dx + dy * dy + dz * dz);
        const float near_ = 1.0f - d / g_film.range;
        gain = near_ > 0.0f ? near_ * near_ : 0.0f;
        const float rl = std::sqrt(cam_right.x * cam_right.x + cam_right.y * cam_right.y + cam_right.z * cam_right.z);
        if (d > 1e-3f && rl > 1e-6f)
            pan = 0.5f * (dx * cam_right.x + dy * cam_right.y + dz * cam_right.z) / (d * rl);
    }
    gain *= k * k * (3.0f - 2.0f * k) * g_binder.volume * g_volume[AUDIO_MIX_PLAYER_ENGINE];
    g_binder_debug_gain = gain;
    custom_sound_voice((((uint64_t) (uintptr_t) player) << 4) | 9u, loop, gain, 1.0f, pan);// rate 1: unpitched
}

// Plays the distant-pod hum directly, or hands the pod on to swrRace_PlayEngineSounds.
extern "C" int __cdecl swrRace_UpdateEngineSound_delta(swrRace *player) {
    track_pod_velocity(player);
    update_film_engine(player);
    update_binder_hum(player);
    if (update_ai_engine(player))
        return 0;// replaced the stock AI hum
    const swrRace *prev = g_engine_racer;
    g_engine_racer = player;
    const int ret = with_context<UpdateEngineSound_t>(engine_category(player),
                                                      swrRace_UpdateEngineSound_ADDR, player);
    g_engine_racer = prev;
    return ret;
}

extern "C" int __cdecl swrRace_PlayEngineSounds_delta(swrRace *player, float gain) {
    const swrRace *prev = g_engine_racer;
    g_engine_racer = player;
    const int ret = with_context<PlayEngineSounds_t>(engine_category(player),
                                                     swrRace_PlayEngineSounds_ADDR, player, gain);
    g_engine_racer = prev;
    return ret;
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
    auto clampf = [](float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); };
    g_film.on = config::get_int("audio_mix", "sebulba_film_engine", g_film.on) != 0;
    g_film.volume = clampf(config::get_float("audio_mix", "sebulba_film_volume", g_film.volume), 0.0f, 1.5f);
    g_film.range = clampf(config::get_float("audio_mix", "sebulba_film_range", g_film.range), 50.0f, 3000.0f);
    g_film.ai_range = clampf(config::get_float("audio_mix", "sebulba_film_ai_range", g_film.ai_range), 100.0f, 5000.0f);
    g_film.doppler = clampf(config::get_float("audio_mix", "sebulba_film_doppler", g_film.doppler), 0.0f, 3.0f);
    g_ai_engine.on = config::get_int("audio_mix", "ai_player_engine", g_ai_engine.on) != 0;
    g_ai_engine.volume = clampf(config::get_float("audio_mix", "ai_engine_volume", g_ai_engine.volume), 0.0f, 1.5f);
    g_ai_engine.range = clampf(config::get_float("audio_mix", "ai_engine_range", g_ai_engine.range), 100.0f, 4000.0f);
    g_ai_engine.doppler = clampf(config::get_float("audio_mix", "ai_engine_doppler", g_ai_engine.doppler), 0.0f, 3.0f);
    {
        const int v = config::get_int("audio_mix", "ai_engine_voices", g_ai_engine.max_voices);
        g_ai_engine.max_voices = v < 1 ? 1 : (v > 12 ? 12 : v);
    }
    g_binder.on = config::get_int("audio_mix", "binder_hum", g_binder.on) != 0;
    g_binder.volume = clampf(config::get_float("audio_mix", "binder_hum_volume", g_binder.volume), 0.0f, 1.5f);
    g_binder.fade_start = clampf(config::get_float("audio_mix", "binder_hum_fade_start", g_binder.fade_start), 0.0f, 1.0f);
    g_binder.fade_end = clampf(config::get_float("audio_mix", "binder_hum_fade_end", g_binder.fade_end), 0.0f, 1.0f);
}

void audio_mix_SaveSettings() {
    for (int i = 0; i < AUDIO_MIX_COUNT; i++)
        config::set_float("audio_mix", g_categories[i].key, g_volume[i]);
    config::set_bool("audio_mix", "sebulba_film_engine", g_film.on);
    config::set_float("audio_mix", "sebulba_film_volume", g_film.volume);
    config::set_float("audio_mix", "sebulba_film_range", g_film.range);
    config::set_float("audio_mix", "sebulba_film_ai_range", g_film.ai_range);
    config::set_float("audio_mix", "sebulba_film_doppler", g_film.doppler);
    config::set_bool("audio_mix", "ai_player_engine", g_ai_engine.on);
    config::set_float("audio_mix", "ai_engine_volume", g_ai_engine.volume);
    config::set_float("audio_mix", "ai_engine_range", g_ai_engine.range);
    config::set_float("audio_mix", "ai_engine_doppler", g_ai_engine.doppler);
    config::set_int("audio_mix", "ai_engine_voices", g_ai_engine.max_voices);
    config::set_bool("audio_mix", "binder_hum", g_binder.on);
    config::set_float("audio_mix", "binder_hum_volume", g_binder.volume);
    config::set_float("audio_mix", "binder_hum_fade_start", g_binder.fade_start);
    config::set_float("audio_mix", "binder_hum_fade_end", g_binder.fade_end);
}

bool audio_mix_DrawSliders() {
    bool changed = false;
    for (int i = 0; i < AUDIO_MIX_COUNT; i++) {
        // Voices at 0% doubles as the game's in-race voices switch, so lines are not triggered at all
        // (rather than played silently); moving off 0 turns them back on.
        const bool voices = i == AUDIO_MIX_VOICES;
        const bool voices_on = swrRace_voices_enabled != 0;
        int pct = (voices && !voices_on) ? 0 : (int) (g_volume[i] * 100.0f + 0.5f);
        if (ImGui::SliderInt(g_categories[i].label, &pct, 0, 100, "%d%%")) {
            g_volume[i] = pct / 100.0f;
            if (voices)
                swrRace_voices_enabled = pct > 0;
            changed = true;
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", g_categories[i].tip);
    }

    ImGui::SeparatorText("AI engines");
    changed |= ImGui::Checkbox("AI pods use the player engine sound", &g_ai_engine.on);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Replaces the AI's flat stock hum with the geared engine loops your own pod\n"
                          "uses (revving through the gears with speed), heard from where each AI pod\n"
                          "is, with Doppler as they pass.");
    ImGui::BeginDisabled(!g_ai_engine.on);
    changed |= ImGui::SliderFloat("AI engine volume", &g_ai_engine.volume, 0.0f, 1.5f, "%.2f");
    changed |= ImGui::SliderFloat("AI engine range", &g_ai_engine.range, 100.0f, 4000.0f, "%.0f");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Distance from the camera at which an AI engine fades out.");
    changed |= ImGui::SliderFloat("AI engine Doppler", &g_ai_engine.doppler, 0.0f, 3.0f, "%.2fx");
    changed |= ImGui::SliderInt("Max AI engines heard", &g_ai_engine.max_voices, 1, 12);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Only the loudest (nearest) AI engines play, so a full grid stays clear.");
    ImGui::EndDisabled();
    if (ImGui::Button("Reset AI engine sound to defaults")) {
        g_ai_engine = AiEngineSettings{};
        changed = true;
    }

    ImGui::SeparatorText("Binder hum");
    changed |= ImGui::Checkbox("Binder hum at idle", &g_binder.on);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Your pod's energy binder humming at its recorded pitch while you idle and in the\n"
                          "lowest gear, fading out as you speed up -- as in the film. Every racer but\n"
                          "Sebulba (his low engine loop already carries it).");
    ImGui::BeginDisabled(!g_binder.on);
    changed |= ImGui::SliderFloat("Binder hum volume", &g_binder.volume, 0.0f, 1.5f, "%.2f");
    changed |= ImGui::SliderFloat("Fade from", &g_binder.fade_start, 0.0f, 1.0f, "%.2f x top speed");
    changed |= ImGui::SliderFloat("Gone at", &g_binder.fade_end, 0.0f, 1.0f, "%.2f x top speed");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("The game's lowest engine gear ends at 0.25 x top speed.");
    if (g_binder_debug_gain >= 0.0f)
        ImGui::TextDisabled("Now: volume %.0f%%", g_binder_debug_gain * 100.0f);
    ImGui::EndDisabled();
    if (ImGui::Button("Reset binder hum to defaults")) {
        g_binder = BinderHumSettings{};
        changed = true;
    }

    ImGui::SeparatorText("Sebulba's pod");
    changed |= ImGui::Checkbox("Film engine sound", &g_film.on);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Plays the film's Sebulba engine loop (sounds\\sebulba_engine_loop.wav) on his pod,\n"
                          "following its speed, throttle and distance from you.");
    ImGui::BeginDisabled(!g_film.on);
    changed |= ImGui::SliderFloat("Film engine volume", &g_film.volume, 0.0f, 1.5f, "%.2f");
    changed |= ImGui::SliderFloat("Film engine range", &g_film.range, 50.0f, 3000.0f, "%.0f");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("When you fly Sebulba: distance from the camera at which the sound fades out.");
    changed |= ImGui::SliderFloat("AI Sebulba range", &g_film.ai_range, 100.0f, 5000.0f, "%.0f");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("When an AI flies Sebulba: how far away you can still hear him.");
    changed |= ImGui::SliderFloat("AI Sebulba Doppler", &g_film.doppler, 0.0f, 3.0f, "%.2fx");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Pitch rise as he approaches and drop as he passes. 0 = off.");
    if (g_film_debug_dist >= 0.0f)
        ImGui::TextDisabled("Your Sebulba: %.0f from camera, volume %.0f%%", g_film_debug_dist, g_film_debug_gain * 100.0f);
    const bool ai_recent = std::chrono::steady_clock::now() - g_film_ai_time < std::chrono::seconds(1);
    if (ai_recent && g_film_ai_dist >= 0.0f)
        ImGui::TextDisabled("AI Sebulba: %.0f from camera, volume %.0f%%, Doppler x%.2f", g_film_ai_dist,
                            g_film_ai_gain * 100.0f, g_film_ai_doppler);
    else if (g_film_debug_dist < 0.0f)
        ImGui::TextDisabled("No Sebulba in this race yet.");
    ImGui::EndDisabled();
    if (g_film.on && custom_engine_sound_status()[0] != 0)
        ImGui::TextDisabled("%s", custom_engine_sound_status());
    // Everything in the Sebulba section: film loop (volume, ranges, Doppler).
    if (ImGui::Button("Reset Sebulba sound to defaults")) {
        g_film = FilmEngineSettings{};
        changed = true;
    }
    return changed;
}
