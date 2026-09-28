#include "player_camera.h"
#include "../hook_helper.h"
#include "../debug_ui.h"
#include "../imgui_utils.h"
#include "../config.h"

#include <imgui.h>

// Defined in hook_helper.cpp (registers a raw game-address detour); not prototyped in hook_helper.h.
extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);
// Defined in imgui_utils.cpp (persists imgui_state to [settings]); not prototyped in imgui_utils.h.
void save_settings_ini();

#include <windows.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

extern "C" {
#include <Primitives/rdMatrix.h>
#include <Primitives/rdVector.h>
#include <Swr/swrObj.h>      // swrObjcMan_* detour targets
#include <Swr/swrModel.h>    // BuildLookAtTransform, swrModel_NodeModifyFlags, sun / light-streak updaters
#include <Swr/swrPlayerHUD.h>// swrPlayerHUD_RenderWorldSprites_ADDR
#include <globals.h>         // swrRacer_PodVisualData, g_objHang2
}

namespace {

// swrObjcMan_UpdateCamera modes the player can drive in; spline / sweep / death modes are left alone.
enum CamMode {
    CAM_MODE_CHASE_NEAR = 1,
    CAM_MODE_CHASE_FAR = 2, // chase with doubled trail / height
    CAM_MODE_FIRST_PERSON = 4,
    CAM_MODE_FIRST_PERSON_WIDE = 5,// first person at the 120-degree FOV
};

// The camera-button cycle, with the true cockpit inserted after the wide first person:
// near -> first person -> first person wide -> true cockpit -> far -> near. The true cockpit is
// camera-man mode 4 on the camera-man recorded in g_cockpit_cman.
enum PreferredView {
    VIEW_GAME_DEFAULT = 0,
    VIEW_CHASE_NEAR,
    VIEW_FIRST_PERSON,
    VIEW_FIRST_PERSON_WIDE,
    VIEW_TRUE_COCKPIT,
    VIEW_CHASE_FAR,
    VIEW_COUNT
};
constexpr int VIEW_MODES[VIEW_COUNT] = {0, CAM_MODE_CHASE_NEAR, CAM_MODE_FIRST_PERSON,
                                        CAM_MODE_FIRST_PERSON_WIDE, CAM_MODE_FIRST_PERSON,
                                        CAM_MODE_CHASE_FAR};
const char *const VIEW_NAMES[VIEW_COUNT] = {"Game default", "Chase (near)", "First person",
                                            "First person (wide)", "True cockpit", "Chase (far)"};

constexpr int EVENT_CAMERA_BUTTON = 0x43427574;// 'CBut': the in-race camera key, handled by swrObjcMan_F4

constexpr int NUM_PILOTS = 23;// swrRacer_PodVisualData[23]

struct PlayerCameraConfig {
    int view = 0;               // PreferredView, applied once per race; updated by the camera key
    float trail_scale = 1.0f;   // chase-camera distance multiplier
    float height_scale = 1.0f;  // chase-camera height multiplier
    float fov_offset = 0.0f;    // degrees added to the game's camera FOV
    float dynamic_fov = 0.0f;   // extra degrees at top speed (0 = off), eased in with speed^2
    float roll_influence = 1.0f;// 1 = the game's camera roll, 0 = level horizon
    float cockpit_near_scale = 0.25f;// near-plane scale while the true cockpit is active
    float cockpit_right = 0.0f; // first-person camera offset (units): pod axes, or cockpit axes in
    float cockpit_forward = 0.0f;// the true cockpit (added to the per-pilot table)
    float cockpit_up = 0.0f;
    bool show_pod_first_person = false;// keep the pod visible in the first-person views
    bool hide_own_pod = false;
    bool hide_hud = false;
    bool hide_guide_arrow = false;
    bool hide_suns = false;        // suns + lens flares
    bool hide_light_streaks = false;
    // Perlin camera shake (port of the GLSEPRAC Cheat Engine camera mod); gains on its amplitudes.
    float shake_intensity = 0.0f;// master gain; 0 = off
    float shake_speed = 6.0f;    // noise-time units per second (the mod advanced 0.1 per tick)
    float shake_boost = 1.0f;    // gain on the steady boost rumble
    float shake_boost_burst = 1.0f;// gain on the boost-onset burst
    float shake_vibration = 1.0f;// gain on the collision / terrain vibration term
};
PlayerCameraConfig g_cfg;

swrObjcMan *g_cockpit_cman = nullptr;// camera-man whose mode 4 is the true cockpit (several exist)
bool cockpit_active(const swrObjcMan *cman) {
    return g_cockpit_cman == cman;
}
bool g_view_applied = false;  // preferred view applied for the current race

enum SpriteGroup { GROUP_NONE, GROUP_SUN, GROUP_LIGHT_STREAKS };
SpriteGroup g_sprite_group = GROUP_NONE;

bool in_race() {
    // hangar / front-end active screen <=> flag bit 0
    swrObjHang *hang = g_objHang2;
    return hang == nullptr || (hang->flag & 1) == 0;
}

bool is_player_view(int mode) {
    return mode == CAM_MODE_CHASE_NEAR || mode == CAM_MODE_CHASE_FAR ||
           mode == CAM_MODE_FIRST_PERSON || mode == CAM_MODE_FIRST_PERSON_WIDE;
}

bool is_first_person(int mode) {
    return mode == CAM_MODE_FIRST_PERSON || mode == CAM_MODE_FIRST_PERSON_WIDE;
}

// Followed racer if it is the local player's pod; spectator / demo cameras are left alone.
swrRace *local_followed_racer(swrObjcMan *cman) {
    swrRace *racer = cman->unkf4_objTest;
    if (racer == nullptr || (racer->flags0 & swrObjTest_FLAG0_LOCAL) == 0)
        return nullptr;
    return racer;
}

typedef void(__cdecl *swrObjcMan_CommitStagedCameraFn)(swrObjcMan *, int);

// Switch the camera-man the way the 'CBut' handler does: chase modes through CommitStagedCamera,
// first-person modes by writing mode_type; mode_respawn follows so a respawn keeps the view.
void set_view(swrObjcMan *cman, int view) {
    const int mode = VIEW_MODES[view];
    if (mode == 0)
        return;
    if (view == VIEW_TRUE_COCKPIT)
        g_cockpit_cman = cman;
    else if (g_cockpit_cman == cman)
        g_cockpit_cman = nullptr;
    if (mode == CAM_MODE_CHASE_NEAR || mode == CAM_MODE_CHASE_FAR)
        ((swrObjcMan_CommitStagedCameraFn) swrObjcMan_CommitStagedCamera_ADDR)(cman, mode);
    else
        cman->mode_type = mode;
    cman->mode_respawn = mode;
}

int view_from_cman(const swrObjcMan *cman) {
    switch (cman->mode_type) {
        case CAM_MODE_CHASE_NEAR:
            return VIEW_CHASE_NEAR;
        case CAM_MODE_CHASE_FAR:
            return VIEW_CHASE_FAR;
        case CAM_MODE_FIRST_PERSON:
            return cockpit_active(cman) ? VIEW_TRUE_COCKPIT : VIEW_FIRST_PERSON;
        case CAM_MODE_FIRST_PERSON_WIDE:
            return VIEW_FIRST_PERSON_WIDE;
        default:
            return VIEW_GAME_DEFAULT;
    }
}

void save_config();

// Apply the persisted view once per race, the first frame the player's camera is in a drivable view
// (after the pre-race sweep, or immediately when it is skipped). Leaving the race re-arms it.
void apply_preferred_view(swrObjcMan *cman) {
    if (cman->mode_type == 0 || cman->metaCamIndex_count < 0 ||
        cman->mode_type == 7 /* pre-race sweep */) {
        g_view_applied = false;
        if (g_cockpit_cman == cman)
            g_cockpit_cman = nullptr;
        return;
    }
    if (g_view_applied || local_followed_racer(cman) == nullptr || !is_player_view(cman->mode_type))
        return;
    g_view_applied = true;
    if (g_cfg.view != VIEW_GAME_DEFAULT)
        set_view(cman, std::clamp(g_cfg.view, 0, VIEW_COUNT - 1));
}

// Per-pilot eye offsets from the cockpit transform (forward, up), the CE mod's CockpitY / CockpitZ.
constexpr float COCKPIT_EYE_FORWARD[NUM_PILOTS] = {
    -0.25f, -0.45f, -0.85f, 0.3f,  1.0f,  -1.25f, -0.05f, 0.35f, -0.78f, -0.4f, 0.05f, -1.0f,
    -0.5f,  0.85f,  1.9f,   -1.0f, -2.6f, -1.0f,  1.75f,  -0.55f, -0.5f,  1.5f, -0.1f};
constexpr float COCKPIT_EYE_UP[NUM_PILOTS] = {
    0.5f,  0.2f, 0.65f, 0.53f, 0.3f, 0.75f, 0.2f,  0.7f, 0.55f, 0.7f, 0.45f, 0.95f,
    -0.3f, 0.6f, 0.6f,  0.6f,  0.8f, 0.95f, 0.5f, 1.2f, 1.0f,  0.8f, 0.1f};
constexpr float COCKPIT_FOCUS_DISTANCE = 100.0f;

int pilot_index(swrRace *racer) {
    if (racer->score_ptr == nullptr || racer->score_ptr->pilotId == nullptr)
        return -1;
    const int pilot = *racer->score_ptr->pilotId;
    return (pilot >= 0 && pilot < NUM_PILOTS) ? pilot : -1;
}

// Camera / aim point += right * x + forward * y + up * z of `basis`.
void offset_camera(swrObjcMan *cman, const rdMatrix44 &basis, float x, float y, float z) {
    if (x == 0.0f && y == 0.0f && z == 0.0f)
        return;
    rdVector3 off;
    off.x = basis.vA.x * x + basis.vB.x * y + basis.vC.x * z;
    off.y = basis.vA.y * x + basis.vB.y * y + basis.vC.y * z;
    off.z = basis.vA.z * x + basis.vB.z * y + basis.vC.z * z;
    rdVector3 *cam = (rdVector3 *) &cman->unk20_mat.vD;
    rdVector3 *focus = (rdVector3 *) &cman->focusTransform_mat.vD;
    rdVector_Scale3Add3(cam, cam, 1.0f, &off);
    rdVector_Scale3Add3(focus, focus, 1.0f, &off);
}

// Replace the first-person camera with the pod's cockpit transform (world space, rewritten each
// frame by swrRace_PoddAnimateEngines; may carry scale on the diagonal, hence the normalize), eye at
// the per-pilot offset, aim straight ahead.
void apply_true_cockpit(swrObjcMan *cman, swrRace *racer) {
    rdMatrix44 cam = racer->cockpitXf;
    rdVector_Normalize3Acc((rdVector3 *) &cam.vA);
    rdVector_Normalize3Acc((rdVector3 *) &cam.vB);
    rdVector_Normalize3Acc((rdVector3 *) &cam.vC);
    cam.vA.w = cam.vB.w = cam.vC.w = 0.0f;
    cam.vD.w = 1.0f;
    cman->unk20_mat = cam;
    rdVector_Scale3Add3((rdVector3 *) &cman->focusTransform_mat.vD, (rdVector3 *) &cam.vD,
                        COCKPIT_FOCUS_DISTANCE, (rdVector3 *) &cam.vB);
    const int pilot = pilot_index(racer);
    if (pilot >= 0)
        offset_camera(cman, cam, 0.0f, COCKPIT_EYE_FORWARD[pilot], COCKPIT_EYE_UP[pilot]);
}

// User offset in pod axes (vA right, vB forward, vC up), or cockpit axes in true-cockpit mode.
void apply_cockpit_offset(swrObjcMan *cman, swrRace *racer) {
    offset_camera(cman, cockpit_active(cman) ? cman->unk20_mat : racer->transform, g_cfg.cockpit_right,
                  g_cfg.cockpit_forward, g_cfg.cockpit_up);
}

// Same look-at rebuild swrObjcMan_UpdateCamera ends with, roll scaled by the user influence.
void scale_roll(swrObjcMan *cman, float influence) {
    swrTranslationRotation tr;
    rdMatrix_ExtractTransform(&cman->unk20_mat, &tr);
    const float roll = tr.yaw_roll_pitch.z * influence;// .z is what UpdateCamera passes as the roll
    rdMatrix44 out;
    BuildLookAtTransform((rdVector3 *) &cman->unk20_mat.vD, (rdVector3 *) &cman->focusTransform_mat.vD,
                         &out, &tr, roll);
    rdMatrix_Copy44(&cman->unk20_mat, &out);
}

// Ken Perlin's improved noise, same permutation table as the CE mod.
namespace perlin {
constexpr unsigned char PERMUTATION[256] = {
    151, 160, 137, 91,  90,  15,  131, 13,  201, 95,  96,  53,  194, 233, 7,   225, 140, 36,  103, 30,
    69,  142, 8,   99,  37,  240, 21,  10,  23,  190, 6,   148, 247, 120, 234, 75,  0,   26,  197, 62,
    94,  252, 219, 203, 117, 35,  11,  32,  57,  177, 33,  88,  237, 149, 56,  87,  174, 20,  125, 136,
    171, 168, 68,  175, 74,  165, 71,  134, 139, 48,  27,  166, 77,  146, 158, 231, 83,  111, 229, 122,
    60,  211, 133, 230, 220, 105, 92,  41,  55,  46,  245, 40,  244, 102, 143, 54,  65,  25,  63,  161,
    1,   216, 80,  73,  209, 76,  132, 187, 208, 89,  18,  169, 200, 196, 135, 130, 116, 188, 159, 86,
    164, 100, 109, 198, 173, 186, 3,   64,  52,  217, 226, 250, 124, 123, 5,   202, 38,  147, 118, 126,
    255, 82,  85,  212, 207, 206, 59,  227, 47,  16,  58,  17,  182, 189, 28,  42,  223, 183, 170, 213,
    119, 248, 152, 2,   44,  154, 163, 70,  221, 153, 101, 155, 167, 43,  172, 9,   129, 22,  39,  253,
    19,  98,  108, 110, 79,  113, 224, 232, 178, 185, 112, 104, 218, 246, 97,  228, 251, 34,  242, 193,
    238, 210, 144, 12,  191, 179, 162, 241, 81,  51,  145, 235, 249, 14,  239, 107, 49,  192, 214, 31,
    181, 199, 106, 157, 184, 84,  204, 176, 115, 121, 50,  45,  127, 4,   150, 254, 138, 236, 205, 93,
    222, 114, 67,  29,  24,  72,  243, 141, 128, 195, 78,  66,  215, 61,  156, 180};

inline int p(int i) {
    return PERMUTATION[i & 255];
}
inline float fade(float t) {
    return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
}
inline float lerp(float t, float a, float b) {
    return a + t * (b - a);
}
inline float grad(int hash, float x, float y, float z) {
    const int h = hash & 15;
    const float u = h < 8 ? x : y;
    const float v = h < 4 ? y : ((h == 12 || h == 14) ? x : z);
    return ((h & 1) == 0 ? u : -u) + ((h & 2) == 0 ? v : -v);
}
float noise(float x, float y, float z) {
    const float fx = std::floor(x), fy = std::floor(y), fz = std::floor(z);
    const int X = (int) fx & 255, Y = (int) fy & 255, Z = (int) fz & 255;
    x -= fx;
    y -= fy;
    z -= fz;
    const float u = fade(x), v = fade(y), w = fade(z);
    const int A = p(X) + Y, AA = p(A) + Z, AB = p(A + 1) + Z;
    const int B = p(X + 1) + Y, BA = p(B) + Z, BB = p(B + 1) + Z;
    return lerp(w,
                lerp(v, lerp(u, grad(p(AA), x, y, z), grad(p(BA), x - 1, y, z)),
                     lerp(u, grad(p(AB), x, y - 1, z), grad(p(BB), x - 1, y - 1, z))),
                lerp(v, lerp(u, grad(p(AA + 1), x, y, z - 1), grad(p(BA + 1), x - 1, y, z - 1)),
                     lerp(u, grad(p(AB + 1), x, y - 1, z - 1), grad(p(BB + 1), x - 1, y - 1, z - 1))));
}
}// namespace perlin

// The mod's amplitudes (degrees): boost rumble noise*4*0.15, onset burst / vibration noise*5.
constexpr float SHAKE_BOOST_AMPLITUDE_DEG = 4.0f * 0.15f;
constexpr float SHAKE_BURST_AMPLITUDE_DEG = 5.0f;
constexpr float SHAKE_VIBRATION_AMPLITUDE_DEG = 5.0f;
constexpr float SHAKE_BURST_PEAK = 25.0f / 50.0f;
constexpr float SHAKE_BURST_SECONDS = 25.0f / 60.0f;// 25 ticks of the mod's ~60 Hz timer

float g_shake_time = 0.0f; // noise-space time
float g_shake_burst = 0.0f;// boost-onset burst, seconds remaining
bool g_shake_was_boosting = false;

// Yaw / pitch / roll (degrees) about the camera's own up / right / forward axes.
void apply_shake(swrObjcMan *cman, swrRace *racer) {
    if (g_cfg.shake_intensity <= 0.0f)
        return;
    const float dt = swrRace_deltaTimeSecs;
    g_shake_time += dt * g_cfg.shake_speed;

    const bool boosting = (racer->flags0 & swrObjTest_FLAG0_BOOSTING) != 0;
    if (boosting && !g_shake_was_boosting)
        g_shake_burst = SHAKE_BURST_SECONDS;
    g_shake_was_boosting = boosting;
    g_shake_burst = std::max(0.0f, g_shake_burst - dt);

    const float t = g_shake_time;
    const float boost = boosting ? SHAKE_BOOST_AMPLITUDE_DEG * g_cfg.shake_boost : 0.0f;
    const float burst = SHAKE_BURST_AMPLITUDE_DEG * SHAKE_BURST_PEAK *
                        (g_shake_burst / SHAKE_BURST_SECONDS) * g_cfg.shake_boost_burst;
    const float vib = std::clamp(racer->vibrationMagnitude, 0.0f, 1.0f);
    const float vibration = SHAKE_VIBRATION_AMPLITUDE_DEG * vib * vib * g_cfg.shake_vibration;

    const float g = g_cfg.shake_intensity;
    const float yaw =
        g * (perlin::noise(t, 0, 50) * boost + perlin::noise(-t, 0, 50) * (burst + vibration));
    const float pitch =
        g * (perlin::noise(0, t, 50) * boost + perlin::noise(0, -t, 50) * (burst + vibration));
    const float roll =
        g * (perlin::noise(50, 50, t) * boost + perlin::noise(0, 0, -t) * (burst + vibration));
    if (yaw == 0.0f && pitch == 0.0f && roll == 0.0f)
        return;

    rdMatrix44 in = cman->unk20_mat;
    rdMatrix_AddRotationFromVectorAngle44Before(&cman->unk20_mat, yaw, 0.0f, 0.0f, 1.0f, &in);
    in = cman->unk20_mat;
    rdMatrix_AddRotationFromVectorAngle44Before(&cman->unk20_mat, pitch, 1.0f, 0.0f, 0.0f, &in);
    in = cman->unk20_mat;
    rdMatrix_AddRotationFromVectorAngle44Before(&cman->unk20_mat, roll, 0.0f, 1.0f, 0.0f, &in);
}

constexpr const char *INI_SECTION = "player_camera";

void load_config() {
    g_cfg.view = std::clamp(config::get_int(INI_SECTION, "view", g_cfg.view), 0, VIEW_COUNT - 1);
    g_cfg.trail_scale = config::get_float(INI_SECTION, "trail_scale", g_cfg.trail_scale);
    g_cfg.height_scale = config::get_float(INI_SECTION, "height_scale", g_cfg.height_scale);
    g_cfg.fov_offset = config::get_float(INI_SECTION, "fov_offset", g_cfg.fov_offset);
    g_cfg.dynamic_fov = config::get_float(INI_SECTION, "dynamic_fov", g_cfg.dynamic_fov);
    g_cfg.roll_influence = config::get_float(INI_SECTION, "roll_influence", g_cfg.roll_influence);
    g_cfg.cockpit_near_scale = config::get_float(INI_SECTION, "cockpit_near_scale", g_cfg.cockpit_near_scale);
    g_cfg.cockpit_right = config::get_float(INI_SECTION, "cockpit_right", g_cfg.cockpit_right);
    g_cfg.cockpit_forward = config::get_float(INI_SECTION, "cockpit_forward", g_cfg.cockpit_forward);
    g_cfg.cockpit_up = config::get_float(INI_SECTION, "cockpit_up", g_cfg.cockpit_up);
    g_cfg.show_pod_first_person =
        config::get_int(INI_SECTION, "show_pod_first_person", g_cfg.show_pod_first_person);
    g_cfg.hide_own_pod = config::get_int(INI_SECTION, "hide_own_pod", g_cfg.hide_own_pod);
    g_cfg.hide_hud = config::get_int(INI_SECTION, "hide_hud", g_cfg.hide_hud);
    g_cfg.hide_guide_arrow = config::get_int(INI_SECTION, "hide_guide_arrow", g_cfg.hide_guide_arrow);
    g_cfg.hide_suns = config::get_int(INI_SECTION, "hide_suns", g_cfg.hide_suns);
    g_cfg.hide_light_streaks = config::get_int(INI_SECTION, "hide_light_streaks", g_cfg.hide_light_streaks);
    g_cfg.shake_intensity = config::get_float(INI_SECTION, "shake_intensity", g_cfg.shake_intensity);
    g_cfg.shake_speed = config::get_float(INI_SECTION, "shake_speed", g_cfg.shake_speed);
    g_cfg.shake_boost = config::get_float(INI_SECTION, "shake_boost", g_cfg.shake_boost);
    g_cfg.shake_boost_burst = config::get_float(INI_SECTION, "shake_boost_burst", g_cfg.shake_boost_burst);
    g_cfg.shake_vibration = config::get_float(INI_SECTION, "shake_vibration", g_cfg.shake_vibration);
}
void save_config() {
    config::set_int(INI_SECTION, "view", g_cfg.view);
    config::set_float(INI_SECTION, "trail_scale", g_cfg.trail_scale);
    config::set_float(INI_SECTION, "height_scale", g_cfg.height_scale);
    config::set_float(INI_SECTION, "fov_offset", g_cfg.fov_offset);
    config::set_float(INI_SECTION, "dynamic_fov", g_cfg.dynamic_fov);
    config::set_float(INI_SECTION, "roll_influence", g_cfg.roll_influence);
    config::set_float(INI_SECTION, "cockpit_near_scale", g_cfg.cockpit_near_scale);
    config::set_float(INI_SECTION, "cockpit_right", g_cfg.cockpit_right);
    config::set_float(INI_SECTION, "cockpit_forward", g_cfg.cockpit_forward);
    config::set_float(INI_SECTION, "cockpit_up", g_cfg.cockpit_up);
    config::set_bool(INI_SECTION, "show_pod_first_person", g_cfg.show_pod_first_person);
    config::set_bool(INI_SECTION, "hide_own_pod", g_cfg.hide_own_pod);
    config::set_bool(INI_SECTION, "hide_hud", g_cfg.hide_hud);
    config::set_bool(INI_SECTION, "hide_guide_arrow", g_cfg.hide_guide_arrow);
    config::set_bool(INI_SECTION, "hide_suns", g_cfg.hide_suns);
    config::set_bool(INI_SECTION, "hide_light_streaks", g_cfg.hide_light_streaks);
    config::set_float(INI_SECTION, "shake_intensity", g_cfg.shake_intensity);
    config::set_float(INI_SECTION, "shake_speed", g_cfg.shake_speed);
    config::set_float(INI_SECTION, "shake_boost", g_cfg.shake_boost);
    config::set_float(INI_SECTION, "shake_boost_burst", g_cfg.shake_boost_burst);
    config::set_float(INI_SECTION, "shake_vibration", g_cfg.shake_vibration);
}

void panel_player_camera() {
    bool dirty = false;

    ImGui::SeparatorText("View");
    if (ImGui::Combo("Camera view", &g_cfg.view, VIEW_NAMES, IM_ARRAYSIZE(VIEW_NAMES))) {
        dirty = true;
        g_view_applied = false;// re-apply now; the camera key keeps updating it afterwards
    }
    dirty |= ImGui::SliderFloat("Chase distance", &g_cfg.trail_scale, 0.25f, 4.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Chase height", &g_cfg.height_scale, 0.25f, 4.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Camera roll", &g_cfg.roll_influence, 0.0f, 1.5f, "x%.2f");

    ImGui::SeparatorText("Field of view");
    dirty |= ImGui::SliderFloat("FOV offset", &g_cfg.fov_offset, -40.0f, 40.0f, "%+.0f deg");
    dirty |= ImGui::SliderFloat("Dynamic FOV (at top speed)", &g_cfg.dynamic_fov, 0.0f, 40.0f,
                                "+%.0f deg");

    ImGui::SeparatorText("First person / cockpit");
    dirty |= ImGui::SliderFloat("Cockpit near clip", &g_cfg.cockpit_near_scale, 0.02f, 1.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Offset right", &g_cfg.cockpit_right, -3.0f, 3.0f, "%.2f");
    dirty |= ImGui::SliderFloat("Offset forward", &g_cfg.cockpit_forward, -6.0f, 6.0f, "%.2f");
    dirty |= ImGui::SliderFloat("Offset up", &g_cfg.cockpit_up, -3.0f, 3.0f, "%.2f");
    dirty |= ImGui::Checkbox("Show my pod in first person", &g_cfg.show_pod_first_person);

    ImGui::SeparatorText("Camera shake");
    dirty |= ImGui::SliderFloat("Shake intensity", &g_cfg.shake_intensity, 0.0f, 3.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Shake speed", &g_cfg.shake_speed, 1.0f, 20.0f, "%.1f");
    dirty |= ImGui::SliderFloat("Boost rumble", &g_cfg.shake_boost, 0.0f, 3.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Boost onset burst", &g_cfg.shake_boost_burst, 0.0f, 3.0f, "x%.2f");
    dirty |= ImGui::SliderFloat("Collision / terrain vibration", &g_cfg.shake_vibration, 0.0f, 3.0f,
                                "x%.2f");

    ImGui::SeparatorText("Visibility");
    dirty |= ImGui::Checkbox("Hide HUD", &g_cfg.hide_hud);
    dirty |= ImGui::Checkbox("Hide guide arrow", &g_cfg.hide_guide_arrow);
    dirty |= ImGui::Checkbox("Hide suns / lens flares", &g_cfg.hide_suns);
    dirty |= ImGui::Checkbox("Hide light streaks", &g_cfg.hide_light_streaks);
    dirty |= ImGui::Checkbox("Hide my pod", &g_cfg.hide_own_pod);
    // shared with the general settings
    bool labels = imgui_state.show_pod_names;
    if (ImGui::Checkbox("Hide racer labels / position numbers", &labels)) {
        imgui_state.show_pod_names = !labels;
        save_settings_ini();
    }
    bool weather = imgui_state.enable_weather;
    if (ImGui::Checkbox("Hide weather", &weather)) {
        imgui_state.enable_weather = !weather;
        save_settings_ini();
    }

    ImGui::Separator();
    ImGui::TextDisabled("The camera key cycles near / first person / wide / true cockpit / far;");
    ImGui::TextDisabled("the view you land on is remembered across sessions.");

    static bool pending = false;
    if (dirty)
        pending = true;
    if (pending && !ImGui::IsAnyItemActive()) {
        save_config();
        pending = false;
    }
}

DebugPanel g_panel = {
    .category = "Camera", .name = "Player Camera", .draw = panel_player_camera, .dev_only = false};

}// namespace

bool playercam_HudHidden() {
    return g_cfg.hide_hud && in_race();
}

bool playercam_SuppressSpriteVisibility() {
    return (g_sprite_group == GROUP_SUN && g_cfg.hide_suns) ||
           (g_sprite_group == GROUP_LIGHT_STREAKS && g_cfg.hide_light_streaks);
}

bool playercam_HideOwnPod() {
    return g_cfg.hide_own_pod;
}

bool playercam_ShowPodInFirstPerson() {
    return g_cfg.show_pod_first_person || g_cockpit_cman != nullptr;
}

float playercam_NearClipScale() {
    return g_cockpit_cman != nullptr ? std::clamp(g_cfg.cockpit_near_scale, 0.02f, 1.0f) : 1.0f;
}

void playercam_RegisterPanel() {
    load_config();
    debug_ui_register(&g_panel);
}

// After the original, unk20_mat / focusTransform_mat hold this frame's camera and aim point; the
// quake pass in swrObjcMan_F3 and the viewport camera-state update consume them afterwards.
typedef void(__cdecl *swrObjcMan_UpdateCameraFn)(swrObjcMan *);
extern "C" void __cdecl swrObjcMan_UpdateCamera_delta(swrObjcMan *cman) {
    apply_preferred_view(cman);
    // Any other drivable view ends the true cockpit (mode 4 alone keeps it, e.g. across a respawn).
    if (g_cockpit_cman == cman && is_player_view(cman->mode_type) &&
        cman->mode_type != CAM_MODE_FIRST_PERSON)
        g_cockpit_cman = nullptr;
    hook_call_original((swrObjcMan_UpdateCameraFn) swrObjcMan_UpdateCamera_ADDR, cman);

    swrRace *racer = local_followed_racer(cman);
    if (racer == nullptr || !is_player_view(cman->mode_type))
        return;
    if (is_first_person(cman->mode_type)) {
        if (cockpit_active(cman))
            apply_true_cockpit(cman, racer);
        apply_cockpit_offset(cman, racer);
    }
    if (g_cfg.roll_influence != 1.0f)
        scale_roll(cman, g_cfg.roll_influence);
    apply_shake(cman, racer);
}

// Scale the followed pilot's swrRacer_PodVisualData trail / height around the call only.
typedef void(__cdecl *swrObjcMan_UpdateChaseCameraFn)(swrObjcMan *);
extern "C" void __cdecl swrObjcMan_UpdateChaseCamera_delta(swrObjcMan *cman) {
    swrRace *racer = local_followed_racer(cman);
    const int pilot = racer != nullptr ? pilot_index(racer) : -1;
    const bool scale = pilot >= 0 && (g_cfg.trail_scale != 1.0f || g_cfg.height_scale != 1.0f);
    if (!scale) {
        hook_call_original((swrObjcMan_UpdateChaseCameraFn) swrObjcMan_UpdateChaseCamera_ADDR, cman);
        return;
    }
    swrRacerVisualData &row = swrRacer_PodVisualData[pilot];
    const float trail = row.chaseCamTrail;
    const float height = row.chaseCamHeight;
    row.chaseCamTrail = trail * g_cfg.trail_scale;
    row.chaseCamHeight = height * g_cfg.height_scale;
    hook_call_original((swrObjcMan_UpdateChaseCameraFn) swrObjcMan_UpdateChaseCamera_ADDR, cman);
    row.chaseCamTrail = trail;
    row.chaseCamHeight = height;
}

// stagingTransformFocus.vD.w is the camera FOV, re-staged every frame by the mode function (100, or
// 120 for the wide first person) and pushed to the viewport here.
typedef void(__cdecl *swrObjcMan_UpdateFogAndViewportFn)(swrObjcMan *);
extern "C" void __cdecl swrObjcMan_UpdateFogAndViewport_delta(swrObjcMan *cman) {
    swrRace *racer = local_followed_racer(cman);
    if (racer != nullptr && is_player_view(cman->mode_type)) {
        float fov = cman->stagingTransformFocus.vD.w + g_cfg.fov_offset;
        if (g_cfg.dynamic_fov > 0.0f && racer->podStats.maxSpeed > 0.0f) {
            const float t = std::clamp(racer->speedValue / racer->podStats.maxSpeed, 0.0f, 1.0f);
            fov += g_cfg.dynamic_fov * t * t;
        }
        cman->stagingTransformFocus.vD.w = std::clamp(fov, 20.0f, 170.0f);
    }
    hook_call_original((swrObjcMan_UpdateFogAndViewportFn) swrObjcMan_UpdateFogAndViewport_ADDR,
                       cman);
}

// The original re-shows the arrow node every frame; hide it again with swrObjJdge_UpdatePlayerHUD's
// flag write. guideArrowNode is stale memory until FLAG0_GUIDE_ARROW is set.
typedef void(__cdecl *swrObjcMan_UpdateSplineGuideMarkerFn)(swrObjcMan *);
extern "C" void __cdecl swrObjcMan_UpdateSplineGuideMarker_delta(swrObjcMan *cman) {
    hook_call_original((swrObjcMan_UpdateSplineGuideMarkerFn) swrObjcMan_UpdateSplineGuideMarker_ADDR,
                       cman);
    if (!g_cfg.hide_guide_arrow)
        return;
    swrRace *racer = cman->unkf4_objTest;
    if (racer != nullptr && (racer->flags0 & swrObjTest_FLAG0_GUIDE_ARROW) != 0 &&
        racer->guideArrowNode != nullptr)
        swrModel_NodeModifyFlags(racer->guideArrowNode, 2, -4, 0x10, 3);
}

// Both updaters re-assert visibility every frame; the SetVisible detour (camera.cpp) forces a hidden
// group off.
typedef void(__cdecl *WorldSpriteUpdaterFn)(swrViewport *);
extern "C" void __cdecl UpdateSunAndLensFlareSprites_delta(swrViewport *vp) {
    g_sprite_group = GROUP_SUN;
    hook_call_original((WorldSpriteUpdaterFn) UpdateSunAndLensFlareSprites_ADDR, vp);
    g_sprite_group = GROUP_NONE;
}
extern "C" void __cdecl UpdateLightStreakSprites_delta(swrViewport *vp) {
    g_sprite_group = GROUP_LIGHT_STREAKS;
    hook_call_original((WorldSpriteUpdaterFn) UpdateLightStreakSprites_ADDR, vp);
    g_sprite_group = GROUP_NONE;
}
extern "C" void __cdecl swrPlayerHUD_RenderWorldSprites_delta(swrViewport *vp) {
    g_sprite_group = GROUP_LIGHT_STREAKS;
    hook_call_original((WorldSpriteUpdaterFn) swrPlayerHUD_RenderWorldSprites_ADDR, vp);
    g_sprite_group = GROUP_NONE;
}

// The camera key: insert the true cockpit between the wide first person and the far chase, and
// remember the view the player lands on. Anything else passes through.
typedef int(__cdecl *swrObjcMan_F4Fn)(swrObjcMan *, int *, int);
extern "C" int __cdecl swrObjcMan_F4_delta(swrObjcMan *cman, int *subEvents, int p3) {
    const bool camera_button = subEvents[0] == EVENT_CAMERA_BUTTON &&
                               (swrRace *) subEvents[1] == cman->unkf4_objTest &&
                               local_followed_racer(cman) != nullptr;
    if (!camera_button)
        return hook_call_original((swrObjcMan_F4Fn) swrObjcMan_F4_ADDR, cman, subEvents, p3);

    const bool was_cockpit = cockpit_active(cman);
    if (cman->mode_type == CAM_MODE_FIRST_PERSON_WIDE && !was_cockpit) {
        cman->mode_type = CAM_MODE_FIRST_PERSON;
        cman->mode_respawn = CAM_MODE_FIRST_PERSON;
        g_cockpit_cman = cman;
    } else {
        if (cman->mode_type == CAM_MODE_FIRST_PERSON && was_cockpit) {
            g_cockpit_cman = nullptr;
            cman->mode_type = CAM_MODE_FIRST_PERSON_WIDE;// the original steps wide -> far
        }
        hook_call_original((swrObjcMan_F4Fn) swrObjcMan_F4_ADDR, cman, subEvents, p3);
    }
    const int view = view_from_cman(cman);
    if (view != VIEW_GAME_DEFAULT && view != g_cfg.view) {
        g_cfg.view = view;
        save_config();
    }
    return 1;
}

void playercam_RegisterHooks() {
    hook_function("swrObjcMan_F4", (uint32_t) swrObjcMan_F4_ADDR, (uint8_t *) swrObjcMan_F4_delta);
    // Raw-address detours, not hook_replace: keeps the reverse hooks intact (see camera.cpp).
    hook_function("swrObjcMan_UpdateCamera", (uint32_t) swrObjcMan_UpdateCamera_ADDR,
                  (uint8_t *) swrObjcMan_UpdateCamera_delta);
    hook_function("swrObjcMan_UpdateChaseCamera", (uint32_t) swrObjcMan_UpdateChaseCamera_ADDR,
                  (uint8_t *) swrObjcMan_UpdateChaseCamera_delta);
    hook_function("swrObjcMan_UpdateFogAndViewport", (uint32_t) swrObjcMan_UpdateFogAndViewport_ADDR,
                  (uint8_t *) swrObjcMan_UpdateFogAndViewport_delta);
    hook_function("swrObjcMan_UpdateSplineGuideMarker",
                  (uint32_t) swrObjcMan_UpdateSplineGuideMarker_ADDR,
                  (uint8_t *) swrObjcMan_UpdateSplineGuideMarker_delta);
    hook_function("UpdateSunAndLensFlareSprites", (uint32_t) UpdateSunAndLensFlareSprites_ADDR,
                  (uint8_t *) UpdateSunAndLensFlareSprites_delta);
    hook_function("UpdateLightStreakSprites", (uint32_t) UpdateLightStreakSprites_ADDR,
                  (uint8_t *) UpdateLightStreakSprites_delta);
    hook_function("swrPlayerHUD_RenderWorldSprites", (uint32_t) swrPlayerHUD_RenderWorldSprites_ADDR,
                  (uint8_t *) swrPlayerHUD_RenderWorldSprites_delta);
}
