//
// Free camera (Phase 1) -- see camera.h.
//
#include "camera.h"
#include "../hook_helper.h"
#include "../debug_ui.h"
#include "../imgui_utils.h"

#include <imgui.h>

// Defined in hook_helper.cpp (registers a raw game-address detour); not prototyped in hook_helper.h.
extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

#include <windows.h>
#include <xinput.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

extern "C" {
#include <Engine/rdCamera.h>
#include <Primitives/rdMatrix.h>
#include <Main/swrControl.h>// swrControl_ProcessInputs
#include <Swr/swrCam.h>     // swrCam_GetActiveViewportCameraTransform_ADDR
#include <Swr/swrUI.h>      // swrUI_HandleKeyEvent (front-end keyboard menu input)
#include <Swr/swrPlayerHUD.h>// swrPlayerHUD_RenderViewport_ADDR (world-sprite render window)
#include <Swr/swrSprite.h>   // swrSprite_SetVisible (record world sprites)
#include <Swr/swrText.h>     // DrawTextEntries (HUD text)
#include <globals.h>         // swrViewport_array, swrSprite_array
}

namespace {

// --- config (tunable via the ImGui "Camera" panel, persisted to [camera] in the ini) ---
struct FreecamConfig {
    float move_speed = 500.0f;   // units / second (base; SWR tracks are large)
    float boost_mult = 4.0f;     // Shift / right bumper
    float slow_mult = 0.25f;     // Alt / left bumper
    float mouse_sens = 0.12f;    // degrees / pixel (RMB-drag look)
    float pad_look_rate = 150.0f;// degrees / second at full right-stick deflection
    float key_turn_rate = 90.0f; // degrees / second (arrow-key look)
    float smoothing = 0.08f;     // movement damping time constant (s); 0 = instant
    float fov_scale = 1.0f;      // FOV multiplier while flying (reuses the Hor+ fov pipeline)
    bool invert_y = false;       // invert look pitch
};
FreecamConfig g_cfg;

constexpr float PITCH_LIMIT = 89.0f;// degrees
constexpr int TOGGLE_KEY = VK_F9;

// --- state ----------------------------------------------------------------
bool g_active = false;
bool g_seeded = false;    // pose captured from the game camera on activation
bool g_toggle_was_down = false;
bool g_ui_toggle_request = false;// set by the panel's Enable/Disable button

rdVector3 g_pos{};// camera world position
rdVector3 g_vel{};// smoothed camera velocity (units/s), for movement damping
// engine Euler convention (rdMatrix_BuildRotation34 / _ExtractAngles34), degrees:
//   x = pitch (look up/down), y = yaw (heading), z = roll
rdVector3 g_ang{};

float g_saved_fov_scale = 1.0f;// user's imgui_state.fov_scale, restored on deactivate

// Latest freecam camera-to-world matrix, published for the audio-listener hook.
rdMatrix34 g_cam{};
bool g_have_cam = false;

// Hide-HUD: sprites the world-sprite renderer (swrPlayerHUD_RenderViewport) makes visible this frame
// are the "sky" sprites (suns / lens flares / light streaks) to keep; everything else drawn through
// swrSprite_Draw2 is HUD and gets dropped. g_world_recording is set only around that render, and only
// while hiding, so the keep-set captures exactly the sky sprites for the current track.
bool g_world_recording = false;
bool g_keep_sprite[251] = {};// indexed by swrSprite_array id (swrSprite[251])

// The pod's control values, written contiguously by swrControl_ProcessInputs from swrRace_ThrottleInput
// onward and read directly by swrRace_UpdatePlayerControl (analog throttle/steer/pitch then the digital
// action floats: brake/taunt/lean/airbrake). Blanking this whole span cuts every pod control.
constexpr size_t POD_CONTROL_INPUT_BLOCK_SIZE = 0x4c;

POINT g_mouse_anchor{};// screen-space recenter point while looking with the mouse
bool g_mouse_looking = false;

bool game_has_focus() {
    DWORD pid = 0;
    GetWindowThreadProcessId(GetForegroundWindow(), &pid);
    return pid == GetCurrentProcessId();
}

bool key_down(int vk) {
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

// --- XInput controller (dynamically loaded; no link-time dependency) -------
typedef DWORD(WINAPI *XInputGetState_t)(DWORD, XINPUT_STATE *);
XInputGetState_t p_XInputGetState = nullptr;
bool g_xinput_tried = false;
int g_pad_index = -1;    // connected pad slot, -1 = none
DWORD g_pad_last_scan = 0;

XINPUT_GAMEPAD g_pad{};// latest gamepad state
bool g_pad_valid = false;

// Refresh g_pad from the first connected controller (rescans slots at most once a second).
void pad_poll() {
    if (!g_xinput_tried) {
        g_xinput_tried = true;
        for (const char *name: {"xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"}) {
            if (HMODULE m = LoadLibraryA(name)) {
                p_XInputGetState = (XInputGetState_t) GetProcAddress(m, "XInputGetState");
                if (p_XInputGetState)
                    break;
            }
        }
    }
    g_pad_valid = false;
    if (!p_XInputGetState)
        return;

    DWORD now = GetTickCount();
    if (g_pad_index < 0 && (now - g_pad_last_scan) >= 1000) {
        g_pad_last_scan = now;
        for (DWORD i = 0; i < XUSER_MAX_COUNT; i++) {
            XINPUT_STATE st;
            if (p_XInputGetState(i, &st) == ERROR_SUCCESS) {
                g_pad_index = (int) i;
                break;
            }
        }
    }
    if (g_pad_index < 0)
        return;

    XINPUT_STATE st;
    if (p_XInputGetState((DWORD) g_pad_index, &st) != ERROR_SUCCESS) {
        g_pad_index = -1;// dropped; rescan next second
        return;
    }
    g_pad = st.Gamepad;
    g_pad_valid = true;
}

// Normalize a thumb-stick axis to [-1,1] past its deadzone.
float stick_norm(short v, short dz) {
    float f = (float) v;
    if (f > dz)
        return std::min((f - dz) / (32767.0f - dz), 1.0f);
    if (f < -dz)
        return std::max((f + dz) / (32767.0f - dz), -1.0f);// -32768 would land just past -1
    return 0.0f;
}

// Normalize a trigger to [0,1] past its threshold.
float trigger_norm(BYTE t) {
    if (t <= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
        return 0.0f;
    return (float) (t - XINPUT_GAMEPAD_TRIGGER_THRESHOLD) /
           (255.0f - XINPUT_GAMEPAD_TRIGGER_THRESHOLD);
}

void seed_from(const rdMatrix34 *cameraToWorld) {
    rdMatrix_ExtractAngles34(const_cast<rdMatrix34 *>(cameraToWorld), &g_ang);
    g_ang.z = 0.0f;// drop the chase cam's banking so the freecam starts level
    g_pos = cameraToWorld->scale;
    g_vel = {0.0f, 0.0f, 0.0f};
    g_mouse_looking = false;
}

// Enter / leave the freecam. On enter, remember the user's FOV to restore on exit; on exit, restore
// FOV and stop publishing the pose to the audio listener. Re-seeds from the game camera on next enter.
void set_active(bool on) {
    if (on == g_active)
        return;
    g_active = on;
    g_seeded = false;
    if (on) {
        g_saved_fov_scale = imgui_state.fov_scale;
        // Fresh hide-HUD keep-set for this session. It accumulates across the frames we fly (a sky
        // sprite made visible on any frame stays kept), so a sprite that isn't re-asserted every
        // frame isn't wrongly dropped -- and it's never cleared per-frame while off (no wasted work).
        std::memset(g_keep_sprite, 0, sizeof(g_keep_sprite));
    } else {
        imgui_state.fov_scale = g_saved_fov_scale;
        g_have_cam = false;
    }
}

// Integrate one frame of input and build the resulting camera-to-world matrix. `focused` gates the
// mouse (which is not dt-scaled and warps the OS cursor) so an unfocused game can't hijack the mouse.
void step(rdMatrix34 *out, float dt, bool focused) {
    const float pitch_sign = g_cfg.invert_y ? -1.0f : 1.0f;

    // --- look ---
    // arrow keys (match the mouse/stick yaw sign: Right looks right)
    if (key_down(VK_LEFT))
        g_ang.y += g_cfg.key_turn_rate * dt;
    if (key_down(VK_RIGHT))
        g_ang.y -= g_cfg.key_turn_rate * dt;
    if (key_down(VK_UP))
        g_ang.x += g_cfg.key_turn_rate * dt * pitch_sign;
    if (key_down(VK_DOWN))
        g_ang.x -= g_cfg.key_turn_rate * dt * pitch_sign;

    // mouse look while right button held (recenter each frame so we never hit an edge). Gated on
    // focus: when the game isn't foreground we must not warp the OS cursor or eat stray mouse motion.
    if (focused && key_down(VK_RBUTTON) && !ImGui::GetIO().WantCaptureMouse) {
        POINT c;
        GetCursorPos(&c);
        if (g_mouse_looking) {
            g_ang.y -= (float) (c.x - g_mouse_anchor.x) * g_cfg.mouse_sens;
            g_ang.x -= (float) (c.y - g_mouse_anchor.y) * g_cfg.mouse_sens * pitch_sign;
        } else {
            // recenter to the game window's center -- the primary-monitor center warps the cursor off
            // a secondary-monitor / non-centered window.
            RECT wr;
            if (GetWindowRect(GetForegroundWindow(), &wr)) {
                g_mouse_anchor.x = (wr.left + wr.right) / 2;
                g_mouse_anchor.y = (wr.top + wr.bottom) / 2;
            } else {
                g_mouse_anchor.x = GetSystemMetrics(SM_CXSCREEN) / 2;
                g_mouse_anchor.y = GetSystemMetrics(SM_CYSCREEN) / 2;
            }
            g_mouse_looking = true;
        }
        SetCursorPos(g_mouse_anchor.x, g_mouse_anchor.y);
    } else {
        g_mouse_looking = false;
    }

    // right stick look (push right -> look right, push up -> look up; matches the mouse sign)
    if (g_pad_valid) {
        float rx = stick_norm(g_pad.sThumbRX, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);
        float ry = stick_norm(g_pad.sThumbRY, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);
        g_ang.y -= rx * g_cfg.pad_look_rate * dt;
        g_ang.x += ry * g_cfg.pad_look_rate * dt * pitch_sign;
    }

    g_ang.x = std::clamp(g_ang.x, -PITCH_LIMIT, PITCH_LIMIT);
    g_ang.y = std::fmod(g_ang.y, 360.0f);// keep yaw bounded (avoids precision loss on long spins)

    // Build once to get the orthonormal basis (rvec=right, lvec=forward, uvec=up).
    rdMatrix_BuildRotation34(out, &g_ang, &g_pos);

    // --- move direction (view-relative WASD/stick + world up/down) ---
    float speed = g_cfg.move_speed;
    if (key_down(VK_SHIFT) || (g_pad_valid && (g_pad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER)))
        speed *= g_cfg.boost_mult;
    if (key_down(VK_MENU) || (g_pad_valid && (g_pad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER)))
        speed *= g_cfg.slow_mult;

    rdVector3 mv{0.0f, 0.0f, 0.0f};
    float fwd = (float) key_down('W') - (float) key_down('S');
    float strafe = (float) key_down('D') - (float) key_down('A');
    float rise = (float) key_down(VK_SPACE) - (float) key_down(VK_CONTROL);
    if (g_pad_valid) {
        fwd += stick_norm(g_pad.sThumbLY, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
        strafe += stick_norm(g_pad.sThumbLX, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
        rise += trigger_norm(g_pad.bRightTrigger) - trigger_norm(g_pad.bLeftTrigger);
    }
    mv.x = out->lvec.x * fwd + out->rvec.x * strafe;
    mv.y = out->lvec.y * fwd + out->rvec.y * strafe;
    mv.z = out->lvec.z * fwd + out->rvec.z * strafe + rise;// rise is world up (+Z)

    // Cap the direction magnitude at 1 so diagonals aren't faster and analog input isn't amplified.
    float len = std::sqrt(mv.x * mv.x + mv.y * mv.y + mv.z * mv.z);
    if (len > 1.0f) {
        mv.x /= len;
        mv.y /= len;
        mv.z /= len;
    }

    // Exponential velocity smoothing toward the target velocity (accel/decel feel; 0 = instant).
    const float a = g_cfg.smoothing > 0.0001f ? (1.0f - std::exp(-dt / g_cfg.smoothing)) : 1.0f;
    g_vel.x += (mv.x * speed - g_vel.x) * a;
    g_vel.y += (mv.y * speed - g_vel.y) * a;
    g_vel.z += (mv.z * speed - g_vel.z) * a;
    g_pos.x += g_vel.x * dt;
    g_pos.y += g_vel.y * dt;
    g_pos.z += g_vel.z * dt;

    // Re-stamp the (updated) position; basis is unchanged.
    out->scale = g_pos;
}

// Drive the active render viewports' camera matrix from the freecam pose. The GL renderer reads
// rdCamera_pCurCamera->view_matrix for the scene view (handled by rewriting the rdCamera_Update arg),
// but the skybox/environment camera position and the in-race world sprites (suns, lens flares, light
// streaks) are placed from the *viewport's* model_matrix (swrPlayerHUD_RenderAllViewports activates
// each flagged viewport and renders both from it). This runs inside the rdCamera_Update hook, which
// fires before that render loop, so the write lands for this frame; on deactivate the sim rebuilds
// the matrix from the camera-man next frame, restoring the game camera.
void drive_viewport_cameras(const rdMatrix34 *cam) {
    for (int i = 0; i < 4; i++) {
        swrViewport *vp = &swrViewport_array[i];
        if ((vp->flag & 1) == 0)
            continue;
        rdMatrix_Copy44_34(&vp->model_matrix, cam);
        vp->model_matrix.vD.w = 1.0f;// Copy44_34 zeroes every row's w; keep the affine convention
    }
}

// True when a flyable 3D scene is being rendered -- an active viewport with scene geometry.
bool in_3d_scene() {
    for (int i = 0; i < 4; i++)
        if ((swrViewport_array[i].flag & 1) && swrViewport_array[i].model_root_node != nullptr)
            return true;
    return false;
}

// True on the flat 2D front-end screens (mode select / options, plus the pre-game legal / splash /
// name-entry screens). These render OVER a loaded 3D scene, so in_3d_scene() alone reports true on
// them and can't tell them apart from a flyable hangar / galaxy view. Neither can swrUI visibility
// nor the page stack: the hangar and galaxy screens also drive swrUI and keep pages pushed. The
// authoritative screen identity is the swrObjHang state machine (swrObjHang_F0): the front-end menu
// lives in the Cantina room during MAIN_MENU, while the hangar / Watto / junkyard rooms and the
// SELECT_* / intro states are the flyable 3D scenes. Gated on the same flag&1 F0 uses to decide the
// hangar is the active screen, so this is false during a race (hangar inactive) -> freecam allowed.
bool front_end_menu_up() {
    swrObjHang *hang = g_objHang2;
    if (hang == nullptr || (hang->flag & 1) == 0)
        return false;// hangar / front-end not the active screen (e.g. in a race)
    switch (hang->menuScreen) {
        case swrObjHang_STATE_LEGAL:
        case swrObjHang_STATE_SPLASH:
        case swrObjHang_STATE_ENTER_NAME:
            return true;// pre-game 2D screens
        case swrObjHang_STATE_MAIN_MENU:
            return hang->room == Cantina;// cantina main menu = mode select / options (2D)
        default:
            return false;// Watto / hangar / galaxy / vehicle & course select = flyable 3D
    }
}

// Wall-clock dt, independent of the game's (possibly fixed) timestep.
float frame_dt() {
    static LARGE_INTEGER freq{};
    static LARGE_INTEGER prev{};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&prev);
        return 0.0f;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    float dt = (float) (now.QuadPart - prev.QuadPart) / (float) freq.QuadPart;
    prev = now;
    // clamp against hitches / breakpoints so a paused frame can't fling the camera
    return std::clamp(dt, 0.0f, 0.1f);
}

// --- config persistence ([camera] in SW_RACER_RE.ini) ----------------------
float ini_get_float(const wchar_t *ini, const wchar_t *key, float def) {
    wchar_t got[48], defbuf[48];
    swprintf(defbuf, 48, L"%.4f", def);
    GetPrivateProfileStringW(L"camera", key, defbuf, got, 48, ini);
    return (float) wcstod(got, nullptr);
}
void ini_set_float(const wchar_t *ini, const wchar_t *key, float v) {
    wchar_t buf[48];
    swprintf(buf, 48, L"%.4f", v);
    WritePrivateProfileStringW(L"camera", key, buf, ini);
}

void load_config() {
    const wchar_t *ini = settings_ini_path();
    g_cfg.move_speed = ini_get_float(ini, L"move_speed", g_cfg.move_speed);
    g_cfg.boost_mult = ini_get_float(ini, L"boost_mult", g_cfg.boost_mult);
    g_cfg.slow_mult = ini_get_float(ini, L"slow_mult", g_cfg.slow_mult);
    g_cfg.mouse_sens = ini_get_float(ini, L"mouse_sens", g_cfg.mouse_sens);
    g_cfg.pad_look_rate = ini_get_float(ini, L"pad_look_rate", g_cfg.pad_look_rate);
    g_cfg.smoothing = ini_get_float(ini, L"smoothing", g_cfg.smoothing);
    g_cfg.fov_scale = ini_get_float(ini, L"fov_scale", g_cfg.fov_scale);
    g_cfg.invert_y = GetPrivateProfileIntW(L"camera", L"invert_y", g_cfg.invert_y, ini) != 0;
}
void save_config() {
    const wchar_t *ini = settings_ini_path();
    ini_set_float(ini, L"move_speed", g_cfg.move_speed);
    ini_set_float(ini, L"boost_mult", g_cfg.boost_mult);
    ini_set_float(ini, L"slow_mult", g_cfg.slow_mult);
    ini_set_float(ini, L"mouse_sens", g_cfg.mouse_sens);
    ini_set_float(ini, L"pad_look_rate", g_cfg.pad_look_rate);
    ini_set_float(ini, L"smoothing", g_cfg.smoothing);
    ini_set_float(ini, L"fov_scale", g_cfg.fov_scale);
    WritePrivateProfileStringW(L"camera", L"invert_y", g_cfg.invert_y ? L"1" : L"0", ini);
}

void panel_camera() {
    ImGui::Text("Status: %s", g_active ? "ACTIVE (flying)" : "off");
    ImGui::SameLine();
    if (ImGui::SmallButton(g_active ? "Disable" : "Enable"))
        g_ui_toggle_request = true;

    bool dirty = false;
    dirty |= ImGui::SliderFloat("Move speed", &g_cfg.move_speed, 50.0f, 5000.0f, "%.0f u/s");
    dirty |= ImGui::SliderFloat("Boost x (Shift/RB)", &g_cfg.boost_mult, 1.0f, 12.0f, "%.1f");
    dirty |= ImGui::SliderFloat("Slow x (Alt/LB)", &g_cfg.slow_mult, 0.05f, 1.0f, "%.2f");
    dirty |= ImGui::SliderFloat("Smoothing", &g_cfg.smoothing, 0.0f, 0.5f, "%.2f s");
    dirty |= ImGui::SliderFloat("FOV scale", &g_cfg.fov_scale, 0.5f, 2.0f, "%.2f");
    dirty |= ImGui::SliderFloat("Mouse sensitivity", &g_cfg.mouse_sens, 0.02f, 0.5f, "%.3f");
    dirty |= ImGui::SliderFloat("Stick look rate", &g_cfg.pad_look_rate, 30.0f, 400.0f, "%.0f");
    dirty |= ImGui::Checkbox("Invert look Y", &g_cfg.invert_y);

    ImGui::Separator();
    ImGui::TextDisabled("Toggle: F9 or right-stick click.");
    ImGui::TextDisabled("Move: WASD + Space/Ctrl, or left stick + triggers.");
    ImGui::TextDisabled("Look: arrows, RMB-drag, or right stick.");
    ImGui::TextDisabled("The pod ignores input and the HUD hides while flying.");

    // Persist once the user finishes editing (no widget active), not every drag frame.
    static bool pending = false;
    if (dirty)
        pending = true;
    if (pending && !ImGui::IsAnyItemActive()) {
        save_config();
        pending = false;
    }
}

DebugPanel g_panel_camera = {
    .category = "Camera", .name = "Free Camera", .draw = panel_camera, .dev_only = false};

}// namespace

bool freecam_IsActive() {
    return g_active;
}

void freecam_RegisterPanel() {
    load_config();
    debug_ui_register(&g_panel_camera);
}

void freecam_ForceOff() {
    set_active(false);
}

extern "C" void rdCamera_Update_delta(rdMatrix34 *cameraToWorld) {
    // Refresh the controller once per frame (drives both the toggle and the fly controls).
    pad_poll();

    // Edge-detect the toggle (F9 / right-stick click, focus-gated) or the panel button. The freecam
    // works on any 3D scene (races + hangar / galaxy map); while active it owns all input (see
    // swrControl_ProcessInputs_delta), so exit with the same toggle -- menus won't respond meanwhile.
    const bool focused = game_has_focus();
    const bool pad_toggle = g_pad_valid && (g_pad.wButtons & XINPUT_GAMEPAD_RIGHT_THUMB);
    const bool toggle_down = focused && (key_down(TOGGLE_KEY) || pad_toggle);
    const bool toggle_edge = (toggle_down && !g_toggle_was_down) || g_ui_toggle_request;
    g_ui_toggle_request = false;
    g_toggle_was_down = toggle_down;
    // Toggle off any time; toggle on only where there's a flyable 3D scene (hangar / galaxy / race)
    // and no 2D front-end menu (mode select / settings) is up over it.
    if (toggle_edge && (g_active || (in_3d_scene() && !front_end_menu_up())))
        set_active(!g_active);
    // Scene unloaded, dropped back to a 2D menu, or a front-end menu opened over the scene while
    // flying -> exit so input / menus return.
    if (g_active && (!in_3d_scene() || front_end_menu_up()))
        set_active(false);

    if (!g_active) {
        hook_call_original(rdCamera_Update, cameraToWorld);
        return;
    }

    if (!g_seeded) {
        seed_from(cameraToWorld);
        g_seeded = true;
    }

    imgui_state.fov_scale = g_cfg.fov_scale;// drive the Hor+ FOV pipeline live while flying

    const float dt = focused ? frame_dt() : 0.0f;
    rdMatrix34 cam;
    step(&cam, dt, focused);
    g_cam = cam;
    g_have_cam = true;
    hook_call_original(rdCamera_Update, &cam);
    drive_viewport_cameras(&cam);
}

// Audio listener: swrSound_Update reads swrCam_GetActiveViewportCameraTransform (its only caller) to
// place the 3D listener. It normally returns the active viewport camera-state transform (the pod cam,
// which we do not touch), so hand back the freecam pose instead -> the listener rides the freecam.
typedef void(__cdecl *swrCam_GetActiveViewportCameraTransformFn)(rdMatrix44 *);
extern "C" void __cdecl swrCam_GetActiveViewportCameraTransform_delta(rdMatrix44 *out) {
    if (g_active && g_have_cam) {
        rdMatrix_Copy44_34(out, &g_cam);
        out->vD.w = 1.0f;
        return;
    }
    hook_call_original(
        (swrCam_GetActiveViewportCameraTransformFn) swrCam_GetActiveViewportCameraTransform_ADDR,
        out);
}

// Pod control: let the game read input normally, then blank the local player's raw pod input so
// nothing steers/throttles the pod while flying.
//
// NB: this hooks the RAW game address (swrControl_ProcessInputs_ADDR) via hook_function, NOT
// hook_replace on the reimpl symbol. hook_replace triggers the hook system's reverse-hook swap, which
// un-redirects the reimpl symbol -> reimpl-side callers (hit during FMV playback) then land on the
// HANG("TODO") stub in swrControl.c and freeze all input (killing cutscene skip). Hooking the game
// address leaves the reverse-hook intact, same pattern the gamepad-nav deltas use.
typedef void(__cdecl *swrControl_ProcessInputsFn)(void);
extern "C" void __cdecl swrControl_ProcessInputs_delta(void) {
    hook_call_original((swrControl_ProcessInputsFn) swrControl_ProcessInputs_ADDR);

    if (!g_active)
        return;

    // The freecam owns ALL game input while active, so neither the pod nor any menu (in-race or the
    // hangar/front-end) responds. The freecam reads the keyboard / mouse / controller directly, so
    // blanking the game's processed input here doesn't affect its own controls. Everything below is
    // rebuilt each ProcessInputs, so it only suppresses input on the frames the freecam is active.
    //
    // Safe re: cutscene skip: the skip reads the same accept/cancel edges, but the freecam is
    // force-exited before any cinematic (freecam_ForceOff in Window_PlayCinematic_delta), so g_active
    // is false during FMVs -> we never blank the edges then. The earlier regression was the reverse-
    // hook HANG (fixed above by hooking the raw address), not this blanking.

    // Pod: the local player's raw steer/action record (-> in-race bitsets + FLOAT steer/pitch arrays)
    // and the contiguous analog+digital control block swrRace_UpdatePlayerControl reads directly.
    std::memset(inRaceLocalPlayerInputRecord, 0, sizeof(inRaceLocalPlayerInputRecord));
    std::memset(&swrRace_ThrottleInput, 0, POD_CONTROL_INPUT_BLOCK_SIZE);

    // Menus: the in-race action bitsets (read via KeyDownForPlayer1Or2 and directly) for nav, and the
    // accept/cancel edges the front-end / hangar menus read for confirm/back.
    std::memset(inRaceLocalPlayerInputBitset1, 0, sizeof(inRaceLocalPlayerInputBitset1));
    std::memset(inRaceLocalPlayerInputBitset2, 0, sizeof(inRaceLocalPlayerInputBitset2));
    std::memset(inRaceLocalPlayerInputBitset3, 0, sizeof(inRaceLocalPlayerInputBitset3));
    swrControl_acceptPressedEdge = 0;
    swrControl_cancelPressedEdge = 0;
    swrControl_acceptReleasedEdge = 0;
    // swrControl_acceptPressedEdge (above) is the mouse-inclusive accept the in-race menus poll; the
    // 3D front-end screens (hangar / galaxy / vehicle & course select) instead poll this keyboard/pad
    // accept edge (PollAccept excluding the mouse) for ENTER/Space confirm, so it must be blanked too
    // or ENTER navigates the menu behind the camera while flying.
    swrControl_menuAcceptPressedEdge = 0;
}

// Hide the HUD for clean shots while keeping the sky sprites. All 2D content shares the swrSprite
// system, so we can't tell HUD from sky by a static id list (it varies per track). Instead we record
// which array sprites the world-sprite renderer (swrPlayerHUD_RenderViewport) makes visible each
// frame -- the suns / lens flares / light streaks -- and, while hiding, let swrSprite_Draw2 draw only
// those, dropping every other array sprite (gauges/minimap/lap/position/flags/labels). HUD text is
// dropped via the DrawTextEntries hooks. (swrSprite_Draw2 / SetPosF are already delta-owned, so the
// Draw2 filter is applied inside swrSprite_Draw2_delta via freecam_HudSpriteHidden.)
static bool hud_hidden() {
    return g_active;
}

// Wrap the world-sprite render so swrSprite_SetVisible records the sky sprites into the keep-set.
typedef void(__cdecl *swrPlayerHUD_RenderViewport_t)(void *, bool);
extern "C" void __cdecl swrPlayerHUD_RenderViewport_delta(void *viewport, bool secondaryPass) {
    const bool rec = hud_hidden();
    if (rec)
        g_world_recording = true;
    hook_call_original((swrPlayerHUD_RenderViewport_t) swrPlayerHUD_RenderViewport_ADDR, viewport,
                       secondaryPass);
    g_world_recording = false;
}
extern "C" void __cdecl swrSprite_SetVisible_delta(short id, int visible) {
    hook_call_original(swrSprite_SetVisible, id, visible);
    if (g_world_recording && visible && id >= 0 && id < 251)
        g_keep_sprite[id] = true;
}
extern "C" void __cdecl DrawTextEntries_delta(void) {
    if (hud_hidden())
        return;
    hook_call_original(DrawTextEntries);
}
extern "C" void __cdecl DrawTextEntries2_delta(void) {
    if (hud_hidden())
        return;
    hook_call_original(DrawTextEntries2);
}

bool freecam_HudSpriteHidden(int spriteId) {
    if (!hud_hidden())
        return false;
    return !(spriteId >= 0 && spriteId < 251 && g_keep_sprite[spriteId]);
}

// Front-end keyboard menu input. swrUI focus screens take keyboard nav/confirm/back through
// swrUI_HandleKeyEvent (game WndProc -> here); the swrControl edge-blanking above doesn't cover this
// path, so ENTER/arrows would still drive the menu behind the camera. Swallow the key while flying.
// Raw-address hook (see swrControl_ProcessInputs note) so the reverse-hook / HANG stub isn't disturbed.
// The freecam reads keys via GetAsyncKeyState, so its own controls are unaffected.
typedef int(__cdecl *swrUI_HandleKeyEventFn)(int, int);
extern "C" int __cdecl swrUI_HandleKeyEvent_delta(int vk, int pressed) {
    if (freecam_IsActive())
        return 0;// not handled -> swrUI ignores the key while flying
    return hook_call_original((swrUI_HandleKeyEventFn) swrUI_HandleKeyEvent_ADDR, vk, pressed);
}

void freecam_RegisterHooks() {
    hook_replace(rdCamera_Update, rdCamera_Update_delta);
    hook_function("swrControl_ProcessInputs", (uint32_t) swrControl_ProcessInputs_ADDR,
                  (uint8_t *) swrControl_ProcessInputs_delta);
    hook_replace(swrSprite_SetVisible, swrSprite_SetVisible_delta);
    hook_replace(DrawTextEntries, DrawTextEntries_delta);
    hook_replace(DrawTextEntries2, DrawTextEntries2_delta);
    hook_function("swrUI_HandleKeyEvent", (uint32_t) swrUI_HandleKeyEvent_ADDR,
                  (uint8_t *) swrUI_HandleKeyEvent_delta);
    hook_function("swrPlayerHUD_RenderViewport", (uint32_t) swrPlayerHUD_RenderViewport_ADDR,
                  (uint8_t *) swrPlayerHUD_RenderViewport_delta);
    hook_function("swrCam_GetActiveViewportCameraTransform",
                  (uint32_t) swrCam_GetActiveViewportCameraTransform_ADDR,
                  (uint8_t *) swrCam_GetActiveViewportCameraTransform_delta);
}
