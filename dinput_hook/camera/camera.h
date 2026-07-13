//
// Free camera (Phase 1). Part of the dinput_hook camera system.
//
// Render-only takeover of the 3D scene camera. Each frame swrMain2_GuiAdvance
// copies swrViewport_array[1].model_matrix (the camera-to-world transform) into
// a local and hands it to rdCamera_Update, which inverts it into
// rdCamera_pCurCamera->view_matrix -- exactly what the GL renderer consumes. We
// hook that seam and, while active, replace the incoming matrix with a freecam
// matrix driven from keyboard / mouse / controller. The same pose is written to
// the active viewport(s) (skybox + world sprites follow) and to the audio
// listener source. No opcode patches; toggling off restores the game camera.
//
// Controls: F9 or right-stick click toggles. WASD / left stick move, Space/Ctrl
// or triggers for up/down, arrows / right stick / RMB-drag look, Shift/RB fast,
// Alt/LB slow. While active the pod ignores all input.
//
// Phase 1 scope. Not yet: LOD/fog when the cam leaves bounds, quaternion look,
// audio-listener follow on this build (3D audio disabled).
//
#pragma once

#include "types.h"// rdMatrix34

// The rdCamera_Update detour (reverse-hooked seam at 0x00490060). Registered via
// freecam_RegisterHooks(). When the freecam is inactive this is a pure passthrough.
extern "C" void rdCamera_Update_delta(rdMatrix34 *cameraToWorld);

// Registers the camera hooks. Call from init_renderer_hooks(), before init_hooks()
// applies the detours.
void freecam_RegisterHooks();

// Registers the ImGui "Camera" panel and loads persisted settings. Call once at
// startup where the other debug panels are registered.
void freecam_RegisterPanel();

// True while the freecam has taken over the scene camera.
bool freecam_IsActive();

// Force the freecam off (e.g. before a cutscene, so its input-suppression can't eat the skip input).
void freecam_ForceOff();

// True if the freecam's hide-HUD is dropping this array sprite (every 2D sprite except the light
// streaks, while flying with Hide HUD on). Consulted by swrSprite_Draw2_delta in the delta layer.
bool freecam_HudSpriteHidden(int spriteId);
