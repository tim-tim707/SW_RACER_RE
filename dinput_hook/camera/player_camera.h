// Player camera settings: tunes the game's own pod camera in place via detours on the camera-man
// (swrObjcMan_UpdateCamera and helpers), so the viewport, sky sprites and audio listener all see the
// adjusted camera. Persisted to [player_camera] in SW_RACER_RE.ini; ImGui panel Camera > Player Camera.
#pragma once

void playercam_RegisterHooks();// from init_renderer_hooks(), before init_hooks()
void playercam_RegisterPanel();

// In a race only; OR'd into the freecam hide-HUD path, which owns the sprite / text filtering.
bool playercam_HudHidden();

// True while a swrSprite_SetVisible from a hidden world-sprite group (suns / light streaks) is
// running; the freecam's SetVisible detour forces those invisible.
bool playercam_SuppressSpriteVisibility();

// Renderer queries for the local player's pod root node.
bool playercam_HideOwnPod();
bool playercam_ShowPodInFirstPerson();// draw it even where its own camera hides it (POD_HIDDEN)

// Multiplier on the GL near plane (< 1 while the true cockpit is active, so the cockpit isn't clipped).
float playercam_NearClipScale();
// Degrees the player camera adds to the game's camera FOV (the "FOV offset" setting).
float playercam_FovOffset();
