#pragma once


#include <vector>

#include "types.h"

// Real-time pod shadows (shadow mapping) for the GL renderer.
//
// Each frame, every opaque mesh of every racer's pod that the scene traversal draws is recorded as
// a shadow caster (world-space triangles; the renderer pre-transforms all geometry). After the
// scene is drawn -- before it is resolved to the window -- the casters are rendered from a
// directional "sun" into a depth map around the camera, then a full-screen pass rebuilds each
// pixel's world position from the scene depth and darkens it where the sun is blocked (soft PCF
// edges). Doing it after the scene means the shadow is never a frame behind the pod. The stock
// flat "blob" shadow quads can be hidden. Settings: Mods > Shadows.

// A dynamic light for the screen-space lighting pass. dir = (0,0,0) for a point light, else the
// spotlight's (unit) aim with its cone given by cos_inner (full) / cos_outer (zero).
struct SceneLight {
    rdVector3 pos;
    rdVector3 dir;
    float r, g, b, intensity, radius;
    float cos_inner, cos_outer;
};

bool shadows_enabled();
// True when pod meshes should be recorded at all: shadows on, or the exhaust tint in use.
bool shadows_capture_active();
bool shadows_hide_blob();// skip the stock pod blob-shadow nodes

// Start of a viewport's traversal: forget last viewport's casters.
void shadows_begin_viewport();

// The renderer is inside a pod subtree (and not in its blob-shadow / exhaust-glow parts) while
// this depth is > 0; meshes drawn then are casters.
extern int g_shadow_caster_depth;

// Record a caster mesh drawn this traversal. `fresh` = its world-space triangle positions were just
// produced (pass them), or nullptr when the draw reused cached geometry (the module keeps its own
// copy per mesh + matrix and re-parses through `reparse` only if it has none).
// role: 0 = shadow caster; 1 = pod exhaust/glow (no shadow; drawn into the screen mask so the shadow
// pass gives those pixels a fixed "exhaust tint" instead of real shadow); 2 = energy binder (no
// shadow; masked so the shadow / lighting pass leaves it untouched).
void shadows_add_caster(const swrModel_Mesh* mesh, const rdMatrix44& model_matrix,
                        const std::vector<rdVector3>* fresh,
                        void (*reparse)(const rdMatrix44&, const swrModel_Mesh*, std::vector<rdVector3>&),
                        int role = 0);

// After the scene is drawn into `scene_fbo` (multisampled colour + DEPTH_COMPONENT32 depth,
// width x height): render the shadow map and darken the shadowed pixels in place.
void shadows_render(const rdMatrix44& proj, const rdMatrix44& view, unsigned int scene_fbo, int width,
                    int height);

// The camera actually used to draw the last race frame (from the inverse of the renderer's view
// matrix), recorded every in-race frame whether or not shadows are on. Used by game-thread code
// that needs the listener / viewer position (e.g. positional custom sounds). Returns false if no
// race frame has been drawn in the last half second.
void camera_record(const rdMatrix44& view);
bool camera_get(rdVector3* pos, rdVector3* right);
bool camera_get_velocity(rdVector3* vel);// smoothed, world units per second

// Drop cached caster geometry (track load: model memory is reused).
void shadows_clear_cache();

// Loads [shadows] from SW_RACER_RE.ini and registers the "Mods/Shadows" panel.
void shadows_register_panel();
