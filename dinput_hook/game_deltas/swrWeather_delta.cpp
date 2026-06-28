#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "swrWeather_delta.h"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>

extern "C" {
#include <macros.h>
#include <Swr/swrWeather.h>
#include <Win95/DirectX.h>
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include "std3D_delta.h"
#include <globals.h>
extern FILE *hook_log;
}

#include "../hook_helper.h"
#include "../imgui_utils.h" // imgui_state.fov_scale

// =============================================================================================
// Weather particle system reimplemented in the renderer layer.
//
// The game's particle system is an 80-slot pool spawned in a fixed camera-relative box, projected
// by the 4:3-calibrated swrViewport_ProjectToScreen, drawn as quantized 320x240 sprites -- and its
// streak (motion-blur) draw was stubbed out (swr_noop2). Rather than keep fighting those limits we
// run our own simulation here: an arbitrary-size pool spawned in a world box around the camera,
// integrated by the per-track world velocity, projected through the actual GL scene view/projection
// (so it lines up with the scene and depth-tests against it -- no 4:3-vs-Hor+ drift), and drawn as
// soft round points or motion-blur streaks batched into a single draw call. Per-track colour,
// velocity, stretch and intensity still come from the game globals so it stays faithful per planet.
// =============================================================================================

// --- soft round particle texture -------------------------------------------------------------
// White RGB with a radial alpha falloff (solid core -> transparent edge, corners clear so the quad
// reads as a disc). The render-list shader is outColor = texture(tex,uv) * passColor, so this softens
// the points and streak edges while the vertex colour tints/fades.
#define WEATHER_TEX_N 32
static GLuint weather_soft_texture() {
    static GLuint tex = 0;
    if (tex == 0) {
        uint32_t px[WEATHER_TEX_N * WEATHER_TEX_N];
        for (int y = 0; y < WEATHER_TEX_N; y++) {
            for (int x = 0; x < WEATHER_TEX_N; x++) {
                const float nx = ((float) x + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float ny = ((float) y + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float r = sqrtf(nx * nx + ny * ny);
                float a = (1.0f - r) * 1.3f; // solid core, soft to 0 by the edge
                if (a < 0.0f)
                    a = 0.0f;
                if (a > 1.0f)
                    a = 1.0f;
                px[y * WEATHER_TEX_N + x] = ((uint32_t) (a * 255.0f) << 24) | 0x00ffffff; // ABGR LE
            }
        }
        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, WEATHER_TEX_N, WEATHER_TEX_N, 0, GL_RGBA,
                     GL_UNSIGNED_BYTE, px);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glBindTexture(GL_TEXTURE_2D, 0);
    }
    return tex;
}

// --- scene view/projection (set by swrWeather_TickAndDraw from the renderer each frame) -------
// Lets us project particle world positions to screen + window-z, aligned with the GL scene so the
// depth buffer (blitted to the default framebuffer) occludes particles behind geometry.
static rdMatrix44 g_scene_proj;
static rdMatrix44 g_scene_view;
static bool g_scene_mats_valid = false;

// Project a world point through the scene view/proj. Returns false if behind the near plane.
// Outputs screen px (top-left origin, matching the 2D render-list ortho), window-z (0..1) and the
// view-space depth (clip w) used to scale particle size with distance.
static bool weather_project(const rdVector3 *world, float *sx, float *sy, float *wz, float *view_w) {
    if (!g_scene_mats_valid)
        return false;
    rdVector4 w = {world->x, world->y, world->z, 1.0f};
    rdVector4 vpos, clip;
    rdMatrix_TransformPoint44(&vpos, &w, &g_scene_view);
    rdMatrix_TransformPoint44(&clip, &vpos, &g_scene_proj);
    if (clip.w <= 0.01f)
        return false;
    const float inv = 1.0f / clip.w;
    *sx = (clip.x * inv * 0.5f + 0.5f) * (float) swrDisplay_screenWidth;
    *sy = (0.5f - clip.y * inv * 0.5f) * (float) swrDisplay_screenHeight; // GL +y up -> screen y down
    *wz = clip.z * inv * 0.5f + 0.5f;
    *view_w = clip.w;
    return true;
}

// --- screen-depth -> world unprojection (used to place rain splashes exactly on the surface) --
// The depth we sample is one frame old (async PBO), so it matches LAST frame's scene. Unprojecting
// it with LAST frame's matrices lands the splash on the real (static) ground regardless of camera
// motion -- so it can't end up hovering or sinking when the pod drives up/downhill.
static rdMatrix44 g_scene_proj_prev, g_scene_view_prev;
static bool g_scene_prev_valid = false;
static rdMatrix44 g_proj_inv, g_view_inv;
static bool g_unproj_valid = false;

// General 4x4 inverse (rdMatrix44 = 16 contiguous floats). Works for either multiply convention:
// feeding the result back through rdMatrix_TransformPoint44 inverts the forward transform. false if
// singular.
static bool mat44_inverse(const rdMatrix44 *src, rdMatrix44 *dst) {
    const float *m = (const float *) src;
    float inv[16];
    inv[0] = m[5] * m[10] * m[15] - m[5] * m[11] * m[14] - m[9] * m[6] * m[15] +
             m[9] * m[7] * m[14] + m[13] * m[6] * m[11] - m[13] * m[7] * m[10];
    inv[4] = -m[4] * m[10] * m[15] + m[4] * m[11] * m[14] + m[8] * m[6] * m[15] -
             m[8] * m[7] * m[14] - m[12] * m[6] * m[11] + m[12] * m[7] * m[10];
    inv[8] = m[4] * m[9] * m[15] - m[4] * m[11] * m[13] - m[8] * m[5] * m[15] +
             m[8] * m[7] * m[13] + m[12] * m[5] * m[11] - m[12] * m[7] * m[9];
    inv[12] = -m[4] * m[9] * m[14] + m[4] * m[10] * m[13] + m[8] * m[5] * m[14] -
              m[8] * m[6] * m[13] - m[12] * m[5] * m[10] + m[12] * m[6] * m[9];
    inv[1] = -m[1] * m[10] * m[15] + m[1] * m[11] * m[14] + m[9] * m[2] * m[15] -
             m[9] * m[3] * m[14] - m[13] * m[2] * m[11] + m[13] * m[3] * m[10];
    inv[5] = m[0] * m[10] * m[15] - m[0] * m[11] * m[14] - m[8] * m[2] * m[15] +
             m[8] * m[3] * m[14] + m[12] * m[2] * m[11] - m[12] * m[3] * m[10];
    inv[9] = -m[0] * m[9] * m[15] + m[0] * m[11] * m[13] + m[8] * m[1] * m[15] -
             m[8] * m[3] * m[13] - m[12] * m[1] * m[11] + m[12] * m[3] * m[9];
    inv[13] = m[0] * m[9] * m[14] - m[0] * m[10] * m[13] - m[8] * m[1] * m[14] +
              m[8] * m[2] * m[13] + m[12] * m[1] * m[10] - m[12] * m[2] * m[9];
    inv[2] = m[1] * m[6] * m[15] - m[1] * m[7] * m[14] - m[5] * m[2] * m[15] +
             m[5] * m[3] * m[14] + m[13] * m[2] * m[7] - m[13] * m[3] * m[6];
    inv[6] = -m[0] * m[6] * m[15] + m[0] * m[7] * m[14] + m[4] * m[2] * m[15] -
             m[4] * m[3] * m[14] - m[12] * m[2] * m[7] + m[12] * m[3] * m[6];
    inv[10] = m[0] * m[5] * m[15] - m[0] * m[7] * m[13] - m[4] * m[1] * m[15] +
              m[4] * m[3] * m[13] + m[12] * m[1] * m[7] - m[12] * m[3] * m[5];
    inv[14] = -m[0] * m[5] * m[14] + m[0] * m[6] * m[13] + m[4] * m[1] * m[14] -
              m[4] * m[2] * m[13] - m[12] * m[1] * m[6] + m[12] * m[2] * m[5];
    inv[3] = -m[1] * m[6] * m[11] + m[1] * m[7] * m[10] + m[5] * m[2] * m[11] -
             m[5] * m[3] * m[10] - m[9] * m[2] * m[7] + m[9] * m[3] * m[6];
    inv[7] = m[0] * m[6] * m[11] - m[0] * m[7] * m[10] - m[4] * m[2] * m[11] +
             m[4] * m[3] * m[10] + m[8] * m[2] * m[7] - m[8] * m[3] * m[6];
    inv[11] = -m[0] * m[5] * m[11] + m[0] * m[7] * m[9] + m[4] * m[1] * m[11] -
              m[4] * m[3] * m[9] - m[8] * m[1] * m[7] + m[8] * m[3] * m[5];
    inv[15] = m[0] * m[5] * m[10] - m[0] * m[6] * m[9] - m[4] * m[1] * m[10] +
              m[4] * m[2] * m[9] + m[8] * m[1] * m[6] - m[8] * m[2] * m[5];

    float det = m[0] * inv[0] + m[1] * inv[4] + m[2] * inv[8] + m[3] * inv[12];
    if (det > -1e-12f && det < 1e-12f)
        return false;
    det = 1.0f / det;
    float *d = (float *) dst;
    for (int i = 0; i < 16; i++)
        d[i] = inv[i] * det;
    return true;
}

// Unproject a top-left-origin screen pixel + window-z (0..1) to a world point through the cached
// inverse of the matrices that rendered the sampled depth. false if unavailable/degenerate.
static bool weather_unproject(float sx, float sy, float wz, rdVector3 *out) {
    if (!g_unproj_valid)
        return false;
    rdVector4 ndc = {(sx / (float) swrDisplay_screenWidth) * 2.0f - 1.0f,
                     1.0f - (sy / (float) swrDisplay_screenHeight) * 2.0f, wz * 2.0f - 1.0f, 1.0f};
    rdVector4 vpos, world4;
    rdMatrix_TransformPoint44(&vpos, &ndc, &g_proj_inv);
    if (vpos.w > -1e-6f && vpos.w < 1e-6f)
        return false;
    const float invw = 1.0f / vpos.w;
    vpos.x *= invw;
    vpos.y *= invw;
    vpos.z *= invw;
    vpos.w = 1.0f;
    rdMatrix_TransformPoint44(&world4, &vpos, &g_view_inv);
    out->x = world4.x;
    out->y = world4.y;
    out->z = world4.z;
    return true;
}

// --- simulation tunables ----------------------------------------------------------------------
#define WPART_MAX 512        // pool size (one batched draw; std3D max is 65536 verts)
#define WPART_PER_CAP 7      // target live particles = swrWeather_particleCap * this
#define WPART_SPAWN_RATE 128 // max new particles per frame (ramp-in + keep up while moving)
#define WPART_LAT 550.0f     // spawn box horizontal half-extent (world units, x FOV)
#define WPART_UP 650.0f      // spawn up to this far above the camera (x FOV) -> falls into view
#define WPART_DOWN 200.0f    // and this far below (x FOV)
#define WPART_MARGIN_PX 96.0f // off-screen cull/despawn margin
#define WPART_SIZE_K_SNOW 0.72f // half-size (px) ~ K * screen_height / view_depth (snow, thicker)
#define WPART_SIZE_K_RAIN 0.28f // ditto, rain (thinner)
#define WPART_SIZE_MIN 0.75f
#define WPART_SIZE_MAX 11.0f
#define WPART_STREAK_MIN 2.0f // screen-px tail length above which a particle draws as a streak
#define WPART_MOTION_BLUR 4.0f // camera-motion streak length (frames), independent of per-track stretch
#define WPART_FADE_TIME 0.4f // seconds to fade weather out when leaving a snow/rain region
#define WEATHER_RAIN_VY 200.0f // |velocityY| above this = rain (additive blend)
#define WEATHER_RAIN_ALPHA_MUL 0.65f // rain opacity scale (< 1 -> more subtle / hazy)
#define WEATHER_SNOW_ALPHA_MUL 1.25f // snow opacity scale (> 1 -> more present; clamped at 255)
#define WPART_TELEPORT2 (1000.0f * 1000.0f) // camera jumps bigger than this/frame = teleport (ignored)

struct WeatherParticle {
    rdVector3 world;
    bool active;
    bool seen_front; // rain: confirmed in front of the scene surface (for impact-crossing detection)
};
static WeatherParticle g_particles[WPART_MAX];
static bool g_weather_fading = false; // SNW->NSNW: spawner off, let live particles fall out
static bool g_weather_wanted = false; // set by RenderParticles_delta (game calls it in-race only)
static float g_fade_alpha = 1.0f; // 1 = full; ramps to 0 over WPART_FADE_TIME while fading out

// Camera translation this frame, used to streak particles relative to the camera (so they come at
// you when the pod travels fast, instead of just falling straight down).
static rdVector3 g_camera_prev;
static bool g_camera_prev_valid = false;
static rdVector3 g_cam_disp;

// Small LCG so spawn jitter doesn't depend on the game RNG.
static uint32_t g_rng = 0x2545f491u;
static inline float wrandf() {
    g_rng = g_rng * 1664525u + 1013904223u;
    return (float) (g_rng >> 8) * (1.0f / 16777216.0f); // [0,1)
}
static inline float wrand_sym(float r) {
    return (wrandf() * 2.0f - 1.0f) * r;
}

// --- per-frame batch (all particles share texture/blend/depth -> one draw call) ---------------
static D3DTLVERTEX g_batch_v[WPART_MAX * 4];
static WORD g_batch_i[WPART_MAX * 6];
static int g_batch_n; // particles appended this frame

static void batch_quad(const float pts[4][2], const D3DCOLOR cols[4], const float uvs[4][2], float sz) {
    if (g_batch_n >= WPART_MAX)
        return;
    const int v = g_batch_n * 4;
    for (int k = 0; k < 4; k++) {
        g_batch_v[v + k].sx = pts[k][0];
        g_batch_v[v + k].sy = pts[k][1];
        g_batch_v[v + k].sz = sz;
        g_batch_v[v + k].rhw = 1.0f;
        g_batch_v[v + k].color = cols[k];
        g_batch_v[v + k].tu = uvs[k][0];
        g_batch_v[v + k].tv = uvs[k][1];
    }
    const int n = g_batch_n * 6;
    g_batch_i[n + 0] = (WORD) (v + 0);
    g_batch_i[n + 1] = (WORD) (v + 1);
    g_batch_i[n + 2] = (WORD) (v + 2);
    g_batch_i[n + 3] = (WORD) (v + 0);
    g_batch_i[n + 4] = (WORD) (v + 2);
    g_batch_i[n + 5] = (WORD) (v + 3);
    g_batch_n++;
}

static void flush_batch(bool additive, GLuint tex) {
    if (g_batch_n == 0)
        return;
    // Depth-test against the scene (GL_DEPTH_TEST isn't tracked by std3D, so toggle directly +
    // restore); depth WRITE off via the render-state flag so particles don't occlude each other.
    const GLboolean had_depth = glIsEnabled(GL_DEPTH_TEST);
    GLint old_func = GL_LESS;
    glGetIntegerv(GL_DEPTH_FUNC, &old_func);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);
    if (additive)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE);

    std3D_DrawRenderList_delta((LPDIRECT3DTEXTURE2) (uintptr_t) tex,
                               (Std3DRenderState) (STD3D_RS_BLEND_MODULATEALPHA |
                                                   STD3D_RS_ZWRITE_DISABLED),
                               g_batch_v, g_batch_n * 4, g_batch_i, g_batch_n * 6);

    if (additive)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glDepthFunc((GLenum) old_func);
    if (!had_depth)
        glDisable(GL_DEPTH_TEST);
    g_batch_n = 0;
}

// Per-frame shared draw inputs (set once at the top of the tick to keep append signatures short).
static float g_dt, g_vx, g_vz, g_stretch, g_sw, g_sh;
static bool g_is_rain;
static D3DCOLOR g_rgb, g_opaque;

// Spawn a particle in a world box around the camera, biased into the view by rejection sampling
// (so we don't waste the budget behind the camera). Spawns high so it falls down into frame.
static void spawn_particle(WeatherParticle *p, float fov) {
    const rdVector3 c = rdVector_model_translation;
    for (int attempt = 0; attempt < 4; attempt++) {
        p->world.x = c.x + wrand_sym(WPART_LAT * fov);
        p->world.y = c.y + wrand_sym(WPART_LAT * fov);
        p->world.z = c.z + (wrandf() * (WPART_UP + WPART_DOWN) - WPART_DOWN) * fov;
        float hx, hy, wz, vw;
        if (weather_project(&p->world, &hx, &hy, &wz, &vw) && hx >= 0.0f && hx <= g_sw &&
            hy >= 0.0f && hy <= g_sh)
            break; // landed in view
    }
    p->active = true;
    p->seen_front = false;
}

// Append one particle (point or streak) to the batch given its projected head.
static void append_particle(const rdVector3 *world, float hx, float hy, float wz, float view_w) {
    float half = (g_is_rain ? WPART_SIZE_K_RAIN : WPART_SIZE_K_SNOW) * g_sh / view_w;
    if (half < WPART_SIZE_MIN)
        half = WPART_SIZE_MIN;
    if (half > WPART_SIZE_MAX)
        half = WPART_SIZE_MAX;

    // Tail = the particle's apparent past position relative to the camera. Two terms: its own fall
    // (velocity * dt * the per-track stretch, so rain trails long and snow short) PLUS the camera's
    // translation this frame (a fixed motion-blur length, so even low-stretch snow streaks when the
    // pod moves fast and rain rakes toward the camera / focus of expansion).
    const rdVector3 tail_world = {
        world->x + g_vx * g_dt * g_stretch + g_cam_disp.x * WPART_MOTION_BLUR,
        world->y + g_cam_disp.y * WPART_MOTION_BLUR,
        world->z + g_vz * g_dt * g_stretch + g_cam_disp.z * WPART_MOTION_BLUR};
    float tx, ty, twz, tvw;
    if (weather_project(&tail_world, &tx, &ty, &twz, &tvw)) {
        const float dxs = hx - tx;
        const float dys = hy - ty;
        const float len = sqrtf(dxs * dxs + dys * dys);
        if (len >= WPART_STREAK_MIN) {
            const float ex = hx - dxs; // tail end on screen
            const float ey = hy - dys;
            const float ox = -dys / len * half;
            const float oy = dxs / len * half;
            const float pts[4][2] = {
                {hx + ox, hy + oy}, {hx - ox, hy - oy}, {ex - ox, ey - oy}, {ex + ox, ey + oy}};
            const D3DCOLOR cols[4] = {g_opaque, g_opaque, g_rgb, g_rgb}; // opaque head -> alpha-0 tail
            // U=0.5 centre column along the length (crisp head/tail) + V across the width (soft edges).
            const float uvs[4][2] = {{0.5f, 0.0f}, {0.5f, 1.0f}, {0.5f, 1.0f}, {0.5f, 0.0f}};
            batch_quad(pts, cols, uvs, wz);
            return;
        }
    }

    // Point: small round dot at the head (full radial UVs -> soft disc).
    const float pts[4][2] = {
        {hx - half, hy - half}, {hx + half, hy - half}, {hx + half, hy + half}, {hx - half, hy + half}};
    const D3DCOLOR cols[4] = {g_opaque, g_opaque, g_opaque, g_opaque};
    const float uvs[4][2] = {{0.0f, 0.0f}, {1.0f, 0.0f}, {1.0f, 1.0f}, {0.0f, 1.0f}};
    batch_quad(pts, cols, uvs, wz);
}

// =============================================================================================
// Rain splash rings. When a falling drop's projected depth crosses the scene surface (read back from
// the depth buffer), the drop has reached the ground: recycle it and spawn an expanding, fading ring
// at the impact. Rings are horizontal world quads (normal = world up), which reads right for the ~90%
// of impacts on roughly-level track; they foreshorten with the scene and depth-test against it.
// =============================================================================================

#define WSPLASH_MAX 96       // ring pool (separate additive draw; the cap throttles ripple density)
#define WSPLASH_LIFE 0.34f   // seconds a ring lives (expand + fade)
#define WSPLASH_R0 0.6f      // ring radius at birth (world units)
#define WSPLASH_R1 4.0f      // ring radius at death (world units)
#define WSPLASH_LIFT 1.5f    // small camera-ward nudge so the ring doesn't z-fight the ground it sits on
#define WSPLASH_MIN_UP 0.5f  // only ripple on surfaces this up-facing (|normal.z|): skips walls/steep faces
#define WSPLASH_POD_RADIUS 16.0f // suppress ripples within this of the player pod's parts (no ripples on your pod)
#define WPART_HIT_EPS 0.0008f // window-z bias so float noise right at the surface can't false-trigger

struct WeatherSplash {
    rdVector3 world; // centre, on the surface the drop hit (z = ground)
    float age;       // seconds since spawn; < 0 = free slot
};
static WeatherSplash g_splashes[WSPLASH_MAX];
static bool g_splash_pool_init = false;

static void clear_splashes() {
    for (int i = 0; i < WSPLASH_MAX; i++)
        g_splashes[i].age = -1.0f;
}

static void spawn_splash(const rdVector3 *c) {
    for (int i = 0; i < WSPLASH_MAX; i++) {
        if (g_splashes[i].age < 0.0f) {
            g_splashes[i].world = *c;
            g_splashes[i].age = 0.0f;
            return;
        }
    }
}

// Hollow ring texture: alpha peaks in a thin annulus and is ~0 at the centre and outer edge, so an
// expanding textured quad reads as a ripple rather than a filled dot.
static GLuint weather_ring_texture() {
    static GLuint tex = 0;
    if (tex == 0) {
        uint32_t px[WEATHER_TEX_N * WEATHER_TEX_N];
        for (int y = 0; y < WEATHER_TEX_N; y++) {
            for (int x = 0; x < WEATHER_TEX_N; x++) {
                const float nx = ((float) x + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float ny = ((float) y + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float r = sqrtf(nx * nx + ny * ny);
                float a = 1.0f - fabsf(r - 0.78f) / 0.22f; // bright thin rim at r ~ 0.78
                if (r > 1.0f || a < 0.0f)
                    a = 0.0f;
                if (a > 1.0f)
                    a = 1.0f;
                px[y * WEATHER_TEX_N + x] = ((uint32_t) (a * 255.0f) << 24) | 0x00ffffff; // ABGR LE
            }
        }
        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, WEATHER_TEX_N, WEATHER_TEX_N, 0, GL_RGBA,
                     GL_UNSIGNED_BYTE, px);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glBindTexture(GL_TEXTURE_2D, 0);
    }
    return tex;
}

// --- scene depth readback (async, for rain-splash impact detection) ---------------------------
// One full-res depth snapshot of FB0 per frame, read into a ping-ponged PBO so the GPU->CPU copy
// doesn't stall: we kick this frame's read into one PBO and sample LAST frame's (already-landed) one.
// The one-frame latency is invisible for splash placement. Only run while rain is active.
static GLuint g_depth_pbo[2] = {0, 0};
static int g_depth_w = 0, g_depth_h = 0;
static int g_depth_cur = 0;                // PBO we read INTO this frame
static bool g_depth_primed = false;        // the other PBO holds a valid prior frame
static const float *g_depth_map = nullptr; // mapped prev-frame depth (valid between begin/end only)

// Kick this frame's async depth read and map the previous frame's result for sampling. Leaves
// GL_PIXEL_PACK_BUFFER unbound (the later picking glReadPixels must not accidentally target a PBO).
static void weather_depth_begin() {
    g_depth_map = nullptr;
    const int w = (int) swrDisplay_screenWidth;
    const int h = (int) swrDisplay_screenHeight;
    if (w <= 0 || h <= 0)
        return;
    if (g_depth_pbo[0] == 0)
        glGenBuffers(2, g_depth_pbo);
    if (g_depth_w != w || g_depth_h != h) {
        for (int k = 0; k < 2; k++) {
            glBindBuffer(GL_PIXEL_PACK_BUFFER, g_depth_pbo[k]);
            glBufferData(GL_PIXEL_PACK_BUFFER, (GLsizeiptr) w * h * (GLsizeiptr) sizeof(float),
                         nullptr, GL_STREAM_READ);
        }
        g_depth_w = w;
        g_depth_h = h;
        g_depth_primed = false; // size changed -> prior contents are stale
        g_depth_cur = 0;
    }
    glBindBuffer(GL_PIXEL_PACK_BUFFER, g_depth_pbo[g_depth_cur]);
    glReadPixels(0, 0, w, h, GL_DEPTH_COMPONENT, GL_FLOAT, nullptr); // async into the current PBO
    if (g_depth_primed) {
        glBindBuffer(GL_PIXEL_PACK_BUFFER, g_depth_pbo[g_depth_cur ^ 1]);
        g_depth_map = (const float *) glMapBufferRange(
            GL_PIXEL_PACK_BUFFER, 0, (GLsizeiptr) w * h * (GLsizeiptr) sizeof(float), GL_MAP_READ_BIT);
    }
    glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
}

// Unmap the sampled PBO and advance the ping-pong. Leaves GL_PIXEL_PACK_BUFFER unbound.
static void weather_depth_end() {
    if (g_depth_map) {
        glBindBuffer(GL_PIXEL_PACK_BUFFER, g_depth_pbo[g_depth_cur ^ 1]);
        glUnmapBuffer(GL_PIXEL_PACK_BUFFER);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
        g_depth_map = nullptr;
    }
    if (g_depth_pbo[0] != 0) {
        g_depth_cur ^= 1; // this frame's read becomes next frame's "previous"
        g_depth_primed = true;
    }
}

// Scene window-z at a top-left-origin screen pixel from the mapped previous-frame depth; returns 1.0
// (far plane = nothing in the way) when no sample is available.
static float weather_depth_at(float sx, float sy) {
    if (!g_depth_map)
        return 1.0f;
    const int x = (int) sx;
    const int y = (int) sy;
    if (x < 0 || y < 0 || x >= g_depth_w || y >= g_depth_h)
        return 1.0f;
    const int row = g_depth_h - 1 - y; // glReadPixels origin is bottom-left; sy is top-left
    return g_depth_map[(size_t) row * (size_t) g_depth_w + (size_t) x];
}

// World hit point + surface normal at a screen pixel, reconstructed from the depth buffer by
// unprojecting three neighbours. Used to keep rain splashes on flat-ish ground: returns false if a
// neighbour misses geometry, the unproject is unavailable, or the surface is degenerate. A wall edge
// makes the neighbours land on different surfaces -> a wild normal that the caller's up-facing test
// then rejects, so the big ring can't straddle the edge and float.
static bool weather_surface_at(float sx, float sy, float s0, rdVector3 *hit, rdVector3 *normal) {
    const float D = 3.0f; // neighbour offset in screen px
    const float sr = weather_depth_at(sx + D, sy);
    const float sd = weather_depth_at(sx, sy + D);
    if (sr >= 0.9999f || sd >= 0.9999f)
        return false;
    rdVector3 pX, pY;
    if (!weather_unproject(sx, sy, s0, hit) || !weather_unproject(sx + D, sy, sr, &pX) ||
        !weather_unproject(sx, sy + D, sd, &pY))
        return false;
    const rdVector3 ax = {pX.x - hit->x, pX.y - hit->y, pX.z - hit->z};
    const rdVector3 ay = {pY.x - hit->x, pY.y - hit->y, pY.z - hit->z};
    normal->x = ax.y * ay.z - ax.z * ay.y;
    normal->y = ax.z * ay.x - ax.x * ay.z;
    normal->z = ax.x * ay.y - ax.y * ay.x;
    const float len = sqrtf(normal->x * normal->x + normal->y * normal->y + normal->z * normal->z);
    if (len < 1e-6f)
        return false;
    normal->x /= len;
    normal->y /= len;
    normal->z /= len;
    return true;
}

// True if a world point is within WSPLASH_POD_RADIUS of the local player's pod (its cockpit or either
// engine) -- used to suppress rain ripples landing on your own pod's flat canopy/engine tops, which
// the up-facing test alone lets through. Pod part transforms are written live for full pods (the local
// player). Near-ground ripples are unaffected (the ground is below/ahead of the pod bodies).
static bool weather_on_player_pod(const rdVector3 *p) {
    const swrRace *pod = currentPlayer_Test;
    if (pod == nullptr)
        return false;
    const float r2 = WSPLASH_POD_RADIUS * WSPLASH_POD_RADIUS;
    const rdVector3 parts[3] = {
        {pod->cockpitXf.vD.x, pod->cockpitXf.vD.y, pod->cockpitXf.vD.z},
        {pod->engineXfR.vD.x, pod->engineXfR.vD.y, pod->engineXfR.vD.z},
        {pod->engineXfL.vD.x, pod->engineXfL.vD.y, pod->engineXfL.vD.z}};
    for (int i = 0; i < 3; i++) {
        const float dx = p->x - parts[i].x;
        const float dy = p->y - parts[i].y;
        const float dz = p->z - parts[i].z;
        if (dx * dx + dy * dy + dz * dz < r2)
            return true;
    }
    return false;
}

// SNW/NSNW region toggles (swrObjcMan_UpdateCamera calls these every frame). Enable resumes the
// spawner; Disable just flags a fade-out (RenderParticles keeps the live particles falling, and
// switches weather fully off once the pool empties).
void swrWeather_Enable_delta(void) {
    swrWeather_enabled = 1;
    g_weather_fading = false;
    g_fade_alpha = 1.0f;
}

// Per-region (swrObjcMan_UpdateCamera, every frame) and per-track (swrPlayerHUD_SetupTrackOverlay) off
// switch. Clear swrWeather_enabled like the original -- the previous fade-only version let the flag get
// stuck on across tracks -- but only arm the graceful fade-out on the on->off edge, so live particles
// drift out instead of popping and the per-frame NSNW calls don't keep re-arming it.
void swrWeather_Disable_delta(void) {
    if (swrWeather_enabled)
        g_weather_fading = true;
    swrWeather_enabled = 0;
}

// Race-boundary hard off. The game calls swrWeather_ResetParticles at exactly the two race
// boundaries: swrObjJdge_InitTrack (race start, BEFORE swrPlayerHUD_SetupTrackOverlay re-enables
// weather for the track) and swrObjJdge_TeardownRace (race end) -- and never mid-race. Nothing else
// clears swrWeather_enabled, and swrObjJdge_TeardownRace leaves InRaceSpritesEnabled set, so without
// this both of our draw-gate flags (RenderParticles-was-called + swrWeather_enabled) stay set after a
// race and weather bleeds into the standings/hangar/galaxy menus. Forcing weather fully off here bounds
// it to the active race: InitTrack clears it, then SetupTrackOverlay re-enables it on weather tracks;
// TeardownRace clears it for all the menus that follow. The game's own particle pool doesn't need
// clearing (RenderParticles_delta no-ops and never reads it).
void swrWeather_ResetParticles_delta(void) {
    swrWeather_enabled = 0;
    // The particle cap is the real per-track gate: swrObjcMan_UpdateCamera flips swrWeather_enabled on
    // for ANY track's active camera, and only weather tracks' SetupTrackOverlay sets a cap. Clear it at
    // the race boundary so a stale cap from a previous weather track can't leak weather onto the next
    // (non-weather) track. Weather tracks re-set it in SetupTrackOverlay, which runs after this.
    swrWeather_particleCap = 0;
    g_weather_wanted = false;
    g_weather_fading = false;
    g_fade_alpha = 1.0f;
    for (int i = 0; i < WPART_MAX; i++)
        g_particles[i].active = false;
    clear_splashes();
    g_depth_primed = false; // drop any stale depth snapshot across the race boundary
}

// Suppress the game's weather setup (it positions/shows its 80 sprites here for the sprite pass) and
// use the call as the in-race weather signal: the game only calls this per viewport when racing on a
// weather track, so it's exactly when we should draw. TickAndDraw consumes the flag.
void swrWeather_RenderParticles_delta(void *viewport) {
    (void) viewport;
    g_weather_wanted = true;
}

// Our particle tick + draw. Called from swrViewport_Render_Hook right AFTER the 3D scene is blitted
// to the default framebuffer, so FB0 + scene depth are bound and the view/proj are current. Drawing
// here (not in RenderParticles, which runs in the pre-scene setup phase) keeps our GL state changes
// from corrupting the scene render. The scene matrices are passed in fresh from the renderer.
void swrWeather_TickAndDraw(const rdMatrix44 *proj, const rdMatrix44 *view) {
    // Only draw when the game asked for weather this frame (RenderParticles called -> in-race).
    // Consume the flag so it stops the instant the game stops calling RenderParticles (e.g. on the
    // post-race menu). Active weather needs BOTH swrWeather_enabled AND a per-track particle cap:
    // swrObjcMan_UpdateCamera flips swrWeather_enabled on for any active camera, so the cap (set only by
    // a weather track's SetupTrackOverlay) is the real per-track gate. Keep ticking while fading so a
    // SNW->NSNW transition drifts out instead of popping.
    // Master weather toggle (debug menu, persisted to the ini). Off = no weather at all: drop any live
    // particles/splashes and bail, so nothing lingers to resume when it is switched back on.
    if (!imgui_state.enable_weather) {
        for (int i = 0; i < WPART_MAX; i++)
            g_particles[i].active = false;
        clear_splashes();
        g_weather_wanted = false;
        g_weather_fading = false;
        g_camera_prev_valid = false;
        return;
    }

    const bool wanted = g_weather_wanted;
    g_weather_wanted = false;
    const bool weather_active = swrWeather_enabled && swrWeather_particleCap > 0;
    if (!wanted || (!weather_active && !g_weather_fading)) {
        // Weather idle: forget the last camera position. g_camera_prev only advances while we tick, so
        // after a fade-out it would go stale; on a quick NSNW->SNW re-entry the first frame's camera
        // displacement would be computed against that far-away old position and rake the motion-blur
        // streaks from where the pod used to be. Dropping it makes the first active frame streak-free
        // (the particle's own fall streak is unaffected).
        g_camera_prev_valid = false;
        return;
    }
    g_scene_proj = *proj;
    g_scene_view = *view;
    g_scene_mats_valid = true;

    if (!g_splash_pool_init) {
        clear_splashes();
        g_splash_pool_init = true;
    }

    const float fov = imgui_state.fov_scale > 0.0f ? imgui_state.fov_scale : 1.0f;
    g_dt = (float) swrRace_deltaTimeSecs;
    g_vx = swrWeather_velocityX;
    g_vz = swrWeather_velocityY;
    g_stretch = swrWeather_stretchFactor;
    g_is_rain = fabsf(g_vz) > WEATHER_RAIN_VY;
    g_sw = (float) swrDisplay_screenWidth;
    g_sh = (float) swrDisplay_screenHeight;
    g_rgb = ((D3DCOLOR) swrWeather_particleColor[0] << 16) |
            ((D3DCOLOR) swrWeather_particleColor[1] << 8) | (D3DCOLOR) swrWeather_particleColor[2];
    // Fade alpha: ramp to 0 over WPART_FADE_TIME while fading out (SNW->NSNW), full otherwise.
    if (g_weather_fading) {
        g_fade_alpha -= g_dt / WPART_FADE_TIME;
        if (g_fade_alpha < 0.0f)
            g_fade_alpha = 0.0f;
    } else {
        g_fade_alpha = 1.0f;
    }
    // Per-type opacity: rain reads more subtle (hazy), snow more present.
    float alpha = (float) swrWeather_particleColor[3] * g_fade_alpha *
                  (g_is_rain ? WEATHER_RAIN_ALPHA_MUL : WEATHER_SNOW_ALPHA_MUL);
    if (alpha > 255.0f)
        alpha = 255.0f;
    g_opaque = ((D3DCOLOR) (uint8_t) alpha << 24) | g_rgb;

    // Camera translation this frame (for the relative-motion streak). Ignore teleport-sized jumps
    // (race start / respawn) so they don't produce one frame of screen-spanning streaks.
    const rdVector3 cam = rdVector_model_translation;
    g_cam_disp = (rdVector3){0.0f, 0.0f, 0.0f};
    if (g_camera_prev_valid) {
        const rdVector3 d = {cam.x - g_camera_prev.x, cam.y - g_camera_prev.y,
                             cam.z - g_camera_prev.z};
        if (d.x * d.x + d.y * d.y + d.z * d.z < WPART_TELEPORT2)
            g_cam_disp = d;
    }
    g_camera_prev = cam;
    g_camera_prev_valid = true;

    int target = g_weather_fading ? 0 : swrWeather_particleCap * WPART_PER_CAP;
    if (target > WPART_MAX)
        target = WPART_MAX;

    g_batch_n = 0;
    int active = 0;

    // Rain only: snapshot the scene depth (async) so we can tell when a drop reaches the ground.
    if (g_is_rain)
        weather_depth_begin();

    // The depth we just mapped was rendered LAST frame; cache the inverse of LAST frame's matrices so
    // an impact can unproject the sampled depth onto the real surface (see weather_unproject).
    g_unproj_valid = false;
    if (g_is_rain && g_depth_map && g_scene_prev_valid)
        g_unproj_valid = mat44_inverse(&g_scene_proj_prev, &g_proj_inv) &&
                         mat44_inverse(&g_scene_view_prev, &g_view_inv);

    // Integrate + cull + draw the live particles.
    for (int i = 0; i < WPART_MAX; i++) {
        if (!g_particles[i].active)
            continue;
        g_particles[i].world.x -= g_vx * g_dt; // world drift
        g_particles[i].world.z -= g_vz * g_dt; // world fall (z is up)
        float hx, hy, wz, vw;
        if (!weather_project(&g_particles[i].world, &hx, &hy, &wz, &vw) || hx < -WPART_MARGIN_PX ||
            hx > g_sw + WPART_MARGIN_PX || hy < -WPART_MARGIN_PX || hy > g_sh + WPART_MARGIN_PX) {
            g_particles[i].active = false; // left the view -> recycle
            continue;
        }
        // Rain hitting the ground: once a drop has been in front of the scene surface and then reaches
        // it, spawn a ripple at the impact and recycle the drop (don't draw it as a streak this frame).
        if (g_is_rain && g_depth_map) {
            const float surf = weather_depth_at(hx, hy);
            if (wz < surf - WPART_HIT_EPS) {
                g_particles[i].seen_front = true;
            } else if (g_particles[i].seen_front) {
                // Spawn the ring on the actual surface (unprojected from the sampled depth, so it sits
                // on the ground regardless of pod motion), but only where it belongs: a real surface
                // (not sky), roughly horizontal (skips walls / the pod's angled shell), and continuous
                // (a wall edge yields a wild normal that fails the up-test, so the ring can't float off
                // it). Otherwise just recycle the drop with no ripple.
                rdVector3 hit, nrm;
                if (surf < 0.9999f && weather_surface_at(hx, hy, surf, &hit, &nrm) &&
                    fabsf(nrm.z) >= WSPLASH_MIN_UP && !weather_on_player_pod(&hit))
                    spawn_splash(&hit);
                g_particles[i].active = false;
                continue;
            }
        }
        active++;
        append_particle(&g_particles[i].world, hx, hy, wz, vw);
    }

    // Spawn toward the target (rate-limited so it ramps in and keeps up while the pod moves).
    int to_spawn = target - active;
    if (to_spawn > WPART_SPAWN_RATE)
        to_spawn = WPART_SPAWN_RATE;
    for (int i = 0; i < WPART_MAX && to_spawn > 0; i++) {
        if (g_particles[i].active)
            continue;
        spawn_particle(&g_particles[i], fov);
        to_spawn--;
        active++;
        float hx, hy, wz, vw;
        if (weather_project(&g_particles[i].world, &hx, &hy, &wz, &vw) && hx >= -WPART_MARGIN_PX &&
            hx <= g_sw + WPART_MARGIN_PX && hy >= -WPART_MARGIN_PX && hy <= g_sh + WPART_MARGIN_PX)
            append_particle(&g_particles[i].world, hx, hy, wz, vw);
    }

    if (g_is_rain)
        weather_depth_end();

    flush_batch(g_is_rain, weather_soft_texture());

    // Rain splash rings: expand + fade flat on the surface each drop hit. Horizontal world quads
    // (normal = world up) so they foreshorten with the scene and depth-test against it; the centre is
    // nudged a few units toward the camera so the ring sits just in front of the ground it lies on
    // (avoids z-fighting / being occluded by that same surface). Additive, like rain.
    const rdVector3 camw = rdVector_model_translation;
    g_batch_n = 0;
    for (int i = 0; i < WSPLASH_MAX; i++) {
        if (g_splashes[i].age < 0.0f)
            continue;
        g_splashes[i].age += g_dt;
        if (g_splashes[i].age >= WSPLASH_LIFE) {
            g_splashes[i].age = -1.0f; // expired
            continue;
        }
        const float t = g_splashes[i].age / WSPLASH_LIFE; // 0..1
        const float r = WSPLASH_R0 + (WSPLASH_R1 - WSPLASH_R0) * t;
        rdVector3 c = g_splashes[i].world;
        const rdVector3 toc = {camw.x - c.x, camw.y - c.y, camw.z - c.z};
        const float l = sqrtf(toc.x * toc.x + toc.y * toc.y + toc.z * toc.z);
        if (l > 1e-3f) {
            const float k = WSPLASH_LIFT / l;
            c.x += toc.x * k;
            c.y += toc.y * k;
            c.z += toc.z * k;
        }
        const rdVector3 corner[4] = {{c.x - r, c.y - r, c.z}, {c.x + r, c.y - r, c.z},
                                     {c.x + r, c.y + r, c.z}, {c.x - r, c.y + r, c.z}};
        float pts[4][2];
        bool ok = true;
        for (int k2 = 0; k2 < 4 && ok; k2++) {
            float wz, vw;
            ok = weather_project(&corner[k2], &pts[k2][0], &pts[k2][1], &wz, &vw);
        }
        float ccx, ccy, ccz, ccw;
        if (!ok || !weather_project(&c, &ccx, &ccy, &ccz, &ccw))
            continue;
        const float fade = (1.0f - t) * g_fade_alpha; // fainter as it grows; honour the region fade
        const uint8_t a = (uint8_t) ((float) swrWeather_particleColor[3] * fade * 0.85f);
        const D3DCOLOR col = ((D3DCOLOR) a << 24) | g_rgb;
        const D3DCOLOR cols[4] = {col, col, col, col};
        const float uvs[4][2] = {{0.0f, 0.0f}, {1.0f, 0.0f}, {1.0f, 1.0f}, {0.0f, 1.0f}};
        batch_quad(pts, cols, uvs, ccz);
    }
    flush_batch(true, weather_ring_texture());

    // Faded out -> fully off + clear the pool, until the next snow/rain region re-enables.
    if (g_weather_fading && g_fade_alpha <= 0.0f) {
        for (int i = 0; i < WPART_MAX; i++)
            g_particles[i].active = false;
        clear_splashes();
        swrWeather_enabled = 0;
        g_weather_fading = false;
    }

    // Remember this frame's matrices: next frame samples this frame's depth and unprojects it with
    // these, so the depth and the matrices that rendered it always match (exact surface placement).
    g_scene_proj_prev = g_scene_proj;
    g_scene_view_prev = g_scene_view;
    g_scene_prev_valid = true;
}
