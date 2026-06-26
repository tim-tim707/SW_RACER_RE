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
#include <Swr/swrSprite.h>
#include <Swr/swrWeather.h>
#include <Win95/DirectX.h>
#include <Platform/std3D.h>
#include "std3D_delta.h"
#include <globals.h>
extern FILE *hook_log;
}

#include "../hook_helper.h"

// LAYER 2: lift the high-resolution weather-despawn deadlock. See swrWeather_delta.h and the
// KNOWN ISSUES block in src/Swr/swrWeather.h for why this exact byte edit fixes it.
//
// The two patched dwords are the float immediates inside these instructions:
//   0x0042B868  MOV dword ptr [ESI], 0xC47A0000   ; *outScreenX = -1000.0f   (imm @ 0x0042B86A)
//   0x0042B87F  MOV dword ptr [EDI], 0xC47A0000   ; *outScreenY = -1000.0f   (imm @ 0x0042B881)
// 0xC47A0000 (LE: 00 00 7A C4) = -1000.0f, 0xFF800000 (LE: 00 00 80 FF) = -INFINITY.
void swrWeather_PatchHiResParticleSentinel() {
    struct SentinelSite {
        uint32_t address;          // address of the 4-byte float immediate (not the opcode)
        uint8_t original[4];       // -1000.0f
        uint8_t patched[4];        // -INFINITY
    };

    static const SentinelSite sites[] = {
        {0x0042b86a, {0x00, 0x00, 0x7a, 0xc4}, {0x00, 0x00, 0x80, 0xff}}, // *outScreenX sentinel
        {0x0042b881, {0x00, 0x00, 0x7a, 0xc4}, {0x00, 0x00, 0x80, 0xff}}, // *outScreenY sentinel
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const SentinelSite &site: sites) {
        uint8_t *code = (uint8_t *) site.address;
        if (std::memcmp(code, site.original, 4) != 0) {
            if (std::memcmp(code, site.patched, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrWeather_PatchHiResParticleSentinel] unexpected bytes at %p; aborting patch. "
                    "Weather will not render at screen_width >= 1000.\n",
                    (void *) code);
            fflush(hook_log);
            return;
        }

        DWORD old_protect = 0;
        VirtualProtect(code, 4, PAGE_EXECUTE_READWRITE, &old_protect);
        std::memcpy(code, site.patched, 4);
        VirtualProtect(code, 4, old_protect, &old_protect);
        patched++;
    }

    fprintf(hook_log,
            "[swrWeather_PatchHiResParticleSentinel] patched %d/%d projection sentinels "
            "(-1000.0f -> -INF); weather now respawns at any resolution.\n",
            patched, total);
    fflush(hook_log);
}

// LAYER 3-A: force the point-sprite path so moving snow stays visible. See swrWeather_delta.h.
//
// The streak-mode selection in swrWeather_RenderParticles:
//   0042d20a  83 7C 24 40 03  CMP dword ptr [ESP+0x40], 3   ; |dy| (px) vs threshold
//   0042d20f  7D 16           JGE 0x0042d227                ; >= 3 -> streak path
//   0042d211  83 F8 03        CMP EAX, 3                    ; |dx| (px) vs threshold
//   0042d214  7D 11           JGE 0x0042d227                ; >= 3 -> streak path
//   0042d216  ...             CALL swrSprite_UnsetFlag(id, 0x4000)  ; < 3 -> point path
// NOP the two JGE bytes so neither jump is taken and the point path always runs.
void swrWeather_PatchForcePointParticles() {
    // One 12-byte site spanning both CMP/JGE pairs; only the two JGE opcodes change (7D xx -> 90 90).
    const uint32_t address = 0x0042d20a;
    static const uint8_t original[12] = {0x83, 0x7c, 0x24, 0x40, 0x03, 0x7d, 0x16,
                                         0x83, 0xf8, 0x03, 0x7d, 0x11};
    static const uint8_t patched[12] = {0x83, 0x7c, 0x24, 0x40, 0x03, 0x90, 0x90,
                                        0x83, 0xf8, 0x03, 0x90, 0x90};

    uint8_t *code = (uint8_t *) address;
    if (std::memcmp(code, original, sizeof(original)) != 0) {
        if (std::memcmp(code, patched, sizeof(patched)) == 0) {
            fprintf(hook_log, "[swrWeather_PatchForcePointParticles] already patched.\n");
            fflush(hook_log);
            return;
        }
        fprintf(hook_log,
                "[swrWeather_PatchForcePointParticles] unexpected bytes at %p; aborting patch. "
                "Snow will keep vanishing when the pod moves.\n",
                (void *) code);
        fflush(hook_log);
        return;
    }

    DWORD old_protect = 0;
    VirtualProtect(code, sizeof(patched), PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(code, patched, sizeof(patched));
    VirtualProtect(code, sizeof(patched), old_protect, &old_protect);

    fprintf(hook_log,
            "[swrWeather_PatchForcePointParticles] forced point-sprite path; moving snow now "
            "renders as points instead of the broken hi-res streak path.\n");
    fflush(hook_log);
}

// ===========================================================================================
// LAYER 3-A, proper streaks + smooth points: GL reimplementation of the weather particle draw.
// See swrWeather_delta.h. The engine stores each sprite's position as shorts in 320x240 space
// (~6 px steps at 1080p, which stair-steps the motion) and stubbed the streak draw (swr_noop2).
// We take over every weather particle (identified via swrWeather_particleSpriteIds): a fast one
// draws as a motion-blur streak (rotated quad head->tail with an alpha-gradient tail), a slow/parked
// one as a small point quad. Both use the un-quantized FLOAT screen position the engine projected
// this frame (swrWeather_particleScreenPositions) for smooth sub-pixel motion, with additive
// blending for rain / alpha for snow and width scaled by the particle's depth-driven size.
// ===========================================================================================

// Soft round particle texture: white RGB with a radial alpha falloff (solid core -> transparent
// edge, corners fully transparent so the quad reads as a disc, not a square). The render-list
// shader is outColor = texture(tex,uv) * passColor, so this softens both the point dots and the
// streak edges while the vertex colour still tints/fades. Lazily built on first draw.
#define WEATHER_TEX_N 32
static GLuint weather_soft_texture() {
    static GLuint tex = 0;
    if (tex == 0) {
        uint32_t px[WEATHER_TEX_N * WEATHER_TEX_N];
        for (int y = 0; y < WEATHER_TEX_N; y++) {
            for (int x = 0; x < WEATHER_TEX_N; x++) {
                const float nx = ((float) x + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float ny = ((float) y + 0.5f) / WEATHER_TEX_N * 2.0f - 1.0f;
                const float r = sqrtf(nx * nx + ny * ny); // 0 at centre, 1 at edge midpoint
                float a = (1.0f - r) * 1.3f; // solid core, soft to 0 by the edge
                if (a < 0.0f)
                    a = 0.0f;
                if (a > 1.0f)
                    a = 1.0f;
                // GL_RGBA byte order R,G,B,A -> uint32 LE = (A<<24)|(B<<16)|(G<<8)|R; white RGB.
                px[y * WEATHER_TEX_N + x] = ((uint32_t) (a * 255.0f) << 24) | 0x00ffffff;
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

// Particle look tunables.
#define WEATHER_WIDTH_K 0.016f // half-extent (px) = swrSprite.width * screen_width * K
#define WEATHER_MIN_HALF_W 0.75f // floor so distant particles stay at least ~a pixel
#define WEATHER_RAIN_VY 200.0f // |swrWeather_velocityY| above this = rain (additive), else snow (alpha)

// Submit a 4-vertex quad (two triangles) through the render-list path with the soft particle
// texture; outColor = falloff(uv) * per-vertex colour. Rain blends additive, snow standard alpha.
static void submit_weather_quad(const float pts[4][2], const D3DCOLOR cols[4], const float uvs[4][2]) {
    D3DTLVERTEX verts[4] = {};
    for (int i = 0; i < 4; i++) {
        verts[i].sx = pts[i][0];
        verts[i].sy = pts[i][1];
        verts[i].sz = 0.0f;
        verts[i].rhw = 1.0f;
        verts[i].color = cols[i];
        verts[i].tu = uvs[i][0];
        verts[i].tv = uvs[i][1];
    }
    static WORD indices[6] = {0, 1, 2, 0, 2, 3};

    // The renderer's default blend func is (SRC_ALPHA, ONE_MINUS_SRC_ALPHA); switch to additive for
    // rain (bright/glowy), then restore.
    const bool additive = fabsf(swrWeather_velocityY) > WEATHER_RAIN_VY;
    if (additive)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE);
    std3D_DrawRenderList_delta((LPDIRECT3DTEXTURE2) (uintptr_t) weather_soft_texture(),
                               STD3D_RS_BLEND_MODULATEALPHA, verts, 4, indices, 6);
    if (additive)
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
}

static void draw_weather_particle(const swrSprite *spr, int slot) {
    const float sw = (float) swrDisplay_screenWidth;
    const float sh = (float) swrDisplay_screenHeight;

    // Quantized (320x240-short) head un-normalized to screen px: the fallback, and the anchor for
    // the head->tail offset.
    const float qhx = (float) spr->x * sw / 320.0f;
    const float qhy = (float) spr->y * sh / 240.0f;

    // Smooth, sub-pixel head: the un-quantized FLOAT screen position the engine projected this
    // frame. Guard the off-screen sentinel; fall back to the quantized head.
    float hx = qhx;
    float hy = qhy;
    const float px = swrWeather_particleScreenPositions[slot].x;
    const float py = swrWeather_particleScreenPositions[slot].y;
    if (px > -100000.0f && px < 100000.0f && py > -100000.0f && py < 100000.0f) {
        hx = px;
        hy = py;
    }

    float half_w = spr->width * sw * WEATHER_WIDTH_K;
    if (half_w < WEATHER_MIN_HALF_W)
        half_w = WEATHER_MIN_HALF_W;

    // D3DCOLOR is 0xAARRGGBB; std3D_DrawRenderList_delta swaps B<->R into the shader's RGBA order.
    const D3DCOLOR rgb = ((D3DCOLOR) spr->r << 16) | ((D3DCOLOR) spr->g << 8) | (D3DCOLOR) spr->b;
    const D3DCOLOR opaque = ((D3DCOLOR) spr->a << 24) | rgb; // particle alpha

    // Fast particles (streak flag 0x4000) draw a motion-blur trail; the rest draw a point.
    if (spr->flags & 0x4000) {
        // Tail = sub-pixel head + the quantized head->tail offset, so the trail is anchored to the
        // smooth head (the bright end the eye tracks).
        const float tx = hx + ((float) spr->unk0x4 * sw / 320.0f - qhx);
        const float ty = hy + ((float) spr->unk0x6 * sh / 240.0f - qhy);
        const float dx = hx - tx;
        const float dy = hy - ty;
        const float len = sqrtf(dx * dx + dy * dy);
        if (len >= 1.0f) {
            const float ox = -dy / len * half_w;
            const float oy = dx / len * half_w;
            const float pts[4][2] = {{hx + ox, hy + oy},
                                     {hx - ox, hy - oy},
                                     {tx - ox, ty - oy},
                                     {tx + ox, ty + oy}};
            // Gradient: opaque at the head, alpha 0 at the tail.
            const D3DCOLOR cols[4] = {opaque, opaque, rgb, rgb};
            // Sample the texture's centre column (U=0.5) along the length -> crisp head/tail, with
            // V across the width for soft perpendicular edges.
            const float uvs[4][2] = {{0.5f, 0.0f}, {0.5f, 1.0f}, {0.5f, 1.0f}, {0.5f, 0.0f}};
            submit_weather_quad(pts, cols, uvs);
            return;
        }
        // degenerate streak -> fall through to a point
    }

    // Point: a small square at the sub-pixel head, full radial UVs so the soft texture renders it
    // as a round dot (corners transparent), uniform colour.
    const float pts[4][2] = {{hx - half_w, hy - half_w},
                             {hx + half_w, hy - half_w},
                             {hx + half_w, hy + half_w},
                             {hx - half_w, hy + half_w}};
    const D3DCOLOR cols[4] = {opaque, opaque, opaque, opaque};
    const float uvs[4][2] = {{0.0f, 0.0f}, {1.0f, 0.0f}, {1.0f, 1.0f}, {0.0f, 1.0f}};
    submit_weather_quad(pts, cols, uvs);
}

typedef void(swrSprite_Draw2_t)(swrSprite *a1, int a2, float a3, float a4);

void swrSprite_Draw2_delta(swrSprite *a1, int a2, float a3, float a4) {
    // Only take over sprites that belong to the active weather particle pool. Gate on the weather
    // being enabled so a stale pool id can never grab a non-weather sprite off a previous track.
    int slot = -1;
    if (a1 && swrWeather_enabled) {
        const int sprite_id = (int) (a1 - &swrSprite_array[0]);
        for (int i = 0; i < swrWeather_particleCap; i++) {
            if (swrWeather_particleSpriteIds[i] == sprite_id) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        // Not a weather particle: unchanged behaviour.
        hook_call_original((swrSprite_Draw2_t *) swrSprite_Draw2_ADDR, a1, a2, a3, a4);
        return;
    }

    // Weather particle: replace the game's draw (a 320x240-quantized point, or the stubbed streak)
    // with our smooth sub-pixel draw. Match the original's visible (0x20) + pass (a2) gate, and skip
    // empty slots (state 0) -- that also hides a particle suppressed mid-frame by the fade-out below.
    if (swrWeather_particleStates[slot] != 0 && (a1->flags & 0x20) && (a1->flags & (uint32_t) a2) &&
        a1->texture) {
        draw_weather_particle(a1, slot);
    }
}

// --- Graceful SNW <-> NSNW transitions -------------------------------------------------------
// The game toggles weather per surface region (swrObjcMan_UpdateCamera calls Enable/Disable every
// frame as the camera crosses SNW/NSNW tags). Vanilla Disable instantly clears swrWeather_enabled
// and hides every particle, so weather pops off at the boundary. Instead we keep the live particles
// updating with the spawner off, so they fall out naturally, and only turn weather fully off once
// the pool is empty.
static bool g_weather_fading = false;

void swrWeather_Enable_delta(void) {
    swrWeather_enabled = 1;
    g_weather_fading = false;
}

void swrWeather_Disable_delta(void) {
    // Don't clear swrWeather_enabled or hide particles; just stop spawning and let the existing ones
    // fall out (handled in swrWeather_RenderParticles_delta).
    g_weather_fading = true;
}

typedef void(swrWeather_RenderParticles_t)(void *viewport);

void swrWeather_RenderParticles_delta(void *viewport) {
    if (!g_weather_fading || !swrWeather_enabled) {
        hook_call_original((swrWeather_RenderParticles_t *) swrWeather_RenderParticles_ADDR,
                           viewport);
        return;
    }

    // Fading out: snapshot which slots are empty, run the normal update (which integrates + despawns
    // the live particles), then undo any spawn that slipped through this frame. A suppressed slot is
    // left at state 0, which the draw gate above skips, so it never flashes.
    int cap = swrWeather_particleCap;
    if (cap > 80)
        cap = 80; // pool is 80 slots (SetParticleCap clamps to 0x50); guard the stack snapshot
    bool was_empty[80];
    for (int i = 0; i < cap; i++)
        was_empty[i] = (swrWeather_particleStates[i] == 0);

    hook_call_original((swrWeather_RenderParticles_t *) swrWeather_RenderParticles_ADDR, viewport);

    bool any_active = false;
    for (int i = 0; i < cap; i++) {
        if (was_empty[i] && swrWeather_particleStates[i] != 0)
            swrWeather_particleStates[i] = 0; // suppress the new spawn
        if (swrWeather_particleStates[i] != 0)
            any_active = true;
    }

    // Pool empty -> fully disable so RenderParticles (and its per-frame Z-buffer lock) stops until
    // weather is enabled again.
    if (!any_active) {
        swrWeather_enabled = 0;
        g_weather_fading = false;
    }
}
