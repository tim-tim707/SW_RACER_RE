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
// LAYER 3-A, proper streaks (Tier 1): GL reimplementation of the cut motion-blur trail.
// See swrWeather_delta.h. We draw a rotated quad from the particle head to its stored tail
// endpoint, flat-coloured for now (gradient/blend/depth/texture come in Tier 2).
// ===========================================================================================

// 1x1 white texture so the render-list shader (outColor = texture(tex,uv) * passColor) yields the
// flat vertex colour. Lazily created on first draw (a valid GL context exists during rendering).
static GLuint streak_white_texture() {
    static GLuint tex = 0;
    if (tex == 0) {
        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        const uint32_t white = 0xffffffff;
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, &white);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glBindTexture(GL_TEXTURE_2D, 0);
    }
    return tex;
}

static void draw_weather_streak(const swrSprite *spr) {
    // Sprite coords are normalized to the 320x240 reference space; un-normalize to screen pixels
    // (the render-list ortho spans 0..swrDisplay_screenWidth/Height, which is the same screen_width
    // the engine divided by when it stored these).
    const float sw = (float) swrDisplay_screenWidth;
    const float sh = (float) swrDisplay_screenHeight;
    const float hx = (float) spr->x * sw / 320.0f; // head = current position
    const float hy = (float) spr->y * sh / 240.0f;
    const float tx = (float) spr->unk0x4 * sw / 320.0f; // tail = stored streak endpoint
    const float ty = (float) spr->unk0x6 * sh / 240.0f;

    const float dx = hx - tx;
    const float dy = hy - ty;
    const float len = sqrtf(dx * dx + dy * dy);
    if (len < 1.0f)
        return; // degenerate (not actually moving)

    // Perpendicular unit vector * half-width gives the quad's cross offset.
    const float half_w = sw / 640.0f * 1.5f; // Tier 1: fixed width, resolution-scaled
    const float ox = -dy / len * half_w;
    const float oy = dx / len * half_w;

    // D3DCOLOR 0xAARRGGBB; std3D_DrawRenderList_delta swaps B<->R into the shader's RGBA order.
    const D3DCOLOR color = ((D3DCOLOR) spr->a << 24) | ((D3DCOLOR) spr->r << 16) |
                           ((D3DCOLOR) spr->g << 8) | (D3DCOLOR) spr->b;

    const float pts[4][2] = {
        {hx + ox, hy + oy}, {hx - ox, hy - oy}, {tx - ox, ty - oy}, {tx + ox, ty + oy}};
    D3DTLVERTEX verts[4] = {};
    for (int i = 0; i < 4; i++) {
        verts[i].sx = pts[i][0];
        verts[i].sy = pts[i][1];
        verts[i].sz = 0.0f;
        verts[i].rhw = 1.0f;
        verts[i].color = color;
        verts[i].tu = 0.0f;
        verts[i].tv = 0.0f;
    }
    static WORD indices[6] = {0, 1, 2, 0, 2, 3};

    std3D_DrawRenderList_delta((LPDIRECT3DTEXTURE2) (uintptr_t) streak_white_texture(),
                               STD3D_RS_BLEND_MODULATEALPHA, verts, 4, indices, 6);
}

typedef void(swrSprite_Draw2_t)(swrSprite *a1, int a2, float a3, float a4);

void swrSprite_Draw2_delta(swrSprite *a1, int a2, float a3, float a4) {
    // Draw the sprite normally first: for a streaking weather sprite the game's path is a no-op
    // (swr_noop2); for every other sprite this is unchanged behaviour.
    hook_call_original((swrSprite_Draw2_t *) swrSprite_Draw2_ADDR, a1, a2, a3, a4);

    // Only weather streak particles carry flag 0x4000. Match the original's visible (0x20) + pass
    // (a2) gate so the trail draws exactly when/where the particle itself would have.
    if (a1 && (a1->flags & 0x4000) && (a1->flags & 0x20) && (a1->flags & (uint32_t) a2) &&
        a1->texture) {
        draw_weather_streak(a1);
    }
}
