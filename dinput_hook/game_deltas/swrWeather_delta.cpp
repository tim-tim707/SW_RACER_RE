#include "swrWeather_delta.h"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
extern FILE *hook_log;
}

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
