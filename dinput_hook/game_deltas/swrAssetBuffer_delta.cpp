#include "swrAssetBuffer_delta.h"

#include <windows.h>
#include <cstdio>
#include <cstring>

extern "C" {
#include <engine_config.h>
}

#include "../imgui_utils.h"// settings_ini_path
#include "../patch.h"

extern "C" FILE *hook_log;

// swrScene_InitWorld sizes the asset buffer with two immediates that must agree -- the malloc
// request and the end pointer derived from the same constant:
//
//   00449041: 68 00 00 80 00     PUSH 0x800000            ; malloc size
//   00449046: e8 ..              CALL malloc
//   0044904b: 8d 88 00 00 80 00  LEA ECX,[EAX + 0x800000] ; -> assetBufferEnd
//
// No other site encodes the size. The two must agree: swrAssetBuffer_CheckOverflow spins forever
// if the buffer top passes assetBufferEnd, so a half-applied pair would hang the game.
static const uint32_t kSizeSites[] = {
    0x00449042,// PUSH imm32: the malloc request
    0x0044904D,// LEA disp32: assetBufferEnd = assetBuffer + size
};

// Read straight from settings.ini: read_settings_ini() has not run this early, the same reason
// read_hd_font_setting() does it for its own patch-time toggle.
static uint32_t read_asset_buffer_size() {
    int mb = (int) GetPrivateProfileIntW(L"settings", L"asset_buffer_mb",
                                         SWR_ASSET_BUFFER_MB_DEFAULT, settings_ini_path());

    const int retail_mb = (int) (SWR_ASSET_BUFFER_SIZE_RETAIL / (1024u * 1024u));
    if (mb < retail_mb) {
        fprintf(hook_log,
                "[swrAssetBuffer_PatchSize] asset_buffer_mb=%d is below retail; using %d MiB.\n",
                mb, retail_mb);
        fflush(hook_log);
        mb = retail_mb;
    } else if (mb > SWR_ASSET_BUFFER_MB_MAX) {
        fprintf(hook_log,
                "[swrAssetBuffer_PatchSize] asset_buffer_mb=%d exceeds the %d MiB ceiling; using "
                "the ceiling.\n",
                mb, SWR_ASSET_BUFFER_MB_MAX);
        fflush(hook_log);
        mb = SWR_ASSET_BUFFER_MB_MAX;
    }

    return (uint32_t) mb * 1024u * 1024u;
}

void swrAssetBuffer_PatchSize() {
    static const PatchOwner kOwner = "asset_buffer_size";

    const uint32_t retail = SWR_ASSET_BUFFER_SIZE_RETAIL;
    const uint32_t wanted = read_asset_buffer_size();
    if (wanted == retail)
        return;

    for (uint32_t address: kSizeSites) {
        uint32_t found = 0;
        std::memcpy(&found, (const void *) address, sizeof(found));
        if (found == wanted)
            continue;// already patched
        if (found != retail) {
            fprintf(hook_log,
                    "[swrAssetBuffer_PatchSize] unexpected size 0x%x at 0x%x; leaving the asset "
                    "buffer at retail (0x%x bytes).\n",
                    found, address, retail);
            fflush(hook_log);
            UndoOwner(kOwner);// a half-applied pair would disagree with assetBufferEnd
            return;
        }

        if (!PatchPointer(kOwner, (void *) address, wanted)) {
            fprintf(hook_log, "[swrAssetBuffer_PatchSize] patch refused at 0x%x.\n", address);
            fflush(hook_log);
            UndoOwner(kOwner);
            return;
        }
    }

    fprintf(hook_log, "[swrAssetBuffer_PatchSize] asset buffer raised 0x%x -> 0x%x bytes.\n",
            retail, wanted);
    fflush(hook_log);
}
