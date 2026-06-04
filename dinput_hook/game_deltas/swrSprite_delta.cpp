#include "../imgui_utils.h"

extern "C" {
#include "swrSprite_delta.h"
#include "globals.h"
}

#include <windows.h>

// 0x0044f640
//
// Original (from disassembly):
//     xscale = (double)(int)swrDisplay_screenWidth  * *(double*)0x004accd8;  // recipW ~ 1/640
//     yscale = (double)(int)swrDisplay_screenHeight * *(double*)0x004acce0;  // recipH ~ 1/480
//   (screen dims are 32-bit ints loaded with FILD; the reciprocals are 64-bit
//    DOUBLES loaded with FMUL qword -- NOT 32-bit floats.)
// X and Y are scaled independently, so a non-4:3 framebuffer stretches the 2D UI
// horizontally.
//
// Phase 1 fix (no stretch): mirror the game's own vertical scale onto X. Sprites
// keep their exact original size; the horizontal stretch is gone. The UI is
// left-anchored (centering is phase 2). Gated by imgui_state.widescreen_ui so
// users can A/B compare against the original stretched behavior.
//
// Text fix: text glyphs do NOT use this function -- they scale inside
// rdProcEntry_Add2DQuad2 (0x0042d990) using their OWN double reciprocals at
// 0x004ac628 (X) / 0x004ac630 (Y), read ONLY there. We make the text X scale
// equal its Y scale by patching the X reciprocal so screenWidth*recipX ==
// screenHeight*recipY. Those constants live in read-only .rdata, so the page
// must be made writable once (VirtualProtect) before patching; the original
// value is cached so the toggle can restore it.
extern "C" void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale) {
    const double recipW = *(double *) 0x004accd8;
    const double recipH = *(double *) 0x004acce0;
    const float yscale = (float) ((double) swrDisplay_screenHeight * recipH);
    const float xscale_original = (float) ((double) swrDisplay_screenWidth * recipW);

    if (imgui_state.widescreen_ui) {
        *out_xscale = yscale;
        *out_yscale = yscale;
    } else {
        *out_xscale = xscale_original;
        *out_yscale = yscale;
    }

    // --- text (patch Add2DQuad2's X reciprocal, toggle-aware) ---
    static int text_recip_writable = 0;
    static double original_text_recipX = 0.0;
    if (!text_recip_writable) {
        DWORD old_protect;
        if (VirtualProtect((LPVOID) 0x004ac628, sizeof(double), PAGE_READWRITE, &old_protect)) {
            original_text_recipX = *(double *) 0x004ac628;
            text_recip_writable = 1;
        }
    }
    if (text_recip_writable && swrDisplay_screenWidth != 0) {
        if (imgui_state.widescreen_ui) {
            const double textRecipH = *(double *) 0x004ac630;
            *(double *) 0x004ac628 =
                textRecipH * (double) swrDisplay_screenHeight / (double) swrDisplay_screenWidth;
        } else {
            *(double *) 0x004ac628 = original_text_recipX;
        }
    }
}
