#ifndef SWRSPRITE_DELTA_H
#define SWRSPRITE_DELTA_H

// 0x0044f640 swrSprite_GetUIScale
// Widescreen UI fix (phase 1): replace independent X/Y screen scaling with a
// uniform scale derived from the vertical axis, removing the 4:3 horizontal
// stretch on non-4:3 framebuffers. See ghidra_analysis/ui_system_notes.md.
void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale);

#endif // SWRSPRITE_DELTA_H
