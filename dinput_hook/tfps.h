#pragma once

// TFPS quick select: the community's "24/20" shorthand (frame rate / traction part) as two toolbar
// buttons, "24 fps" (or "24 Hz" under fixed timestep) and "R20". Traction follows the context:
// multiplayer (per-player MP upgrades), Free Play (non-saved override), tournament (read-only).

// Toolbar buttons, drawn at the right end of the main menu bar (F5 toolbar visible).
void tfps_draw_menu_bar_item();
float tfps_menu_bar_item_width();

// The "always show" buttons, pinned top-right while the toolbar is hidden.
void tfps_draw_chip();

// Screen-space bottom of the pinned buttons last frame (0 when not drawn), so other top-right
// overlays can stack below it.
float tfps_chip_bottom();

extern "C" {
#include <types.h>
}

// Hook for swrObjHang_BuildRosterSinglePlayer (0x0045b7d0): applies the Free Play traction override
// to the first local racer after the vanilla build.
void *swrObjHang_BuildRosterSinglePlayer_delta(swrObjHang *hang, int *out);
