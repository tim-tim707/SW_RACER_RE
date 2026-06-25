#pragma once

#include "types.h"

void swrModel_LoadFonts_delta(void);

swrModel_Header *swrModel_LoadFromId_delta(MODELID id);

void swrModel_InitializeTextureBuffer_delta();

// 0x00450310 -- swrText_SetEntryClipRect. Per-text-entry scissor rect (used by swrUI_DrawText for
// e.g. the scrolling profile list). The vanilla X mapping uses the stretched screen_width/640 while
// res-independent text now draws uniform, so clipped text fell left of the clip box and vanished.
// When the toggle is on, scales all four edges by the uniform ui_layout_scale so the box tracks the
// text; otherwise reproduces vanilla exactly.
void swrText_SetEntryClipRect_delta(int *rect);

// 0x00450530 -- swrText_CreateTextEntry1. The chokepoint every menu/HUD text string flows through
// (swrUI_DrawText, swrObj HUD). When centering is active, shifts the text origin right by the
// UI-centering offset (design units). Projected text reaches CreateTextEntry1 via the DLL-internal
// copy (called from swrText_CreateTextEntry2_delta), not this EXE hook, so it is not centered.
void swrText_CreateTextEntry1_delta(int x, int y, int r, int g, int b, int a, char *screenText);

// 0x004173c0 -- swrUI_DrawText. Wraps the original to flag "menu text in progress" so the
// CreateTextEntry1 hook can scale the centering offset by the widget space (vs the HUD space for
// direct callers). swrUI_DrawTextAligned routes through this too.
void swrUI_DrawText_delta(int font, int x, int y, int color0, int color1, int color2, int color3,
                          char *text, int unk9, int unk10, int disabled);

// 0x00417540 -- swrUI_DrawTextAligned. Same menu-text flagging as swrUI_DrawText, for aligned/
// centered swrUI widget text that does not route through swrUI_DrawText. (The hangar titles "SELECT
// VEHICLE" / "MAIN MENU" are NOT drawn here -- they go through swrText_CreateColorlessEntry1 below.)
void swrUI_DrawTextAligned_delta(int font, char *text, short *bbox, unsigned int alignFlags,
                                 int color0, int color1, int color2, int color3, int unk9, int unk10,
                                 int unk11);

// 0x00450560 -- swrText_CreateColorlessEntry1 / 0x00450590 -- swrText_CreateColorlessFormattedEntry1.
// Sibling text-entry wrappers that sink into swrText_CreateEntry without passing through
// swrText_CreateTextEntry1, so they need their own centering hooks. Used for the hangar screen titles
// ("SELECT VEHICLE", "MAIN MENU"); apply the same UI-centering X shift as CreateTextEntry1.
void swrText_CreateColorlessEntry1_delta(short x, short y, char *screenText);
void swrText_CreateColorlessFormattedEntry1_delta(int formatInt, short x, short y, char *screenText);

// 0x004505c0 -- swrText_CreateEntry2. The entries2-buffer sink; its only caller is the in-race pause
// menu (swrRace_UpdateInRaceMenu's option text). Apply the same UI-centering X shift as the entries1
// wrappers. (Projected text uses swrText_CreateTextEntry2 (0x42c7a0), a different function.)
void swrText_CreateEntry2_delta(short x, short y, char r, char g, char b, char a, char *screenText);

