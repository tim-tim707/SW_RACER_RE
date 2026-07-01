#pragma once

#include <cstdint>

extern "C" {
#include <Swr/swrModel.h>     // swrText_CreateTextEntry2 prototype + _ADDR
#include <Swr/swrPlayerHUD.h> // swrPlayerHUD_RenderDistanceText_ADDR
}

// Multiplayer: draw each player's name above their pod instead of the vanilla position number.
// Single-player is untouched (the wrapper only redirects when multiplayer_enabled).
void swrPlayerHUD_RenderDistanceText_delta(void *viewport, bool secondaryPass);
void swrText_CreateTextEntry2_delta(int16_t screen_x, int16_t screen_y, char r, char g, char b,
                                    char a, char *screenText);
void swrText_RenderEntries1_delta(void);
