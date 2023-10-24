#include "swrMultiplayer.h"

#include "globals.h"
#include "macros.h"

// 0x0041d6b0
int swrMultiplayer_IsMultiplayerEnabled(void)
{
    return multiplayer_enabled;
}

// 0x0041da00
void swrMultiplayer_InRace(void)
{
    HANG("TODO");
}

// 0x0041dc30
void swrMultiplayer_RacerPick(int a)
{
    HANG("TODO");
}

// 0x00486e60
unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2)
{
    HANG("TODO");
    return 0;
}
