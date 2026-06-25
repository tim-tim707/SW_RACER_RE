#pragma once

extern "C" {
#include <Dss/sithMulti.h>
#include <Win95/stdComm.h>
#include <Swr/swrUI.h>
}

int sithMulti_HandleIncomingPacket_delta(DPID dpid);
int stdComm_Send_delta(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags);

// Multiplayer lobby lap stepper with free-play parity: fine +/-1 to 5, then jump-by-5, wrap at
// 1/125. Hooks swrUI_Menu_MpRaceSetup; defers every non-laps message to the original handler.
int swrUI_Menu_MpRaceSetup_delta(swrUI_unk *self, unsigned int msg, void *element,
                                 swrUI_unk *widget);
