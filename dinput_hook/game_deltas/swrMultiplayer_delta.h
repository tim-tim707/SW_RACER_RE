#pragma once

extern "C" {
#include <Dss/sithMulti.h>
#include <Win95/stdComm.h>
#include <Swr/swrUI.h>
#include <Swr/swrObj.h>
}

int sithMulti_HandleIncomingPacket_delta(DPID dpid);
int stdComm_Send_delta(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags);

// Multiplayer pod upgrades: vanilla swrObjHang_BuildRosterMultiplayer copies each pod's raw base
// stats with no upgrades (unlike the single-player builder). When the "allow pod upgrades" toggle is
// on, this wrapper layers the local player's active-profile upgrades onto its own 'Locl' score entry
// after the original runs. Hooked by address; the original is called back through the _ADDR cast.
void *swrObjHang_BuildRosterMultiplayer_delta(swrObjHang *hang, int *out);

// Multiplayer lobby lap stepper with free-play parity: fine +/-1 to 5, then jump-by-5, wrap at
// 1/125. Hooks swrUI_Menu_MpRaceSetup; defers every non-laps message to the original handler.
int swrUI_Menu_MpRaceSetup_delta(swrUI_unk *self, unsigned int msg, void *element,
                                 swrUI_unk *widget);
