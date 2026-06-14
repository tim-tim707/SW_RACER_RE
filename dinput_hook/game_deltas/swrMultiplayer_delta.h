#pragma once

extern "C" {
#include <Dss/sithMulti.h>
#include <Win95/stdComm.h>
}

int sithMulti_HandleIncomingPacket_delta(DPID dpid);
int stdComm_Send_delta(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags);
