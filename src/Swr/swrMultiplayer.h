#ifndef SWRMULTIPLAYER_H
#define SWRMULTIPLAYER_H

#define swrMultiplayer_IsMultiplayerEnabled_ADDR (0x0041d6b0)
#define swrMultiplayer_InRace_ADDR (0x0041da00)
#define swrMultiplayer_RacerPick_ADDR (0x0041dc30)

#define swrMultiplayer_SetSessionDesc_ADDR (0x00486e60)

// 0x00412640
void swrMultiplayer_SetInMultiplayer(int bInMultiplayer);

int swrMultiplayer_IsMultiplayerEnabled(void);

void swrMultiplayer_InRace(void);

void swrMultiplayer_RacerPick(int a);

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)

unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2);

#endif // SWRMULTIPLAYER_H
