#ifndef SWRMULTIPLAYER_H
#define SWRMULTIPLAYER_H

#define swrMultiplayer_SetInMultiplayer_ADDR (0x00412640)
#define swrMultiplayer_IsMultiplayerEnabled_ADDR (0x0041d6b0)
#define swrMultiplayer_InRace_ADDR (0x0041da00)
#define swrMultiplayer_RacerPick_ADDR (0x0041dc30)

#define swrMultiplayer_Initialize_ADDR (0x0042830)
#define swrMultiplayer_Shutdown_ADDR (0x004208c0)

#define swrMultiplayer_SetLastGame_ADDR (0x00420c20)

#define swrMultiplayer_SetSessionDesc_ADDR (0x00486e60)

void swrMultiplayer_SetInMultiplayer(int bInMultiplayer);

int swrMultiplayer_IsMultiplayerEnabled(void);

void swrMultiplayer_InRace(void);

void swrMultiplayer_RacerPick(int a);

int swrMultiplayer_Initialize(void);
void swrMultiplayer_Shutdown(void);

void swrMultiplayer_SetLastGame(char* str);

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)

unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2);

#endif // SWRMULTIPLAYER_H
