#ifndef SITHMULTI_H
#define SITHMULTI_H

#include "types.h"

// TODO: Match real addresses
// #define sithMulti_RemovePlayer_ADDR (0x0041cae0)
// #define sithMulti_ProcessQuit_ADDR (0x0041d2f0)
// #define sithMulti_GetPlayerNum_ADDR (0x0041d350)

#define sithMulti_InitializeConnection_ADDR (0x00404760)

#define sithMulti_CloseGame_ADDR (0x0041c570)

void sithMulti_InitializeConnection(int connectionIndex);

void sithMulti_CloseGame(void);

#endif // SITHMULTI_H
