#ifndef SITHMESSAGE_H
#define SITHMESSAGE_H

#include "types.h"

#define sithMessage_NetWrite_ADDR (0x004047b0)

#define sithMessage_SendMessage_ADDR (0x0041b760)

#define sithMulti_ProcessPlayerLost_ADDR (0x0041c780)

#define sithMulti_RemovePlayer_ADDR (0x0041cae0)

#define sithMulti_GetPlayerNum_ADDR (0x0041d350)

#define sithPlayer_HidePlayer_ADDR (0x00420ff0)

// 0x004047b0
int sithMessage_NetWrite(tSithMessage* pMsg, DPID idTo);

// 0x0041b760
int sithMessage_SendMessage(tSithMessage* pMessage, DPID idTo, unsigned int outstream, unsigned int dwDPFlags);

// 0x0041c780
void sithMulti_ProcessPlayerLost(DPID idPlayer);

// 0x0041cae0
void sithMulti_RemovePlayer(unsigned int playerNum);

// 0x0041d350
int sithMulti_GetPlayerNum(DPID idPlayer);

// 0x00420ff0
void sithPlayer_HidePlayer(unsigned int playerNum);

#endif // SITHMESSAGE_H
