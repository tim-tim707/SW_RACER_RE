#ifndef SWRSOUND_H
#define SWRSOUND_H

#include "types.h"

#define swrSound_CreateThread_ADDR (0x00423210)

#define swrSound_SetPlayEvent_ADDR (0x00423350)

#define swrSound_NewSource_ADDR (0x00484aa0)

int swrSound_CreateThread(void);

void swrSound_SetPlayEvent(void);

IA3dSource* swrSound_NewSource(int mono_stereo, int samplesPerSec, uint32_t param3, int nSizeWaveData, char param5);

#endif // SWRSOUND_H
