#ifndef SWRCONFIG_H
#define SWRCONFIG_H

#include "types.h"
#include <stdbool.h>

#define swrConfig_WriteMappings_ADDR (0x00406080)

#define swrConfig_ControlToString_ADDR (0x00407b00)

#define swrConfig_SetDefaultVideo_ADDR (0x00408820)

#define swrConfig_WriteVideoConfig_ADDR (0x00408880)
#define swrConfig_ReadVideoConfig_ADDR (0x00408b60)

#define swrConfig_AssignForceValues_ADDR (0x0040a680)

#define swrConfig_SetDefaultForce_ADDR (0x0040ab60)

#define swrConfig_WriteForceFeedbackConfig_ADDR (0x0040ab80)
#define swrConfig_ReadForceFeedbackConfig_ADDR (0x0040ae40)

#define swrConfig_WriteAudioConfig_ADDR (0x00422140)
#define swrConfig_ReadAudioConfig_ADDR (0x00422440)

#define swrConfig_Puts_ADDR (0x004879a0)
#define swrConfig_Printf_ADDR (0x004879f0)

int swrConfig_WriteMappings(char* dirname);

void swrConfig_ControlToString(unsigned int controlId, char* pDest);

void swrConfig_SetDefaultVideo(void);

int swrConfig_WriteVideoConfig(char* dirname);
int swrConfig_ReadVideoConfig(char* config_type);

void swrConfig_AssignForceValues(void);

void swrConfig_SetDefaultForce(void);

int swrConfig_WriteForceFeedbackConfig(char* filename);
int swrConfig_ReadForceFeedbackConfig(char* config_type);

int swrConfig_WriteAudioConfig(char* dirname);
int swrConfig_ReadAudioConfig(char* dirname);

size_t swrConfig_Puts(char* string);
size_t swrConfig_Printf(char* format, ...);

#endif // SWRCONFIG_H
