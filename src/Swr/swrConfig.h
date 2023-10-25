#ifndef SWRCONFIG_H
#define SWRCONFIG_H

#include "types.h"
#include <stdbool.h>

#define swrConfig_WriteMappings_ADDR (0x00406080)

#define swrConfig_SetDefaultVideo_ADDR (0x00408820)

#define swrConfig_WriteVideoConfig_ADDR (0x00408880)

#define swrConfig_AssignForceValues_ADDR (0x0040a680)

#define swrConfig_SetDefaultForce_ADDR (0x0040ab60)

#define swrConfig_WriteForceFeedbackConfig_ADDR (0x0040ab80)

#define swrConfig_WriteAudioConfig_ADDR (0x00422140)
#define swrConfig_ReadAudioConfig_ADDR (0x00422440)

#define swrConfig_Open_ADDR (0x004877d0)
#define swrConfig_Close_ADDR (0x00487960)
#define swrConfig_Puts_ADDR (0x004879a0)
#define swrConfig_Printf_ADDR (0x004879f0)
#define swrConfig_Tokenizer_ADDR (0x00487a50)

#define swrConfig_NextTokens_ADDR (0x00487ae0)

#define swrConfig_GetLine_ADDR (0x00487b20)

int swrConfig_WriteMappings(char* dirname);

void swrConfig_SetDefaultVideo(void);

int swrConfig_WriteVideoConfig(char* dirname);

void swrConfig_AssignForceValues(void);

void swrConfig_SetDefaultForce(void);

int swrConfig_WriteForceFeedbackConfig(char* filename);

int swrConfig_WriteAudioConfig(char* dirname);
int swrConfig_ReadAudioConfig(char* dirname);

int swrConfig_Open(char* filename);
void swrConfig_Close(void);
size_t swrConfig_Puts(char* string);
size_t swrConfig_Printf(char* format, ...);
size_t swrConfig_Tokenizer(char* line);

int swrConfig_NextTokens(void);

int swrConfig_GetLine(void);

#endif // SWRCONFIG_H
