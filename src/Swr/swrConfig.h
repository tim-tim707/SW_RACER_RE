#ifndef SWRCONFIG_H
#define SWRCONFIG_H

#include "types.h"
#include <stdbool.h>

#define swrConfig_Open_ADDR (0x004877d0)
#define swrConfig_Close_ADDR (0x00487960)
#define swrConfig_Puts_ADDR (0x004879a0)
#define swrConfig_Printf_ADDR (0x004879f0)
#define swrConfig_Tokenizer_ADDR (0x00487a50)

#define swrConfig_WriteVideoConfig_ADDR (0x00408880)

int swrConfig_Open(char* filename);
void swrConfig_Close(void);
size_t swrConfig_Puts(char* string);
size_t swrConfig_Printf(char* format, ...);
size_t swrConfig_Tokenizer(char* line);

int swrConfig_WriteVideoConfig(char* dirname);

#endif // SWRCONFIG_H
