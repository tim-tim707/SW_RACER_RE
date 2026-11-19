#ifndef SMUSH_H
#define SMUSH_H

#include <Windows.h>
#include "types.h"

// smush.dll (SMUSH video player) is imported by the EXE; there is no import library, so calls go
// through the EXE's import address table slots.
#define SMUSH_IAT_SET_VOLUME (0x004ac1bc)
#define SMUSH_IAT_PLAY (0x004ac1c0)
#define SMUSH_IAT_SHUTDOWN (0x004ac1c4)
#define SMUSH_IAT_STARTUP (0x004ac1c8)

typedef int (*SmushFrameCallback)(const SmushImage* image);

typedef int (*SmushStartup_t)(HWND hwnd, int unk);
typedef void (*SmushSetVolume_t)(int volume);
typedef int (*SmushPlay_t)(const char* file, int flags, int unk2, int unk3, int unk4, int width, int height, int unk7, int unk8, SmushFrameCallback callback, int unk10, int unk11, int unk12);
typedef void (*SmushShutdown_t)(void);

#define SmushStartup (*(SmushStartup_t*)SMUSH_IAT_STARTUP)
#define SmushSetVolume (*(SmushSetVolume_t*)SMUSH_IAT_SET_VOLUME)
#define SmushPlay (*(SmushPlay_t*)SMUSH_IAT_PLAY)
#define SmushShutdown (*(SmushShutdown_t*)SMUSH_IAT_SHUTDOWN)

#endif // SMUSH_H
