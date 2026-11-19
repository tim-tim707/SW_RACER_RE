#ifndef SWRDISPLAY_H
#define SWRDISPLAY_H

#include "types.h"

#define swrDisplay_Open_ADDR (0x00409B10)
#define swrDisplay_Shutdown_ADDR (0x00409d00)

#define swrDisplay_Resize_ADDR (0x00423840)
#define swrDisplay_SetWindowSize_ADDR (0x004238a0)

#define swrDisplay_SetSettingsFromRegistry_ADDR (0x00424180)
#define FindMatchingVideoMode_ADDR (0x004243C0)

BOOL swrDisplay_Open(swrMainDisplaySettings* a1);
void swrDisplay_Shutdown(void);

// Picks the display device, 3D device and video mode named in the registry (defaults: last device, 640x480).
int swrDisplay_SetSettingsFromRegistry(StdDisplayEnvironment* env, swrMainDisplaySettings* displaySettings);
// Index of the current display device's first 16-bpp mode with mode's width/height (0 when none).
int FindMatchingVideoMode(StdVideoMode mode, swrMainDisplaySettings* displaySettings);

bool swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height);
int swrDisplay_SetWindowSize(void);

#endif // SWRDISPLAY_H
