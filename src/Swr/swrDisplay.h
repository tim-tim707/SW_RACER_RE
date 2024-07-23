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

int swrDisplay_SetSettingsFromRegistry(StdDisplayEnvironment* a1, swrMainDisplaySettings* a2);
int FindMatchingVideoMode(float a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, int a14, int a15, int a16, int a17, int a18, int a19, int a20, swrMainDisplaySettings* a21);

bool swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height);
int swrDisplay_SetWindowSize(void);

#endif // SWRDISPLAY_H
