#ifndef SWRDISPLAY_H
#define SWRDISPLAY_H

#include "types.h"

#define swrDisplay_Shutdown_ADDR (0x00409d00)

#define swrDisplay_Resize_ADDR (0x00423840)
#define swrDisplay_SetWindowPos_ADDR (0x004238a0)

void swrDisplay_Shutdown(void);

bool swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height);
int swrDisplay_SetWindowPos(void);

#endif // SWRDISPLAY_H
