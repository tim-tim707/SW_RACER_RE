#include "swrGui.h"

#include "globals.h"

// 0x004804b0
void swrGui_Stop(int bStopped)
{
    swrGui_Stopped = bStopped;
}
