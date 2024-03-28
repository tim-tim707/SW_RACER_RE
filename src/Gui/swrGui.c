#include "swrGui.h"

#include "globals.h"

// 0x004804b0 HOOK
void swrGui_Stop(int bStopped)
{
    swrGui_Stopped = bStopped;
}
