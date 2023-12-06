#include "stdControl.h"

// 0x00485570
int stdControl_Open(void)
{
    if (stdControl_g_bStartup == 0)
    {
        return 1;
    }
    stdControl_g_bOpen = 1;
    stdControl_SetActivation(1);
    return 0;
}

// 0x004855a0
void stdControl_Close(void)
{
    if (stdControl_g_bOpen != 0)
    {
        stdControl_SetActivation(0);
        stdControl_g_bOpen = 0;
    }
}

// 0x00485630
void stdControl_ReadControls(void)
{
    HANG("TODO");
}

// 0x00485a30
int stdControl_SetActivation(int bActive)
{
    HANG("TODO");
}

// 0x00486170
void stdControl_ReadKeyboard(void)
{
    HANG("TODO");
}

// 0x00486340
void stdControl_ReadJoysticks(void)
{
    HANG("TODO");
}

// 0x00486710
void stdControl_ReadMouse(void)
{
    HANG("TODO");
}
