#include "stdControl.h"

#include "globals.h"

#include <macros.h>

// 0x00485360
int stdControl_Startup(void)
{
    HANG("TODO");
}

// 0x00485460
void stdControl_Shutdown(void)
{
    HANG("TODO");
}

// 0x00485570 TODO: crashes on release build, works fine on debug
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

// 0x004855a0 TODO: crashes on release build, works fine on debug
void stdControl_Close(void)
{
    if (stdControl_g_bOpen != 0)
    {
        stdControl_SetActivation(0);
        stdControl_g_bOpen = 0;
    }
}

// 0x004855c0
void stdControl_Reset(void)
{
    HANG("TODO");
}

// 0x004855f0
int stdControl_EnableAxis(int axisID)
{
    HANG("TODO");
}

// 0x00485630
void stdControl_ReadControls(void)
{
    HANG("TODO");
}

// 0x004856e0
float stdControl_ReadAxis(int controlId)
{
    HANG("TODO");
}

// 0x004857b0
float stdControl_ReadKeyAsAxis(unsigned int keyId)
{
    HANG("TODO");
}

// 0x00485840
int stdControl_ReadAxisAsKeyEx(int controlId)
{
    HANG("TODO");
}

// 0x00485880
int stdControl_ReadKey(unsigned int keyNum, int* pNumPressed)
{
    HANG("TODO");
}

// 0x00485a30
int stdControl_SetActivation(int bActive)
{
    HANG("TODO");
}

// 0x00485c40
void stdControl_InitJoysticks(void)
{
    HANG("TODO");
}

// 0x00485f20
void stdControl_InitKeyboard(void)
{
    HANG("TODO");
}

// 0x00486010
void stdControl_InitMouse(void)
{
    HANG("TODO");
}

// 0x00486140
void stdControl_EnableAxisRead(unsigned int axisID)
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

// 0x00486970
void stdControl_RegisterAxis(int axisID, int min, int max, float scale)
{
    HANG("TODO");
}
