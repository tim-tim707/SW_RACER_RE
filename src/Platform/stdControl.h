#ifndef STDCONTROL_H
#define STDCONTROL_H

#include "types.h"

#define stdControl_Startup_ADDR (0x00485360)
#define stdControl_Shutdown_ADDR (0x00485460)
#define stdControl_Open_ADDR (0x00485570)
#define stdControl_Close_ADDR (0x004855a0)
#define stdControl_Reset_ADDR (0x004855c0)
#define stdControl_EnableAxis_ADDR (0x004855f0)
#define stdControl_ReadControls_ADDR (0x00485630)
#define stdControl_ReadAxis_ADDR (0x004856e0)
#define stdControl_ReadKeyAsAxis_ADDR (0x004857b0)
#define stdControl_ReadAxisAsKeyEx_ADDR (0x00485840)
#define stdControl_ReadKey_ADDR (0x00485880)

#define stdControl_SetActivation_ADDR (0x00485a30)
#define stdControl_InitJoysticks_ADDR (0x00485c40)
#define stdControl_InitKeyboard_ADDR (0x00485f20)
#define stdControl_InitMouse_ADDR (0x00486010)
#define stdControl_EnableAxisRead_ADDR (0x00486140)
#define stdControl_ReadKeyboard_ADDR (0x00486170)
#define stdControl_ReadJoysticks_ADDR (0x00486340)
#define stdControl_ReadMouse_ADDR (0x00486710)
#define stdControl_RegisterAxis_ADDR (0x00486970)

int stdControl_Startup(void);
void stdControl_Shutdown(void);
int stdControl_Open(void);
void stdControl_Close(void);
void stdControl_Reset(void);
int stdControl_EnableAxis(int axisID);
void stdControl_ReadControls(void);
float stdControl_ReadAxis(int controlId);
float stdControl_ReadKeyAsAxis(unsigned int keyId);
int stdControl_ReadAxisAsKeyEx(int controlId);
int stdControl_ReadKey(unsigned int keyNum, int* pNumPressed);

int stdControl_SetActivation(int bActive);
void stdControl_InitJoysticks(void);
void stdControl_InitKeyboard(void);
void stdControl_InitMouse(void);
void stdControl_EnableAxisRead(unsigned int axisID);
void stdControl_ReadKeyboard(void);
void stdControl_ReadJoysticks(void);
void stdControl_ReadMouse(void);
void stdControl_RegisterAxis(int axisID, int min, int max, float scale);

#endif // STDCONTROL_H
