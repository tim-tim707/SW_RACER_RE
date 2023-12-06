#ifndef STDCONTROL_H
#define STDCONTROL_H

#include "types.h"

#define stdControl_Open_ADDR (0x00485570)
#define stdControl_Close_ADDR (0x004855a0)

#define stdControl_ReadControls_ADDR (0x00485630)

#define stdControl_SetActivation_ADDR (0x00485a30)

#define stdControl_ReadKeyboard_ADDR (0x00486170)

#define stdControl_ReadJoysticks_ADDR (0x00486340)

#define stdControl_ReadMouse_ADDR (0x00486710)

int stdControl_Open(void);
void stdControl_Close(void);

void stdControl_ReadControls(void);

int stdControl_SetActivation(int bActive);

void stdControl_ReadKeyboard(void);

void stdControl_ReadJoysticks(void);

void stdControl_ReadMouse(void);

#endif // STDCONTROL_H
