#ifndef SWR_CONTROL_H
#define SWR_CONTROL_H

#include "types.h"

#define swrControl_MappingsMenu_ADDR (0x00402250)

#define swrControl_Shutdown_ADDR (0x00404da0)
#define swrControl_ProcessInputs_ADDR (0x00404dd0)

#define swrControl_RemoveMapping_ADDR (0x00407500)

#define swrControl_AddMapping_ADDR (0x004078e0)

#define swrControl_ReplaceMapping_ADDR (0x004078a0)

#define swrControl_Startup_ADDR (0x00423efd)

int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4);

int swrControl_Shutdown(void);
void swrControl_ProcessInputs(void);

int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk);

int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int unk, int unk2);

void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int unk, int controllerBinding);

int swrControl_Startup(void);

#endif // SWR_CONTROL_H
