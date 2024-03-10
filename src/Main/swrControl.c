#include "swrControl.h"

#include "Win95/Window.h"

#include "macros.h"

// 0x00402250
int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4)
{
    HANG("TODO");
}

// 0x00404da0
int swrControl_Shutdown(void)
{
    HANG("TODO");
    return 0;
}

// 0x00404dd0
void swrControl_ProcessInputs(void)
{
    HANG("TODO");
}

// 0x00407500
int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk)
{
    HANG("TODO");
}

// 0x004078e0
int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int unk, int unk2)
{
    HANG("TODO");
}

// 0x004078a0
void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int unk, int controllerBinding)
{
    HANG("TODO");
}

// 0x00423efd
int swrControl_Startup(void)
{
    HANG("TODO");
    Window_set_msg_handler(Window_msg_default_handler);
    HANG("TODO");
    return 0;
}
