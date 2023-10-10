#include "swrControl.h"

#include "Window.h"

#include "macros.h"

// 0x00402250
int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4)
{
    HANG("TODO");
}

// 0x00407500
int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk)
{
    HANG("TODO");
}

// 0x00423efd
int swrControl_Startup(void)
{
    HANG("TODO");
    Window_SetMsgHandler(Window_msg_default_handler);
    HANG("TODO");
    return 0;
}
