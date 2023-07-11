#include "swrControl.h"

#include "Window.h"

// 0x00423efd
int swrControl_Startup(void)
{
    // TODO
    Window_SetMsgHandler(Window_msg_default_handler);
    // TODO
    return 0;
}
