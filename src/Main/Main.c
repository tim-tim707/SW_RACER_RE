#include "Main.h"

#include "globals.h"

// 0x004240d0
void Main_Shutdown(void)
{
    // TODO
    (*stdPlatform_hostServices_ptr->debugPrint)("rdShutdown...");
    // TODO
}

// 0x00423cc0
int Main_Startup(char* cmdline)
{
    // TODO
    return 0;
}
