#ifndef GLOBALS_H
#define GLOBALS_H

// Generate this file with jinja2 or cog (like OpenJKDF2)

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif
    
    // Line 0: rdMatrixStack34_modified 0x004c3c0c int
    int rdMatrixStack34_modified;
    
    // Line 1: rdMatrixStack44_size 0x0050c5e8 int
    int rdMatrixStack44_size;
    
    // Line 2: rdMatrixStack34_size 0x0050c6f4 int
    int rdMatrixStack34_size;
    
    // Line 4: stdFilePrintf_buffer 0x0052e658 char[0x800]
    char stdFilePrintf_buffer[0x800];
    
    // Line 6: stdConsole_hConsoleOutput 0x0052ee78 HANDLE
    HANDLE stdConsole_hConsoleOutput;
    
    // Line 7: stdConsole_wAttributes 0x0052ee7c WORD
    WORD stdConsole_wAttributes;
    
    // Line 9: g_hWnd 0x00dfaa28 HWND
    HWND g_hWnd;
    
    // Line 10: g_WndProc 0x00dfaa30 Window_MSGHANDLER
    Window_MSGHANDLER g_WndProc;
    
    // Line 12: rdMatrix44_00e37580 0x00e37580 rdMatrix44
    rdMatrix44 rdMatrix44_00e37580;
    
    // Line 13: rdMatrixStack34 0x00e375c0 rdMatrix34[0x30]
    rdMatrix34 rdMatrixStack34[0x30];
    
    // Line 15: rdMatrixStack44 0x00e985c0 rdMatrix44[0x30]
    rdMatrix44 rdMatrixStack44[0x30];
    
    // Line 16: stdPlatform_hostServices 0x00e9f280 HostServices
    HostServices stdPlatform_hostServices;
    
    // Line 18: std_output_buffer 0x00ecbc20 char[0x800]
    char std_output_buffer[0x800];
    
    // Line 20: stdPlatform_hostServices_ptr 0x00ecc420 HostServices*
    HostServices* stdPlatform_hostServices_ptr;
    
#ifdef __cplusplus
}
#endif

#endif // GLOBALS_H