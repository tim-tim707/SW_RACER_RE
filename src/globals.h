#ifndef GLOBALS_H
#define GLOBALS_H

// Generate this file with jinja2 or cog (like OpenJKDF2)

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif
    
    // Line 0: Window_UUID 0x004af9b0 uint32_t[4] = { 0xC95FB584, 0x11D2FA31, 0xAA009D90, 0xAD22A300 }
    uint32_t Window_UUID[4] = { 0xC95FB584, 0x11D2FA31, 0xAA009D90, 0xAD22A300 };
    
    // Line 2: rdMatrixStack34_modified 0x004c3c0c int
    int rdMatrixStack34_modified;
    
    // Line 3: rdMatrixStack44_size 0x0050c5e8 int
    int rdMatrixStack44_size;
    
    // Line 4: rdMatrixStack34_size 0x0050c6f4 int
    int rdMatrixStack34_size;
    
    // Line 6: stdFilePrintf_buffer 0x0052e658 char[0x800]
    char stdFilePrintf_buffer[0x800];
    
    // Line 8: Window_UUID_0 0x0052ee60 uint32_t
    uint32_t Window_UUID_0;
    
    // Line 9: Window_UUID_1 0x0052ee64 uint32_t
    uint32_t Window_UUID_1;
    
    // Line 10: Window_UUID_2 0x0052ee68 uint32_t
    uint32_t Window_UUID_2;
    
    // Line 11: Window_UUID_3 0x0052ee6c uint32_t
    uint32_t Window_UUID_3;
    
    // Line 12: Window_hWnd 0x0052ee70 HWND
    HWND Window_hWnd;
    
    // Line 13: Window_hinstance 0x0052ee74 HINSTANCE
    HINSTANCE Window_hinstance;
    
    // Line 15: stdConsole_hConsoleOutput 0x0052ee78 HANDLE
    HANDLE stdConsole_hConsoleOutput;
    
    // Line 16: stdConsole_wAttributes 0x0052ee7c WORD
    WORD stdConsole_wAttributes;
    
    // Line 18: g_hWnd 0x00dfaa28 HWND
    HWND g_hWnd;
    
    // Line 19: g_nCmdShow 0x00dfaa2c int
    int g_nCmdShow;
    
    // Line 20: g_WndProc 0x00dfaa30 Window_MSGHANDLER_ptr
    Window_MSGHANDLER_ptr g_WndProc;
    
    // Line 21: Window_width 0x00dfaa34 int
    int Window_width;
    
    // Line 22: Window_height 0x00dfaa38 int
    int Window_height;
    
    // Line 24: rdMatrix44_00e37580 0x00e37580 rdMatrix44
    rdMatrix44 rdMatrix44_00e37580;
    
    // Line 25: rdMatrixStack34 0x00e375c0 rdMatrix34[0x30]
    rdMatrix34 rdMatrixStack34[0x30];
    
    // Line 27: rdMatrixStack44 0x00e985c0 rdMatrix44[0x30]
    rdMatrix44 rdMatrixStack44[0x30];
    
    // Line 28: stdPlatform_hostServices 0x00e9f280 HostServices
    HostServices stdPlatform_hostServices;
    
    // Line 30: std_output_buffer 0x00ecbc20 char[0x800]
    char std_output_buffer[0x800];
    
    // Line 32: stdPlatform_hostServices_ptr 0x00ecc420 HostServices*
    HostServices* stdPlatform_hostServices_ptr;
    
#ifdef __cplusplus
}
#endif

#endif // GLOBALS_H