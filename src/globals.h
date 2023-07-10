#ifndef GLOBALS_H
#define GLOBALS_H

// Generate this file with jinja2 or cog (like OpenJKDF2)

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif
    
    // Line 0: rdMatrixStack44_size 0x0050c5e8 int
    int rdMatrixStack44_size;
    
    // Line 1: rdMatrixStack44 0x00e985c0 rdMatrix44[0x30]
    rdMatrix44 rdMatrixStack44[0x30];
    
    // Line 3: rdMatrix44_00e37580 0x00e37580 rdMatrix44
    rdMatrix44 rdMatrix44_00e37580;
    
    // Line 5: rdMatrixStack34_size 0x0050c6f4 int
    int rdMatrixStack34_size;
    
    // Line 6: rdMatrixStack34 0x00e375c0 rdMatrix34[0x30]
    rdMatrix34 rdMatrixStack34[0x30];
    
    // Line 7: rdMatrixStack34_modified 0x004c3c0c int
    int rdMatrixStack34_modified;
    
    // Line 9: std_output_buffer 0x00ecbc20 char[0x800]
    char std_output_buffer[0x800];
    
    // Line 10: stdFilePrintf_buffer 0x0052e658 char[0x800]
    char stdFilePrintf_buffer[0x800];
    
#ifdef __cplusplus
}
#endif

#endif // GLOBALS_H