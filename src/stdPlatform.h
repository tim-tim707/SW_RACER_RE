#ifndef STD_PLATFORM_H
#define STD_PLATFORM_H

#include "types.h"

#define stdPlatform_Alloc_ADDR (0x00408e40)

#define stdPlatform_Initialize_ADDR (0x00484720)

#define stdPlatform_Shutdown_ADDR (0x00484760)

#define stdPlatform_DebugLog_ADDR (0x00484780)

#define stdPlatform_Printf_ADDR (0x0048c570)
#define stdPlatform_Assert_ADDR (0x0048c4a0)
#define stdPlatform_AllocHandle_ADDR (0x0048c5a0)
#define stdPlatform_FreeHandle_ADDR (0x0048c5b0)
#define stdPlatform_ReallocHandle_ADDR (0x0048c5c0)
#define stdPlatform_LockHandle_ADDR (0x0048c5e0)
#define stdPlatform_noop_ADDR (0x00423cb0)
#define stdPlatform_InitServices_ADDR (0x0048c3d0)

void* stdPlatform_Alloc(unsigned int size);

unsigned int stdPlatform_Initialize(HostServices* hs);

void stdPlatform_Shutdown(void);

int stdPlatform_DebugLog(void* log_function, char* compile_filepath, int line_nb, char* msg, ...);

int stdPlatform_Printf(const char* format, ...);
void stdPlatform_Assert(const char* param_1, const char* param_2, int param_3);
void* stdPlatform_AllocHandle(size_t _Size);
void stdPlatform_FreeHandle(void* _Memory);
void* stdPlatform_ReallocHandle(void* _Memory, size_t _NewSize);
uint32_t stdPlatform_LockHandle(uint32_t param_1);
void stdPlatform_noop(uint32_t param);
void stdPlatform_InitServices(HostServices* handlers);

#endif // STD_PLATFORM_H
