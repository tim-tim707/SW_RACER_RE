#include "stdPlatform.h"
#include "./Win95/std.h"
#include "General/stdMemory.h"
#include "types.h"
#include "globals.h"

#include <macros.h>
#include <engine_config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// 0x00408e40
void* stdPlatform_Alloc(unsigned int size)
{
    return (*stdPlatform_hostServices_ptr->alloc)(size);
}

// 0x00484720
unsigned int stdPlatform_Initialize(HostServices* hs)
{
    unsigned short cw;

    stdPlatform_hostServices_ptr = hs;
    __asm__ volatile("fnstcw %0" : "=m"(cw));
    stdPlatfom_FPU1 = cw;
    *(unsigned short*)&stdPlatfom_FPU3 = (cw & 0xff) | STD_FPU_CW_ROUND_UP;
    stdPlatfom_FPU2 = (cw & 0xff) | STD_FPU_CW_ROUND_DOWN;
    stdPlatform_hostServices_initialized = 1;
    // retail leaves the control word in AX
    return ((unsigned int)hs & 0xffff0000) | cw;
}

// 0x00484760
void stdPlatform_Shutdown(void)
{
    stdPlatform_hostServices_initialized = 0;
}

// Called as a macro using errorPrint, __FILE__, __LINE__, "msg", ...
// 0x00484780
int stdPlatform_DebugLog(void* log_function, char* compile_filepath, int line_nb, char* msg, ...)
{
    int baseOffset = 0;
    int hasSeparator = 0;
    int i;
    int len;
    int remaining;
    va_list args;

    if (log_function == NULL)
        return 0;

    for (i = 0; compile_filepath[i] != '\0'; i++) {
        if (compile_filepath[i] == '\\') {
            hasSeparator = 1;
            baseOffset = i;
        }
    }
    if (hasSeparator)
        baseOffset++;

    len = _snprintf(debug_buffer, sizeof(debug_buffer), compile_filepath + baseOffset);
    remaining = sizeof(debug_buffer) - len;
    i = _snprintf(debug_buffer + len, remaining, "(%d): ", line_nb);
    remaining -= i;
    len += i;
    va_start(args, msg);
    _vsnprintf(debug_buffer + len, remaining, msg, args);
    va_end(args);
    ((int (*)(const char*, ...))log_function)(debug_buffer);
    return 0;
}

// 0x0048c570
int stdPlatform_Printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    vsnprintf(std_output_buffer, 0x800, format, args);
    OutputDebugStringA(std_output_buffer);

    va_end(args);

    return 1;
}

// 0x0048c4a0
void stdPlatform_Assert(const char* msg, const char* filePath, int line)
{
    char buffer[512];
    int baseOffset = 0;
    int hasSeparator = 0;
    int i;

    if (stdPlatform_bAssertInProgress) {
        DebugBreak();
        exit(1);
    }
    stdPlatform_bAssertInProgress = 1;

    for (i = 0; filePath[i] != '\0'; i++) {
        if (filePath[i] == '\\') {
            hasSeparator = 1;
            baseOffset = i;
        }
    }
    if (hasSeparator)
        baseOffset++;

    _snprintf(buffer, sizeof(buffer), "%s(%d):  %s\n", filePath + baseOffset, line, msg);
    stdPlatform_hostServices_ptr->errorPrint("ASSERT: %s", buffer);
    MessageBoxA(NULL, buffer, "Assert Handler", MB_TASKMODAL);
    DebugBreak();
    exit(1);
}

// 0x48c5a0
void* stdPlatform_AllocHandle(size_t _Size)
{
    return malloc(_Size);
}

// 0x0048c5b0
void stdPlatform_FreeHandle(void* _Memory)
{
    return free(_Memory);
}

// 0x0048c5c0
void* stdPlatform_ReallocHandle(void* _Memory, size_t _NewSize)
{
    return realloc(_Memory, _NewSize);
}

// 0x0048c5e0
uint32_t stdPlatform_LockHandle(uint32_t param_1)
{
    return param_1;
}

// 0x00423cb0
void stdPlatform_noop(uint32_t x)
{
    return;
}

// 0x0048c3d0
void stdPlatform_InitServices(HostServices* handlers)
{
    handlers->some_float = 1000.0;
    handlers->statusPrint = stdPlatform_Printf;
    handlers->messagePrint = stdPlatform_Printf;
    handlers->warningPrint = stdPlatform_Printf;
    handlers->errorPrint = stdPlatform_Printf;
    handlers->debugPrint = NULL;
    handlers->assert = stdPlatform_Assert;
    handlers->unk_0 = 0;
    handlers->alloc = daAlloc;
    handlers->free = daFree;
    handlers->realloc = daRealloc;
    handlers->getTimerTick = (uint32_t(*)(void))timeGetTime; // stdcall without args can be safely converted to cdecl
    handlers->fileOpen = stdFileOpen;
    handlers->fileClose = stdFileClose;
    handlers->fileRead = stdFileRead;
    handlers->fileGets = stdFileGets;
    handlers->fileWrite = stdFileWrite;
    handlers->feof = feof;
    handlers->ftell = stdFtell;
    handlers->fseek = stdFseek;
    handlers->fileSize = stdFileSize;
    handlers->filePrintf = stdFilePrintf;
    handlers->fileGetws = stdFileGetws;
    handlers->allocHandle = stdPlatform_AllocHandle;
    handlers->freeHandle = stdPlatform_FreeHandle;
    handlers->reallocHandle = stdPlatform_ReallocHandle;
    handlers->lockHandle = stdPlatform_LockHandle;
    handlers->unlockHandle = stdPlatform_noop;
}
