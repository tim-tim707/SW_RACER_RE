#include "stdPlatform.h"
#include "./Win95/std.h"
#include "General/stdMemory.h"
#include "types.h"
#include "globals.h"

#include <macros.h>
#include <stdio.h>

// 0x00408e40
void* stdPlatform_Alloc(unsigned int size)
{
    return (*stdPlatform_hostServices_ptr->alloc)(size);
}

// 0x00484720 TODO: crashes on release, works on debug
unsigned int stdPlatform_Initialize(HostServices* hs)
{
    // unsigned short in_FPUControlWord;

    stdPlatform_hostServices_ptr = hs;

    // Modified here. Is the FPU stuff manually done ?

    // stdPlatform_FPU1 = in_FPUControlWord;
    // stdPlatform_FPU3 = CONCAT11(0xb, (char)in_FPUControlWord);
    // stdPlatform_FPU2 = CONCAT11(7, (char)in_FPUControlWord);
    stdPlatform_hostServices_initialized = 1;
    // return (unsigned int)hs & 0xffff0000 | (unsigned int)in_FPUControlWord;
    return 1;
}

// 0x00484760
void stdPlatform_Shutdown(void)
{
    stdPlatform_hostServices_initialized = 0;
}

// 0x00484780
// Called as a macro using errorPrint, __FILE__, __LINE__, "msg", ...
int stdPlatform_DebugLog(void* log_function, char* compile_filepath, int line_nb, char* msg, ...)
{
    HANG("TODO");
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
void stdPlatform_Assert(const char* param_1, const char* param_2, int param_3)
{
    HANG("");

    // int iVar1;
    // char cVar2;
    // bool is_path;
    // int iVar4;
    // int iVar5;
    // char buffer[512];

    // iVar5 = 0;
    // is_path = false;
    // if (DAT_0052ee58 != 0) // static variable only used in this function
    // {
    //     DebugBreak();
    //     exit(1);
    // }
    // DAT_0052ee58 = 1;
    // iVar4 = 0;
    // cVar2 = *param_2;
    // while (cVar2 != '\0')
    // {
    //     if (cVar2 == '\\')
    //     {
    //         is_path = true;
    //         iVar5 = iVar4;
    //     }
    //     iVar1 = iVar4 + 1;
    //     iVar4 = iVar4 + 1;
    //     cVar2 = param_2[iVar1];
    // }
    // if (is_path)
    // {
    //     iVar5 = iVar5 + 1;
    // }
    // snprintf(buffer, sizeof(buffer), "%s(%d):  %s\n", param_2 + iVar5, param_3, param_1);
    // (**(code**)(DAT_00ecc420 + 0x10))("ASSERT: %s", buffer);
    // MessageBoxA(NULL, buffer, "Assert Handler", 0x2000);
    // DebugBreak();
    // exit(1);
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
void stdPlatform_noop(uint32_t)
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
