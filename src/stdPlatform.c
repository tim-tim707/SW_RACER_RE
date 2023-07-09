#include "stdPlatform.h"
#include "types.h"

// 0x0048c570
int stdPlatform_Printf(const char* param1, ...)
{
    vsnprintf(std_output_buffer, 0x800, param1, ...);
    OutputDebugStringA();
}

// 0x0048c4a0
void stdPlatform_Assert(const char*, const char*, int)
{}

// 0x48c5a0
void stdPlatform_AllocHandle(size_t _Size)
{
    return malloc(_Size);
}

// 0x0048c5b0
void stdPlatform_FreeHandle(void* _Memory)
{
    return free(_Memory);
}

// 0x0048c5c0
void* stdPlatform_ReallocHandle(void* _Memory, void* _NewSize)
{
    return realloc(_Memory, _NewSize);
}

// 0x0048c5e0
uint32_t stdPlatform_LockHandle(uint32_t param_1)
{
    return param_1;
}

// 0x00423cb0
void stdPlatform_UnlockHandle(void)
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
    handlers->unk_0 = NULL;
    handlers->alloc = daAlloc;
    handlers->free = daFree;
    handlers->realloc = daRealloc;
    handlers->getTimerTick = timeGetTime;
    handlers->fileOpen = stdFileOpen;
    handlers->fileClose = stdFileClose;
    handlers->fileRead = stdFileRead;
    handlers->fileGets = stdFileGets;
    handlers->fileWrite = stdFileWrite;
    handlers->feof = stdFeof;
    handlers->ftell = stdFtell;
    handlers->fseek = stdFseek;
    handlers->fileSize = stdFileSize;
    handlers->filePrintf = stdFilePrintf;
    handlers->fileGetws = stdFileGetws;
    handlers->allocHandle = stdPlatform_AllocHandle;
    handlers->freeHandle = stdPlatform_FreeHandle;
    handlers->reallocHandle = stdPlatform_ReallocHandle;
    handlers->lockHandle = stdPlatform_LockHandle;
    handlers->unlockHandle = stdPlatform_UnlockHandle;
}
