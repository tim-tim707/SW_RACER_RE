#include "swrEvent.h"

// 0x00447300
void swrEvent_AllocateAndLoadObjs(int event, int count)
{
    HANG("TODO");
}

// 0x00447350 TODO: crashes on release build, works fine on debug
void swrEvent_ClearObjs(int event)
{
    swrEvent_SetObjs(event, 0, NULL);
}

// 0x00450850
void swrEvent_Initialize(int event)
{
    HANG("TODO");
}

// 0x00450aa0
void* swrEvent_FindObjectById(int event, int id)
{
    HANG("TODO");
    return NULL;
}

// 0x00450c00
void swrEvent_DispatchSubEvents(void* obj, int* subEvents)
{
    HANG("TODO");
}

// 0x00450ce0
void* swrEvent_SetObjs(int event, int count, void* obj)
{
    HANG("TODO");
}

// 0x00450d20
void* swrEvent_AllocObj(int event)
{
    HANG("TODO");
    return NULL;
}

// 0x00450db0
void swrEvent_FreeObjs(int event)
{
    HANG("TODO");
}
