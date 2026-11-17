#include "cifr.h"

#include "macros.h"

// 0x00403e10
void cifr_Init(void* effects)
{
    HANG("TODO");
}

// 0x00403f00
void cifr_ReinitEffects_Maybe(void* controller)
{
    HANG("TODO");
}

// 0x00403f30
int cifr_LoadProjectFile(void* effects, char* projectFile, void* nameIndices, void* nameTable)
{
    HANG("TODO");
    return 0;
}

// 0x00403fd0
int cifr_LoadAllEffects(void* controller)
{
    HANG("TODO");
    return 0;
}

// 0x004040a0
int cifr_CreateEffect(void* effect, void* params, void* device)
{
    HANG("TODO");
    return 0;
}

// 0x004041c0
int cifr_StartEffect(void* effect, int checkPlaying)
{
    HANG("TODO");
    return 0;
}

// 0x00404230
int cifr_StopEffect(void* effect)
{
    HANG("TODO");
    return 0;
}

// 0x00404280
int cifr_IsPlaying(void* effect)
{
    HANG("TODO");
    return 0;
}

// 0x00404330
int cifr_SetDirection(void* effect, int degrees, int deferred)
{
    HANG("TODO");
    return 0;
}

// 0x00404400
int cifr_SetMagnitude(void* effect, int percent, int deferred)
{
    HANG("TODO");
    return 0;
}

// 0x004044e0
int cifr_SetDuration(void* effect, int durationMs, int deferred)
{
    HANG("TODO");
    return 0;
}

// 0x00404590
int cifr_SetCustomForceData_Maybe(void* effect, unsigned int size, void* data, int deferred)
{
    HANG("TODO");
    return 0;
}

// 0x00404670
int cifr_GetForceFeedbackState_Maybe(void* effect, char* outState)
{
    HANG("TODO");
    return 0;
}
