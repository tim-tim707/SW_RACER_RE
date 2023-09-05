#include "swrSound.h"

#include "types.h"
#include "globals.h"

// 0x00423210
int swrSound_CreateThread(void)
{
    HANG("TODO");
    return 1;
}

// 0x004232c0

// 0x00423350
void swrSound_SetPlayEvent(void)
{
    HANG("TODO, easy");
}

// 0x00423330
DWORD __attribute__((__stdcall__)) swrSound_ThreadRoutine(LPVOID lpThreadParameter)
{
    do
    {
        WaitForSingleObject(ia3dSourceEventHandle2, 0xffffffff);
        EnterCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
        FUN_004234c0();
        LeaveCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
    } while (true);
}

// 0x004234c0
// TODO

// 0x00484aa0
IA3dSource* swrSound_NewSource(int mono_stereo, int samplesPerSec, uint32_t param3, int nSizeWaveData, char param5)
{
    HANG("TODO, easy one");
    return NULL;
}
