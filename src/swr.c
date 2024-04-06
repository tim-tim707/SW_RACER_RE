#include "swr.h"

#include "macros.h"
#include "globals.h"

// 0x00426910
void swr_noop2(void)
{
    return;
}

// 0x00426A00
void playASoundImpl(int, short, float, float, short, int, int, int*)
{
    HANG("TODO");
}

// 0x00426C80
void playASound(int, short, float, float, int)
{
    HANG("TODO");
}

// 0x00426CC0
void playASound2(int, short, float, float, int)
{
    HANG("TODO");
}

// 0x004270c0
void swr_noop4(void)
{
    if (swrSound_unk_init != 0)
        swr_noop1();
}

// 0x00482E50
void swr_noop1(void)
{
    return;
}

// 0x00483ba0
void swr_noop3(void)
{
    swr_noop1();
}
