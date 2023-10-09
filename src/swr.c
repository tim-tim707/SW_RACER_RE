#include "swr.h"

#include "macros.h"
#include "globals.h"

// 0x00426910
void swr_noop2(void)
{
    return;
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
