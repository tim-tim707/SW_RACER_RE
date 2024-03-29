#include "utils.h"

#include "../macros.h"

// 0x0045cf00 TODO: crashes on release build, works fine on debug
float swrUtils_RandFloat(void)
{
    int tmp = swrUtils_Rand();
    return (float)(tmp * 2 - 1);
}

// 0x004816b0
int swrUtils_Rand(void) // randInt
{
    HANG("TODO, easy");
    return 0;
}
