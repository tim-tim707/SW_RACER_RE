#include "utils.h"

#include "../macros.h"

// 0x0045cf00
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
