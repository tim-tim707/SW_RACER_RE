#include "utils.h"

#include "globals.h"
#include "../macros.h"

#include <limits.h>

// 0x0045cf00 TODO: crashes on release build, works fine on debug
float swrUtils_RandFloat(void)
{
    int tmp = swrUtils_Rand();
    return (float)(tmp * 2 - 1);
}

// 0x004816b0
int swrUtils_Rand(void) // randInt
{
    // self-seeding linear congruential generator (ANSI constants)
    if (!swrUtils_randInitialized) {
        swrUtils_randState = 0x2750250;
        swrUtils_randInitialized = 1;
    }
    int value = swrUtils_randState * 0x41c64e6d + 0x3039;
    swrUtils_randState = value;
    // -INT_MIN overflows, so the most-negative state maps to 0 instead of abs()
    if (value == INT_MIN) {
        return 0;
    }
    if (value < 0) {
        value = -value;
    }
    return value;
}
