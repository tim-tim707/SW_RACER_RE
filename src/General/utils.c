#include "utils.h"

#include "globals.h"
#include "../engine_config.h"
#include "../macros.h"

#include <limits.h>

// Random sign: -1.0 or +1.0 with equal odds.
// 0x0045cf00
RETAIL_FP long double swrUtils_RandFloat(void)
{
    int bit = (int)((long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * 2.0f);
    return bit * 2 - 1;
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
