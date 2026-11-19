#include "stdEffect.h"

#include "globals.h"

// 0x0049ea00
tStdFadeFactor* stdEffect_GetFadeFactor(void)
{
    return &stdEffect_fadeFactor;
}
