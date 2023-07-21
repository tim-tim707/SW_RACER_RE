#include "stdMath.h"

#include "../macros.h"

// 0x0042f380
void stdMath_SinCos(float angle, float* pSinOut, float* pCosOut)
{
    float angle_rad = angle * PI * 0.005555555555555556;
    *pCosOut = cosf(angle_rad);
    *pSinOut = sinf(angle_rad);
    return;
}

// 0x0042f3b0
float stdMath_Tan(float angle)
{
    float cos;
    stdMath_SinCos(angle, &angle, &cos);
    return angle / cos;
}

// 0x0042f3e0
float stdMath_ArcSin(float angle)
{
    float fVar1;
    bool bVar2;
    float fVar3;
    float fVar4;
    float fVar5;
    float local_4;

    if (0.999999 < angle)
    {
        return 90.0;
    }
    if (angle < -0.999999)
    {
        return -90.0;
    }
    if ((0.7071068 <= angle) || (angle <= -0.7071068))
    {
        local_4 = angle;
        bVar2 = true;
        fVar1 = 1.0 - angle * angle;
        if (0.0 <= angle)
        {
            fVar3 = stdMath_Sqrt(fVar1);
        }
        else
        {
            fVar3 = stdMath_Sqrt(fVar1);
            fVar3 = -fVar3;
        }
        angle = (float)fVar3;
    }
    else
    {
        bVar2 = false;
    }
    if ((0.001 <= angle) || (angle <= -0.001))
    {
        fVar1 = angle * angle;
        fVar3 = angle * angle * angle;
        fVar4 = fVar3 * fVar1;
        fVar5 = fVar4 * fVar1;
        fVar3 = angle - ((float)fVar5 * -0.04464286 + fVar4 * -0.075 + fVar3 * -0.1666667 + fVar5 * fVar1 * -0.047446);
    }
    else
    {
        fVar3 = angle;
    }
    fVar3 = fVar3 * 180.0 * 0.3183098861837907;
    if (bVar2)
    {
        if (local_4 < 0.0)
        {
            return -90.0 - fVar3;
        }
        fVar3 = 90.0 - fVar3;
    }
    return fVar3;
}

// 0x0042f540
float stdMath_ArcCos(float angle)

{
    return 90.0 - stdMath_ArcSin(angle);
}

// 0x0042f560
float stdMath_ArcTan2(float x1, float x2)
{
    float fVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    float fVar5;
    float fVar6;
    float fVar7;

    if ((0.0001 <= x2) || (x2 < -0.0001))
    {
        if ((0.0001 <= x1) || (x1 < -0.0001))
        {
            fVar2 = x1;
            if (x1 < 0.0)
            {
                fVar2 = -x1;
            }
            fVar4 = x2;
            if (x2 < 0.0)
            {
                fVar4 = -x2;
            }
            fVar1 = fVar4;
            fVar3 = fVar2;
            if (fVar4 < fVar2)
            {
                fVar1 = fVar2;
                fVar3 = fVar4;
            }
            fVar3 = fVar3 / fVar1;
            if ((0.0001 <= fVar3) || (fVar3 < -0.0001))
            {
                fVar1 = fVar3 * fVar3;
                fVar5 = fVar3 * fVar3 * fVar3;
                fVar6 = fVar5 * fVar1;
                fVar7 = fVar6 * fVar1;
                fVar5 = ((((fVar3 - fVar5 * 0.3333333) - fVar6 * -0.2) - fVar7 * 0.1428571) - fVar7 * fVar1 * -0.063235) * 180.0 * 0.3183098861837907;
            }
            else
            {
                fVar5 = 0.0;
            }
            if (fVar4 < fVar2)
            {
                fVar5 = 90.0 - fVar5;
            }
        }
        else
        {
            fVar5 = 0.0;
        }
    }
    else
    {
        fVar5 = 90.0;
    }
    if (x2 < -0.0001)
    {
        fVar5 = 180.0 - fVar5;
    }
    if (x1 < -0.0001)
    {
        fVar5 = -fVar5;
    }
    return fVar5;
}
// 0x00480650
float stdMath_Decelerator(float deceleration, float time)
{
    return 1.0 - (time * 33.33334) / (time * 33.33334 + deceleration);
}

// 0x00480670
float stdMath_Sqrt(float a)
{
    return sqrtf(a);
}

// 0x0048c830
float stdMath_NormalizeAngle(float angle)
{
    float retval;

    if (angle >= 0.0)
    {
        if (angle < 360.0)
            return angle;
        retval = angle - stdMath_fround(angle / 360.0) * 360.0;
    }
    else
    {
        if (-angle >= 360.0)
        {
            retval = 360.0 - (-angle - stdMath_fround(-angle / 360.0) * 360.0);
        }
        else
        {
            retval = 360.0 + angle;
        }
    }

    if (retval == 360.0)
        retval = 0.0;

    return retval;
}

// 0x0048c8f0
float stdMath_fround(float f)
{
    return roundf(f);
}

// 0x0048cd30
int stdMath_FRoundInt(float f)
{
    return (int)roundf(f);
}

// 0x0048cd50
float stdMath_FastTan(float f)
{
    hang("TODO");
    return 0.0f;
}
