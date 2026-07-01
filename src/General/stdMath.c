#include "stdMath.h"

#include "globals.h"
#include "macros.h"

// stdMath_SinTable and stdMath_TanTable each hold one 90-degree quarter wave in
// this many entries (they sit contiguously: TanTable == SinTable + this). The
// quadrant reflections below index off multiples of it.
#define STDMATH_TRIG_QUARTER 0x1000

// 0x00429d50
void stdMath_MultiplyAddClamped(float* res_inout, float value, float multiplier, float min, float max)
{
    float tmp = multiplier * value + *res_inout;
    *res_inout = tmp;
    if (tmp < min)
    {
        *res_inout = min;
    }
    if (max < *res_inout)
    {
        *res_inout = max;
    }
}

// 0x00429d90
void stdMath_AddScaledValueAndClamp_i32(int* res_inout, int value, float multiplier, int min, int max)
{
    if (*res_inout < min)
    {
        *res_inout = min;
    }
    if (max < *res_inout)
    {
        *res_inout = max;
    }
}

// 0x0042f380
void stdMath_SinCos(float angle_degrees, float* pSinOut, float* pCosOut)
{
    double angle_rad = angle_degrees * PI * 0.005555555555555556;
    *pCosOut = cos(angle_rad);
    *pSinOut = sin(angle_rad);
    return;
}

// 0x0042f3b0
float stdMath_Tan(float angle_degrees)
{
    float cos;
    stdMath_SinCos(angle_degrees, &angle_degrees, &cos);
    return angle_degrees / cos;
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

// 0x0048c910
float stdMath_NormalizeAngleAcute(float angle)
{
    float tmp;

    tmp = stdMath_NormalizeAngle(angle);
    if (180.0 < tmp)
    {
        tmp = -(360.0 - tmp);
    }
    return tmp;
}

// 0x0048c950
void stdMath_SinCosFast(float angle, float* pSinOut, float* pCosOut)
{
    float a;
    float idx;
    float frac;
    int quadrant;
    int i1;
    int i2;
    float sinEdge;
    float cosEdge;
    float sinBase;
    float cosBase;

    a = stdMath_NormalizeAngle(angle);
    if (90.0f <= a) {
        if (180.0f <= a) {
            if (270.0f <= a) {
                quadrant = 3;
            } else {
                quadrant = 2;
            }
        } else {
            quadrant = 1;
        }
    } else {
        quadrant = 0;
    }
    idx = a * ((float)STDMATH_TRIG_QUARTER / 90.0f);
    frac = idx - stdMath_fround(idx);
    i1 = stdMath_FRoundInt(idx);
    i2 = i1 + 1;
    switch (quadrant) {
    case 0:
        if (i2 < STDMATH_TRIG_QUARTER) {
            sinEdge = stdMath_SinTable[i2];
        } else {
            sinEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (STDMATH_TRIG_QUARTER - 1))];
        }
        *pSinOut = (sinEdge - stdMath_SinTable[i1]) * frac + stdMath_SinTable[i1];
        if (i2 < STDMATH_TRIG_QUARTER) {
            cosEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - i2];
        } else {
            cosEdge = -stdMath_SinTable[i2 - STDMATH_TRIG_QUARTER];
        }
        *pCosOut = (cosEdge - stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - i1]) * frac + stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - i1];
        break;
    case 1:
        if (i2 < 2 * STDMATH_TRIG_QUARTER) {
            sinEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (STDMATH_TRIG_QUARTER - 1))];
        } else {
            sinEdge = -stdMath_SinTable[i2 - 2 * STDMATH_TRIG_QUARTER];
        }
        sinBase = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - STDMATH_TRIG_QUARTER)];
        *pSinOut = (sinEdge - sinBase) * frac + sinBase;
        if (i2 < 2 * STDMATH_TRIG_QUARTER) {
            cosEdge = stdMath_SinTable[i2 - STDMATH_TRIG_QUARTER];
        } else {
            cosEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (2 * STDMATH_TRIG_QUARTER - 1))];
        }
        cosEdge = -cosEdge;
        cosBase = -stdMath_SinTable[i1 - STDMATH_TRIG_QUARTER];
        *pCosOut = (cosEdge - cosBase) * frac + cosBase;
        break;
    case 2:
        if (i2 < 3 * STDMATH_TRIG_QUARTER) {
            sinEdge = stdMath_SinTable[i2 - 2 * STDMATH_TRIG_QUARTER];
        } else {
            sinEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (3 * STDMATH_TRIG_QUARTER - 1))];
        }
        sinEdge = -sinEdge;
        sinBase = -stdMath_SinTable[i1 - 2 * STDMATH_TRIG_QUARTER];
        *pSinOut = (sinEdge - sinBase) * frac + sinBase;
        if (i2 < 3 * STDMATH_TRIG_QUARTER) {
            cosEdge = -stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (2 * STDMATH_TRIG_QUARTER - 1))];
        } else {
            cosEdge = stdMath_SinTable[i2 - 3 * STDMATH_TRIG_QUARTER];
        }
        cosBase = -stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - 2 * STDMATH_TRIG_QUARTER)];
        *pCosOut = (cosEdge - cosBase) * frac + cosBase;
        break;
    case 3:
        if (i2 < 4 * STDMATH_TRIG_QUARTER) {
            sinEdge = -stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (3 * STDMATH_TRIG_QUARTER - 1))];
        } else {
            sinEdge = stdMath_SinTable[i2 - 4 * STDMATH_TRIG_QUARTER];
        }
        sinBase = -stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - 3 * STDMATH_TRIG_QUARTER)];
        *pSinOut = (sinEdge - sinBase) * frac + sinBase;
        if (i2 < 4 * STDMATH_TRIG_QUARTER) {
            cosEdge = stdMath_SinTable[i2 - 3 * STDMATH_TRIG_QUARTER];
        } else {
            cosEdge = stdMath_SinTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (4 * STDMATH_TRIG_QUARTER - 1))];
        }
        cosBase = stdMath_SinTable[i1 - 3 * STDMATH_TRIG_QUARTER];
        *pCosOut = (cosEdge - cosBase) * frac + cosBase;
        break;
    }
}

// 0x0048cd30
int stdMath_FRoundInt(float f)
{
    return (int)roundf(f);
}

// 0x0048cd50
float stdMath_FastTan(float f)
{
    float a;
    float idx;
    float frac;
    int quadrant;
    int i1;
    int i2;
    float tanEdge;
    float tanBase;
    float result;

    result = 0.0f;
    a = stdMath_NormalizeAngle(f);
    if (90.0f <= a) {
        if (180.0f <= a) {
            if (270.0f <= a) {
                quadrant = 3;
            } else {
                quadrant = 2;
            }
        } else {
            quadrant = 1;
        }
    } else {
        quadrant = 0;
    }
    idx = (a / 360.0f) * (float)(4 * STDMATH_TRIG_QUARTER);
    frac = idx - stdMath_fround(idx);
    i1 = stdMath_FRoundInt(idx);
    i2 = i1 + 1;
    switch (quadrant) {
    case 0:
        if (i2 < STDMATH_TRIG_QUARTER) {
            tanEdge = stdMath_TanTable[i2];
        } else {
            tanEdge = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (STDMATH_TRIG_QUARTER - 1))];
        }
        result = (tanEdge - stdMath_TanTable[i1]) * frac + stdMath_TanTable[i1];
        break;
    case 1:
        if (i2 < 2 * STDMATH_TRIG_QUARTER) {
            tanEdge = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (STDMATH_TRIG_QUARTER - 1))];
        } else {
            tanEdge = stdMath_TanTable[i2 - 2 * STDMATH_TRIG_QUARTER];
        }
        tanBase = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - STDMATH_TRIG_QUARTER)];
        result = (tanEdge - tanBase) * frac + tanBase;
        break;
    case 2:
        if (i2 < 3 * STDMATH_TRIG_QUARTER) {
            tanEdge = stdMath_TanTable[i2 - 2 * STDMATH_TRIG_QUARTER];
        } else {
            tanEdge = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (3 * STDMATH_TRIG_QUARTER - 1))];
        }
        tanBase = stdMath_TanTable[i1 - 2 * STDMATH_TRIG_QUARTER];
        result = (tanEdge - tanBase) * frac + tanBase;
        break;
    case 3:
        if (i2 < 4 * STDMATH_TRIG_QUARTER) {
            tanEdge = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - (3 * STDMATH_TRIG_QUARTER - 1))];
        } else {
            tanEdge = stdMath_TanTable[i2 - 4 * STDMATH_TRIG_QUARTER];
        }
        tanBase = -stdMath_TanTable[(STDMATH_TRIG_QUARTER - 1) - (i1 - 3 * STDMATH_TRIG_QUARTER)];
        result = (tanEdge - tanBase) * frac + tanBase;
        break;
    }
    return result;
}

// 0x0048c7f0
float stdMath_FlexPower(float x, int exp)
{
    int i;
    float res;

    res = x;
    for (i = 0; i < exp + -1; i = i + 1)
    {
        res = res * x;
    }
    return res;
}

// 0x0048cff0
float stdMath_Sqrt_2(float f)
{
    return sqrtf(f);
}

// 0x0048d010
float stdMath_ArcSin3(float x_)
{
    float res;
    float taylor_1;
    float taylor_3;
    float taylor_2;
    float taylor_4;
    float x;
    float expansion;

    if (0.0 <= x_)
    {
        x = x_;
    }
    else
    {
        x = -x_;
    }
    if (x <= 0.7071068)
    {
        taylor_4 = stdMath_FlexPower(x, 3);
        taylor_1 = stdMath_FlexPower(x, 5);
        taylor_3 = stdMath_FlexPower(x, 7);
        expansion = (taylor_3 * 0.066797 + taylor_1 * 0.075 + taylor_4 / 6.0 + x) * 57.29578;
    }
    else
    {
        res = stdMath_Sqrt_2(1.0 - x * x);
        taylor_4 = res;
        taylor_1 = stdMath_FlexPower(taylor_4, 3);
        taylor_3 = stdMath_FlexPower(taylor_4, 5);
        taylor_2 = stdMath_FlexPower(taylor_4, 7);
        expansion = 90.0 - (taylor_2 * 0.066797 + taylor_3 * 0.075 + taylor_1 / 6.0 + taylor_4) * 57.29578;
    }
    if (0.0 <= x_)
    {
        res = expansion;
    }
    else
    {
        res = -expansion;
    }
    return res;
}
