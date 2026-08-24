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
void stdMath_AddScaledValueAndClamp_i32(int* res_inout, float value, float multiplier, int min, int max)
{
    // Retail is FLD multiplier / FMUL value / FILD *res_inout / FADDP / __ftol, so the
    // whole accumulate happens on the x87 stack: the product is formed at register
    // precision, the running total arrives exactly via FILD, and only the final result
    // is truncated toward zero. Double intermediates reproduce that -- float ones would
    // round the product down to 24 bits of mantissa before the add.
    //
    // `value` is a float, not an int: retail reads it with FMUL m32fp, and the sole
    // caller (swrRace_DebugSetGameValue) hands its own float parameter straight through.
    // The scaled add was missing here entirely, so this only ever clamped.
    *res_inout = (int)((double)multiplier * (double)value + (double)*res_inout);

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
    float original_angle;

    // Every literal below is a float32 constant in .rdata (0x004ac660..0x004ac698) except
    // the final 1/pi, which really is stored as a double at 0x004ac6a0. Ghidra prints
    // float32 constants as shortened decimals that do not always round-trip, so these
    // come from the stored bits: 0x004ac670 is 0.70710677f, not the 0.7071068 that was
    // here, and 0x004ac68c is -0.16666667f, not -0.1666667. Dropping the `f` suffix makes
    // each one a third, different value again.
    if (0.999999f < angle)
    {
        return 90.0f;
    }
    if (angle < -0.999999f)
    {
        return -90.0f;
    }
    if ((0.70710677f <= angle) || (angle <= -0.70710677f))
    {
        original_angle = angle;
        bVar2 = true;
        fVar1 = 1.0f - angle * angle;
        if (0.0f <= angle)
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
    if ((0.001f <= angle) || (angle <= -0.001f))
    {
        fVar1 = angle * angle;
        fVar3 = angle * angle * angle;
        fVar4 = fVar3 * fVar1;
        fVar5 = fVar4 * fVar1;
        // Term order follows retail's FADDP sequence, which accumulates
        // ((x9 + x3) + x5) + x7 rather than the x7-first order the decompiler emitted.
        //
        // Kept as a single expression through to the degree conversion for the same
        // reason: retail runs FSUBR / FMUL 180.0f / FMUL 1-over-pi back to back with
        // nothing spilled between them, so `angle - sum` is never rounded to 32 bits on
        // the way through. Both details mirror the original's data flow.
        fVar3 = (angle - (fVar5 * fVar1 * -0.047446f + fVar3 * -0.16666667f + fVar4 * -0.075f + (float)fVar5 * -0.04464286f)) * 180.0f * 0.3183098861837907;
    }
    else
    {
        fVar3 = angle * 180.0f * 0.3183098861837907;
    }
    if (bVar2)
    {
        if (original_angle < 0.0f)
        {
            return -90.0f - fVar3;
        }
        fVar3 = 90.0f - fVar3;
    }
    return fVar3;
}

// 0x0042f540
float stdMath_ArcCos(float angle)

{
    return 90.0f - stdMath_ArcSin(angle);
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

    // The 0.0001 thresholds are float32 constants at 0x004ac6a8 / 0x004ac6ac, whose value
    // is 9.999999747e-05 -- strictly LESS than the double 0.0001. That difference decides a
    // branch, not just a rounding: at x2 == 0.0001f retail compares equal and evaluates the
    // polynomial, while a double 0.0001 compares greater and takes the 90-degree early-out,
    // which is where the 751 ULP divergence came from. Polynomial coefficients are the
    // exact float32 values from 0x004ac6b0..0x004ac6bc; only the trailing 1/pi is a double.
    if ((0.0001f <= x2) || (x2 < -0.0001f))
    {
        if ((0.0001f <= x1) || (x1 < -0.0001f))
        {
            fVar2 = x1;
            if (x1 < 0.0f)
            {
                fVar2 = -x1;
            }
            fVar4 = x2;
            if (x2 < 0.0f)
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
            if ((0.0001f <= fVar3) || (fVar3 < -0.0001f))
            {
                fVar1 = fVar3 * fVar3;
                fVar5 = fVar3 * fVar3 * fVar3;
                fVar6 = fVar5 * fVar1;
                fVar7 = fVar6 * fVar1;
                fVar5 = ((((fVar3 - fVar5 * 0.33333334f) - fVar6 * -0.2f) - fVar7 * 0.14285715f) - fVar7 * fVar1 * -0.063235f) * 180.0f * 0.3183098861837907;
            }
            else
            {
                fVar5 = 0.0f;
            }
            if (fVar4 < fVar2)
            {
                fVar5 = 90.0f - fVar5;
            }
        }
        else
        {
            fVar5 = 0.0f;
        }
    }
    else
    {
        fVar5 = 90.0f;
    }
    if (x2 < -0.0001f)
    {
        fVar5 = 180.0f - fVar5;
    }
    if (x1 < -0.0001f)
    {
        fVar5 = -fVar5;
    }
    return fVar5;
}

// 0x00480650
float stdMath_Decelerator(float deceleration, float time)
{
    // 33.333336f is the exact float32 at 0x004adf9c (bits 0x42055556). Ghidra prints it
    // as "33.33334", which does NOT round-trip -- float("33.33334") is 0x42055557, one
    // ULP away -- and written without the `f` suffix it becomes a double constant, which
    // is a third distinct value. All three disagree, so the literal has to come from the
    // stored bits rather than the decompiler's text.
    return 1.0f - (time * 33.333336f) / (time * 33.333336f + deceleration);
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
    // Rounds toward negative infinity, not to nearest. Retail brackets its FRNDINT
    // with `FLDCW [0x00ec8c82]` / `FLDCW [0x00ec8c80]`, loading a control word whose
    // rounding-control field selects round-down: 0.5 comes back 0 and -0.5 comes back
    // -1, which is floor rather than either roundf() or truncf().
    //
    // roundf() here was wrong for every input with a fractional part of 0.5 or more
    // (~47% of them), and the error propagated into stdMath_NormalizeAngle,
    // stdMath_SinCosFast and stdMath_FastTan, which all index off this result. Those
    // three only ever pass positive values, where floor and trunc agree, so they alone
    // cannot distinguish the two -- negative inputs here are what pin it down.
    return floorf(f);
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
    // Unlike stdMath_fround this one does NOT touch the control word, so its FRNDINT
    // runs in the ambient mode -- round half to even. rintf() is the same deal: it
    // honours the current mode rather than imposing one. roundf() rounds halves away
    // from zero instead, which differed on every exact .5 input.
    return (int)rintf(f);
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

    // Exact float32 constants from 0x004af6c8..0x004af704. The degrees-per-radian factor
    // is 57.295784f (0x004af6f4), not the 57.29578 Ghidra printed, and the split point is
    // 0.70710677f rather than 0.7071068.
    if (0.0f <= x_)
    {
        x = x_;
    }
    else
    {
        x = -x_;
    }
    if (x <= 0.70710677f)
    {
        taylor_4 = stdMath_FlexPower(x, 3);
        taylor_1 = stdMath_FlexPower(x, 5);
        taylor_3 = stdMath_FlexPower(x, 7);
        expansion = (taylor_3 * 0.066797f + taylor_1 * 0.075f + taylor_4 / 6.0f + x) * 57.295784f;
    }
    else
    {
        res = stdMath_Sqrt_2(1.0f - x * x);
        taylor_4 = res;
        taylor_1 = stdMath_FlexPower(taylor_4, 3);
        taylor_3 = stdMath_FlexPower(taylor_4, 5);
        taylor_2 = stdMath_FlexPower(taylor_4, 7);
        expansion = 90.0f - (taylor_2 * 0.066797f + taylor_3 * 0.075f + taylor_1 / 6.0f + taylor_4) * 57.295784f;
    }
    if (0.0f <= x_)
    {
        res = expansion;
    }
    else
    {
        res = -expansion;
    }
    return res;
}
