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

// Retail uses the FSIN/FCOS instructions inline; the CRT sin()/cos() reduce the argument
// differently (cos(90 deg) comes out -1.6e-16 instead of 6.1e-17).
static long double stdMath_x87Sin(long double x)
{
    __asm__("fsin" : "+t"(x));
    return x;
}

static long double stdMath_x87Cos(long double x)
{
    __asm__("fcos" : "+t"(x));
    return x;
}

// 0x0042f380
void stdMath_SinCos(float angle_degrees, float* pSinOut, float* pCosOut)
{
    long double angle_rad = angle_degrees * PI * 0x1.6c16c16c16c17p-8; // 0.005555555555555556
    *pCosOut = stdMath_x87Cos(angle_rad);
    *pSinOut = stdMath_x87Sin(angle_rad);
    return;
}

// 0x0042f3b0
long double stdMath_Tan(float angle_degrees)
{
    float cos;
    stdMath_SinCos(angle_degrees, &angle_degrees, &cos);
    return angle_degrees / cos;
}

// x87 returns the result in ST0 at register width; retail ArcCos consumes it unrounded.
static long double stdMath_ArcSinX87(float angle)
{
    bool reflected;
    float original_angle;
    float x2_32;
    float x7_32;
    long double x2;
    long double x3;
    long double x5;
    long double x7;
    long double x9;
    long double degrees;

    // Constants are the float32s at 0x004ac660..0x004ac698; 1/pi is the double at 0x004ac6a0.
    if (0x1.ffffdep-1f < angle) // 0.999999f
    {
        return 90.0f;
    }
    if (angle < -0x1.ffffdep-1f)
    {
        return -90.0f;
    }
    if ((0x1.6a09e6p-1f <= angle) || (angle <= -0x1.6a09e6p-1f)) // 0.70710677f
    {
        original_angle = angle;
        reflected = true;
        if (0.0f <= angle)
            angle = stdMath_Sqrt(1.0f - angle * angle);
        else
            angle = -stdMath_Sqrt(1.0f - angle * angle);
    }
    else
    {
        reflected = false;
    }
    if ((0x1.0624dep-10f <= angle) || (angle <= -0x1.0624dep-10f)) // 0.001f
    {
        // Retail keeps the odd powers at register width and spills only x^2 and x^7 to
        // float, reusing those copies as multiplicands. Sum is ((x9 + x3) + x5) + x7.
        x2 = (long double)angle * angle;
        x2_32 = x2;
        x3 = x2 * angle;
        x5 = x3 * x2_32;
        x7 = x5 * x2_32;
        x7_32 = x7;
        x9 = x7 * x2_32;
        degrees = (angle - (x9 * -0x1.84ad7ap-5f + x3 * -0x1.555556p-3f + x5 * -0x1.333334p-4f + x7_32 * -0x1.6db6dcp-5f)) * 180.0f * 0x1.45f306dc9c883p-2; // 0.047446f, 1/6, 0.075f, 0.04464286f, 1/pi
    }
    else
    {
        degrees = angle * 180.0f * 0x1.45f306dc9c883p-2;
    }
    if (reflected)
    {
        if (original_angle < 0.0f)
            return -90.0f - degrees;
        return 90.0f - degrees;
    }
    return degrees;
}

// 0x0042f3e0
long double stdMath_ArcSin(float angle)
{
    return stdMath_ArcSinX87(angle);
}

// 0x0042f540
long double stdMath_ArcCos(float angle)
{
    return stdMath_ArcCosUnrounded(angle);
}

long double stdMath_ArcCosUnrounded(float angle)
{
    return 90.0f - stdMath_ArcSinX87(angle);
}

// 0x0042f560
long double stdMath_ArcTan2(float x1, float x2)
{
    float abs1;
    float abs2;
    float t;
    float t2_32;
    float t7_32;
    bool swapped;
    long double t2;
    long double t3;
    long double t5;
    long double t7;
    long double t9;
    long double degrees;

    // The 0.0001 thresholds are the float32s at 0x004ac6a8 / 0x004ac6ac (9.999999747e-05,
    // strictly below the double 0.0001), which decides branches at x == 0.0001f.
    // Coefficients are the float32s at 0x004ac6b0..0x004ac6bc; 1/pi is a double.
    if ((0x1.a36e2ep-14f <= x2) || (x2 < -0x1.a36e2ep-14f)) // 0.0001f
    {
        if ((0x1.a36e2ep-14f <= x1) || (x1 < -0x1.a36e2ep-14f))
        {
            abs1 = x1 < 0.0f ? -x1 : x1;
            abs2 = x2 < 0.0f ? -x2 : x2;
            swapped = abs2 < abs1;
            t = swapped ? abs2 / abs1 : abs1 / abs2;
            if ((0x1.a36e2ep-14f <= t) || (t < -0x1.a36e2ep-14f))
            {
                // Odd powers at register width; t^2 and t^7 spilled to float and reused.
                t2 = (long double)t * t;
                t2_32 = t2;
                t3 = t2 * t;
                t5 = t3 * t2_32;
                t7 = t5 * t2_32;
                t7_32 = t7;
                t9 = t7 * t2_32;
                degrees = ((((t - t3 * 0x1.555556p-2f) - t5 * -0x1.99999ap-3f) - t7_32 * 0x1.24924ap-3f) - t9 * -0x1.0302b4p-4f) * 180.0f * 0x1.45f306dc9c883p-2; // 1/3, 0.2f, 1/7, 0.063235f, 1/pi
            }
            else
            {
                degrees = 0.0f;
            }
            if (swapped)
                degrees = 90.0f - degrees;
        }
        else
        {
            degrees = 0.0f;
        }
    }
    else
    {
        degrees = 90.0f;
    }
    if (x2 < -0x1.a36e2ep-14f)
        degrees = 180.0f - degrees;
    if (x1 < -0x1.a36e2ep-14f)
        degrees = -degrees;
    return degrees;
}

// Returns the unrounded ST0 result: retail callers multiply by it before any store.
// 0x00480650
long double stdMath_Decelerator(float deceleration, float time)
{
    // 33.333336f is the exact float32 at 0x004adf9c (bits 0x42055556). Ghidra prints it
    // as "33.33334", which does NOT round-trip -- float("33.33334") is 0x42055557, one
    // ULP away -- and written without the `f` suffix it becomes a double constant, which
    // is a third distinct value. All three disagree, so the literal has to come from the
    // stored bits rather than the decompiler's text.
    return 1.0f - (time * 0x1.0aaaacp+5f) / (time * 0x1.0aaaacp+5f + deceleration); // 33.333336f
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
    idx = a * 0x1.6c16c2p+5f; // (float)(4096 / 90.0), stored at 0x004af6e0
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
    bool negative;
    float x;
    float partial;
    float res;

    // Exact float32 constants from 0x004af6c8..0x004af704. Retail sums the series as
    // ((x + x^3/6) + 0.075x^5) + 0.066797x^7, spilling each partial sum to float.
    negative = x_ < 0.0f;
    x = negative ? -x_ : x_;
    if (x <= 0x1.6a09e6p-1f) // 0.70710677f
    {
        partial = stdMath_FlexPower(x, 3) / 6.0f + x;
        partial = stdMath_FlexPower(x, 5) * 0x1.333334p-4f + partial; // 0.075f
        res = (stdMath_FlexPower(x, 7) * 0x1.1199bcp-4f + partial) * 0x1.ca5dc4p+5f; // 0.066797f, 57.295784f
    }
    else
    {
        x = stdMath_Sqrt_2(1.0f - x * x);
        partial = stdMath_FlexPower(x, 3) / 6.0f + x;
        partial = stdMath_FlexPower(x, 5) * 0x1.333334p-4f + partial;
        res = 90.0f - (stdMath_FlexPower(x, 7) * 0x1.1199bcp-4f + partial) * 0x1.ca5dc4p+5f;
    }
    return negative ? -res : res;
}
