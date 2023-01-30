//----- (0048C7F0) --------------------------------------------------------
// a1 = base
// a2 = exponent
// Simple power function
float __cdecl sub_48C7F0(float a1, int32_t a2)
{
    float r = a1;
    for (int32_t i = 0; i < (a2 - 1); i++)
    {
        r *= a1;
    }
    return r;
}

//----- (00492440) --------------------------------------------------------
// a1 = 3 component vector
// Probably returns nothing, if it has to return something, it's the prior
// vector length [in 80 bit or maybe double precision]
void __cdecl sub_492440(float *a1)
{
    float squared_length = a1[0] * a1[0] + a1[1] * a1[1] + a1[2] * a1[2];
    float length = sqrt(squared_length);
    if (length != 0.0)
    {
        a1[0] = a1[0] * (1.0 / length);
        a1[1] = a1[1] * (1.0 / length);
        a1[2] = a1[2] * (1.0 / length);
    }
}
//----- (00429D90) --------------------------------------------------------
// a1 = pointer to value to be modified
// a2 = factor a (from user input for example)
// a3 = factor b (constant scaling factor for example)
// a4 = min value
// a5 = max value
// Probably void, but would return a5 otherwise
void __cdecl sub_429D90(int *a1, float a2, float a3, int a4, int a5)
{
    *a1 = (int)(a3 * a2 + (float)a1);
    if (*a1 < a4)
    {
        *a1 = a4;
    }
    if (*a1 > a5)
    {
        *a1 = a5;
    }
}
//----- (00429D50) --------------------------------------------------------
// a1 = pointer to value to be modified
// a2 = factor a (from user input for example)
// a3 = factor b (constant scaling factor for example)
// a4 = min value
// a5 = max value
void __cdecl sub_429D50(float *a1, float a2, float a3, float a4, float a5)
{
    *a1 = a3 * a2 + *a1;
    if (*a1 < a4)
    {
        *a1 = a4;
    } // FIXME: This is different in the decompilation, but I assume the
      // decompiler messed up
    if (*a1 > a5)
    {
        *a1 = a5;
    }
}
int __cdecl sub_4800C0(float *a1)
{
    if (dword_4C7BE4 < 0)
    {
        return 0;
    }

    // FIXME: Fix datatype of dword_E25960 to be a float array
    a1[0] = dword_E25960;
    a1[1] = dword_E25964;
    a1[2] = dword_E25968;
    a2[3] = dword_E2596C;
    a2[4] = dword_E25970;
    a2[5] = dword_E25974;
    a2[6] = dword_E25978;
    a2[7] = dword_E2597C;
    a2[8] = dword_E25980;
    a2[9] = dword_E25984;
    a2[10] = dword_E25988;
    a2[11] = dword_E2598C;
    a2[12] = dword_E25990;
    a2[13] = dword_E25994;
    a2[14] = dword_E25998;
    a2[15] = dword_E2599C;

    return 1;
}
//----- (00480650) --------------------------------------------------------
double __cdecl sub_480650(float a1, float a2)
{
    return 1.0 - a2 * 33.333336 / (a2 * 33.333336 + a1);
}
//----- (00480670) --------------------------------------------------------
float __cdecl sub_480670(float a1)
{
    return sqrt(a1);
}
//----- (00480690) --------------------------------------------------------
// a1 is a 4 component output
// a2 is a 3 component vector
// a3 is a 4x4 matrix
// Probably  void function, but if it returns something, then it's the input
// matrix. not the output vector(!)
void __cdecl sub_480690(float *a1, float *a2, float *a3)
{
    a1[0] = a3[8] * a2[2] + a3[4] * a2[1] + a3[0] * a2[0] + a3[12];
    a1[1] = a3[9] * a2[2] + a3[5] * a2[1] + a3[1] * a2[0] + a3[13];
    a1[2] = a3[10] * a2[2] + a3[6] * a2[1] + a3[2] * a2[0] + a3[14];
    a1[3] = a3[11] * a2[2] + a3[7] * a2[1] + a3[3] * a2[0] + a3[15];
}
//----- (00492B70) --------------------------------------------------------
// a1 = output matrix [12 floats]
// a2 = input matrix [12 floats]
// a3 = input matrix [12 floats]
const float *__cdecl sub_492B70(float *a1, const float *a2, const float *a3)
{
    a1[0] = a2[0] * a3[0] + a2[3] * a3[1] + a2[6] * a3[2];
    a1[1] = a2[1] * a3[0] + a2[4] * a3[1] + a2[7] * a3[2];
    a1[2] = a2[2] * a3[0] + a2[5] * a3[1] + a2[8] * a3[2];

    a1[3] = a2[0] * a3[3] + a2[3] * a3[4] + a2[6] * a3[5];
    a1[4] = a2[1] * a3[3] + a2[4] * a3[4] + a2[7] * a3[5];
    a1[5] = a2[2] * a3[3] + a2[5] * a3[4] + a2[8] * a3[5];

    a1[6] = a2[0] * a3[6] + a2[3] * a3[7] + a2[6] * a3[8];
    a1[7] = a2[1] * a3[6] + a2[4] * a3[7] + a2[7] * a3[8];
    a1[8] = a2[2] * a3[6] + a2[5] * a3[7] + a2[8] * a3[8];

    a1[9] = a2[0] * a3[9] + a2[3] * a3[10] + a2[6] * a3[11] + a2[9];
    a1[10] = a2[1] * a3[9] + a2[4] * a3[10] + a2[7] * a3[11] + a2[10];
    a1[11] = a2[2] * a3[9] + a2[5] * a3[10] + a2[8] * a3[11] + a2[11];

    return a2;
}
//----- (00492D50) --------------------------------------------------------
// Transposed matrix multiplication, otherwise like sub_492F40
// a1 = input & output matrix [12 floats]
// a2 = input matrix [12 floats]
const float *__cdecl sub_492D50(float *a1, const float *a2)
{
    float tmp[12];
    qmemcpy(tmp, a1, sizeof(tmp));

    a1[0] = a2[0] * tmp[0] + a2[1] * tmp[3] + a2[2] * tmp[6];
    a1[1] = a2[0] * tmp[1] + a2[1] * tmp[4] + a2[2] * tmp[7];
    a1[2] = a2[0] * tmp[2] + a2[1] * tmp[5] + a2[2] * tmp[8];

    a1[3] = a2[3] * tmp[0] + a2[4] * tmp[3] + a2[5] * tmp[6];
    a1[4] = a2[3] * tmp[1] + a2[4] * tmp[4] + a2[5] * tmp[7];
    a1[5] = a2[3] * tmp[2] + a2[4] * tmp[5] + a2[5] * tmp[8];

    a1[6] = a2[6] * tmp[0] + a2[7] * tmp[3] + a2[8] * tmp[6];
    a1[7] = a2[6] * tmp[1] + a2[7] * tmp[4] + a2[8] * tmp[7];
    a1[8] = a2[6] * tmp[2] + a2[7] * tmp[5] + a2[8] * tmp[8];

    a1[9] = a2[9] * tmp[0] + a2[10] * tmp[3] + a2[11] * tmp[6] + tmp[9];
    a1[10] = a2[9] * tmp[1] + a2[10] * tmp[4] + a2[11] * tmp[7] + tmp[10];
    a1[11] = a2[9] * tmp[2] + a2[10] * tmp[5] + a2[11] * tmp[8] + tmp[11];

    return a2;
}
//----- (00492F40) --------------------------------------------------------
// a1 = input & output matrix [12 floats]
// a2 = input matrix [12 floats]
// (Same as sub_492B70(a1, a1, a2) if it allowed overlapping matrices)
const float *__cdecl sub_492F40(float *a1, const float *a2)
{
    float tmp[12];
    qmemcpy(tmp, a1, sizeof(tmp));

    a1[0] = a2[0] * tmp[0] + a2[3] * tmp[1] + a2[6] * tmp[2];
    a1[1] = a2[1] * tmp[0] + a2[4] * tmp[1] + a2[7] * tmp[2];
    a1[2] = a2[2] * tmp[0] + a2[5] * tmp[1] + a2[8] * tmp[2];

    a1[3] = a2[0] * tmp[3] + a2[3] * tmp[4] + a2[6] * tmp[5];
    a1[4] = a2[1] * tmp[3] + a2[4] * tmp[4] + a2[7] * tmp[5];
    a1[5] = a2[2] * tmp[3] + a2[5] * tmp[4] + a2[8] * tmp[5];

    a1[6] = a2[0] * tmp[6] + a2[3] * tmp[7] + a2[6] * tmp[8];
    a1[7] = a2[1] * tmp[6] + a2[4] * tmp[7] + a2[7] * tmp[8];
    a1[8] = a2[2] * tmp[6] + a2[5] * tmp[7] + a2[8] * tmp[8];

    a1[9] = a2[0] * tmp[9] + a2[3] * tmp[10] + a2[6] * tmp[11] + a2[9];
    a1[10] = a2[1] * tmp[9] + a2[4] * tmp[10] + a2[7] * tmp[11] + a2[10];
    a1[11] = a2[2] * tmp[9] + a2[5] * tmp[10] + a2[8] * tmp[11] + a2[11];

    return a2;
}
//----- (00493130) --------------------------------------------------------
// a1 = output matrix (12 floats)
// a2 = ?
float *__cdecl sub_493130(float *a1, float *a2)
{
    float tmp[12];
    sub_492810(tmp, a2);
    return sub_492D50(a1, tmp);
}
//----- (00493160) --------------------------------------------------------
// a1 = 12 component matrix
// a2 = 3 component vector
// Translates a matrix?
float *__cdecl sub_493160(float *a1, const float *a2)
{
    a1[9] = a2[0] + a1[9];
    a1[10] = a2[1] + a1[10];
    a1[11] = a2[2] + a1[11];
    return a1;
}
//----- (00493190) --------------------------------------------------------
const float *__cdecl sub_493190(float *a1, const float *a2, const float *a3)
{
    a1[0] = a3[0] * a2[0] + a3[3] * a2[1] + a3[6] * a2[2];
    a1[1] = a3[1] * a2[0] + a3[4] * a2[1] + a3[7] * a2[2];
    a1[2] = a3[2] * a2[0] + a3[5] * a2[1] + a3[8] * a2[2];
    return a3;
}
//----- (00493200) --------------------------------------------------------
const float *__cdecl sub_493200(float *a1, const float *a2, const float *a3)
{
    a1[0] = a3[0] * a2[0] + a3[3] * a2[1] + a3[6] * a2[2] + a3[9];
    a1[1] = a3[1] * a2[0] + a3[4] * a2[1] + a3[7] * a2[2] + a3[10];
    a1[2] = a3[2] * a2[0] + a3[5] * a2[1] + a3[8] * a2[2] + a3[11];
    return a3;
}
//----- (00493270) --------------------------------------------------------
// a1 = some 12 component matrix
// a2 = n x 3 component input vectors
// a3 = n x 3 component output vectors
// a4 = n [number of vectors to transform]
// Return value is kind of complicated. a1 if a4 is set, otherwise a4.
// Probably just returns void though.
void __cdecl sub_493270(const float *a1, const float *a2, float *a3, int a4)
{
    for (int i = 0; i < a4; i++)
    {
        a3[0] = a1[0] * a2[0] + a1[3] * a2[1] + a1[6] * a2[2] + a1[9];
        a3[1] = a1[1] * a2[0] + a1[4] * a2[1] + a1[7] * a2[2] + a1[10];
        a3[2] = a1[2] * a2[0] + a1[5] * a2[1] + a1[8] * a2[2] + a1[11];

        a2 += 3;
        a3 += 3;
    }
}
//----- (00490060) --------------------------------------------------------
// a1 = 12 component matrix
void __cdecl sub_490060(const float *a1)
{
    sub_4925D0(dword_DF7F2C + 8, a1);
    qmemcpy(&unk_ECC440, a1, 0x30u);
    sub_492960((int)&unk_ECC440, COERCE_FLOAT(&unk_DF7F20));
}
//----- (004925D0) --------------------------------------------------------
const float *__cdecl sub_4925D0(float *a1, const float *a2)
{
    a1[0] = a2[0];
    a1[1] = a2[3];
    a1[2] = a2[6];

    a1[3] = a2[1];
    a1[4] = a2[4];
    a1[5] = a2[7];

    a1[6] = a2[2];
    a1[7] = a2[5];
    a1[8] = a2[8];

    a1[9] = -(a2[0] * a2[9] + a2[1] * a2[10] + a2[2] * a2[11]);
    a1[10] = -(a2[3] * a2[9] + a2[4] * a2[10] + a2[5] * a2[11]);
    a1[11] = -(a2[6] * a2[9] + a2[7] * a2[10] + a2[8] * a2[11]);

    return a2;
}
//----- (00492960) --------------------------------------------------------
// a1 = 2x 3 component vectors input
// a2 = 3 component vector output
void __cdecl sub_492960(const float *a1, float *a2)
{
    // FIXME: Create Vector3 type ?

    float v11; // [esp+14h] [ebp-24h]
    float v12; // [esp+18h] [ebp-20h]
    float v13; // [esp+1Ch] [ebp-1Ch]
    v11 = -a1[0];
    v12 = -a1[1];
    v13 = -a1[2];

    float v14; // [esp+20h] [ebp-18h]
    float v15; // [esp+24h] [ebp-14h]
    float v16; // [esp+28h] [ebp-10h]
    v14 = a1[3];
    v15 = a1[4];
    v16 = a1[5];

    // Get length of v14v.xy
    float v2 = v15 * v15 + v14 * v14;
    float v20 = sqrt(v2);

    if (v20 >= 0.001f)
    {
        float v6 = v15 / v20; // normalize(x)
        a2[1] = 90.0f - sub_48D010(v6);

        // FIXME: Why is this conditional here? See check for v16 below!
        if (v14 > 0.0f)
        {
            a2[1] = -a2[1];
        }

        float v8 = v2 / v20; // normalize(x*x + y*y)
        if (v8 < 1.0f)
        {
            a2[0] = 90.0f - sub_48D010(v8);
        }
        else
        {
            a2[0] = 0.0f;
        }

        // v2 is originally changed to `(-v15) * (-v15) + v14 * v14` here [to
        // v23]
        //  v20 is updated equally [to v19]
        v20 = sqrt(v2); // FIXME: Chose to preserve the sqrt, if this is just an
                        // instruction, change it

        // Cross product Z: ax*by - bx*ay
        // v12 = -ay
        // v14 =  bx
        // v15 =  by => -v15 = -by
        // v11 = -ax
        // => ax*by - bx*ay
        float v24 = (v12 * v14 + (-v15) * v11) / v20;
        if (v24 < 1.0f)
        {
            if (v24 > -1.0f)
            {
                a2[2] = 90.0f - sub_48D010(v24);
            }
            else
            {
                a2[2] = 180.0f;
            }
        }
        else
        {
            a2[2] = 0.0f;
        }

        // FIXME: Why is this conditional here? See check for v16 below!
        if (v13 < 0.0f)
        {
            a2[2] = -a2[2];
        }
    }
    else
    {
        a2[0] = 90.0f;
        a2[1] = 0.0f;
        a2[2] = 90.0f - sub_48D010(-v11);

        // v2 is originally changed to `(-v15) * (-v15) + v14 * v14` here [to
        // v23]
        //  v20 is updated equally [to v19]
        v20 = sqrt(v2); // FIXME: Chose to preserve the sqrt, if this is just an
                        // instruction, change it

        // FIXME: And why is this check conditional here?
        if ((v12 > 0.0f && v16 > 0.0f) || (v12 < 0.0f && v16 < 0.0f))
        {
            a2[2] = -a2[2];
        }
    }
    if (v16 < 0.0f)
    {
        a2[0] = -a2[0];
    }
}
//----- (0048D010) --------------------------------------------------------
float __cdecl sub_48D010(float a1)
{
    // Keep track of sign
    bool v8 = a1 < 0.0;

    // Switch to absolute values for calculations
    // FIXME: Should there be some kind of "abs" macro?
    float v7;
    if (a1 >= 0.0)
    {
        v7 = a1;
    }
    else
    {
        v7 = -a1;
    }

    // This looks like a Maclaurin expansion of arcin(x)
    // Compare:
    // https://en.wikipedia.org/wiki/Taylor_series#Trigonometric_functions
    float v10;
    float v9;
    // This probably attempts to minimize errors
    if (v7 <= 0.70710677)
    {
        v10 = v7;
        v10 += sub_48C7F0(v7, 3) / 6.0f; // (1*x^3)/6
        v10 += sub_48C7F0(v7, 5) * 0.075f; // (3*x^5)/40
        v10 +=
            sub_48C7F0(v7, 7) * 0.066797003; // ???? should probably be
                                             // (5*x^7)/112 .. except it's not
        v9 = v10 * 57.295784; // convert from radian to degree
    }
    else
    {
        v10 =
            sub_48CFF0(1.0f - v7 * v7); // This is basically f(x) on the circle
                                        // with radius 1 around point (0,1)
        v10 += sub_48C7F0(v10, 3) / 6.0f; // (1*x^3)/6
        v10 += sub_48C7F0(v10, 5) * 0.075f; // (3*x^5)/40
        v10 += sub_48C7F0(v10, 7) * 0.066797003;
        v9 = 90.0f - v10 * 57.295784; // convert from radian to degree and ...?
    }

    // Restore sign
    float result;
    if (v8)
    {
        result = -v9;
    }
    else
    {
        result = v9;
    }
    return result;
}
//----- (0048CFF0) --------------------------------------------------------
float __cdecl sub_48CFF0(float a1)
{
    return sqrt(a1);
}
