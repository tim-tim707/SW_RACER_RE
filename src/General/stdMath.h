#ifndef STD_MATH_H
#define STD_MATH_H

#include <math.h>
#include <stdbool.h>

#ifndef PI
#define PI (3.141592653589793)
#endif // PI

#define stdMath_SinCos_ADDR (0x0042f380)
#define stdMath_Tan_ADDR (0x0042f3b0)
#define stdMath_ArcSin_ADDR (0x0042f3e0)
#define stdMath_ArcCos_ADDR (0x0042f540)
#define stdMath_ArcTan2_ADDR (0x0042f560)
// address gap
#define stdMath_Decelerator_ADDR (0x00480650)
#define stdMath_Sqrt_ADDR (0x00480670)

#define stdMath_FlexPower_ADDR (0x0048c7f0)

#define stdMath_NormalizeAngle_ADDR (0x0048c830)
#define stdMath_fround_ADDR (0x0048c8f0)

#define stdMath_FRoundInt_ADDR (0x0048cd30)
#define stdMath_FastTan_ADDR (0x0048cd50)

#define stdMath_Sqrt_2_ADDR (0x0048cff0)

#define stdMath_ArcSin3_ADDR (0x0048d010)

void stdMath_SinCos(float angle, float* pSinOut, float* pCosOut);
float stdMath_Tan(float angle);
float stdMath_ArcSin(float angle);
float stdMath_ArcCos(float angle);
float stdMath_ArcTan2(float x1, float x2);

float stdMath_Decelerator(float param_1, float param_2);
float stdMath_Sqrt(float a);

float stdMath_FlexPower(float x, int exp);

float stdMath_NormalizeAngle(float angle);
float stdMath_fround(float f);

int stdMath_FRoundInt(float f);
float stdMath_FastTan(float f);

float stdMath_Sqrt_2(float f);

float stdMath_ArcSin3(float x_);

#endif // STD_MATH_H
