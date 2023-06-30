#ifndef RD_VECTOR_H
#define RD_VECTOR_H

#include "types.h"

#define rdVector_Add2_ADDR (0x0042f6e0)
#define rdVector_Scale2_ADDR (0x0042f700)
#define rdVector_Scale2Add2_ADDR (0x0042f720)
#define rdVector_Len2_ADDR (0x0042f750)
#define rdVector_Normalize2Acc_ADDR (0x0042f780)
#define rdVector_Set3_ADDR (0x0042f7b0)
#define rdVector_Copy3_ADDR (0x0042f7d0)
#define rdVector_AreSame3_ADDR (0x0042f7f0)
#define rdVector_Add3_ADDR (0x0042f830)
#define rdVector_Sub3_ADDR (0x0042f860)
#define rdVector_Dot3_ADDR (0x0042f890)
#define rdVector_Len3_ADDR (0x0042f8c0)
#define rdVector_DistSquared3_ADDR (0x0042f910)
#define rdVector_Dist3_ADDR (0x0042f950)
#define rdVector_Normalize3Acc_ADDR (0x0042f9b0)
#define rdVector_Cross3_ADDR (0x0042f9f0)
#define rdVector_Scale3_ADDR (0x0042fa50)
#define rdVector_Scale3Add3_ADDR (0x0042fa80)
#define rdVector_Scale3Add3_both_ADDR (0x0042fac0)

rdVector2 *rdVector_Add2(rdVector2 *v1, const rdVector2 *v2, const rdVector2 *v3);
rdVector2 *rdVector_Scale2(rdVector2 *v1, float scale, const rdVector2 *v2);
void rdVector_Scale2Add2(rdVector2 *v1, rdVector2 *v2, float scale, rdVector2 *v3);
float rdVector_Len2(const rdVector2 *v);
float rdVector_Normalize2Acc(rdVector2 *v1);
rdVector3 *rdVector_Set3(rdVector3 *v, float x, float y, float z);
void rdVector_Copy3(rdVector3 *v1, const rdVector3 *v2);
bool rdVector_AreSame3(rdVector3 *v1, rdVector3 *v2);
rdVector3 *rdVector_Add3(rdVector3 *v1, const rdVector3 *v2, rdVector3 *v3);
rdVector3 *rdVector_Sub3(rdVector3 *v1, const rdVector3 *v2, const rdVector3 *v3);
float rdVector_Dot3(const rdVector3 *v1, const rdVector3 *v2);
float rdVector_Len3(const rdVector3 *v);
float rdVector_DistSquared3(const rdVector3 *v1, const rdVector3 *v2);
float rdVector_Dist3(const rdVector3 *v1, const rdVector3 *v2);
float rdVector_Normalize3Acc(rdVector3 *v1);
void rdVector_Cross3(rdVector3 *v1, const rdVector3 *v2, const rdVector3 *v3);
rdVector3 *rdVector_Scale3(rdVector3 *v1, float scale, const rdVector3 *v2);
void rdVector_Scale3Add3(rdVector3 *v1, rdVector3 *v2, float scale, rdVector *v3);
void rdVector_Scale3Add3_both(rdVector3 *v1, float scale1, rdVector3 *v2, float scale2, rdVector3 *v3);

#endif // RD_VECTOR_H
