#include "rdMatrix.h"

// 0x0042fb70
void rdMatrix_Multiply44(rdMatrix44* out, rdMatrix44* mat1, rdMatrix44* mat2)
{
    out->vA.x = mat2->vA.y * mat1->vB.x + mat1->vD.x * mat2->vA.w + mat1->vC.x * mat2->vA.z + mat2->vA.x * mat1->vA.x;
    out->vA.y = mat1->vA.y * mat2->vA.x + mat1->vC.y * mat2->vA.z + mat1->vD.y * mat2->vA.w + mat1->vB.y * mat2->vA.y;
    out->vA.z = mat1->vA.z * mat2->vA.x + mat1->vC.z * mat2->vA.z + mat1->vD.z * mat2->vA.w + mat1->vB.z * mat2->vA.y;
    out->vA.w = mat1->vA.w * mat2->vA.x + mat1->vC.w * mat2->vA.z + mat1->vD.w * mat2->vA.w + mat1->vB.w * mat2->vA.y;
    out->vB.x = mat2->vB.x * mat1->vA.x + mat2->vB.w * mat1->vD.x + mat2->vB.y * mat1->vB.x + mat2->vB.z * mat1->vC.x;
    out->vB.y = mat2->vB.x * mat1->vA.y + mat2->vB.z * mat1->vC.y + mat2->vB.w * mat1->vD.y + mat2->vB.y * mat1->vB.y;
    out->vB.z = mat2->vB.x * mat1->vA.z + mat2->vB.z * mat1->vC.z + mat2->vB.w * mat1->vD.z + mat2->vB.y * mat1->vB.z;
    out->vB.w = mat2->vB.x * mat1->vA.w + mat2->vB.w * mat1->vD.w + mat2->vB.z * mat1->vC.w + mat2->vB.y * mat1->vB.w;
    out->vC.x = mat2->vC.x * mat1->vA.x + mat2->vC.z * mat1->vC.x + mat2->vC.y * mat1->vB.x + mat2->vC.w * mat1->vD.x;
    out->vC.y = mat2->vC.x * mat1->vA.y + mat2->vC.y * mat1->vB.y + mat2->vC.w * mat1->vD.y + mat2->vC.z * mat1->vC.y;
    out->vC.z = mat2->vC.x * mat1->vA.z + mat2->vC.y * mat1->vB.z + mat2->vC.z * mat1->vC.z + mat2->vC.w * mat1->vD.z;
    out->vC.w = mat2->vC.x * mat1->vA.w + mat2->vC.y * mat1->vB.w + mat2->vC.w * mat1->vD.w + mat2->vC.z * mat1->vC.w;
    out->vD.x = mat2->vD.x * mat1->vA.x + mat2->vD.z * mat1->vC.x + mat2->vD.y * mat1->vB.x + mat2->vD.w * mat1->vD.x;
    out->vD.y = mat2->vD.w * mat1->vD.y + mat2->vD.y * mat1->vB.y + mat2->vD.x * mat1->vA.y + mat2->vD.z * mat1->vC.y;
    out->vD.z = mat2->vD.z * mat1->vC.z + mat2->vD.y * mat1->vB.z + mat2->vD.w * mat1->vD.z + mat2->vD.x * mat1->vA.z;
    out->vD.w = mat2->vD.w * mat1->vD.w + mat2->vD.y * mat1->vB.w + mat2->vD.x * mat1->vA.w + mat2->vD.z * mat1->vC.w;
}

// 0x0042ff80
void rdMatrix_Multiply44Acc(rdMatrix44* out, rdMatrix44* mat2)
{
    rdMatrix44 mat1;
    memcpy(&mat1, out, sizeof(rdMatrix44));

    out->vA.x = mat2->vA.y * mat1.vB.x + mat1.vD.x * mat2->vA.w + mat1.vC.x * mat2->vA.z + mat2->vA.x * mat1.vA.x;
    out->vA.y = mat1.vA.y * mat2->vA.x + mat1.vC.y * mat2->vA.z + mat1.vD.y * mat2->vA.w + mat1.vB.y * mat2->vA.y;
    out->vA.z = mat1.vA.z * mat2->vA.x + mat1.vC.z * mat2->vA.z + mat1.vD.z * mat2->vA.w + mat1.vB.z * mat2->vA.y;
    out->vA.w = mat1.vA.w * mat2->vA.x + mat1.vC.w * mat2->vA.z + mat1.vD.w * mat2->vA.w + mat1.vB.w * mat2->vA.y;
    out->vB.x = mat2->vB.x * mat1.vA.x + mat2->vB.w * mat1.vD.x + mat2->vB.y * mat1.vB.x + mat2->vB.z * mat1.vC.x;
    out->vB.y = mat2->vB.x * mat1.vA.y + mat2->vB.z * mat1.vC.y + mat2->vB.w * mat1.vD.y + mat2->vB.y * mat1.vB.y;
    out->vB.z = mat2->vB.x * mat1.vA.z + mat2->vB.z * mat1.vC.z + mat2->vB.w * mat1.vD.z + mat2->vB.y * mat1.vB.z;
    out->vB.w = mat2->vB.x * mat1.vA.w + mat2->vB.w * mat1.vD.w + mat2->vB.z * mat1.vC.w + mat2->vB.y * mat1.vB.w;
    out->vC.x = mat2->vC.x * mat1.vA.x + mat2->vC.z * mat1.vC.x + mat2->vC.y * mat1.vB.x + mat2->vC.w * mat1.vD.x;
    out->vC.y = mat2->vC.x * mat1.vA.y + mat2->vC.y * mat1.vB.y + mat2->vC.w * mat1.vD.y + mat2->vC.z * mat1.vC.y;
    out->vC.z = mat2->vC.x * mat1.vA.z + mat2->vC.y * mat1.vB.z + mat2->vC.z * mat1.vC.z + mat2->vC.w * mat1.vD.z;
    out->vC.w = mat2->vC.x * mat1.vA.w + mat2->vC.y * mat1.vB.w + mat2->vC.w * mat1.vD.w + mat2->vC.z * mat1.vC.w;
    out->vD.x = mat2->vD.x * mat1.vA.x + mat2->vD.z * mat1.vC.x + mat2->vD.y * mat1.vB.x + mat2->vD.w * mat1.vD.x;
    out->vD.y = mat2->vD.w * mat1.vD.y + mat2->vD.y * mat1.vB.y + mat2->vD.x * mat1.vA.y + mat2->vD.z * mat1.vC.y;
    out->vD.z = mat2->vD.z * mat1.vC.z + mat2->vD.y * mat1.vB.z + mat2->vD.w * mat1.vD.z + mat2->vD.x * mat1.vA.z;
    out->vD.w = mat2->vD.w * mat1.vD.w + mat2->vD.y * mat1.vB.w + mat2->vD.x * mat1.vA.w + mat2->vD.z * mat1.vC.w;
}

// TODO
// 0x00430310
void FUN_00430310(float* param_1, float* param_2)

{
    float dot = param_2[0] * param_2[0] + param_2[1] * param_2[1] + param_2[2] * param_2[2];
    param_1[0] = param_2[0] / dot;
    param_1[4] = param_2[1] / dot;
    param_1[8] = param_2[2] / dot;

    dot = param_2[4] * param_2[4] + param_2[5] * param_2[5] + param_2[6] * param_2[6];
    param_1[1] = param_2[4] / dot;
    param_1[5] = param_2[5] / dot;
    param_1[9] = param_2[6] / dot;

    dot = param_2[8] * param_2[8] + param_2[9] * param_2[9] + param_2[10] * param_2[10];
    param_1[2] = param_2[8] / dot;
    param_1[6] = param_2[9] / dot;
    param_1[10] = param_2[10] / dot;

    param_1[3] = 0.0;
    param_1[7] = 0.0;
    param_1[0xb] = 0.0;
    param_1[0xf] = 1.0;

    param_1[0xc] = -(param_1[0] * param_2[0xc] + param_2[0xd] * param_1[4] + param_2[0xe] * param_1[8]);
    param_1[0xd] = -(param_2[0xd] * param_1[5] + param_2[0xc] * param_1[1] + param_2[0xe] * param_1[9]);
    param_1[0xe] = -(param_2[0xe] * param_1[10] + param_2[0xd] * param_1[6] + param_2[0xc] * param_1[2]);
    return;
}

// 0x00480690
void rdMatrix_TransformPoint44(rdVector4* a1, const rdVector4* a2, const rdMatrix44* a3)

{
    a1->x = (a3->vA.x * a2->x) + (a3->vB.x * a2->y) + (a3->vC.x * a2->z) + a3->vD.x;
    a1->y = (a3->vA.y * a2->x) + (a3->vB.y * a2->y) + (a3->vC.y * a2->z) + a3->vD.y;
    a1->z = (a3->vA.z * a2->x) + (a3->vB.z * a2->y) + (a3->vC.z * a2->z) + a3->vD.z;
    a1->w = (a3->vA.w * a2->x) + (a3->vB.w * a2->y) + (a3->vC.w * a2->z) + a3->vD.w;
    return;
}
