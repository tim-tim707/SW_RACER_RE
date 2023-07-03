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

// 0x00430310
void rdMatrix_Unk1(rdMatrix44* m1, rdMatrix44* m2)
{
    float fVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    float fVar5;
    float fVar6;
    float fVar7;

    fVar3 = (m2->vB).y;
    fVar4 = (m2->vB).x;
    fVar1 = (m2->vB).z;
    fVar2 = (m2->vC).x;
    fVar7 = fVar1 * fVar1 + fVar3 * fVar3 + fVar4 * fVar4;
    fVar1 = (m2->vC).y;
    fVar4 = (m2->vA).y;
    fVar3 = (m2->vC).z;
    fVar5 = (m2->vA).z;
    fVar6 = (m2->vA).x;
    fVar2 = fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2;
    (m1->vA).y = (m2->vB).x / fVar7;
    (m1->vA).z = (m2->vC).x / fVar2;
    (m1->vB).z = (m2->vC).y / fVar2;
    fVar1 = fVar6 * fVar6 + fVar5 * fVar5 + fVar4 * fVar4;
    (m1->vB).x = (m2->vA).y / fVar1;
    (m1->vC).x = (m2->vA).z / fVar1;
    (m1->vC).y = (m2->vB).z / fVar7;
    (m1->vA).x = (m2->vA).x / fVar1;
    (m1->vB).y = (m2->vB).y / fVar7;
    fVar1 = (m2->vC).z;
    (m1->vA).w = 0.0;
    (m1->vB).w = 0.0;
    (m1->vC).w = 0.0;
    (m1->vD).w = 1.0;
    (m1->vC).z = fVar1 / fVar2;

    fVar6 = (m2->vD).x;
    fVar1 = (m2->vD).z;
    fVar7 = (m2->vD).y;
    fVar2 = (m1->vC).y;
    fVar3 = (m1->vA).z;
    fVar4 = (m1->vB).z;
    fVar5 = (m1->vC).z;
    (m1->vD).x = -((m1->vA).x * fVar6 + fVar7 * (m1->vB).x + fVar1 * (m1->vC).x);
    (m1->vD).y = -(fVar7 * (m1->vB).y + fVar6 * (m1->vA).y + fVar1 * fVar2);
    (m1->vD).z = -(fVar1 * fVar5 + fVar7 * fVar4 + fVar6 * fVar3);
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

// 0x00480730
void rdMatrix_Unk0(rdMatrix44* mat, rdVector3* out_vec1, rdMatrix44* out_mat, rdVector3* out_vec2)

{
    float fVar1;
    float fVar2;

    fVar2 = rdVector_Len3((rdVector3*)&mat->vA);
    fVar1 = 1.0 / fVar2;
    out_vec2->x = fVar2;
    (out_mat->vA).x = (mat->vA).x * fVar1;
    (out_mat->vA).y = (mat->vA).y * fVar1;
    fVar2 = (mat->vA).z;
    (out_mat->vA).w = 0.0;
    (out_mat->vA).z = fVar2 * fVar1;
    fVar2 = rdVector_Len3((rdVector3*)&mat->vB);
    fVar1 = 1.0 / fVar2;
    out_vec2->y = fVar2;
    (out_mat->vB).x = (mat->vB).x * fVar1;
    (out_mat->vB).y = (mat->vB).y * fVar1;
    fVar2 = (mat->vB).z;
    (out_mat->vB).w = 0.0;
    (out_mat->vB).z = fVar2 * fVar1;
    fVar2 = rdVector_Len3((rdVector3*)&mat->vC);
    fVar1 = 1.0 / fVar2;
    out_vec2->z = fVar2;
    (out_mat->vC).x = (mat->vC).x * fVar1;
    (out_mat->vC).y = (mat->vC).y * fVar1;
    fVar2 = (mat->vC).z;
    (out_mat->vC).w = 0.0;
    (out_mat->vC).z = fVar2 * fVar1;
    out_vec1->x = (mat->vD).x;
    out_vec1->y = (mat->vD).y;
    out_vec1->z = (mat->vD).z;
    (out_mat->vD).x = 0.0;
    (out_mat->vD).y = 0.0;
    (out_mat->vD).z = 0.0;
    (out_mat->vD).w = 1.0;
    return;
}

// 0x00430980
void rdMatrix_Multiply3(rdVector3* out, rdVector3* in, rdMatrix44* mat)
{
    out->x = (mat->vA).x * in->x + (mat->vB).x * in->y + (mat->vC).x * in->z;
    out->y = (mat->vA).y * in->x + (mat->vB).y * in->y + (mat->vC).y * in->z;
    out->z = (mat->vA).z * in->x + (mat->vB).z * in->y + (mat->vC).z * in->z;
    return;
}

// 0x00430a00
void rdMatrix_Transform3(rdVector3* out, rdVector3* in, rdMatrix44* mat)

{
    out->x = (mat->vA).x * in->x + (mat->vB).x * in->y + (mat->vC).x * in->z + (mat->vD).x;
    out->y = (mat->vA).y * in->x + (mat->vB).y * in->y + (mat->vC).y * in->z + (mat->vD).y;
    out->z = (mat->vA).z * in->x + (mat->vB).z * in->y + (mat->vC).z * in->z + (mat->vD).z;
    return;
}

// 0x00430ab0
void rdMatrix_Multiply4(rdVector4* out, rdVector4* in, rdMatrix44* mat)
{
    out->x = (mat->vA).x * in->x + (mat->vB).x * in->y + (mat->vC).x * in->z + (mat->vD).x * in->w;
    out->y = (mat->vA).y * in->x + (mat->vB).y * in->y + (mat->vC).y * in->z + (mat->vD).y * in->w;
    out->z = (mat->vA).z * in->x + (mat->vB).z * in->y + (mat->vC).z * in->z + (mat->vD).z * in->w;
    out->w = (mat->vA).w * in->x + (mat->vB).w * in->y + (mat->vC).w * in->z + (mat->vD).w * in->w;
    return;
}

// 0x00430b80
// Feel like this could build the translation,rotation parameter of the pod ?
void rdMatrix_Unk2(rdMatrix44* param_1, float* param_2)

{
    float fVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    float fVar5;
    rdVector3 local_24;
    float local_18;
    float local_14;
    float local_10;
    rdVector3 local_c;

    *param_2 = (param_1->vD).x;
    param_2[1] = (param_1->vD).y;
    param_2[2] = (param_1->vD).z;
    fVar5 = (param_1->vB).x;
    fVar1 = (param_1->vB).y;
    fVar2 = (param_1->vB).z;
    local_18 = -(param_1->vA).x;
    local_14 = -(param_1->vA).y;
    local_10 = -(param_1->vA).z;
    local_24.z = 0.0;
    local_24.x = fVar5;
    local_24.y = fVar1;
    fVar3 = rdVector_Len3(&local_24);
    if (0.001 <= fVar3)
    {
        if (local_24.y / fVar3 <= 1.0)
        {
            fVar4 = stdMath_ArcCos(local_24.y / fVar3);
            if (0.0 < fVar5)
            {
                fVar4 = -fVar4;
            }
        }
        else
        {
            fVar4 = 0.0;
        }
        param_2[3] = fVar4;
    }
    else
    {
        fVar4 = stdMath_ArcCos(-local_18);
        if (0.0 < local_14 == 0.0 < fVar2)
        {
            fVar4 = -fVar4;
        }
        param_2[5] = fVar4;
        param_2[3] = 0.0;
    }
    if (0.001 <= fVar3)
    {
        fVar5 = (local_24.z * fVar2 + local_24.y * fVar1 + local_24.x * fVar5) / fVar3;
        if (fVar5 < 1.0)
        {
            fVar5 = stdMath_ArcCos(fVar5);
            param_2[4] = fVar5;
        }
        else
        {
            param_2[4] = 0.0;
        }
    }
    else
    {
        param_2[4] = 90.0;
    }
    if (fVar2 < 0.0)
    {
        param_2[4] = -param_2[4];
    }
    local_c.x = -local_24.y;
    local_c.y = local_24.x;
    local_c.z = 0.0;
    fVar5 = rdVector_Len3(&local_c);
    if (0.001 <= fVar3)
    {
        fVar5 = (local_c.z * local_10 + local_c.y * local_14 + local_c.x * local_18) / fVar5;
        if (fVar5 < 1.0)
        {
            if (-1.0 < fVar5)
            {
                fVar5 = stdMath_ArcCos(fVar5);
                param_2[5] = fVar5;
            }
            else
            {
                param_2[5] = 180.0;
            }
        }
        else
        {
            param_2[5] = 0.0;
        }
        if (local_10 < 0.0)
        {
            param_2[5] = -param_2[5];
            return;
        }
    }
    return;
}

/*
gamma alpha beta

{{cos(gamma),-sin(gamma),0},{sin(gamma),cos(gamma),0},{0,0,1}}
{{1,0,0},{0,cos(alpha),-sin(alpha)},{0,sin(alpha),cos(alpha)}}
{{cos(beta),0,sin(beta)},{0,1,0},{-sin(beta),0,cos(beta)}}
*/

// 0x00430e00
void rdMatrix_BuildRotation44(rdMatrix44* out, float gamma, float alpha, float beta)

{
    float sin_alpha;
    float cos_alpha;
    float sin_beta;
    float cos_beta;
    float sin_gamma;
    float cos_gamma;

    stdMath_SinCos(gamma, &sin_gamma, &cos_gamma);
    stdMath_SinCos(alpha, &sin_alpha, &cos_alpha);
    stdMath_SinCos(beta, &sin_beta, &cos_beta);
    (out->vA).x = cos_beta * cos_gamma - sin_beta * sin_gamma * sin_alpha;
    (out->vA).y = sin_beta * cos_gamma * sin_alpha + cos_beta * sin_gamma;
    (out->vA).z = -(sin_beta * cos_alpha);
    (out->vB).x = -(cos_alpha * sin_gamma);
    (out->vB).y = cos_alpha * cos_gamma;
    (out->vB).z = sin_alpha;
    (out->vC).x = cos_beta * sin_gamma * sin_alpha + sin_beta * cos_gamma;
    (out->vC).y = sin_beta * sin_gamma - cos_beta * cos_gamma * sin_alpha;
    (out->vC).z = cos_beta * cos_alpha;
    return;
}

// 0x00430f10
void rdMatrix_BuildRotation33(rdMatrix33* out, float gamma, float alpha, float beta)

{
    float cos_alpha;
    float sin_beta;
    float cos_beta;
    float sin_gamma;
    float cos_gamma;

    stdMath_SinCos(gamma, &sin_gamma, &cos_gamma);
    stdMath_SinCos(alpha, &gamma, &cos_alpha);
    stdMath_SinCos(beta, &sin_beta, &cos_beta);
    (out->rvec).x = cos_beta * cos_gamma - sin_beta * sin_gamma * gamma;
    (out->rvec).y = sin_beta * cos_gamma * gamma + cos_beta * sin_gamma;
    (out->rvec).z = -(sin_beta * cos_alpha);
    (out->lvec).x = -(cos_alpha * sin_gamma);
    (out->lvec).y = cos_alpha * cos_gamma;
    (out->lvec).z = gamma;
    (out->uvec).x = cos_beta * sin_gamma * gamma + sin_beta * cos_gamma;
    (out->uvec).y = sin_beta * sin_gamma - cos_beta * cos_gamma * gamma;
    (out->uvec).z = cos_beta * cos_alpha;
    return;
}

// 0x00431020
void rdMatrix_SetRotation44(rdMatrix44* out, float gamma, float alpha, float beta)

{
    (out->vD).x = 0.0;
    (out->vD).y = 0.0;
    (out->vD).z = 0.0;
    (out->vA).w = 0.0;
    (out->vB).w = 0.0;
    (out->vC).w = 0.0;
    (out->vD).w = 1.0;
    rdMatrix_BuildRotation44(out, gamma, alpha, beta);
    return;
}
