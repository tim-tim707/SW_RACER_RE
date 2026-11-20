#include "rdMatrix.h"

#include "../General/stdMath.h"
#include "globals.h"

#include <macros.h>

// 0x0042fb10
void rdMatrix_SetColumn(rdMatrix44* mat, int n, rdVector3* in)
{
    rdVector4* tmp = &mat->vA + n;
    tmp->x = in->x;
    tmp->y = in->y;
    tmp->z = in->z;
}

// 0x0042fb40
void rdMatrix_GetColumn(rdMatrix44* mat, int n, rdVector3* out)
{
    rdVector4* tmp = &mat->vA + n;
    out->x = tmp->x;
    out->y = tmp->y;
    out->z = tmp->z;
}

// 0x0042fb70
void rdMatrix_Multiply44(rdMatrix44* out, const rdMatrix44* mat1, const rdMatrix44* mat2)
{
    // we need to copy to local variables before multiplying
    // this is because the out, mat1 and mat2 are not restrict pointers
    // this is called with the same parameter as input and output
    // e.g. in FUN_004819b0 calling this, out and mat2 are the same pointer
    rdMatrix44 m1;
    rdMatrix44 m2;
    memcpy(&m1, mat1, sizeof(rdMatrix44));
    memcpy(&m2, mat2, sizeof(rdMatrix44));

    out->vA.x = m2.vD.x * m1.vA.w + m2.vC.x * m1.vA.z + m2.vB.x * m1.vA.y + m2.vA.x * m1.vA.x;
    out->vA.y = m2.vD.y * m1.vA.w + m2.vC.y * m1.vA.z + m2.vB.y * m1.vA.y + m2.vA.y * m1.vA.x;
    out->vA.z = m2.vD.z * m1.vA.w + m2.vC.z * m1.vA.z + m2.vB.z * m1.vA.y + m2.vA.z * m1.vA.x;
    out->vA.w = m2.vD.w * m1.vA.w + m2.vC.w * m1.vA.z + m2.vB.w * m1.vA.y + m2.vA.w * m1.vA.x;
    out->vB.x = m2.vD.x * m1.vB.w + m2.vC.x * m1.vB.z + m2.vB.x * m1.vB.y + m2.vA.x * m1.vB.x;
    out->vB.y = m2.vD.y * m1.vB.w + m2.vC.y * m1.vB.z + m2.vB.y * m1.vB.y + m2.vA.y * m1.vB.x;
    out->vB.z = m2.vD.z * m1.vB.w + m2.vC.z * m1.vB.z + m2.vB.z * m1.vB.y + m2.vA.z * m1.vB.x;
    out->vB.w = m2.vD.w * m1.vB.w + m2.vC.w * m1.vB.z + m2.vB.w * m1.vB.y + m2.vA.w * m1.vB.x;
    out->vC.x = m2.vD.x * m1.vC.w + m2.vC.x * m1.vC.z + m2.vB.x * m1.vC.y + m2.vA.x * m1.vC.x;
    out->vC.y = m2.vD.y * m1.vC.w + m2.vC.y * m1.vC.z + m2.vB.y * m1.vC.y + m2.vA.y * m1.vC.x;
    out->vC.z = m2.vD.z * m1.vC.w + m2.vC.z * m1.vC.z + m2.vB.z * m1.vC.y + m2.vA.z * m1.vC.x;
    out->vC.w = m2.vD.w * m1.vC.w + m2.vC.w * m1.vC.z + m2.vB.w * m1.vC.y + m2.vA.w * m1.vC.x;
    out->vD.x = m2.vD.x * m1.vD.w + m2.vC.x * m1.vD.z + m2.vB.x * m1.vD.y + m2.vA.x * m1.vD.x;
    out->vD.y = m2.vD.y * m1.vD.w + m2.vC.y * m1.vD.z + m2.vB.y * m1.vD.y + m2.vA.y * m1.vD.x;
    out->vD.z = m2.vD.z * m1.vD.w + m2.vC.z * m1.vD.z + m2.vB.z * m1.vD.y + m2.vA.z * m1.vD.x;
    out->vD.w = m2.vD.w * m1.vD.w + m2.vC.w * m1.vD.z + m2.vB.w * m1.vD.y + m2.vA.w * m1.vD.x;
}

// 0x0042ff80
void rdMatrix_Multiply44Acc(rdMatrix44* out, rdMatrix44* mat2)
{
    rdMatrix44 m1;
    rdMatrix44 m2;
    memcpy(&m1, out, sizeof(rdMatrix44));
    // not a restrict pointer, copy before read
    memcpy(&m2, mat2, sizeof(rdMatrix44));

    out->vA.x = m2.vD.x * m1.vA.w + m2.vC.x * m1.vA.z + m2.vB.x * m1.vA.y + m2.vA.x * m1.vA.x;
    out->vA.y = m2.vD.y * m1.vA.w + m2.vC.y * m1.vA.z + m2.vB.y * m1.vA.y + m2.vA.y * m1.vA.x;
    out->vA.z = m2.vD.z * m1.vA.w + m2.vC.z * m1.vA.z + m2.vB.z * m1.vA.y + m2.vA.z * m1.vA.x;
    out->vA.w = m2.vD.w * m1.vA.w + m2.vC.w * m1.vA.z + m2.vB.w * m1.vA.y + m2.vA.w * m1.vA.x;
    out->vB.x = m2.vD.x * m1.vB.w + m2.vC.x * m1.vB.z + m2.vB.x * m1.vB.y + m2.vA.x * m1.vB.x;
    out->vB.y = m2.vD.y * m1.vB.w + m2.vC.y * m1.vB.z + m2.vB.y * m1.vB.y + m2.vA.y * m1.vB.x;
    out->vB.z = m2.vD.z * m1.vB.w + m2.vC.z * m1.vB.z + m2.vB.z * m1.vB.y + m2.vA.z * m1.vB.x;
    out->vB.w = m2.vD.w * m1.vB.w + m2.vC.w * m1.vB.z + m2.vB.w * m1.vB.y + m2.vA.w * m1.vB.x;
    out->vC.x = m2.vD.x * m1.vC.w + m2.vC.x * m1.vC.z + m2.vB.x * m1.vC.y + m2.vA.x * m1.vC.x;
    out->vC.y = m2.vD.y * m1.vC.w + m2.vC.y * m1.vC.z + m2.vB.y * m1.vC.y + m2.vA.y * m1.vC.x;
    out->vC.z = m2.vD.z * m1.vC.w + m2.vC.z * m1.vC.z + m2.vB.z * m1.vC.y + m2.vA.z * m1.vC.x;
    out->vC.w = m2.vD.w * m1.vC.w + m2.vC.w * m1.vC.z + m2.vB.w * m1.vC.y + m2.vA.w * m1.vC.x;
    out->vD.x = m2.vD.x * m1.vD.w + m2.vC.x * m1.vD.z + m2.vB.x * m1.vD.y + m2.vA.x * m1.vD.x;
    out->vD.y = m2.vD.y * m1.vD.w + m2.vC.y * m1.vD.z + m2.vB.y * m1.vD.y + m2.vA.y * m1.vD.x;
    out->vD.z = m2.vD.z * m1.vD.w + m2.vC.z * m1.vD.z + m2.vB.z * m1.vD.y + m2.vA.z * m1.vD.x;
    out->vD.w = m2.vD.w * m1.vD.w + m2.vC.w * m1.vD.z + m2.vB.w * m1.vD.y + m2.vA.w * m1.vD.x;
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
    // DELTA: Added memcpy not present in disassembly to protect against
    // pointer aliasing
    rdVector4 v;
    rdMatrix44 m;
    memcpy(&v, a2, sizeof(rdVector4));
    memcpy(&m, a3, sizeof(rdMatrix44));
    // END DELTA
    a1->x = (m.vA.x * v.x) + (m.vB.x * v.y) + (m.vC.x * v.z) + m.vD.x;
    a1->y = (m.vA.y * v.x) + (m.vB.y * v.y) + (m.vC.y * v.z) + m.vD.y;
    a1->z = (m.vA.z * v.x) + (m.vB.z * v.y) + (m.vC.z * v.z) + m.vD.z;
    a1->w = (m.vA.w * v.x) + (m.vB.w * v.y) + (m.vC.w * v.z) + m.vD.w;
    return;
}

// 0x00480730
void rdMatrix_ToTransRotScale(const rdMatrix44* mat, rdVector3* translation, rdMatrix44* rotation, rdVector3* scale)
{
    float fVar1;
    float fVar2;

    fVar2 = rdVector_Len3((rdVector3*)&mat->vA);
    fVar1 = 1.0 / fVar2;
    scale->x = fVar2;
    (rotation->vA).x = (mat->vA).x * fVar1;
    (rotation->vA).y = (mat->vA).y * fVar1;
    fVar2 = (mat->vA).z;
    (rotation->vA).w = 0.0;
    (rotation->vA).z = fVar2 * fVar1;
    fVar2 = rdVector_Len3((rdVector3*)&mat->vB);
    fVar1 = 1.0 / fVar2;
    scale->y = fVar2;
    (rotation->vB).x = (mat->vB).x * fVar1;
    (rotation->vB).y = (mat->vB).y * fVar1;
    fVar2 = (mat->vB).z;
    (rotation->vB).w = 0.0;
    (rotation->vB).z = fVar2 * fVar1;
    fVar2 = rdVector_Len3((rdVector3*)&mat->vC);
    fVar1 = 1.0 / fVar2;
    scale->z = fVar2;
    (rotation->vC).x = (mat->vC).x * fVar1;
    (rotation->vC).y = (mat->vC).y * fVar1;
    fVar2 = (mat->vC).z;
    (rotation->vC).w = 0.0;
    (rotation->vC).z = fVar2 * fVar1;
    translation->x = (mat->vD).x;
    translation->y = (mat->vD).y;
    translation->z = (mat->vD).z;
    (rotation->vD).x = 0.0;
    (rotation->vD).y = 0.0;
    (rotation->vD).z = 0.0;
    (rotation->vD).w = 1.0;
    return;
}

// 0x00480850
void rdMatrix_FromTransRotScale(rdMatrix44* mat, const rdVector3* translation, const rdMatrix44* rotation, const rdVector3* scale)
{
    rdMatrix_Copy44(mat, rotation);
    rdVector_Add3((rdVector3*)&mat->vD, (const rdVector3*)&mat->vD, translation);
    rdMatrix_ScaleBasis44(mat, scale->x, scale->y, scale->z, mat);
}

// 0x00480890
void ProjectPointOntoPlane(float* plane, rdVector3* point, rdVector3* out)
{
    long double t = plane[3] - (point->z * plane[2] + point->y * plane[1] + point->x * plane[0]);
    // Retail stores each t * normal product into out before adding the point.
    out->x = t * plane[0];
    out->y = t * plane[1];
    out->z = t * plane[2];
    out->x = point->x + out->x;
    out->y = out->y + point->y;
    out->z = out->z + point->z;
}

// 0x004808f0
void ClosestPointOnSegment(rdVector3* point, rdVector3* segStart, rdVector3* segEnd, rdVector3* out)
{
    // Retail spills dx/dy/dz but keeps raw dx and dy on the stack for the first two squares.
    long double dxRaw = segEnd->x - segStart->x;
    long double dyRaw = segEnd->y - segStart->y;
    float dx = dxRaw;
    float dy = dyRaw;
    float dz = segEnd->z - segStart->z;
    long double lenSq = (dxRaw * dx + dyRaw * dy) + dz * dz;
    if (lenSq <= 0x1.0624dd2f1a9fcp-10) { // 0.001
        *out = *segStart;
        return;
    }
    long double along = (point->y * dy + point->z * dz) + dx * point->x;
    long double base = (dx * segStart->x + dz * segStart->z) + dy * segStart->y;
    float t = (along - base) / lenSq;
    if (t <= 0.0f) {
        *out = *segStart;
        return;
    }
    if (1.0f <= t) {
        *out = *segEnd;
        return;
    }
    // Retail writes the products into out first; x then adds the unrounded product.
    long double stepX = dx * t;
    float stepY = dy * t;
    float stepZ = dz * t;
    out->x = stepX;
    out->y = stepY;
    out->z = stepZ;
    out->x = segStart->x + stepX;
    out->y = segStart->y + stepY;
    out->z = segStart->z + stepZ;
}

// Crout LU decomposition with implicit partial pivoting (Numerical Recipes ludcmp) of the upper-left
// 3x3 of a stride-4 matrix; returns 0 on a zero pivot.
// 0x004304c0
int rdMatrix_LUDecompose_Maybe(float* mat, float* in, int* pivots)
{
    float rowScale[3];
    float big;
    float sum;
    float v;
    int i, j, k;
    int imax = 0; // uninitialized in the original; only unset when every candidate is NaN

    for (i = 0; i < 3; i++) {
        big = 0.0f;
        for (j = 0; j < 3; j++) {
            mat[i * 4 + j] = in[i * 4 + j];
            v = in[i * 4 + j];
            if (v < 0.0f)
                v = -v;
            if (big < v) {
                // unreachable singular-row check (v > big >= 0); an all-zero row leaves rowScale[i] unset
                if (v == 0.0f)
                    return 0;
                rowScale[i] = 1.0f / v;
                big = v;
            }
        }
    }

    for (j = 0; j < 3; j++) {
        for (i = 0; i < j; i++) {
            sum = mat[i * 4 + j];
            for (k = 0; k < i; k++)
                sum = sum - mat[k * 4 + j] * mat[i * 4 + k];
            mat[i * 4 + j] = sum;
        }
        big = 0.0f;
        for (i = j; i < 3; i++) {
            sum = mat[i * 4 + j];
            for (k = 0; k < j; k++)
                sum = sum - mat[k * 4 + j] * mat[i * 4 + k];
            mat[i * 4 + j] = sum;
            if (sum < 0.0f)
                sum = -sum;
            if (big <= sum * rowScale[i]) {
                big = sum * rowScale[i];
                imax = i;
            }
        }
        if (j != imax) {
            for (k = 0; k < 3; k++) {
                v = mat[imax * 4 + k];
                mat[imax * 4 + k] = mat[j * 4 + k];
                mat[j * 4 + k] = v;
            }
            rowScale[imax] = rowScale[j];
        }
        pivots[j] = imax;
        if (mat[j * 4 + j] == 0.0f)
            return 0;
        if (j != 2) {
            v = 1.0f / mat[j * 4 + j];
            for (i = j + 1; i < 3; i++)
                mat[i * 4 + j] = mat[i * 4 + j] * v;
        }
    }
    return 1;
}

// Forward + back substitution (Numerical Recipes lubksb) on the 3x3 LU of rdMatrix_LUDecompose_Maybe.
// 0x00430730
void rdMatrix_LUSolve_Maybe(float* lu, int* pivots, float* b)
{
    float sum;
    int i, j;
    int first = -1;

    for (i = 0; i < 3; i++) {
        int ip = pivots[i];
        sum = b[ip];
        b[ip] = b[i];
        if (first < 0) {
            if (sum != 0.0f)
                first = i;
        } else {
            for (j = first; j <= i - 1; j++)
                sum = sum - b[j] * lu[i * 4 + j];
        }
        b[i] = sum;
    }
    for (i = 2; i >= 0; i--) {
        sum = b[i];
        for (j = i + 1; j < 3; j++)
            sum = sum - lu[i * 4 + j] * b[j];
        b[i] = sum / lu[i * 4 + i];
    }
}

// Inverts an affine matrix: the 3x3 part column by column through the LU solve, then the
// translation as -t * inverse. On a singular 3x3 the LU scratch is left in out.
// 0x00430810
void rdMatrix_InvertGeneral_Maybe(rdMatrix44* out, rdMatrix44* in)
{
    float* dst = &out->vA.x;
    float inverse[12];
    float column[3];
    int pivots[3];
    int k, r;

    if (rdMatrix_LUDecompose_Maybe(dst, &in->vA.x, pivots) == 0)
        return;
    for (k = 0; k < 3; k++) {
        column[0] = 0.0f;
        column[1] = 0.0f;
        column[2] = 0.0f;
        column[k] = 1.0f;
        rdMatrix_LUSolve_Maybe(dst, pivots, column);
        for (r = 0; r < 3; r++)
            inverse[r * 4 + k] = column[r];
    }
    out->vA.x = inverse[0];
    out->vA.y = inverse[1];
    out->vA.z = inverse[2];
    out->vB.x = inverse[4];
    out->vD.w = 1.0f;
    out->vB.y = inverse[5];
    out->vB.z = inverse[6];
    out->vC.x = inverse[8];
    out->vA.w = 0.0f;
    out->vB.w = 0.0f;
    out->vC.y = inverse[9];
    out->vC.w = 0.0f;
    out->vC.z = inverse[10];
    out->vD.x = -(in->vD.x * inverse[0] + in->vD.z * inverse[8] + in->vD.y * inverse[4]);
    out->vD.y = -(in->vD.x * inverse[1] + in->vD.z * inverse[9] + in->vD.y * inverse[5]);
    out->vD.z = -(in->vD.x * inverse[2] + in->vD.z * inverse[10] + in->vD.y * inverse[6]);
}

// 0x00430980
void rdMatrix_Multiply3(rdVector3* out, rdVector3* in, const rdMatrix44* mat)
{
    // prevent pointer aliasing
    // DELTA: decomp assigns to local variables rather than a memcpy
    rdVector3 v;
    rdMatrix44 m;
    memcpy(&v, in, sizeof(rdVector3));
    memcpy(&m, mat, sizeof(rdMatrix44));
    // END DELTA
    out->x = (m.vA).x * v.x + (m.vB).x * v.y + (m.vC).x * v.z;
    out->y = (m.vA).y * v.x + (m.vB).y * v.y + (m.vC).y * v.z;
    out->z = (m.vA).z * v.x + (m.vB).z * v.y + (m.vC).z * v.z;
    return;
}

// 0x00430a00
void rdMatrix_Transform3(rdVector3* out, rdVector3* in, const rdMatrix44* mat)
{
    // prevent pointer aliasing
    // DELTA: decomp assigns to local variables rather than a memcpy
    rdVector3 v;
    rdMatrix44 m;
    memcpy(&v, in, sizeof(rdVector3));
    memcpy(&m, mat, sizeof(rdMatrix44));
    // END DELTA
    // Retail sums (B*y + C*z) + A*x before adding the translation.
    out->x = (m.vB).x * v.y + (m.vC).x * v.z + (m.vA).x * v.x + (m.vD).x;
    out->y = (m.vB).y * v.y + (m.vC).y * v.z + (m.vA).y * v.x + (m.vD).y;
    out->z = (m.vB).z * v.y + (m.vC).z * v.z + (m.vA).z * v.x + (m.vD).z;
    return;
}

// 0x00430ab0
void rdMatrix_Multiply4(rdVector4* out, rdVector4* in, rdMatrix44* mat)
{
    // prevent pointer aliasing
    // DELTA: decomp assigns to local variables rather than a memcpy
    rdVector4 v;
    rdMatrix44 m;
    memcpy(&v, in, sizeof(rdVector4));
    memcpy(&m, mat, sizeof(rdMatrix44));
    // END DELTA
    out->x = (m.vA).x * v.x + (m.vB).x * v.y + (m.vC).x * v.z + (m.vD).x * v.w;
    out->y = (m.vA).y * v.x + (m.vB).y * v.y + (m.vC).y * v.z + (m.vD).y * v.w;
    out->z = (m.vA).z * v.x + (m.vB).z * v.y + (m.vC).z * v.z + (m.vD).z * v.w;
    out->w = (m.vA).w * v.x + (m.vB).w * v.y + (m.vC).w * v.z + (m.vD).w * v.w;
    return;
}

// 0x00430b80
void rdMatrix_ExtractTransform(rdMatrix44* mat, swrTranslationRotation* tr_rot)
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

    (tr_rot->translation).x = (mat->vD).x;
    (tr_rot->translation).y = (mat->vD).y;
    (tr_rot->translation).z = (mat->vD).z;
    fVar5 = (mat->vB).x;
    fVar1 = (mat->vB).y;
    fVar2 = (mat->vB).z;
    local_18 = -(mat->vA).x;
    local_14 = -(mat->vA).y;
    local_10 = -(mat->vA).z;
    local_24.z = 0.0;
    local_24.x = fVar5;
    local_24.y = fVar1;
    fVar3 = rdVector_Len3(&local_24);
    if (0x1.0624dd2f1a9fcp-10 <= fVar3) // 0.001
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
        tr_rot->yaw_roll_pitch.x = fVar4;
    }
    else
    {
        fVar4 = stdMath_ArcCos(-local_18);
        if ((0.0 < local_14) == (0.0 < fVar2))
        {
            fVar4 = -fVar4;
        }
        tr_rot->yaw_roll_pitch.z = fVar4;
        tr_rot->yaw_roll_pitch.x = 0.0;
    }
    if (0x1.0624dd2f1a9fcp-10 <= fVar3) // 0.001
    {
        fVar5 = (local_24.z * fVar2 + local_24.y * fVar1 + local_24.x * fVar5) / fVar3;
        if (fVar5 < 1.0)
        {
            fVar5 = stdMath_ArcCos(fVar5);
            tr_rot->yaw_roll_pitch.y = fVar5;
        }
        else
        {
            tr_rot->yaw_roll_pitch.y = 0.0;
        }
    }
    else
    {
        tr_rot->yaw_roll_pitch.y = 90.0;
    }
    if (fVar2 < 0.0)
    {
        tr_rot->yaw_roll_pitch.y = -tr_rot->yaw_roll_pitch.y;
    }
    local_c.x = -local_24.y;
    local_c.y = local_24.x;
    local_c.z = 0.0;
    fVar5 = rdVector_Len3(&local_c);
    if (0x1.0624dd2f1a9fcp-10 <= fVar3) // 0.001
    {
        fVar5 = (local_c.z * local_10 + local_c.y * local_14 + local_c.x * local_18) / fVar5;
        if (fVar5 < 1.0)
        {
            if (-1.0 < fVar5)
            {
                fVar5 = stdMath_ArcCos(fVar5);
                tr_rot->yaw_roll_pitch.z = fVar5;
            }
            else
            {
                tr_rot->yaw_roll_pitch.z = 180.0;
            }
        }
        else
        {
            tr_rot->yaw_roll_pitch.z = 0.0;
        }
        if (local_10 < 0.0)
        {
            tr_rot->yaw_roll_pitch.z = -tr_rot->yaw_roll_pitch.z;
            return;
        }
    }
    return;
}

/*
Z X Y
yaw roll pitch <=> gamma alpha beta

{{cos(gamma),-sin(gamma),0},{sin(gamma),cos(gamma),0},{0,0,1}}
{{1,0,0},{0,cos(alpha),-sin(alpha)},{0,sin(alpha),cos(alpha)}}
{{cos(beta),0,sin(beta)},{0,1,0},{-sin(beta),0,cos(beta)}}
*/

// 0x00430e00
void rdMatrix_BuildRotation44(rdMatrix44* out, float yaw, float roll, float pitch)
{
    float sin_roll;
    float cos_roll;
    float sin_pitch;
    float cos_pitch;
    float sin_yaw;
    float cos_yaw;
    float cp_cy32;
    float sp_cy32;
    float cp_sy32;

    stdMath_SinCos(yaw, &sin_yaw, &cos_yaw);
    stdMath_SinCos(roll, &sin_roll, &cos_roll);
    stdMath_SinCos(pitch, &sin_pitch, &cos_pitch);

    // Retail spills cp*cy, sp*cy and cp*sy to float and adds those copies to the
    // register-width cross terms; every other product stays at register width.
    cp_cy32 = (long double)cos_pitch * cos_yaw;
    sp_cy32 = (long double)sin_pitch * cos_yaw;
    cp_sy32 = (long double)cos_pitch * sin_yaw;
    (out->vA).x = cp_cy32 - ((long double)sin_pitch * sin_yaw) * sin_roll;
    (out->vA).y = ((long double)sin_pitch * cos_yaw) * sin_roll + cp_sy32;
    (out->vA).z = -((long double)sin_pitch * cos_roll);
    (out->vB).x = -((long double)cos_roll * sin_yaw);
    (out->vB).y = (long double)cos_roll * cos_yaw;
    (out->vB).z = sin_roll;
    (out->vC).x = ((long double)cos_pitch * sin_yaw) * sin_roll + sp_cy32;
    (out->vC).y = (long double)sin_pitch * sin_yaw - ((long double)cos_pitch * cos_yaw) * sin_roll;
    (out->vC).z = (long double)cos_pitch * cos_roll;
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
    // Retail spills these three products to the stack and reads the rounded copies back for
    // rvec.x/y and uvec.x; uvec.y uses the unrounded register copy of cos_beta * cos_gamma.
    float cb_cg = cos_beta * cos_gamma;
    float sb_cg = sin_beta * cos_gamma;
    float cb_sg = cos_beta * sin_gamma;
    (out->rvec).x = cb_cg - sin_beta * sin_gamma * gamma;
    (out->rvec).y = sin_beta * cos_gamma * gamma + cb_sg;
    (out->rvec).z = -(sin_beta * cos_alpha);
    (out->lvec).x = -(cos_alpha * sin_gamma);
    (out->lvec).y = cos_alpha * cos_gamma;
    (out->lvec).z = gamma;
    (out->uvec).x = cos_beta * sin_gamma * gamma + sb_cg;
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

// 0x00431060
void rdMatrix_SetTransform44(rdMatrix44* mat, swrTranslationRotation* v)
{
    (mat->vD).x = (v->translation).x;
    (mat->vD).y = (v->translation).y;
    (mat->vD).z = (v->translation).z;
    (mat->vA).w = 0.0;
    (mat->vB).w = 0.0;
    (mat->vC).w = 0.0;
    (mat->vD).w = 1.0;
    rdMatrix_BuildRotation44(mat, v->yaw_roll_pitch.x, v->yaw_roll_pitch.y, v->yaw_roll_pitch.z);
    return;
}

// 0x004310b0
void rdMatrix_SetDiagonal44(rdMatrix44* mat, float x, float y, float z)

{
    (mat->vA).x = x;
    (mat->vB).y = y;
    (mat->vC).z = z;
    (mat->vA).y = 0.0;
    (mat->vA).z = 0.0;
    (mat->vA).w = 0.0;
    (mat->vB).x = 0.0;
    (mat->vB).z = 0.0;
    (mat->vB).w = 0.0;
    (mat->vC).x = 0.0;
    (mat->vC).y = 0.0;
    (mat->vC).w = 0.0;
    (mat->vD).x = 0.0;
    (mat->vD).y = 0.0;
    (mat->vD).z = 0.0;
    (mat->vD).w = 1.0;
    return;
}

// 0x00431100
void rdMatrix_SetTranslation44(rdMatrix44* mat, float x, float y, float z)
{
    (mat->vA).y = 0.0;
    (mat->vA).z = 0.0;
    (mat->vA).w = 0.0;
    (mat->vB).x = 0.0;
    (mat->vB).z = 0.0;
    (mat->vB).w = 0.0;
    (mat->vC).x = 0.0;
    (mat->vC).y = 0.0;
    (mat->vC).w = 0.0;
    (mat->vD).x = x;
    (mat->vD).y = y;
    (mat->vD).z = z;
    (mat->vA).x = 1.0;
    (mat->vB).y = 1.0;
    (mat->vC).z = 1.0;
    (mat->vD).w = 1.0;
    return;
}

// 0x00431150
void rdMatrix_BuildFromVectorAngle44(rdMatrix44* mat, float angle, float x, float y, float z)
{
    float s;
    float c;
    float xx32;
    float yy32;
    float w32;
    float xxc32;
    float yyc32;
    float one_minus_c32;
    float sx32;
    float sy32;
    float sz32;
    float zx_omc32;
    float zy_omc32;
    float yx_omc32;
    long double yy;
    long double xxc;
    long double yyc;
    long double d;
    long double yx_omc;
    long double zx_omc;

    stdMath_SinCos(angle, &s, &c);
    // 0.999f is the float32 at 0x004ac6cc (0.9990000128746033); as a bare double literal
    // 0.999 is a slightly smaller number, and this is a branch threshold.
    if (z < 0x1.ff7ceep-1f) // 0.999f
    {
        if (-0x1.ff7ceep-1f < z)
        {
            // Spill points follow retail's x87 schedule: values named *32 are rounded to
            // float before reuse, everything else stays at register width.
            xx32 = (long double)x * x;
            yy = (long double)y * y;
            yy32 = yy;
            w32 = (1.0f - xx32) - yy32;
            yyc = yy * c;
            yyc32 = yyc;
            xxc = (long double)xx32 * c;
            xxc32 = xxc;
            d = 1.0f - w32;
            (mat->vA).x = (xxc * w32 + yyc32) / d + xx32;
            (mat->vB).y = (yyc * w32 + xxc32) / d + yy32;

            one_minus_c32 = 1.0f - c;
            yx_omc = ((long double)y * x) * one_minus_c32;
            zx_omc = ((long double)z * x) * one_minus_c32;
            zy_omc32 = ((long double)z * y) * one_minus_c32;
            sx32 = (long double)s * x;
            sy32 = (long double)s * y;
            sz32 = (long double)s * z;
            yx_omc32 = yx_omc;
            zx_omc32 = zx_omc;

            (mat->vC).z = (xxc32 + yyc32) + w32;
            (mat->vA).y = sz32 + yx_omc32;
            (mat->vB).x = yx_omc - sz32;
            (mat->vA).z = zx_omc - sy32;
            (mat->vC).x = sy32 + zx_omc32;
            (mat->vB).z = (long double)s * x + zy_omc32;
            (mat->vC).y = zy_omc32 - sx32;
        }
        else
        {
            (mat->vA).x = c;
            (mat->vB).y = c;
            (mat->vA).y = -s;
            (mat->vB).x = s;
            (mat->vA).z = 0.0;
            (mat->vB).z = 0.0;
            (mat->vC).x = 0.0;
            (mat->vC).y = 0.0;
            (mat->vC).z = 1.0;
        }
    }
    else
    {
        (mat->vA).x = c;
        (mat->vB).y = c;
        (mat->vB).x = -s;
        (mat->vA).y = s;
        (mat->vA).z = 0.0;
        (mat->vB).z = 0.0;
        (mat->vC).x = 0.0;
        (mat->vC).y = 0.0;
        (mat->vC).z = 1.0;
    }
    (mat->vD).x = 0.0;
    (mat->vD).y = 0.0;
    (mat->vD).z = 0.0;
    (mat->vA).w = 0.0;
    (mat->vB).w = 0.0;
    (mat->vC).w = 0.0;
    (mat->vD).w = 1.0;
}

// 0x00431390
void rdMatrix_AddRotationFromVectorAngle44Before(rdMatrix44* mat_out, float angle, float x, float y, float z, rdMatrix44* mat_in)
{
    rdMatrix44 tmp;

    rdMatrix_BuildFromVectorAngle44(&tmp, angle, x, y, z);
    rdMatrix_Multiply44(mat_out, &tmp, mat_in);
    return;
}

// 0x004313d0
void rdMatrix_SetIdentity44(rdMatrix44* mat)

{
    (mat->vA).x = 1.0;
    (mat->vA).y = 0.0;
    (mat->vA).z = 0.0;
    (mat->vA).w = 0.0;
    (mat->vB).x = 0.0;
    (mat->vB).y = 1.0;
    (mat->vB).z = 0.0;
    (mat->vB).w = 0.0;
    (mat->vC).x = 0.0;
    (mat->vC).y = 0.0;
    (mat->vC).z = 1.0;
    (mat->vC).w = 0.0;
    (mat->vD).x = 0.0;
    (mat->vD).y = 0.0;
    (mat->vD).z = 0.0;
    (mat->vD).w = 1.0;
    return;
}

// 0x00431410
void rdMatrix_AddRotationFromVectorAngle44After(rdMatrix44* mat_out, rdMatrix44* mat_in, float angle, float x, float y, float z)
{
    rdMatrix44 tmp;

    rdMatrix_BuildFromVectorAngle44(&tmp, angle, x, y, z);
    rdMatrix_Multiply44(mat_out, mat_in, &tmp);
    return;
}

// 0x00431450
void rdMatrix_ScaleBasis44(rdMatrix44* out, float scale_right, float scale_forward, float scale_up, const rdMatrix44* in)
{
    // avoid pointer alias
    // DELTA: decomp does not include memcpy, added to prevent aliasing
    rdMatrix44 m;
    memcpy(&m, in, sizeof(rdMatrix44));
    // END DELTA
    (out->vA).x = scale_right * (m.vA).x;
    (out->vA).y = (m.vA).y * scale_right;
    (out->vA).z = (m.vA).z * scale_right;
    (out->vA).w = (m.vA).w * scale_right;
    (out->vB).x = (m.vB).x * scale_forward;
    (out->vB).y = (m.vB).y * scale_forward;
    (out->vB).z = (m.vB).z * scale_forward;
    (out->vB).w = (m.vB).w * scale_forward;
    (out->vC).x = (m.vC).x * scale_up;
    (out->vC).y = (m.vC).y * scale_up;
    (out->vC).z = (m.vC).z * scale_up;
    (out->vC).w = (m.vC).w * scale_up;
    (out->vD).x = (m.vD).x;
    (out->vD).y = (m.vD).y;
    (out->vD).z = (m.vD).z;
    (out->vD).w = (m.vD).w;
    return;
}

// 0x0044bad0
void rdMatrix_Copy44_34(rdMatrix44* dest, const rdMatrix34* src)
{
    rdMatrix44* cols_dest;
    rdMatrix44* rows_dest;
    int j;
    int i;
    const rdVector3* cols_src;

    i = 4;
    rows_dest = dest;
    do
    {
        j = 3;
        cols_dest = rows_dest;
        do
        {
            cols_src = &src->rvec;
            src = (rdMatrix34*)&(src->rvec).y;
            (cols_dest->vA).x = cols_src->x;
            cols_dest = (rdMatrix44*)&(cols_dest->vA).y;
            j = j + -1;
        } while (j != 0);
        (rows_dest->vA).w = 0.0;
        rows_dest = (rdMatrix44*)&rows_dest->vB;
        i = i + -1;
    } while (i != 0);
    (dest->vD).w = 1.0;
    return;
}

// 0x0044bb10
void rdMatrix_Copy44(rdMatrix44* out, const rdMatrix44* in)
{
    // DELTA: original was a loop
    // the disassembly shows a double loop over the 16 entries of the matrix
    // copy out each value independently. This equivalently can be done as a
    // memcpy, trying to do this requires some tricky pointer manipulation
    // and treating a structure as an array is non-standard
    memcpy(out, in, sizeof(rdMatrix44));
    // END DELTA
}

// 0x00483690
void rdMatrix_BuildViewMatrix(rdMatrix44* viewMatrix_out, rdMatrix44* world)
{
    rdMatrix44* out = viewMatrix_out;
    const rdVector4* t = &world->vD;

    (out->vA).x = (world->vA).x;
    (out->vB).x = (world->vA).y;
    (out->vC).x = (world->vA).z;
    (out->vA).z = -(world->vB).x;
    (out->vB).z = -(world->vB).y;
    (out->vC).z = -(world->vB).z;
    (out->vA).y = (world->vC).x;
    (out->vB).y = (world->vC).y;
    (out->vC).y = (world->vC).z;
    // Per-row accumulation order follows retail: (A + C) + B, (A + C) + B, (B + C) + A.
    (out->vD).x = -(((long double)(out->vA).x * t->x + (long double)(out->vC).x * t->z) + (long double)(out->vB).x * t->y);
    (out->vD).y = -(((long double)t->x * (out->vA).y + (long double)t->z * (out->vC).y) + (long double)t->y * (out->vB).y);
    (out->vD).z = -(((long double)(out->vB).z * t->y + (long double)(out->vC).z * t->z) + (long double)(out->vA).z * t->x);
    (out->vA).w = (world->vA).w;
    (out->vB).w = (world->vB).w;
    (out->vC).w = (world->vC).w;
    (out->vD).w = (world->vD).w;
}

// 0x004924b0
void rdMatrix_BuildRotation34(rdMatrix34* out, rdVector3* angles, rdVector3* translation)
{
    float sin_alpha;
    float cos_alpha;
    float sin_beta;
    float sin_gamma;
    float cos_gamma;
    rdVector3 cos_beta;
    rdVector3* angles_;

    stdMath_SinCosFast(angles->x, &sin_alpha, &cos_alpha);
    stdMath_SinCosFast(angles->y, &sin_gamma, &cos_gamma);
    stdMath_SinCosFast(angles->z, &sin_beta, &cos_beta.x);
    // Retail spills these two products and reads the rounded copies back for rvec.y and uvec.x.
    float sb_cg = sin_beta * cos_gamma;
    float cb_sg = cos_beta.x * sin_gamma;
    (out->rvec).x = -(sin_beta * sin_gamma) * sin_alpha + cos_beta.x * cos_gamma;
    (out->rvec).y = sin_beta * cos_gamma * sin_alpha + cb_sg;
    (out->rvec).z = -sin_beta * cos_alpha;
    (out->lvec).x = -sin_gamma * cos_alpha;
    (out->lvec).y = cos_gamma * cos_alpha;
    (out->lvec).z = sin_alpha;
    (out->uvec).x = cos_beta.x * sin_gamma * sin_alpha + sb_cg;
    (out->uvec).y = -sin_alpha * (cos_beta.x * cos_gamma) + sin_beta * sin_gamma;
    (out->uvec).z = cos_beta.x * cos_alpha;
    (out->scale).x = translation->x;
    (out->scale).y = translation->y;
    (out->scale).z = translation->z;
}

// 0x004925d0 World to Camera matrix
void rdMatrix_InvertOrtho34(rdMatrix34* out, rdMatrix34* in)
{
    float scalex;
    float scaley;
    float scalez;

    (out->rvec).y = (in->lvec).x;
    (out->rvec).z = (in->uvec).x;
    (out->lvec).z = (in->uvec).y;
    (out->lvec).x = (in->rvec).y;
    (out->uvec).x = (in->rvec).z;
    (out->uvec).y = (in->lvec).z;
    (out->rvec).x = (in->rvec).x;
    (out->lvec).y = (in->lvec).y;
    (out->uvec).z = (in->uvec).z;

    scaley = (in->scale).y;
    scalez = (in->scale).z;
    scalex = (in->scale).x;

    (out->scale).x = -((in->rvec).y * scaley + (in->rvec).z * scalez + scalex * (in->rvec).x);
    (out->scale).y = -((in->lvec).x * scalex + (in->lvec).y * scaley + (in->lvec).z * scalez);
    (out->scale).z = -((in->uvec).y * scaley + (in->uvec).z * scalez + (in->uvec).x * scalex);
}

// 0x00492680 World to Camera matrix
void rdMatrix_InvertOrthoNorm34(rdMatrix34* out, rdMatrix34* in)
{
    // Retail spills the rvec and uvec squared lengths to float but keeps lvec's on the FPU stack.
    long double lvec_normsquare;
    float uvec_normsquare;
    float rvec_normsquare;

    lvec_normsquare = (in->lvec).x * (in->lvec).x + (in->lvec).y * (in->lvec).y + (in->lvec).z * (in->lvec).z;
    uvec_normsquare = (in->uvec).x * (in->uvec).x + (in->uvec).y * (in->uvec).y + (in->uvec).z * (in->uvec).z;
    rvec_normsquare = (in->rvec).y * (in->rvec).y + (in->rvec).z * (in->rvec).z + (in->rvec).x * (in->rvec).x;

    (out->rvec).x = (in->rvec).x / rvec_normsquare;
    (out->rvec).y = (in->lvec).x / lvec_normsquare;
    (out->rvec).z = (in->uvec).x / uvec_normsquare;

    (out->lvec).x = (in->rvec).y / rvec_normsquare;
    (out->lvec).y = (in->lvec).y / lvec_normsquare;
    (out->lvec).z = (in->uvec).y / uvec_normsquare;

    (out->uvec).x = (in->rvec).z / rvec_normsquare;
    (out->uvec).y = (in->lvec).z / lvec_normsquare;
    (out->uvec).z = (in->uvec).z / uvec_normsquare;

    (out->scale).x = -((in->scale).z * (out->uvec).x + (in->scale).y * (out->lvec).x + (in->scale).x * (out->rvec).x);
    (out->scale).y = -((in->scale).x * (out->rvec).y + (in->scale).y * (out->lvec).y + (in->scale).z * (out->uvec).y);
    (out->scale).z = -((in->scale).x * (out->rvec).z + (in->scale).y * (out->lvec).z + (in->scale).z * (out->uvec).z);
}

// 0x00492810
void rdMatrix_BuildRotate34(rdMatrix34* out, rdVector3* rot)
{
    float x_rad_sin, x_rad_cos;
    float y_rad_sin, y_rad_cos;
    float z_rad_sin, z_rad_cos;
    rdVector3* scale;
    float zs_yc32;
    float zc_ys32;

    scale = &out->scale;

    // Retail calls stdMath_SinCosFast (0x0048c950), the quarter-wave table with linear
    // interpolation -- not the exact stdMath_SinCos. The table carries about 1e-5 of
    // interpolation error, so using the precise version here made our rotation matrices
    // *more* accurate than the game's and diverged from retail on ~74% of inputs.
    stdMath_SinCosFast(rot->x, &x_rad_sin, &x_rad_cos);
    stdMath_SinCosFast(rot->y, &y_rad_sin, &y_rad_cos);
    stdMath_SinCosFast(rot->z, &z_rad_sin, &z_rad_cos);
    // Retail spills zs*yc and zc*ys to float and adds those copies to the register-width
    // cross terms of rvec.y and uvec.x.
    zs_yc32 = (long double)z_rad_sin * y_rad_cos;
    zc_ys32 = (long double)z_rad_cos * y_rad_sin;
    out->rvec.x = -(z_rad_sin * y_rad_sin) * x_rad_sin + (z_rad_cos * y_rad_cos);
    out->rvec.y = ((long double)z_rad_sin * y_rad_cos) * x_rad_sin + zc_ys32;
    out->rvec.z = -z_rad_sin * x_rad_cos;
    out->lvec.x = -y_rad_sin * x_rad_cos;
    out->lvec.y = (y_rad_cos * x_rad_cos);
    out->lvec.z = x_rad_sin;
    out->uvec.x = ((long double)z_rad_cos * y_rad_sin) * x_rad_sin + zs_yc32;
    out->uvec.y = -x_rad_sin * (y_rad_cos * z_rad_cos) + (y_rad_sin * z_rad_sin);
    out->uvec.z = z_rad_cos * x_rad_cos;
    scale->x = 0.0;
    scale->y = 0.0;
    scale->z = 0.0;
}

// 0x00492930
void rdMatrix_BuildTranslate34(rdMatrix34* out, rdVector3* tV)
{
    // DELTA: original copies in a loop
    memcpy(out, &rdMatrix34_identity, sizeof(rdMatrix34));
    rdVector_Copy3(&out->scale, tV);
    // END DELTA
}

// Retail squares roots with an inline FSQRT and stores the result as float.
static float rdMatrix_x87Sqrt(float x)
{
    long double r = x;
    __asm__("fsqrt" : "+t"(r));
    return r;
}

// 0x00492960
void rdMatrix_ExtractAngles34(rdMatrix34* in, rdVector3* out)
{
    float neg_rx;
    float neg_ry;
    float neg_rz;
    float lx;
    float ly;
    float lz;
    float lx2_32;
    float q32;
    float h32;
    float neg_ly;
    float h2_32;
    float r32;

    // Thresholds are the float32s at 0x004af940..0x004af95c (0.001f, not the double 0.001).
    neg_rx = -(in->rvec).x;
    neg_ry = -(in->rvec).y;
    neg_rz = -(in->rvec).z;
    lx = (in->lvec).x;
    ly = (in->lvec).y;
    lz = (in->lvec).z;
    lx2_32 = (long double)lx * lx;
    q32 = (long double)ly * ly + lx2_32;
    h32 = rdMatrix_x87Sqrt(q32);
    if (h32 < 0x1.0624dep-10f) // 0.001f
    {
        out->z = 90.0f - stdMath_ArcSin3(-neg_rx);
        if (((0.0f < neg_ry) && (0.0f < lz)) || ((neg_ry < 0.0f) && (lz < 0.0f)))
            out->z = -out->z;
        out->y = 0.0f;
    }
    else
    {
        out->y = 90.0f - stdMath_ArcSin3(ly / h32);
        if (0.0f < lx)
            out->y = -out->y;
    }
    if (h32 < 0x1.0624dep-10f)
    {
        out->x = 90.0f;
    }
    else
    {
        r32 = q32 / h32;
        if (r32 < 1.0f)
            out->x = 90.0f - stdMath_ArcSin3(r32);
        else
            out->x = 0.0f;
    }
    if (lz < 0.0f)
        out->x = -out->x;

    neg_ly = -ly;
    h2_32 = rdMatrix_x87Sqrt((long double)neg_ly * neg_ly + lx2_32);
    if (h32 < 0x1.0624dep-10f)
        return;
    r32 = ((long double)neg_ry * lx + (long double)neg_ly * neg_rx) / h2_32;
    if (r32 < 1.0f)
    {
        if (-1.0f < r32)
            out->z = 90.0f - stdMath_ArcSin3(r32);
        else
            out->z = 180.0f;
    }
    else
    {
        out->z = 0.0f;
    }
    if (neg_rz < 0.0f)
        out->z = -out->z;
}

// 0x00492b70
void rdMatrix_Multiply34(rdMatrix34* out, rdMatrix34* mat1, rdMatrix34* mat2)
{
    // avoid pointer aliasing
    // DELTA: original does not include memcpy, added to avoid pointer aliasing
    rdMatrix34 m1;
    rdMatrix34 m2;
    memcpy(&m1, mat1, sizeof(rdMatrix34));
    memcpy(&m2, mat2, sizeof(rdMatrix34));
    // END DELTA
    (out->rvec).x = (m1.uvec).x * (m2.rvec).z + (m1.lvec).x * (m2.rvec).y + (m2.rvec).x * (m1.rvec).x;
    (out->rvec).y = (m2.rvec).y * (m1.lvec).y + (m2.rvec).z * (m1.uvec).y + (m1.rvec).y * (m2.rvec).x;
    (out->rvec).z = (m2.rvec).y * (m1.lvec).z + (m2.rvec).z * (m1.uvec).z + (m1.rvec).z * (m2.rvec).x;
    (out->lvec).x = (m1.lvec).x * (m2.lvec).y + (m1.uvec).x * (m2.lvec).z + (m2.lvec).x * (m1.rvec).x;
    (out->lvec).y = (m1.rvec).y * (m2.lvec).x + (m1.uvec).y * (m2.lvec).z + (m1.lvec).y * (m2.lvec).y;
    (out->lvec).z = (m1.rvec).z * (m2.lvec).x + (m2.lvec).y * (m1.lvec).z + (m1.uvec).z * (m2.lvec).z;
    (out->uvec).x = (m1.uvec).x * (m2.uvec).z + (m1.lvec).x * (m2.uvec).y + (m2.uvec).x * (m1.rvec).x;
    (out->uvec).y = (m1.uvec).y * (m2.uvec).z + (m1.lvec).y * (m2.uvec).y + (m1.rvec).y * (m2.uvec).x;
    (out->uvec).z = (m1.lvec).z * (m2.uvec).y + (m1.rvec).z * (m2.uvec).x + (m1.uvec).z * (m2.uvec).z;
    (out->scale).x = (m1.uvec).x * (m2.scale).z + (m1.lvec).x * (m2.scale).y + (m2.scale).x * (m1.rvec).x + (m1.scale).x;
    (out->scale).y = (m1.lvec).y * (m2.scale).y + (m1.uvec).y * (m2.scale).z + (m1.rvec).y * (m2.scale).x + (m1.scale).y;
    (out->scale).z = (m1.uvec).z * (m2.scale).z + (m1.rvec).z * (m2.scale).x + (m1.lvec).z * (m2.scale).y + (m1.scale).z;
}

// 0x00492d50
void rdMatrix_PreMultiply34(rdMatrix34* mat1, rdMatrix34* mat2)
{
    // avoid pointer aliasing
    // DELTA: original assigns to local variables, replace with a memcpy
    rdMatrix34 tmp;
    rdMatrix34 m2;
    memcpy(&tmp, mat1, sizeof(tmp));
    memcpy(&m2, mat2, sizeof(rdMatrix34));
    // END DELTA
    // Accumulation order follows retail: a + (b + c) for rvec/uvec/scale, (a + b) + c for lvec.
    (mat1->rvec).x = (long double)tmp.rvec.x * m2.rvec.x + ((long double)m2.rvec.y * tmp.lvec.x + (long double)m2.rvec.z * tmp.uvec.x);
    (mat1->rvec).y = (long double)tmp.rvec.y * m2.rvec.x + ((long double)m2.rvec.y * tmp.lvec.y + (long double)m2.rvec.z * tmp.uvec.y);
    (mat1->rvec).z = (long double)tmp.rvec.z * m2.rvec.x + ((long double)m2.rvec.y * tmp.lvec.z + (long double)m2.rvec.z * tmp.uvec.z);
    (mat1->lvec).x = ((long double)m2.lvec.x * tmp.rvec.x + (long double)m2.lvec.y * tmp.lvec.x) + (long double)m2.lvec.z * tmp.uvec.x;
    (mat1->lvec).y = ((long double)m2.lvec.x * tmp.rvec.y + (long double)m2.lvec.y * tmp.lvec.y) + (long double)m2.lvec.z * tmp.uvec.y;
    (mat1->lvec).z = ((long double)m2.lvec.x * tmp.rvec.z + (long double)m2.lvec.y * tmp.lvec.z) + (long double)m2.lvec.z * tmp.uvec.z;
    (mat1->uvec).x = (long double)m2.uvec.x * tmp.rvec.x + ((long double)m2.uvec.y * tmp.lvec.x + (long double)m2.uvec.z * tmp.uvec.x);
    (mat1->uvec).y = (long double)m2.uvec.x * tmp.rvec.y + ((long double)m2.uvec.y * tmp.lvec.y + (long double)m2.uvec.z * tmp.uvec.y);
    (mat1->uvec).z = (long double)m2.uvec.x * tmp.rvec.z + ((long double)m2.uvec.y * tmp.lvec.z + (long double)m2.uvec.z * tmp.uvec.z);
    (mat1->scale).x = ((long double)m2.scale.x * tmp.rvec.x + ((long double)m2.scale.y * tmp.lvec.x + (long double)m2.scale.z * tmp.uvec.x)) + tmp.scale.x;
    (mat1->scale).y = ((long double)m2.scale.x * tmp.rvec.y + ((long double)m2.scale.y * tmp.lvec.y + (long double)m2.scale.z * tmp.uvec.y)) + tmp.scale.y;
    (mat1->scale).z = ((long double)m2.scale.x * tmp.rvec.z + ((long double)m2.scale.y * tmp.lvec.z + (long double)m2.scale.z * tmp.uvec.z)) + tmp.scale.z;
}

// 0x00492f40
void rdMatrix_PostMultiply34(rdMatrix34* mat1, rdMatrix34* mat2)
{
    // avoid pointer aliasing
    // DELTA: original assigns to local variables, replace with a memcpy
    rdMatrix34 tmp;
    rdMatrix34 m2;
    memcpy(&tmp, mat1, sizeof(tmp));
    memcpy(&m2, mat2, sizeof(rdMatrix34));
    // END DELTA
    (mat1->rvec).x = tmp.rvec.x * (m2.rvec).x + (m2.lvec).x * tmp.rvec.y + (m2.uvec).x * tmp.rvec.z;
    (mat1->rvec).y = (m2.lvec).y * tmp.rvec.y + (m2.uvec).y * tmp.rvec.z + (m2.rvec).y * tmp.rvec.x;
    (mat1->rvec).z = (m2.rvec).z * tmp.rvec.x + (m2.uvec).z * tmp.rvec.z + (m2.lvec).z * tmp.rvec.y;
    (mat1->lvec).x = tmp.lvec.x * (m2.rvec).x + (m2.lvec).x * tmp.lvec.y + (m2.uvec).x * tmp.lvec.z;
    (mat1->lvec).y = (m2.lvec).y * tmp.lvec.y + (m2.uvec).y * tmp.lvec.z + (m2.rvec).y * tmp.lvec.x;
    (mat1->lvec).z = (m2.rvec).z * tmp.lvec.x + (m2.uvec).z * tmp.lvec.z + (m2.lvec).z * tmp.lvec.y;
    (mat1->uvec).x = tmp.uvec.x * (m2.rvec).x + (m2.lvec).x * tmp.uvec.y + (m2.uvec).x * tmp.uvec.z;
    (mat1->uvec).y = (m2.lvec).y * tmp.uvec.y + (m2.uvec).y * tmp.uvec.z + (m2.rvec).y * tmp.uvec.x;
    (mat1->uvec).z = (m2.rvec).z * tmp.uvec.x + (m2.uvec).z * tmp.uvec.z + (m2.lvec).z * tmp.uvec.y;
    (mat1->scale).x = tmp.scale.x * (m2.rvec).x + (m2.lvec).x * tmp.scale.y + (m2.uvec).x * tmp.scale.z + (m2.scale).x;
    (mat1->scale).y = (m2.lvec).y * tmp.scale.y + (m2.uvec).y * tmp.scale.z + (m2.rvec).y * tmp.scale.x + (m2.scale).y;
    (mat1->scale).z = (m2.rvec).z * tmp.scale.x + (m2.uvec).z * tmp.scale.z + (m2.lvec).z * tmp.scale.y + (m2.scale).z;
}

// 0x00493130
void rdMatrix_PreRotate34(rdMatrix34* out, rdVector3* rot)
{
    rdMatrix34 tmp;
    rdMatrix_BuildRotate34(&tmp, rot);
    rdMatrix_PreMultiply34(out, &tmp);
}

// 0x00493160
void rdMatrix_PostTranslate34(rdMatrix34* mat, rdVector3* v)
{
    (mat->scale).x = v->x + (mat->scale).x;
    (mat->scale).y = v->y + (mat->scale).y;
    (mat->scale).z = v->z + (mat->scale).z;
}

// 0x00493190
void rdMatrix_TransformVector34(rdVector3* out, rdVector3* v, rdMatrix34* m)
{
    // avoid pointer aliasing
    // DELTA: original does not include memcpy
    rdVector3 v1;
    rdMatrix34 m1;
    memcpy(&v1, v, sizeof(rdVector3));
    memcpy(&m1, m, sizeof(rdMatrix34));
    // END DELTA
    out->x = v1.x * (m1.rvec).x + v1.y * (m1.lvec).x + v1.z * (m1.uvec).x;
    out->y = (m1.rvec).y * v1.x + (m1.uvec).y * v1.z + v1.y * (m1.lvec).y;
    out->z = (m1.rvec).z * v1.x + (m1.uvec).z * v1.z + v1.y * (m1.lvec).z;
}

// 0x00493200
void rdMatrix_TransformPoint34(rdVector3* vOut, rdVector3* vIn, rdMatrix34* camera)
{
    // avoid pointer aliasing
    // DELTA: original does not include memcpy
    rdVector3 v;
    rdMatrix34 m;
    memcpy(&v, vIn, sizeof(rdVector3));
    memcpy(&m, camera, sizeof(rdMatrix34));
    // END DELTA
    vOut->x = v.x * (m.rvec).x + v.z * (m.uvec).x + v.y * (m.lvec).x + (m.scale).x;
    vOut->y = (m.rvec).y * v.x + (m.uvec).y * v.z + v.y * (m.lvec).y + (m.scale).y;
    vOut->z = (m.rvec).z * v.x + (m.uvec).z * v.z + v.y * (m.lvec).z + (m.scale).z;
}

// 0x00493270
void rdMatrix_TransformPointLst34(rdMatrix34* m, rdVector3* in, rdVector3* out, int num)
{
    if (num != 0)
    {
        do
        {
            out->x = in->x * (m->rvec).x + in->z * (m->uvec).x + in->y * (m->lvec).x + (m->scale).x;
            out->y = in->z * (m->uvec).y + in->y * (m->lvec).y + (m->rvec).y * in->x + (m->scale).y;
            out->z = in->z * (m->uvec).z + in->y * (m->lvec).z + (m->rvec).z * in->x + (m->scale).z;
            out = out + 1;
            num = num + -1;
            in = in + 1;
        } while (num != 0);
    }
}
