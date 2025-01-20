#include "rdMatrix_delta.h"

#include <Primitives/rdMatrix.h>
#include <General/stdMath.h>
#include "globals.h"

#include <macros.h>

// 0x0042fb70
void rdMatrix_Multiply44_delta(rdMatrix44 *out, const rdMatrix44 *mat1, const rdMatrix44 *mat2) {
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
void rdMatrix_Multiply44Acc_delta(rdMatrix44 *out, rdMatrix44 *mat2) {
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

// 0x00430980
void rdMatrix_Multiply3_delta(rdVector3 *out, rdVector3 *in, const rdMatrix44 *mat) {
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
void rdMatrix_Transform3_delta(rdVector3 *out, rdVector3 *in, const rdMatrix44 *mat) {
    // prevent pointer aliasing
    // DELTA: decomp assigns to local variables rather than a memcpy
    rdVector3 v;
    rdMatrix44 m;
    memcpy(&v, in, sizeof(rdVector3));
    memcpy(&m, mat, sizeof(rdMatrix44));
    // END DELTA
    out->x = (m.vA).x * v.x + (m.vB).x * v.y + (m.vC).x * v.z + (m.vD).x;
    out->y = (m.vA).y * v.x + (m.vB).y * v.y + (m.vC).y * v.z + (m.vD).y;
    out->z = (m.vA).z * v.x + (m.vB).z * v.y + (m.vC).z * v.z + (m.vD).z;
    return;
}

// 0x00430ab0
void rdMatrix_Multiply4_delta(rdVector4 *out, rdVector4 *in, rdMatrix44 *mat) {
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

// 0x00431450
void rdMatrix_ScaleBasis44_delta(rdMatrix44 *out, float scale_right, float scale_forward,
                                 float scale_up, const rdMatrix44 *in) {
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

// 0x00480690
void rdMatrix_TransformPoint44_delta(rdVector4 *a1, const rdVector4 *a2, const rdMatrix44 *a3) {
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

// 0x00492b70
void rdMatrix_Multiply34_delta(rdMatrix34 *out, rdMatrix34 *mat1, rdMatrix34 *mat2) {
    // avoid pointer aliasing
    // DELTA: original does not include memcpy, added to avoid pointer aliasing
    rdMatrix34 m1;
    rdMatrix34 m2;
    memcpy(&m1, mat1, sizeof(rdMatrix34));
    memcpy(&m2, mat2, sizeof(rdMatrix34));
    // END DELTA
    (out->rvec).x =
        (m1.uvec).x * (m2.rvec).z + (m1.lvec).x * (m2.rvec).y + (m2.rvec).x * (m1.rvec).x;
    (out->rvec).y =
        (m2.rvec).y * (m1.lvec).y + (m2.rvec).z * (m1.uvec).y + (m1.rvec).y * (m2.rvec).x;
    (out->rvec).z =
        (m2.rvec).y * (m1.lvec).z + (m2.rvec).z * (m1.uvec).z + (m1.rvec).z * (m2.rvec).x;
    (out->lvec).x =
        (m1.lvec).x * (m2.lvec).y + (m1.uvec).x * (m2.lvec).z + (m2.lvec).x * (m1.rvec).x;
    (out->lvec).y =
        (m1.rvec).y * (m2.lvec).x + (m1.uvec).y * (m2.lvec).z + (m1.lvec).y * (m2.lvec).y;
    (out->lvec).z =
        (m1.rvec).z * (m2.lvec).x + (m2.lvec).y * (m1.lvec).z + (m1.uvec).z * (m2.lvec).z;
    (out->uvec).x =
        (m1.uvec).x * (m2.uvec).z + (m1.lvec).x * (m2.uvec).y + (m2.uvec).x * (m1.rvec).x;
    (out->uvec).y =
        (m1.uvec).y * (m2.uvec).z + (m1.lvec).y * (m2.uvec).y + (m1.rvec).y * (m2.uvec).x;
    (out->uvec).z =
        (m1.lvec).z * (m2.uvec).y + (m1.rvec).z * (m2.uvec).x + (m1.uvec).z * (m2.uvec).z;
    (out->scale).x = (m1.uvec).x * (m2.scale).z + (m1.lvec).x * (m2.scale).y +
                     (m2.scale).x * (m1.rvec).x + (m1.scale).x;
    (out->scale).y = (m1.lvec).y * (m2.scale).y + (m1.uvec).y * (m2.scale).z +
                     (m1.rvec).y * (m2.scale).x + (m1.scale).y;
    (out->scale).z = (m1.uvec).z * (m2.scale).z + (m1.rvec).z * (m2.scale).x +
                     (m1.lvec).z * (m2.scale).y + (m1.scale).z;
}

// 0x00492d50
void rdMatrix_PreMultiply34_delta(rdMatrix34 *mat1, rdMatrix34 *mat2) {
    // avoid pointer aliasing
    // DELTA: original assigns to local variables, replace with a memcpy
    rdMatrix34 tmp;
    rdMatrix34 m2;
    memcpy(&tmp, mat1, sizeof(tmp));
    memcpy(&m2, mat2, sizeof(rdMatrix34));
    // END DELTA
    (mat1->rvec).x = tmp.rvec.x * (m2.rvec).x + (m2.rvec).z * tmp.uvec.x + (m2.rvec).y * tmp.lvec.x;
    (mat1->rvec).y = tmp.rvec.y * (m2.rvec).x + (m2.rvec).z * tmp.uvec.y + (m2.rvec).y * tmp.lvec.y;
    (mat1->rvec).z = tmp.rvec.z * (m2.rvec).x + (m2.rvec).z * tmp.uvec.z + (m2.rvec).y * tmp.lvec.z;
    (mat1->lvec).x = (m2.lvec).z * tmp.uvec.x + (m2.lvec).x * tmp.rvec.x + (m2.lvec).y * tmp.lvec.x;
    (mat1->lvec).y = (m2.lvec).z * tmp.uvec.y + (m2.lvec).x * tmp.rvec.y + (m2.lvec).y * tmp.lvec.y;
    (mat1->lvec).z = (m2.lvec).z * tmp.uvec.z + (m2.lvec).x * tmp.rvec.z + (m2.lvec).y * tmp.lvec.z;
    (mat1->uvec).x = (m2.uvec).x * tmp.rvec.x + (m2.uvec).y * tmp.lvec.x + (m2.uvec).z * tmp.uvec.x;
    (mat1->uvec).y = (m2.uvec).x * tmp.rvec.y + (m2.uvec).y * tmp.lvec.y + (m2.uvec).z * tmp.uvec.y;
    (mat1->uvec).z = (m2.uvec).x * tmp.rvec.z + (m2.uvec).y * tmp.lvec.z + (m2.uvec).z * tmp.uvec.z;
    (mat1->scale).x = (m2.scale).x * tmp.rvec.x + (m2.scale).y * tmp.lvec.x +
                      (m2.scale).z * tmp.uvec.x + tmp.scale.x;
    (mat1->scale).y = (m2.scale).x * tmp.rvec.y + (m2.scale).y * tmp.lvec.y +
                      (m2.scale).z * tmp.uvec.y + tmp.scale.y;
    (mat1->scale).z = (m2.scale).x * tmp.rvec.z + (m2.scale).y * tmp.lvec.z +
                      (m2.scale).z * tmp.uvec.z + tmp.scale.z;
}

// 0x00492f40
void rdMatrix_PostMultiply34_delta(rdMatrix34 *mat1, rdMatrix34 *mat2) {
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
    (mat1->scale).x = tmp.scale.x * (m2.rvec).x + (m2.lvec).x * tmp.scale.y +
                      (m2.uvec).x * tmp.scale.z + (m2.scale).x;
    (mat1->scale).y = (m2.lvec).y * tmp.scale.y + (m2.uvec).y * tmp.scale.z +
                      (m2.rvec).y * tmp.scale.x + (m2.scale).y;
    (mat1->scale).z = (m2.rvec).z * tmp.scale.x + (m2.uvec).z * tmp.scale.z +
                      (m2.lvec).z * tmp.scale.y + (m2.scale).z;
}

// 0x00493130
void rdMatrix_PreRotate34_delta(rdMatrix34 *out, rdVector3 *rot) {
    rdMatrix34 tmp;
    rdMatrix_BuildRotate34(&tmp, rot);
    rdMatrix_PreMultiply34(out, &tmp);
}

// 0x00493160
void rdMatrix_PostTranslate34_delta(rdMatrix34 *mat, rdVector3 *v) {
    (mat->scale).x = v->x + (mat->scale).x;
    (mat->scale).y = v->y + (mat->scale).y;
    (mat->scale).z = v->z + (mat->scale).z;
}

// 0x00493190
void rdMatrix_TransformVector34_delta(rdVector3 *out, rdVector3 *v, rdMatrix34 *m) {
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
void rdMatrix_TransformPoint34_delta(rdVector3 *vOut, rdVector3 *vIn, rdMatrix34 *camera) {
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
