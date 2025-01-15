#pragma once

#include <Primitives/rdVector.h>
#include "types.h"

void rdMatrix_Multiply44_delta(rdMatrix44 *out, const rdMatrix44 *mat1, const rdMatrix44 *mat2);
void rdMatrix_Multiply44Acc_delta(rdMatrix44 *out, rdMatrix44 *mat2);
void rdMatrix_Multiply3_delta(rdVector3 *out, rdVector3 *in, const rdMatrix44 *mat);
void rdMatrix_Transform3_delta(rdVector3 *out, rdVector3 *in, const rdMatrix44 *mat);
void rdMatrix_Multiply4_delta(rdVector4 *out, rdVector4 *in, rdMatrix44 *mat);
void rdMatrix_ScaleBasis44_delta(rdMatrix44 *out, float scale_right, float scale_forward,
                                 float scale_up, const rdMatrix44 *in);

void rdMatrix_TransformPoint44_delta(rdVector4 *a1, const rdVector4 *a2, const rdMatrix44 *a3);

void rdMatrix_Multiply34_delta(rdMatrix34 *out, rdMatrix34 *mat1, rdMatrix34 *mat2);
void rdMatrix_PreMultiply34_delta(rdMatrix34 *mat1, rdMatrix34 *mat2);
void rdMatrix_PostMultiply34_delta(rdMatrix34 *mat1, rdMatrix34 *mat2);
void rdMatrix_TransformVector34_delta(rdVector3 *out, rdVector3 *v, rdMatrix34 *m);
void rdMatrix_TransformPoint34_delta(rdVector3 *vOut, rdVector3 *vIn, rdMatrix34 *camera);
