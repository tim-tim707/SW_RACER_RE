#ifndef RD_MATRIX_H
#define RD_MATRIX_H

#include "rdVector.h"
#include "types.h"

#define rdMatrix_SetColumn_ADDR (0x0042fb10)
#define rdMatrix_GetColumn_ADDR (0x0042fb40)
#define rdMatrix_Multiply44_ADDR (0x0042fb70)
#define rdMatrix_Multiply44Acc_ADDR (0x0042ff80)
#define rdMatrix_Unk1_ADDR (0x00430310)
#define rdMatrix_Multiply3_ADDR (0x00430980)
#define rdMatrix_Transform3_ADDR (0x00430a00)
#define rdMatrix_Multiply4_ADDR (0x00430ab0)
#define rdMatrix_ExtractTransform_ADDR (0x00430b80)
#define rdMatrix_BuildRotation44_ADDR (0x00430e00)
#define rdMatrix_BuildRotation33_ADDR (0x00430f10)
#define rdMatrix_SetRotation44_ADDR (0x00431020)
#define rdMatrix_SetTransform44_ADDR (0x00431060)
#define rdMatrix_SetDiagonal44_ADDR (0x004310b0)
#define rdMatrix_SetTranslation44_ADDR (0x00431100)
#define rdMatrix_BuildFromVectorAngle44_ADDR (0x00431150)
#define rdMatrix_AddRotationFromVectorAngle44Before_ADDR (0x00431390)
#define rdMatrix_SetIdentity44_ADDR (0x004313d0)
#define rdMatrix_AddRotationFromVectorAngle44After_ADDR (0x00431410)
#define rdMatrix_ScaleBasis44_ADDR (0x00431450)

#define rdMatrix_Copy44_34_ADDR (0x0044bad0)

#define rdMatrix_Copy44_ADDR (0x0044bb10)
// address gap
#define rdMatrix_TransformPoint44_ADDR (0x00480690)
#define rdMatrix_ToTransRotScale_ADDR (0x00480730)
#define rdMatrix_FromTransRotScale_ADDR (0x00480850)

#define rdMatrix_BuildViewMatrix_ADDR (0x00483690)

#define rdMatrix_BuildRotation34_ADDR (0x004924b0)

#define rdMatrix_InvertOrtho34_ADDR (0x004925d0)
#define rdMatrix_InvertOrthoNorm34_ADDR (0x00492680)

#define rdMatrix_BuildRotate34_ADDR (0x00492810)
#define rdMatrix_BuildTranslate34_ADDR (0x00492930)
#define rdMatrix_ExtractAngles34_ADDR (0x00492960)
#define rdMatrix_Multiply34_ADDR (0x00492b70)
#define rdMatrix_PreMultiply34_ADDR (0x00492d50)
#define rdMatrix_PostMultiply34_ADDR (0x00492f40)
#define rdMatrix_PreRotate34_ADDR (0x00493130)
#define rdMatrix_PostTranslate34_ADDR (0x00493160)
#define rdMatrix_TransformVector34_ADDR (0x00493190)
#define rdMatrix_TransformPoint34_ADDR (0x00493200)
#define rdMatrix_TransformPointLst34_ADDR (0x00493270)

void rdMatrix_SetColumn(rdMatrix44* mat, int n, rdVector3* in);
void rdMatrix_GetColumn(rdMatrix44* mat, int n, rdVector3* out);
void rdMatrix_Multiply44(rdMatrix44* out, rdMatrix44* mat1, rdMatrix44* mat2);
void rdMatrix_Multiply44Acc(rdMatrix44* out, rdMatrix44* mat2);
void rdMatrix_Unk1(rdMatrix44* m1, rdMatrix44* m2);
void rdMatrix_Multiply3(rdVector3* out, rdVector3* in, const rdMatrix44* mat);
void rdMatrix_Transform3(rdVector3* out, rdVector3* in, const rdMatrix44* mat);
void rdMatrix_Multiply4(rdVector4* out, rdVector4* in, rdMatrix44* mat);
void rdMatrix_ExtractTransform(rdMatrix44* mat, swrTranslationRotation* tr_rot);
void rdMatrix_BuildRotation44(rdMatrix44* out, float gamma, float alpha, float beta);
void rdMatrix_BuildRotation33(rdMatrix33* out, float gamma, float alpha, float beta);
void rdMatrix_SetRotation44(rdMatrix44* out, float gamma, float alpha, float beta);
void rdMatrix_SetTransform44(rdMatrix44* mat, swrTranslationRotation* v);
void rdMatrix_SetDiagonal44(rdMatrix44* mat, float x, float y, float z);
void rdMatrix_SetTranslation44(rdMatrix44* mat, float x, float y, float z);
void rdMatrix_BuildFromVectorAngle44(rdMatrix44* mat, float angle, float x, float y, float z);
void rdMatrix_AddRotationFromVectorAngle44Before(rdMatrix44* mat_out, float angle, float x, float y, float z, rdMatrix44* mat_in);
void rdMatrix_SetIdentity44(rdMatrix44* mat);
void rdMatrix_AddRotationFromVectorAngle44After(rdMatrix44* mat_out, rdMatrix44* mat_in, float angle, float x, float y, float z);
void rdMatrix_ScaleBasis44(rdMatrix44* out, float scale_right, float scale_forward, float scale_up, rdMatrix44* in);

void rdMatrix_Copy44_34(rdMatrix44* dest, const rdMatrix34* src);

void rdMatrix_Copy44(rdMatrix44* out, rdMatrix44* in);

void rdMatrix_TransformPoint44(rdVector4* a1, const rdVector4* a2, const rdMatrix44* a3);
void rdMatrix_ToTransRotScale(const rdMatrix44* mat, rdVector3* translation, rdMatrix44* rotation, rdVector3* scale);
void rdMatrix_FromTransRotScale(rdMatrix44* mat, const rdVector3* translation, const rdMatrix44* rotation,const  rdVector3* scale);

void rdMatrix_BuildViewMatrix(rdMatrix44* viewMatrix_out, rdMatrix44* world);

void rdMatrix_BuildRotation34(rdMatrix34* out, rdVector3* angles, rdVector3* translation);

void rdMatrix_InvertOrtho34(rdMatrix34* out, rdMatrix34* in);
void rdMatrix_InvertOrthoNorm34(rdMatrix34* out, rdMatrix34* in);

void rdMatrix_BuildRotate34(rdMatrix34* out, rdVector3* rot);
void rdMatrix_BuildTranslate34(rdMatrix34* out, rdVector3* tV);
void rdMatrix_ExtractAngles34(rdMatrix34* in, rdVector3* out);
void rdMatrix_Multiply34(rdMatrix34* out, rdMatrix34* mat1, rdMatrix34* mat2);
void rdMatrix_PreMultiply34(rdMatrix34* mat1, rdMatrix34* mat2);
void rdMatrix_PostMultiply34(rdMatrix34* mat1, rdMatrix34* mat2);
void rdMatrix_PreRotate34(rdMatrix34* out, rdVector3* rot);
void rdMatrix_PostTranslate34(rdMatrix34* mat, rdVector3* v);
void rdMatrix_TransformVector34(rdVector3* out, rdVector3* v, rdMatrix34* m);
void rdMatrix_TransformPoint34(rdVector3* vOut, rdVector3* vIn, rdMatrix34* camera);
void rdMatrix_TransformPointLst34(rdMatrix34* m, rdVector3* in, rdVector3* out, int num);

#endif // RD_MATRIX_H
