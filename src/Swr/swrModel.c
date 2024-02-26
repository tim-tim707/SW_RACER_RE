#include "swrModel.h"

// 0x00431900
void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation)
{
    swrTranslationRotation tmp;
    rdMatrix_ExtractTransform(&param_1->unk_mat4, &tmp);
    translation->x = tmp.translation.x;
    translation->y = tmp.translation.y;
    translation->z = tmp.translation.z;
    rotation->x = tmp.yaw_roll_pitch.x;
    rotation->y = tmp.yaw_roll_pitch.y;
    rotation->z = tmp.yaw_roll_pitch.z;
}

// 0x00448780
void* swrModel_LoadFromId(int id)
{
    HANG("TODO");
    return NULL;
}

// 0x00482f10
void swrModel_ComputeClipMatrix(swrModel_unk* model)
{
    HANG("TODO");
}
