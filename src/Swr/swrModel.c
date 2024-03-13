#include "swrModel.h"

#include "globals.h"

// 0x004258e0
void swrModel_ClearSceneAnimations(void)
{
    int i;
    void** animations;

    animations = swrScene_animations;
    for (i = 300; i != 0; i = i + -1)
    {
        *animations = NULL;
        animations = animations + 1;
    }
    swrScene_animations_count = 0;
}

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

// 0x00454c60
void swrModel_ClearBuffers(void)
{
    int i;
    int* flags;
    swrModel_unk** models;

    flags = swr_sceneModelFlags;
    for (i = 0x97; i != 0; i = i + -1)
    {
        *flags = 0;
        flags = flags + 1;
    }
    models = swr_sceneModels;
    for (i = 0x97; i != 0; i = i + -1)
    {
        *models = NULL;
        models = models + 1;
    }
    swrModel_ClearSceneAnimations();
}

// 0x0045cf30
void swrModel_SwapSceneModels(int index, int index2)
{
    swrModel_unk* ptr;

    ptr = swr_sceneModels[index];
    swr_sceneModels[index] = swr_sceneModels[index2];
    swr_sceneModels[index2] = ptr;
}

// 0x00482f10
void swrModel_ComputeClipMatrix(swrModel_unk* model)
{
    HANG("TODO");
}
