#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"

#define swrModel_ClearSceneAnimations_ADDR (0x004258e0)

#define swrModel_GetTransforms_ADDR (0x00431900)

#define swrModel_LoadFromId_ADDR (0x00448780)

#define swrModel_ClearBufferse_ADDR (0x00454c60)

#define swrModel_ComputeClipMatrix_ADDR (0x00482f10)

#define swrModel_SwapSceneModels_ADDR (0x0045cf30)

void swrModel_ClearSceneAnimations(void);

void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation);

void* swrModel_LoadFromId(int id);

void swrModel_ClearBuffers(void);

void swrModel_ComputeClipMatrix(swrModel_unk* model);

void swrModel_SwapSceneModels(int index, int index2);

#endif // SWRMODEL_H
