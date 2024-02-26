#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"

#define swrModel_GetTransforms_ADDR (0x00431900)

#define swrModel_LoadFromId_ADDR (0x00448780)

#define swrModel_ComputeClipMatrix_ADDR (0x00482f10)

void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation);

void* swrModel_LoadFromId(int id);

void swrModel_ComputeClipMatrix(swrModel_unk* model);

#endif // SWRMODEL_H
