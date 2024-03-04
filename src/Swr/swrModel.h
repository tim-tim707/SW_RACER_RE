#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"
#include "types_model.h"

#define swrModel_GetTransforms_ADDR (0x00431900)

#define swrModel_LoadFromId_ADDR (0x00448780)

#define swrModel_swrModel_ByteSwapNode_ADDR (0x004476B0)

#define swrModel_MeshMaterialAlreadyByteSwapped_ADDR (0x004475F0)

#define swrModel_MeshTextureAlreadyByteSwapped_ADDR (0x00447630)

#define swrModel_MaterialAlreadyByteSwapped_ADDR (0x00447670)

#define swrModel_ByteSwapAnimation_ADDR (0x00448180)

void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation);

void* swrModel_LoadFromId(int id);

void swrModel_ByteSwapNode(swrModel_Node* node);

void swrModel_ByteSwapAnimation(swrModel_Animation* animation);

bool swrModel_MeshMaterialAlreadyByteSwapped(swrModel_MeshMaterial* mesh_material);

bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MaterialTexture* texture);

bool swrModel_MaterialAlreadyByteSwapped(swrModel_Material* material);

#endif // SWRMODEL_H
