#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"
#include "types_model.h"

#define swrModel_GetTransforms_ADDR (0x00431900)

#define swrModel_LoadFromId_ADDR (0x00448780)

#define swrModel_ByteSwapModelData_ADDR (0x004485D0)

#define swrModel_swrModel_ByteSwapNode_ADDR (0x004476B0)

#define swrModel_MeshMaterialAlreadyByteSwapped_ADDR (0x004475F0)

#define swrModel_MeshTextureAlreadyByteSwapped_ADDR (0x00447630)

#define swrModel_MaterialAlreadyByteSwapped_ADDR (0x00447670)

#define swrModel_ByteSwapAnimation_ADDR (0x00448180)

#define swrModel_ClearLoadedAnimations_ADDR (0x004258E0)

#define swrModel_LoadAnimation_ADDR (0x00425900)

#define swrModel_LoadAllAnimationsOfModel_ADDR (0x00448BD0)

#define swrModel_FindLoadedAnimation_ADDR (0x00426740)

#define swrModel_AnimationComputeInterpFactor_ADDR (0x00425980)

#define swrModel_AnimationInterpolateSingleValue_ADDR (0x004259B0)

#define swrModel_AnimationInterpolateVec3_ADDR (0x00425A60)

void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation);

swrModel_Header* swrModel_LoadFromId(int id);

void swrModel_ByteSwapModelData(swrModel_Header* header);

void swrModel_ByteSwapNode(swrModel_Node* node);

void swrModel_ByteSwapAnimation(swrModel_Animation* animation);

bool swrModel_MeshMaterialAlreadyByteSwapped(swrModel_MeshMaterial* mesh_material);

bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MaterialTexture* texture);

bool swrModel_MaterialAlreadyByteSwapped(swrModel_Material* material);

void swrModel_ClearLoadedAnimations();

void swrModel_LoadAnimation(swrModel_Animation* animation);

// returns pointer to first animation in model header
swrModel_Animation** swrModel_LoadAllAnimationsOfModel(swrModel_Header* model_header);

swrModel_Animation* swrModel_FindLoadedAnimation(void* affected_object, int animation_type);

double swrModel_AnimationComputeInterpFactor(swrModel_Animation* anim, float anim_time, int key_frame_index);

void swrModel_AnimationInterpolateSingleValue(float* result, swrModel_Animation* anim, float time, int key_frame_index);

void swrModel_AnimationInterpolateVec3(rdVector3* result, swrModel_Animation* anim, float time, int key_frame_index);

#endif // SWRMODEL_H
