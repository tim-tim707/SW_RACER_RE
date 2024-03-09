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

#define swrModel_AnimationInterpolateAxisAngle_ADDR (0x00425BA0)

#define swrModel_UpdateTranslationAnimation_ADDR (0x00425D10)

#define swrModel_UpdateScaleAnimation_ADDR (0x00425DE0)

#define swrModel_UpdateAxisAngleAnimation_ADDR (0x00425F00)

#define swrModel_UpdateUnknownAnimation_ADDR (0x00426080)

#define swrModel_UpdateTextureScrollAnimation_ADRR (0x004260F0)

#define swrModel_AnimationUpdateTime_ADDR (0x00426330)

#define swrModel_AnimationHandleTransition_ADDR (0x00426290)

#define swrModel_UpdateAnimations_ADDR (0x00426660)

#define swrModel_AnimationSetLoopPoints_ADDR (0x004267A0)

#define swrModel_AnimationSetFlags_ADDR (0x00426810)

#define swrModel_AnimationClearFlags_ADDR (0x00426820)

#define swrModel_AnimationSetTime_ADDR (0x00426840)

#define swrModel_AnimationSetSpeed_ADDR (0x00426880)

#define swrModel_AnimationTransitionToTime_ADDR (0x00426890)

#define swrModel_AnimationSetLoopTransitionSpeed_ADDR (0x00426900)

#define swrModel_AnimationsSetSettings_ADDR (0x0044B360)

#define swrModel_AnimationsResetToZero_ADRR (0x0046D610)

#define swrModel_AnimationsResetToZero2_ADRR (0x0046D5C0)

#define swrModel_NodeSetTranslation_ADDR (0x00431620)

#define swrModel_NodeGetTransform_ADDR (0x004316A0)

#define swrModel_NodeSetTransform_ADDR (0x00431640)

#define swrModel_NodeSetRotationByEulerAngles_ADDR (0x004315F0)

#define swrModel_NodeFindFirstMeshMaterial_ADDR (0x0042B560)

#define swrModel_MeshMaterialSetColors_ADDR (0x0042B5E0)

#define swrModel_NodeSetColorsOnAllMaterials_ADDR (0x0042B640)

#define swrModel_NodeSetTransformFromTranslationRotation_ADDR (0x00431710)

#define swrModel_Node5065SetUnknownBool_ADDR (0x00431740)

#define swrModel_NodeGetFlags_ADDR (0x00431770)

#define swrModel_NodeGetNumChildren_ADDR (0x00431780)

#define swrModel_NodeGetChild_ADDR (0x00431790)

#define swrModel_MeshGetAABB_ADDR (0x00431820)

#define swrModel_NodeGetMesh_ADDR (0x00431850)

#define swrModel_NodeGetFlags1Or2_ADDR (0x00431B00)

#define swrModel_NodeInit_ADDR (0x00431B20)

#define swrModel_MeshMaterialSetTextureUVOffset_ADDR (0x0044FC00)

#define swrModel_ClearLoadedModels_ADDR (0x00454C60)

#define swrModel_ReloadAnimations_ADDR (0x00454C90)

#define swrModel_NodeSetAnimationFlagsAndSpeed_ADDR (0x0047BD80)

#define swrModel_NodeComputeFirstMeshAABB_ADDR (0x00482000)

#define swrModel_LoadModelTexture_ADDR (0x00447490)

#define swrModel_DecompressData_ADDR (0x0042D520)

#define swrModel_AnimationFindKeyFrameIndex_ADDR (0x00426220)

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

void swrModel_AnimationInterpolateAxisAngle(rdVector4* result, swrModel_Animation* animation, float time, int key_frame_index);

void swrModel_UpdateTranslationAnimation(swrModel_Animation* anim);

void swrModel_UpdateScaleAnimation(swrModel_Animation* anim);

void swrModel_UpdateAxisAngleAnimation(swrModel_Animation* anim);

void swrModel_UpdateUnknownAnimation(swrModel_Animation* anim);

void swrModel_UpdateTextureScrollAnimation(swrModel_Animation* animation, int direction);

void swrModel_AnimationUpdateTime(swrModel_Animation* anim);

void swrModel_AnimationHandleLoopTransition(swrModel_Animation* anim, float curr_time, float new_time);

uint32_t swrModel_AnimationFindKeyFrameIndex(swrModel_Animation* anim);

void swrModel_UpdateAnimations();

void swrModel_AnimationSetLoopPoints(swrModel_Animation* anim, float start_time, float end_time);

void swrModel_AnimationSetFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags);

void swrModel_AnimationClearFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags);

void swrModel_AnimationSetTime(swrModel_Animation* anim, float time);

void swrModel_AnimationSetSpeed(swrModel_Animation* anim, float speed);

void swrModel_AnimationTransitionToTime(swrModel_Animation* anim, float time, float transition_speed);

void swrModel_AnimationSetLoopTransitionSpeed(swrModel_Animation* anim, float transition_speed);

void swrModel_AnimationsSetSettings(swrModel_Animation** anims, float animation_time, float loop_start_time, float loop_end_time, bool set_loop, float transition_speed, float loop_transition_speed);

void swrModel_AnimationsResetToZero(swrModel_Animation** anims);

void swrModel_AnimationsResetToZero2(swrModel_Animation** anims, float animation_speed);

// node stuff

void swrModel_NodeSetTranslation(swrModel_Node* node, float x, float y, float z);

void swrModel_NodeGetTransform(const swrModel_Node* node, rdMatrix44* matrix);

void swrModel_NodeSetTransform(swrModel_Node* node, const rdMatrix44* matrix);

void swrModel_NodeSetRotationByEulerAngles(swrModel_Node* node, float rot_x, float rot_y, float rot_z);

swrModel_MeshMaterial* swrModel_NodeFindFirstMeshMaterial(swrModel_Node* node);

void swrModel_MeshMaterialSetColors(swrModel_MeshMaterial* a1, int16_t a2, int16_t a3, int16_t a4, int16_t a5_G, int16_t a6, int16_t a7);

void swrModel_NodeSetColorsOnAllMaterials(swrModel_Node* a1_pJdge0x10, int a2, int a3, int a4, int a5_G, int a6, int a7);

void swrModel_NodeSetTransformFromTranslationRotation(swrModel_Node* a1, swrTranslationRotation* arg4);

void swrModel_Node5065SetUnknownBool(swrModel_Node* a1, int a2);

int swrModel_NodeGetFlags(const swrModel_Node* a1);

uint32_t swrModel_NodeGetNumChildren(swrModel_Node* a1);

swrModel_Node* swrModel_NodeGetChild(swrModel_Node* a1, int a2);

void swrModel_MeshGetAABB(swrModel_Mesh* a1, float* aabb);

swrModel_Mesh* swrModel_NodeGetMesh(swrModel_Node* a1, int a2);

uint32_t swrModel_NodeGetFlags1Or2(swrModel_Node* a1, int a2);

void swrModel_NodeInit(swrModel_Node* a1, uint32_t base_flags);

void swrModel_MeshMaterialSetTextureUVOffset(swrModel_MeshMaterial* a1, float a2, float a3);

void swrModel_ClearLoadedModels();

void swrModel_ReloadAnimations();

void swrModel_NodeSetAnimationFlagsAndSpeed(swrModel_Node* a1, swrModel_AnimationFlags flags_to_disable, swrModel_AnimationFlags flags_to_enable, float speed);

int swrModel_NodeComputeFirstMeshAABB(swrModel_Node *a1, float *aabb, int a3);

void swrModel_LoadModelTexture(int texture_index, uint32_t* texture_ptr, uint32_t* texture_ptr_1);

void swrModel_DecompressData(char *compressed, char *decompressed);

#endif // SWRMODEL_H
