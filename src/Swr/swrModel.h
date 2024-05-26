#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"

#define swrModel_AllocMaterial_ADDR (0x00408e60)

#define swrModel_ClearSceneAnimations_ADDR (0x004258E0)
#define swrModel_LoadAnimation_ADDR (0x00425900)
#define swrModel_AnimationComputeInterpFactor_ADDR (0x00425980)
#define swrModel_AnimationInterpolateSingleValue_ADDR (0x004259B0)
#define swrModel_AnimationInterpolateVec3_ADDR (0x00425A60)
#define swrModel_AnimationInterpolateAxisAngle_ADDR (0x00425BA0)
#define swrModel_UpdateTranslationAnimation_ADDR (0x00425D10)
#define swrModel_UpdateScaleAnimation_ADDR (0x00425DE0)
#define swrModel_UpdateAxisAngleAnimation_ADDR (0x00425F00)
#define swrModel_UpdateTextureFlipbookAnimation_ADDR (0x00426080)
#define swrModel_UpdateTextureScrollAnimation_ADDR (0x004260F0)
#define swrModel_AnimationFindKeyFrameIndex_ADDR (0x00426220)
#define swrModel_AnimationHandleLoopTransition_ADDR (0x00426290)
#define swrModel_AnimationUpdateTime_ADDR (0x00426330)
#define swrModel_UpdateAnimations_ADDR (0x00426660)
#define swrModel_FindLoadedAnimation_ADDR (0x00426740)
#define swrModel_AnimationSetLoopPoints_ADDR (0x004267A0)
#define swrModel_AnimationSetFlags_ADDR (0x00426810)
#define swrModel_AnimationClearFlags_ADDR (0x00426820)
#define swrModel_AnimationSetTime_ADDR (0x00426840)
#define swrModel_AnimationSetSpeed_ADDR (0x00426880)
#define swrModel_AnimationTransitionToTime_ADDR (0x00426890)
#define swrModel_AnimationSetLoopTransitionSpeed_ADDR (0x00426900)

#define swrModel_NodeFindFirstMeshMaterial_ADDR (0x0042B560)
#define swrModel_MeshMaterialSetColors_ADDR (0x0042B5E0)
#define swrModel_NodeSetColorsOnAllMaterials_ADDR (0x0042B640)
#define ProjectPointOntoScreen_ADDR (0x0042B710)
#define swrSprite_UpdateLensFlareSpriteSettings_ADDR (0x0042BA20)
#define swrSprite_SetScreenPos_ADDR (0x0042BB00)
#define UpdateSunAndLensFlareSprites2_ADDR (0x0042BB50)
#define UpdateDepthValuesOfSpritesWithZBuffer_ADDR (0x42BE60)
#define UpdateSunAndLensFlareSprites_ADDR (0x0042C1A0)

#define ResetPlayerSpriteValues_ADDR (0x0042C400)
#define SetPlayerSpritePositionOnMap_ADDR (0x0042C420)
#define ResetLightStreakSprites_ADDR (0x0042C460)
#define InitLightStreak_ADDR (0x0042C490)
#define SetLightStreakSpriteIDs_ADDR (0x0042C4E0)

#define UpdatePlayerPositionSprites_ADDR (0x0042C510)
#define swrText_CreateTextEntry2_ADDR (0x0042C7A0)
#define UpdateLightStreakSprites_ADDR (0x0042C800)
#define UpdateUnknownIngameSprites1_ADDR (0x0042CB00)
#define UpdateUnknownIngameSprites2_ADDR (0x0042CCA0)

#define UpdateIngameSprites_ADDR (0x0042D490)
#define EnableIngameSprites_ADDR (0x0042D500)
#define DisableIngameSprites_ADDR (0x0042D510)

#define swrModel_NodeSetRotationByEulerAngles_ADDR (0x004315F0)
#define swrModel_NodeSetTranslation_ADDR (0x00431620)
#define swrModel_NodeSetTransform_ADDR (0x00431640)
#define swrModel_NodeGetTransform_ADDR (0x004316A0)
#define swrModel_NodeSetTransformFromTranslationRotation_ADDR (0x00431710)
#define swrModel_NodeSetSelectedChildNode_ADDR (0x00431740)
#define swrModel_NodeSetLodDistance_ADDR (0x00431750)
#define swrModel_NodeGetFlags_ADDR (0x00431770)
#define swrModel_NodeGetNumChildren_ADDR (0x00431780)
#define swrModel_NodeGetChild_ADDR (0x00431790)
#define swrModel_MeshGetNumPrimitives_ADDR (0x004317B0)
#define swrModel_MeshGetPrimitiveType_ADDR (0x004317C0)
#define swrModel_MeshGetPrimitiveSizes_ADDR (0x004317D0)
#define swrModel_MeshGetCollisionData_ADDR (0x004317E0)
#define swrModel_MeshGetAABB_ADDR (0x00431820)
#define swrModel_NodeGetMesh_ADDR (0x00431850)

#define swrModel_MeshGetMapping_ADDR (0x004318b0)

#define swrModel_NodeModifyFlags_ADDR (0x00431A50)
#define swrModel_NodeGetFlags1Or2_ADDR (0x00431B00)
#define swrModel_NodeInit_ADDR (0x00431B20)

#define swrModel_MeshCollisionFaceCallbackIndexed_ADDR (0x00442720)
#define swrModel_MeshCollisionFaceCallback_ADDR (0x00442C30)

#define swrModel_MeshCollisionFaceCallback2Indexed_ADDR (0x00443560)
#define swrModel_MeshCollisionFaceCallback2_ADDR (0x004437C0)
#define swrModel_MeshIterateOverCollisionFaces_ADDR (0x004439F0)

#define swrModel_LoadTextureDataAndPalette_ADDR (0x00447370)
#define swrModel_InitializeTextureBuffer_ADDR (0x00447420)
#define swrModel_LoadModelTexture_ADDR (0x00447490)

#define swrModel_MeshMaterialAlreadyByteSwapped_ADDR (0x004475F0)
#define swrModel_MeshTextureAlreadyByteSwapped_ADDR (0x00447630)
#define swrModel_MaterialAlreadyByteSwapped_ADDR (0x00447670)
#define swrModel_ByteSwapNode_ADDR (0x004476B0)
#define swrModel_ByteSwapAnimation_ADDR (0x00448180)
#define swrModel_ByteSwapModelData_ADDR (0x004485D0)
#define swrModel_LoadFromId_ADDR (0x00448780)
#define swrModel_LoadAllAnimationsOfModel_ADDR (0x00448BD0)

#define swrModel_AnimationsSetSettings_ADDR (0x0044B360)

#define swrModel_MeshGetDisplayList_ADDR (0x0044C9D0)

#define swrModel_MeshMaterialSetTextureUVOffset_ADDR (0x0044FC00)

#define swrModel_LoadModelIntoScene_ADDR (0x00454BC0)
#define swrModel_ClearLoadedModels_ADDR (0x00454C60)
#define swrModel_ReloadAnimations_ADDR (0x00454C90)

#define swrModel_LoadAllLightStreaks_ADDR (0x00465480)

#define swrModel_AnimationsResetToZero2_ADDR (0x0046D5C0)
#define swrModel_AnimationsResetToZero_ADDR (0x0046D610)

#define swrModel_NodeFindFirstMaterial_ADDR (0x0047BCE0)
#define swrModel_NodeSetAnimationFlagsAndSpeed_ADDR (0x0047BD80)

#define swrModel_NodeSetLodDistances_ADDR (0x00481B30)

#define swrModel_NodeComputeFirstMeshAABB_ADDR (0x00482000)

#define swrModel_LoadPuppet_ADDR (0x0045CE10)

#define swrModel_SwapSceneModels_ADDR (0x0045cf30)

void* swrModel_AllocMaterial(unsigned int offset, unsigned int byteSize);

void swrModel_ClearSceneAnimations();
void swrModel_LoadAnimation(swrModel_Animation* animation);
double swrModel_AnimationComputeInterpFactor(swrModel_Animation* anim, float anim_time, int key_frame_index);
void swrModel_AnimationInterpolateSingleValue(float* result, swrModel_Animation* anim, float time, int key_frame_index);
void swrModel_AnimationInterpolateVec3(rdVector3* result, swrModel_Animation* anim, float time, int key_frame_index);
void swrModel_AnimationInterpolateAxisAngle(rdVector4* result, swrModel_Animation* animation, float time, int key_frame_index);
void swrModel_UpdateTranslationAnimation(swrModel_Animation* anim);
void swrModel_UpdateScaleAnimation(swrModel_Animation* anim);
void swrModel_UpdateAxisAngleAnimation(swrModel_Animation* anim);
void swrModel_UpdateTextureFlipbookAnimation(swrModel_Animation* anim);
void swrModel_UpdateTextureScrollAnimation(swrModel_Animation* animation, int direction);
uint32_t swrModel_AnimationFindKeyFrameIndex(swrModel_Animation* anim);
void swrModel_AnimationHandleLoopTransition(swrModel_Animation* anim, float curr_time, float new_time);
void swrModel_AnimationUpdateTime(swrModel_Animation* anim);
void swrModel_UpdateAnimations();
swrModel_Animation* swrModel_FindLoadedAnimation(void* affected_object, int animation_type);
void swrModel_AnimationSetLoopPoints(swrModel_Animation* anim, float start_time, float end_time);
void swrModel_AnimationSetFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags);
void swrModel_AnimationClearFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags);
void swrModel_AnimationSetTime(swrModel_Animation* anim, float time);
void swrModel_AnimationSetSpeed(swrModel_Animation* anim, float speed);
void swrModel_AnimationTransitionToTime(swrModel_Animation* anim, float time, float transition_speed);
void swrModel_AnimationSetLoopTransitionSpeed(swrModel_Animation* anim, float transition_speed);

void swrViewport_SetCameraIndex(short a1, swrViewport* mesh);

void swrViewport_UpdateCameras();

swrModel_MeshMaterial* swrModel_NodeFindFirstMeshMaterial(swrModel_Node* node);
void swrModel_MeshMaterialSetColors(swrModel_MeshMaterial* a1, int16_t a2, int16_t a3, int16_t a4, int16_t a5_G, int16_t a6, int16_t a7);
void swrModel_NodeSetColorsOnAllMaterials(swrModel_Node* a1_pJdge0x10, int a2, int a3, int a4, int a5_G, int a6, int a7);
void ProjectPointOntoScreen(swrViewport* arg0, rdVector3* position, float* pixel_pos_x, float* pixel_pos_y, float* pixel_depth, float* pixel_w, bool position_is_global);
void swrSprite_UpdateLensFlareSpriteSettings(int16_t id, int a2, int a3, float a4, float width, float a6, uint8_t r, uint8_t g, uint8_t b);
void swrSprite_SetScreenPos(int16_t id, int16_t x, int16_t y);
void UpdateSunAndLensFlareSprites2(int a1, int a2, int a3);
void UpdateDepthValuesOfSpritesWithZBuffer();
void UpdateSunAndLensFlareSprites(swrViewport* a1);
void ResetPlayerSpriteValues();
void SetPlayerSpritePositionOnMap(int player_id, const rdVector3* position, int unknown_value);
void ResetLightStreakSprites();
void InitLightStreak(int index, rdVector3* position);
void SetLightStreakSpriteIDs(int index, int sprite_id1, int sprite_id2);

void UpdatePlayerPositionSprites(swrViewport* a1, BOOL a2);
void swrText_CreateTextEntry2(int16_t screen_x, int16_t screen_y, char r, char g, char b, char a, char* screenText);
void UpdateLightStreakSprites(swrViewport* a1);
void UpdateUnknownIngameSprites1(swrViewport* a1);
void UpdateUnknownIngameSprites2(swrViewport* a1);

void UpdateIngameSprites(swrViewport* a1, BOOL a2);
void EnableIngameSprites();
void DisableIngameSprites();

void swrModel_NodeSetRotationByEulerAngles(swrModel_NodeTransformed* node, float rot_x, float rot_y, float rot_z);
void swrModel_NodeSetTranslation(swrModel_NodeTransformed* node, float x, float y, float z);
void swrModel_NodeSetTransform(swrModel_NodeTransformed* node, const rdMatrix44* matrix);
void swrModel_NodeGetTransform(const swrModel_NodeTransformed* node, rdMatrix44* matrix);
void swrModel_NodeSetTransformFromTranslationRotation(swrModel_NodeTransformed* node, swrTranslationRotation* arg4);
void swrModel_NodeSetSelectedChildNode(swrModel_NodeSelector* node, int a2);
void swrModel_NodeSetLodDistance(swrModel_NodeLODSelector* node, unsigned int a2, float a3);
int swrModel_NodeGetFlags(const swrModel_Node* node);
uint32_t swrModel_NodeGetNumChildren(swrModel_Node* node);
swrModel_Node* swrModel_NodeGetChild(swrModel_Node* node, int a2);
int swrModel_MeshGetNumPrimitives(const swrModel_Mesh*);
int swrModel_MeshGetPrimitiveType(const swrModel_Mesh*);
uint32_t* swrModel_MeshGetPrimitiveSizes(swrModel_Mesh* mesh);
void swrModel_MeshGetCollisionData(swrModel_Mesh* mesh, int disable, swrModel_CollisionVertex** vertices, uint16_t** optional_indices);
void swrModel_MeshGetAABB(swrModel_Mesh* mesh, float* aabb);
swrModel_Mesh* swrModel_NodeGetMesh(swrModel_NodeMeshGroup* node, int a2);

swrModel_Mapping* swrModel_MeshGetMapping(swrModel_Mesh* mesh);

void swrModel_NodeModifyFlags(swrModel_Node* node, int flag_id, int value, char modify_children, int modify_op);
uint32_t swrModel_NodeGetFlags1Or2(swrModel_Node* node, int a2);
void swrModel_NodeInit(swrModel_Node* node, uint32_t base_flags);

void swrModel_MeshCollisionFaceCallbackIndexed(swrModel_CollisionVertex* vertices, int16_t primitive_type, uint16_t* indices);
void swrModel_MeshCollisionFaceCallback(swrModel_CollisionVertex* vertices, int16_t primitive_type);

void swrModel_MeshCollisionFaceCallback2Indexed(swrModel_CollisionVertex* a1, int16_t primitive_type, uint16_t* indices);
void swrModel_MeshCollisionFaceCallback2(swrModel_CollisionVertex* a1, int16_t primitive_type);
void swrModel_MeshIterateOverCollisionFaces(swrModel_Mesh* mesh);

void swrModel_LoadTextureDataAndPalette(int* texture_offsets, uint8_t** texture_data_ptr, uint8_t** palette_ptr);
void swrModel_InitializeTextureBuffer();
void swrModel_LoadModelTexture(TEXID texture_index, swrMaterial** material_ptr, uint8_t** palette_data_ptr);

bool swrModel_MeshMaterialAlreadyByteSwapped(swrModel_MeshMaterial* mesh_material);
bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MaterialTexture* texture);
bool swrModel_MaterialAlreadyByteSwapped(swrModel_Material* material);
void swrModel_ByteSwapNode(swrModel_Node* node);
void swrModel_ByteSwapAnimation(swrModel_Animation* animation);
void swrModel_ByteSwapModelData(swrModel_Header* header);
swrModel_Header* swrModel_LoadFromId(MODELID id);
swrModel_Animation** swrModel_LoadAllAnimationsOfModel(swrModel_Header* model_header); // returns pointer to first animation in model header

void swrModel_AnimationsSetSettings(swrModel_Animation** anims, float animation_time, float loop_start_time, float loop_end_time, bool set_loop, float transition_speed, float loop_transition_speed);

Gfx* swrModel_MeshGetDisplayList(const swrModel_Mesh* a1);

void swrModel_MeshMaterialSetTextureUVOffset(swrModel_MeshMaterial* a1, float a2, float a3);

void swrModel_LoadModelIntoScene(MODELID model_id, MODELID alt_model_id, INGAME_MODELID ingame_model_id, bool load_animations);
void swrModel_ClearLoadedModels();
void swrModel_ReloadAnimations();

void swrModel_LoadAllLightStreaks(swrModel_Header* header);

void swrModel_AnimationsResetToZero2(swrModel_Animation** anims, float animation_speed);
void swrModel_AnimationsResetToZero(swrModel_Animation** anims);

swrModel_Material* swrModel_NodeFindFirstMaterial(swrModel_Node* node);
void swrModel_NodeSetAnimationFlagsAndSpeed(swrModel_Node* node, swrModel_AnimationFlags flags_to_disable, swrModel_AnimationFlags flags_to_enable, float speed);

void swrModel_NodeSetLodDistances(swrModel_NodeLODSelector* node, float* a2);

int swrModel_NodeComputeFirstMeshAABB(swrModel_Node* node, float* aabb, int a3);

void swrModel_LoadPuppet(MODELID model, INGAME_MODELID index, int a3, float a4);

void swrModel_SwapSceneModels(int index, int index2);

#endif // SWRMODEL_H
