#ifndef SWRMODEL_H
#define SWRMODEL_H

#include "types.h"

#define swrModel_AllocMaterial_ADDR (0x00408e60)

// Root-model material + mesh registry (per asset-buffer slot; used during model load).
#define swrModel_FreeSlotMaterials_ADDR (0x00408eb0)
#define swrModel_PopRootMaterial_ADDR (0x00408f90)
#define swrModel_RegisterRootMaterial_ADDR (0x00408fb0)
#define swrModel_AllocRootMeshIndex_ADDR (0x00409230)
#define swrModel_ResetRootMeshCounts_ADDR (0x00409270)

#define swrModel_SplitTextureIntoTiles_ADDR (0x004188b0)
#define swrModel_ExtractTextureTile_ADDR (0x00418a80)

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
#define swrSprite_UpdateLensFlareSpriteSettings_ADDR (0x0042BA20)
#define UpdateSunAndLensFlareSprites2_ADDR (0x0042BB50)
#define UpdateSunAndLensFlareSprites_ADDR (0x0042C1A0)

#define ResetPlayerSpriteValues_ADDR (0x0042C400)
#define SetPlayerSpritePositionOnMap_ADDR (0x0042C420)
#define ResetLightStreakSprites_ADDR (0x0042C460)
#define InitLightStreak_ADDR (0x0042C490)
#define SetLightStreakSpriteIDs_ADDR (0x0042C4E0)

#define swrText_CreateTextEntry2_ADDR (0x0042C7A0)
#define UpdateLightStreakSprites_ADDR (0x0042C800)

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

#define swrModel_MeshGetBehavior_ADDR (0x004318b0)

#define swrModel_NodeModifyFlags_ADDR (0x00431A50)
#define swrModel_NodeGetFlags1Or2_ADDR (0x00431B00)
#define swrModel_NodeInit_ADDR (0x00431B20)

// Sphere / ray vs mesh collision (the swept-collision pipeline).
#define swrModel_PointInTriangle_ADDR (0x00441040)
#define swrModel_RecordClosestHit_ADDR (0x00441390)
#define swrModel_TestTriangleEdges_ADDR (0x004414e0)
#define swrModel_ClipAndTestTriangle_ADDR (0x00441810)
#define swrModel_CollideSphereTriangle_ADDR (0x00442090)
#define swrModel_CollideRayTriangle_ADDR (0x00442550)

#define swrModel_MeshCollisionFaceCallbackIndexed_ADDR (0x00442720)
#define swrModel_MeshCollisionFaceCallback_ADDR (0x00442C30)

#define swrModel_MeshCollisionFaceCallback2Indexed_ADDR (0x00443560)
#define swrModel_MeshCollisionFaceCallback2_ADDR (0x004437C0)
#define swrModel_MeshIterateOverCollisionFaces_ADDR (0x004439F0)

#define swrModel_QuadInCollisionBounds_ADDR (0x00443110)
#define swrModel_TriInCollisionBounds_ADDR (0x00443380)
#define swrModel_TransformCollisionQuery_ADDR (0x00443c50)
#define swrModel_TransformCollisionResult_ADDR (0x00443e70)
#define swrModel_CollideMeshNode_ADDR (0x00443f10)
#define swrModel_CollideNodeRecursive_ADDR (0x004440e0)
#define swrModel_SetupSphereCollision_ADDR (0x00444200)
#define swrModel_ResolveSphereCollision_ADDR (0x00444300)
#define swrModel_CollideSphereWithModel_ADDR (0x00444740)
#define swrModel_TransformCollisionVerts_ADDR (0x004447b0)
#define swrModel_CollideMeshNodeRay_ADDR (0x00444910)
#define swrModel_CollideNodeRecursiveRay_ADDR (0x00444bf0)
#define swrModel_CollideRayWithModel_ADDR (0x00444e40)
#define swrModel_CollideRayWithMesh_ADDR (0x00444f10)

#define swrModel_CreateTextureMaterialFromPixels_ADDR (0x00445cd0)
#define swrModel_ConvertIndexedTextureRows_ADDR (0x00445e50)
#define swrModel_BuildTiledTextureMaterial_ADDR (0x00446a20)
#define swrModel_ConvertTileToRdMaterial_ADDR (0x00446b60)

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

#define swrModel_FixupAltNodePointers_ADDR (0x00448c70)
#define swrModel_SetAnimListSpeed_ADDR (0x0044b330)

#define swrModel_AnimationsSetSettings_ADDR (0x0044B360)

// Per-node render-matrix (MVP) compose + cache into swrModel_NodeTransformed +0xf4.
#define swrModel_GetNodeYaw_ADDR (0x0044b4a0)
#define swrModel_CachePrecomputedMatrices_ADDR (0x0044bbe0)
#define swrModel_ComputeNodeRenderMatrix_ADDR (0x0044bfb0)
#define swrModel_CopyNodeRenderMatrix_ADDR (0x0044c3b0)

#define swrModel_MeshGetDisplayList_ADDR (0x0044C9D0)

#define swrModel_MeshMaterialSetTextureUVOffset_ADDR (0x0044FC00)

#define swrModel_LoadModelIntoScene_ADDR (0x00454BC0)
#define swrModel_ClearLoadedModels_ADDR (0x00454C60)
#define swrModel_ReloadAnimations_ADDR (0x00454C90)

#define swrModel_LoadAllLightStreaks_ADDR (0x00465480)

#define swrModel_AnimationsResetToZero2_ADDR (0x0046D5C0)
#define swrModel_AnimationsResetToZero_ADDR (0x0046D610)
#define swrModel_AnyFxAnimDone_ADDR (0x0046D650)

#define swrModel_NodeFindFirstMaterial_ADDR (0x0047BCE0)
#define swrModel_NodeSetAnimationFlagsAndSpeed_ADDR (0x0047BD80)

// Inner helpers of the closest-point query (swrModel_ClosestPointOnTriangle @0x482120 calls Impl).
#define swrModel_PointInTriangle2_ADDR (0x00480a70)
#define swrModel_ClosestPointOnTriangleImpl_ADDR (0x00480dc0)

#define swrModel_NodeSetLodDistances_ADDR (0x00481B30)
#define swrModel_SetupFaceNormal_ADDR (0x00481be0)

#define swrModel_NodeComputeFirstMeshAABB_ADDR (0x00482000)

// Closest-point-on-model surface query (collision / ground projection): walk a model's
// node tree (applying transforms + LOD selection) and return the surface point nearest a
// query point, plus its normal. swrModel_FindClosestPointOnModel is the entry point.
#define swrModel_ClosestPointOnTriangle_ADDR (0x00482120)
#define swrModel_ClosestPointInDisplayList_ADDR (0x00482320)
#define swrModel_NodeClosestPoint_ADDR (0x00482690)
#define swrModel_NodeSelectLOD_ADDR (0x004827b0)
#define swrModel_NodeTreeClosestPoint_ADDR (0x00482820)
#define swrModel_FindClosestPointOnModel_ADDR (0x00482c40)

#define swrModel_LoadPuppet_ADDR (0x0045CE10)

#define swrModel_SwapSceneModels_ADDR (0x0045cf30)

void* swrModel_AllocMaterial(unsigned int offset, unsigned int byteSize);

// Root-model material + mesh registry (per asset-buffer slot; used during model load):
void swrModel_FreeSlotMaterials(int slot);                        // free a buffer slot's materials + meshes
void swrModel_PopRootMaterial(void);                              // drop the last-registered material
void swrModel_RegisterRootMaterial(unsigned int bufferKind, void* material); // append to swrModel3_root_materials
int swrModel_AllocRootMeshIndex(unsigned int bufferKind);         // bump the root mesh count, return its index
void swrModel_ResetRootMeshCounts(void);                          // zero the per-slot mesh counts

// Tiled-texture build pipeline (split a loaded texture into power-of-two tiles).
void* swrModel_SplitTextureIntoTiles(void* tex, int bytesPerPixel);
void* swrModel_ExtractTextureTile(void* outTile, void* src, int x, int y, int tileWidth, int tileHeight, int bytesPerPixel, int srcStride);

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

swrModel_MeshMaterial* swrModel_NodeFindFirstMeshMaterial(swrModel_Node* node);
void swrModel_MeshMaterialSetColors(swrModel_MeshMaterial* a1, int16_t a2, int16_t a3, int16_t a4, int16_t a5_G, int16_t a6, int16_t a7);
void swrModel_NodeSetColorsOnAllMaterials(swrModel_Node* a1_pJdge0x10, int a2, int a3, int a4, int a5_G, int a6, int a7);
void swrSprite_UpdateLensFlareSpriteSettings(int16_t id, int a2, int a3, float a4, float width, float a6, uint8_t r, uint8_t g, uint8_t b);
void UpdateSunAndLensFlareSprites2(int a1, int a2, int a3);
void UpdateSunAndLensFlareSprites(swrViewport* a1);
void ResetPlayerSpriteValues();
void SetPlayerSpritePositionOnMap(int player_id, const rdVector3* position, int unknown_value);
void ResetLightStreakSprites();
void InitLightStreak(int index, rdVector3* position);
void SetLightStreakSpriteIDs(int index, int sprite_id1, int sprite_id2);

void swrText_CreateTextEntry2(int16_t screen_x, int16_t screen_y, char r, char g, char b, char a, char* screenText);
void UpdateLightStreakSprites(swrViewport* a1);

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

swrModel_Behavior* swrModel_MeshGetBehavior(swrModel_Mesh* mesh);

void swrModel_NodeModifyFlags(swrModel_Node* node, int flag_id, int value, char modify_children, int modify_op);
uint32_t swrModel_NodeGetFlags1Or2(swrModel_Node* node, int a2);
void swrModel_NodeInit(swrModel_Node* node, uint32_t base_flags);

// Sphere/ray-vs-mesh collision (distinct from the closest-point query family
// further down). The MeshCollisionFaceCallback* below are the per-face hooks
// that feed these triangle/edge tests; results land in the global closest-hit.
int swrModel_PointInTriangle(float* origin, float* a, float* b, float* c, rdVector3* edgeAB, rdVector3* edgeBC, rdVector3* edgeCA);
void swrModel_RecordClosestHit(float distSq, float* point, float* hitPoint, float* normal);
void swrModel_TestTriangleEdges(float* point, float* a, float* b, float* c, float* p5, void* face);
void swrModel_ClipAndTestTriangle(float* normal, float* a, float* b, float* c, void* p5, void* face, void* p7);
void swrModel_CollideSphereTriangle(float* faceNormal, float* a, float* b, float* c, float* point);
void swrModel_CollideRayTriangle(float* faceNormal, float* a, float* b, float* c, int face);

void swrModel_MeshCollisionFaceCallbackIndexed(swrModel_CollisionVertex* vertices, int16_t primitive_type, uint16_t* indices);
void swrModel_MeshCollisionFaceCallback(swrModel_CollisionVertex* vertices, int16_t primitive_type);

void swrModel_MeshCollisionFaceCallback2Indexed(swrModel_CollisionVertex* a1, int16_t primitive_type, uint16_t* indices);
void swrModel_MeshCollisionFaceCallback2(swrModel_CollisionVertex* a1, int16_t primitive_type);
void swrModel_MeshIterateOverCollisionFaces(swrModel_Mesh* mesh);

// Broad-phase: triangle/quad vs the active collision bounds.
int swrModel_QuadInCollisionBounds(float* a, float* b, float* c, float* d);
int swrModel_TriInCollisionBounds(float* a, float* b, float* c);
// Transform the collision query into / the hit result out of mesh-local space.
void swrModel_TransformCollisionQuery(unsigned char flags, rdVector3* outPos, rdVector3* inPos, rdVector3* outNormal, rdVector3* inNormal);
void swrModel_TransformCollisionResult(unsigned char flags);
// Tree traversal: recurse the node tree (matrix stack), test each mesh node.
void swrModel_CollideMeshNode(swrModel_Node* node, void* query, unsigned int flags);
void swrModel_CollideNodeRecursive(swrModel_NodeTransformed* node, void* query, unsigned int flags);
// Sphere sweep: setup global state, then resolve the slide/deflection after traversal.
void swrModel_SetupSphereCollision(float* center, float radius, float* velocity, float a4, float a5);
int swrModel_ResolveSphereCollision(rdVector3* pos, float radius, rdVector3* dir, float a4, float a5, rdVector3* outNormal, rdVector3* a7, float* outHit);
// Public sphere-vs-model entry (setup -> recurse -> resolve).
int swrModel_CollideSphereWithModel(swrModel_NodeTransformed* node, rdVector3* center, float radius, rdVector3* velocity, float a5, float a6, rdVector3* outNormal, rdVector3* a8, float* outHit);
// Ray/segment variant of the pipeline.
void swrModel_TransformCollisionVerts(unsigned char flags, int count, int dst, rdVector3* src);
void swrModel_CollideMeshNodeRay(swrModel_Node* node, void* query, unsigned int flags);
void swrModel_CollideNodeRecursiveRay(swrModel_NodeTransformed* node, void* query, unsigned int flags);
int swrModel_CollideRayWithModel(swrModel_NodeTransformed* node, float* ray);
float swrModel_CollideRayWithMesh(swrModel_Mesh* mesh, float* ray, float* outPoint, float* outNormal);

void swrModel_CreateTextureMaterialFromPixels(int srcWidth, int srcHeight, int width, int height, unsigned int bufferKind, void** outMaterial, uint8_t* pixels);
void swrModel_ConvertIndexedTextureRows(int width, int height, int paddedWidth, uint8_t* indices, uint16_t* palette, uint16_t** outCursor);
void swrModel_BuildTiledTextureMaterial(void* tex);
void swrModel_ConvertTileToRdMaterial(void* tex, void* tile);

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

// Merges a second model's 'AltN' node pointers into the primary (walks Data/Anim/AltN chunks, byte-swaps).
void swrModel_FixupAltNodePointers(int* model, int* altModel);
// Sets the playback speed on every animation in a NULL-terminated list.
void swrModel_SetAnimListSpeed(swrModel_Animation** anims, float speed);

void swrModel_AnimationsSetSettings(swrModel_Animation** anims, float animation_time, float loop_start_time, float loop_end_time, bool set_loop, float transition_speed, float loop_transition_speed);

// Per-node render-matrix caching (fills swrModel_NodeTransformed +0xf4 block used for collision/render).
float swrModel_GetNodeYaw(int a1, int* nodePair);
void swrModel_CachePrecomputedMatrices(void);
void swrModel_ComputeNodeRenderMatrix(swrModel_NodeTransformed* node, int a2);
void swrModel_CopyNodeRenderMatrix(void* srcNode, swrModel_NodeTransformed* dstNode, int a3);

Gfx* swrModel_MeshGetDisplayList(const swrModel_Mesh* a1);

void swrModel_MeshMaterialSetTextureUVOffset(swrModel_MeshMaterial* a1, float a2, float a3);

void swrModel_LoadModelIntoScene(MODELID model_id, MODELID alt_model_id, INGAME_MODELID ingame_model_id, bool load_animations);
void swrModel_ClearLoadedModels();
void swrModel_ReloadAnimations();

void swrModel_LoadAllLightStreaks(swrModel_Header* header);

void swrModel_AnimationsResetToZero2(swrModel_Animation** anims, float animation_speed);
void swrModel_AnimationsResetToZero(swrModel_Animation** anims);

// Returns nonzero if any animation in the array has finished (a free slot exists); 0 if
// all are still playing or the array is empty. Used to gate engine-fireball spawning.
int swrModel_AnyFxAnimDone(swrModel_Animation** anims);

swrModel_Material* swrModel_NodeFindFirstMaterial(swrModel_Node* node);
void swrModel_NodeSetAnimationFlagsAndSpeed(swrModel_Node* node, swrModel_AnimationFlags flags_to_disable, swrModel_AnimationFlags flags_to_enable, float speed);

// Inner helpers of the closest-point query: swrModel_ClosestPointOnTriangle (@0x482120) de-quantizes
// the model's short verts + transform, then calls ...Impl on float verts; ...Impl tests via ...2.
int swrModel_PointInTriangle2(float* origin, float* a, float* b, float* c, rdVector3* edgeAB, rdVector3* edgeBC, rdVector3* edgeCA);
float swrModel_ClosestPointOnTriangleImpl(float* query, float* a, float* b, float* c, float maxDistSq, float* outPoint, float* outNormal);

void swrModel_NodeSetLodDistances(swrModel_NodeLODSelector* node, float* a2);
void swrModel_SetupFaceNormal(int vertexArray, int faceOut, int i0, int i1, int i2); // rdMath_CalcSurfaceNormal + store the 3 vertex indices

int swrModel_NodeComputeFirstMeshAABB(swrModel_Node* node, float* aabb, int a3);

// Closest-point-on-model surface query (collision / ground projection).
// Test one transformed triangle; if its closest point to the query beats minDistSq,
// write outPoint/outNormal and update minDistSq.
void swrModel_ClosestPointOnTriangle(short* v0, short* v1, short* v2, rdMatrix44* transform, float* minDistSq, int mode, rdVector3* outPoint, rdVector3* outNormal);
// Walk an N64 GBI display list (0x01 = load verts, 0x05 = 1 tri, 0x06 = 2 tris, 0xdf = end),
// testing each triangle via swrModel_ClosestPointOnTriangle.
void swrModel_ClosestPointInDisplayList(Gfx* displayList, rdMatrix44* transform, float* minDistSq, int mode, rdVector3* outPoint, rdVector3* outNormal);
// Test all of a node's meshes (mode 0 = via display list, else raw vertices).
void swrModel_NodeClosestPoint(swrModel_Node* node, rdMatrix44* transform, int mode, float* minDistSq, rdVector3* queryPoint, rdVector3* outPoint, rdVector3* outNormal);
// Pick the LOD child index for a node from its per-level distance thresholds (-1 = none).
int swrModel_NodeSelectLOD(swrModel_Node* node);
// Recursively walk the node tree from a query point, accumulating transforms and resolving
// selector/LOD nodes, calling swrModel_NodeClosestPoint at each mesh node.
void swrModel_NodeTreeClosestPoint(swrModel_Node* targetNode, swrModel_Node* node, rdMatrix44* transform, int active, int mode, float* minDistSq, rdVector3* queryPoint, rdVector3* outPoint, rdVector3* outNormal);
// Entry point: find the surface point on a model nearest queryPoint, writing outPoint + outNormal.
void swrModel_FindClosestPointOnModel(swrModel_Node* node, swrModel_Node* targetNode, rdVector3* queryPoint, int maxNodeDepth, void* nodeChainOut, rdVector3* outPoint, rdVector3* outNormal);

void swrModel_LoadPuppet(MODELID model, INGAME_MODELID index, int a3, float a4);

void swrModel_SwapSceneModels(int index, int index2);

#endif // SWRMODEL_H
