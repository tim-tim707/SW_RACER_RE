#ifndef RDMODEL_H
#define RDMODEL_H

#include "types.h"

#define rdModel3_SetRootMaterials_ADDR (0x00408f70)

#define rdMaterial_GetOrCreateDefaultMaterial_ADDR (0x00409040)

#define rdModel3Mesh_CalculateSurfaceNormals_ADDR (0x00409290)

#define rdModel3Mesh_ApplySwrModelColors_ADDR (0x00432B80)
#define rdModel_ConvertSwrModelMesh_ADDR (0x00432D30)

#define AABBFrustumTest_ADDR (0x0044c510)
#define rdModel_Add3064NodeToScene_ADDR (0x0044ca00)
#define rdModel_Add3064NodeToScene2_ADDR (0x0044ceb0)
#define ApplyD065PivotTransform_ADDR (0x0044d1e0)
#define rdModel_AddTransformedNodeToScene_ADDR (0x0044d240)
#define rdModel_AddD066NodeToScene_ADDR (0x0044d310)
#define SelectLODIndexIn5066Node_ADDR (0x0044d740)
#define rdModel_AddNodeToScene_ADDR (0x0044d7c0)
#define rdModel_AddNodeToScene2_ADDR (0x0044dae0)

#define rdModel3_NewEntry_ADDR (0x0048ee10)
#define rdModel3_Free_ADDR (0x0048ee40)
#define rdModel3_FreeEntry_ADDR (0x0048ee70)
#define rdModel3_Draw_ADDR (0x0048efe0)
#define rdModel3_DrawHNode_ADDR (0x0048f180)
#define rdModel3_DrawMesh_ADDR (0x0048f210)
#define rdModel3_DrawFace_ADDR (0x0048f700)

void rdModel3_SetRootMaterials(RdModel3* rootModel);

RdMaterial* rdMaterial_GetOrCreateDefaultMaterial(void* curr_asset_buffer_offset);

void rdModel3Mesh_CalculateSurfaceNormals(rdModel3Mesh* mesh);

void rdModel3Mesh_ApplySwrModelColors(rdModel3Mesh *rdmesh, swrModel_Mesh *mesh);
void rdModel_ConvertSwrModelMesh(Gfx* display_list, rdModel3Mesh* result, swrModel_Mesh* mesh, RdFaceFlag material_flags);

int16_t AABBFrustumTest(float *aabb, bool full_test);
void rdModel_Add3064NodeToScene(swrModel_Node *node);
void rdModel_Add3064NodeToScene2(swrModel_Node *node);
void ApplyD065PivotTransform(rdMatrix34 *inout_transform, const rdMatrix34 *transform, const rdVector3 *pivot);
void rdModel_AddTransformedNodeToScene(int a1, rdMatrix34 *transform, swrModel_Node *node);
void rdModel_AddD066NodeToScene(swrModel_Node *node);
int SelectLODIndexIn5066Node(swrModel_Node *node);
void rdModel_AddNodeToScene(swrModel_Node *a1);
void rdModel_AddNodeToScene2(swrModel_Node *a1);

void rdModel3_NewEntry(RdModel3* pModel);
void rdModel3_Free(RdModel3* model);
void rdModel3_FreeEntry(RdModel3* pModel3);
int rdModel3_Draw(RdThing* pThing, rdMatrix34* pPlacement);
void rdModel3_DrawHNode(rdModel3HNode* pNode);
// Prototype differ from both jkdf and Indy with 2 additional parameters
void rdModel3_DrawMesh(rdModel3Mesh* pMesh, rdMatrix34* pOrient, rdMatrix34* pOrient2, int numVerts2);
void rdModel3_DrawFace(RdFace* pFace, rdVector3* aTransformedVertices, int bIsBackFace, rdVector4* pMeshColor, void* unk5);

#endif // RDMODEL_H
