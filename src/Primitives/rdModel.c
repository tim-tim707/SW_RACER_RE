#include "rdModel.h"

#include "globals.h"

#include <macros.h>

// 0x00408f70 HOOK
void rdModel3_SetRootMaterials(RdModel3* rootModel)
{
    rootModel->apMaterials = swrModel3_root_materials;
    rootModel->numMaterials = swrModel3_root_numMaterials;
}

// 0x00409040
RdMaterial* rdMaterial_GetOrCreateDefaultMaterial(void* curr_asset_buffer_offset)
{
    HANG("TODO");
}

// 0x00409290
void rdModel3Mesh_CalculateSurfaceNormals(rdModel3Mesh* mesh)
{
    HANG("TODO");
}

// 0x00432B80
void rdModel3Mesh_ApplySwrModelColors(rdModel3Mesh* rdmesh, swrModel_Mesh* mesh)
{
    HANG("TODO");
}

// 0x00432D30
void rdModel_ConvertSwrModelMesh(Gfx* display_list, rdModel3Mesh* result, swrModel_Mesh* mesh, RdFaceFlag material_flags)
{
    HANG("TODO");
}

// 0x0044c510
int16_t AABBFrustumTest(float* aabb, bool full_test)
{
    HANG("TODO");
}

// 0x0044ca00
void rdModel_Add3064NodeToScene(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044ceb0
void rdModel_Add3064NodeToScene2(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d1e0
void ApplyD065PivotTransform(rdMatrix34* inout_transform, const rdMatrix34* transform, const rdVector3* pivot)
{
    HANG("TODO");
}

// 0x0044d240
void rdModel_AddTransformedNodeToScene(int a1, rdMatrix34* transform, swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d310
void rdModel_AddD066NodeToScene(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d740
int SelectLODIndexIn5066Node(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d7c0
void rdModel_AddNodeToScene(swrModel_Node* a1)
{
    HANG("TODO");
}

// 0x0044dae0
void rdModel_AddNodeToScene2(swrModel_Node* a1)
{
    HANG("TODO");
}

// 0x0048ee10
void rdModel3_NewEntry(RdModel3* pModel)
{
    HANG("TODO");
}

// 0x0048ee40
void rdModel3_Free(RdModel3* model)
{
    HANG("TODO");
}

// 0x0048ee70
void rdModel3_FreeEntry(RdModel3* pModel3)
{
    HANG("TODO");
}

// 0x0048efe0
int rdModel3_Draw(RdThing* pThing, rdMatrix34* pPlacement)
{
    HANG("TODO");
}

// 0x0048f180
void rdModel3_DrawHNode(rdModel3HNode* pNode)
{
    HANG("TODO");
}

// 0x0048f210
// Prototype differ from both jkdf and Indy with 2 additional parameters
void rdModel3_DrawMesh(rdModel3Mesh* pMesh, rdMatrix34* pOrient, rdMatrix34* pOrient2, int numVerts2)
{
    HANG("TODO");
}

// 0x0048f700
void rdModel3_DrawFace(RdFace* pFace, rdVector3* aTransformedVertices, int bIsBackFace, rdVector4* pMeshColor, void* unk5)
{
    HANG("TODO");
}
