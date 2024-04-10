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

// 0x0048FAB0
void rdModel3_SetFogFlags(int)
{
    HANG("TODO");
}