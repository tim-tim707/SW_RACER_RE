#ifndef RDMODEL_H
#define RDMODEL_H

#include "types.h"

#define rdModel3_SetRootMaterials_ADDR (0x00408f70)

#define rdMaterial_GetOrCreateDefaultMaterial_ADDR (0x00409040)

#define rdModel3_NewEntry_ADDR (0x0048ee10)
#define rdModel3_Free_ADDR (0x0048ee40)
#define rdModel3_FreeEntry_ADDR (0x0048ee70)
#define rdModel3_Draw_ADDR (0x0048efe0)
#define rdModel3_DrawHNode_ADDR (0x0048f180)
#define rdModel3_DrawMesh_ADDR (0x0048f210)
#define rdModel3_DrawFace_ADDR (0x0048f700)

#define rdModel3_SetFogFlags_ADDR (0x0048FAB0)

void rdModel3_SetRootMaterials(RdModel3* rootModel);

RdMaterial* rdMaterial_GetOrCreateDefaultMaterial(void* curr_asset_buffer_offset);

void rdModel3_NewEntry(RdModel3* pModel);
void rdModel3_Free(RdModel3* model);
void rdModel3_FreeEntry(RdModel3* pModel3);
int rdModel3_Draw(RdThing* pThing, rdMatrix34* pPlacement);
void rdModel3_DrawHNode(rdModel3HNode* pNode);
// Prototype differ from both jkdf and Indy with 2 additional parameters
void rdModel3_DrawMesh(rdModel3Mesh* pMesh, rdMatrix34* pOrient, rdMatrix34* pOrient2, int numVerts2);
void rdModel3_DrawFace(RdFace* pFace, rdVector3* aTransformedVertices, int bIsBackFace, rdVector4* pMeshColor, void* unk5);

void  rdModel3_SetFogFlags(int);

#endif // RDMODEL_H
