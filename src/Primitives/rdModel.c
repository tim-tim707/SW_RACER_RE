#include "rdModel.h"

#include "globals.h"

#include <Engine/rdMaterial.h>
#include <Platform/std3D.h>
#include <Raster/rdFace.h>
#include <Swr/swrModel.h>

#include <macros.h>

#include <stdio.h>
#include <string.h>

// 0x00408f70
void rdModel3_SetRootMaterials(RdModel3* rootModel)
{
    rootModel->apMaterials = swrModel3_root_materials;
    rootModel->numMaterials = swrModel3_root_numMaterials;
}

// 0x00409040
RdMaterial* rdMaterial_GetOrCreateDefaultMaterial(void* curr_asset_buffer_offset)
{
    tVBuffer buffer;
    tVBuffer* pBuffer;
    uint8_t* pixels;

    if (defaultMaterial == NULL) {
        defaultMaterial = rdMaterial_Load(".\\data\\default.mat");
        pBuffer = &buffer;
        pixels = swrModel_AllocMaterial((unsigned int)curr_asset_buffer_offset, 16 * 16 * 2);
        sprintf(defaultMaterial->aName, "Rovermatic");
        // UV scale floats stored unaligned inside the name, overwriting its terminator
        *(float*)(defaultMaterial->aName + 10) = 1.0f;
        *(float*)(defaultMaterial->aName + 14) = 1.0f;
        defaultMaterial->colorInfo.colorMode = T_STDCOLOR_RGB;
        defaultMaterial->colorInfo.bpp = 16;
        defaultMaterial->colorInfo.redBPP = 5;
        defaultMaterial->colorInfo.greenBPP = 6;
        defaultMaterial->colorInfo.blueBPP = 5;
        defaultMaterial->colorInfo.alphaBPP = 0;
        defaultMaterial->colorInfo.redPosShift = 11;
        defaultMaterial->colorInfo.greenPosShift = 5;
        defaultMaterial->colorInfo.bluePosShift = 0;
        defaultMaterial->colorInfo.alphaPosShift = 0;
        defaultMaterial->colorInfo.RedShr = 3;
        defaultMaterial->colorInfo.GreenShr = 2;
        defaultMaterial->colorInfo.BlueShr = 3;
        defaultMaterial->colorInfo.AlphaShr = 0;
        defaultMaterial->formatType = STDCOLOR_FORMAT_RGB;
        defaultMaterial->curCelNum = 1;
        defaultMaterial->numCels = 0;

        pBuffer->bSurfaceAllocated = 0;
        pBuffer->lockSurfRefCount = 0;
        pBuffer->bVideoMemory = 0;
        pBuffer->rasterInfo.width = 16;
        pBuffer->rasterInfo.height = 16;
        pBuffer->rasterInfo.size = 16 * 16 * 2;
        pBuffer->rasterInfo.rowSize = 16 * 2;
        pBuffer->rasterInfo.rowWidth = 16;
        pBuffer->rasterInfo.colorInfo = defaultMaterial->colorInfo;
        pBuffer->pPixels = pixels;
        pBuffer->dword5C = 0;
        memset(pixels, 0xff, 16 * 16 * 2);

        std3D_ClearTexture(defaultMaterial->aTextures);
        std3D_AllocSystemTexture(defaultMaterial->aTextures, &pBuffer, 1, defaultMaterial->formatType);
    }
    return defaultMaterial;
}

// 0x0048ee10
void rdModel3_NewEntry(RdModel3* pModel)
{
    memset(pModel, 0, sizeof(RdModel3));
    strncpy(pModel->aName, "UNKNOWN", 0x3f);
    pModel->aName[0x3f] = '\0';
    pModel->curGeoNum = 0;
}

// 0x0048ee40
void rdModel3_Free(RdModel3* model)
{
    if (model != NULL) {
        if (rdModel3_pUnloader != NULL) {
            rdModel3_pUnloader(model);
            return;
        }
        rdModel3_FreeEntry(model);
        (*rdroid_hostServices_ptr->free)(model);
    }
}

// 0x0048ee70
void rdModel3_FreeEntry(RdModel3* pModel3)
{
    rdModel3GeoSet* geoSet;
    rdModel3Mesh* mesh;
    RdFace* face;
    int geoIdx;
    int meshIdx;
    int faceIdx;
    int matIdx;

    if (pModel3 == NULL) {
        return;
    }
    geoSet = pModel3->aGeos;
    for (geoIdx = 0; geoIdx < pModel3->numGeos; geoIdx++) {
        for (meshIdx = 0; meshIdx < geoSet->numMeshes; meshIdx++) {
            mesh = geoSet->aMeshes + meshIdx;
            if (mesh->apVertices != NULL) {
                (*rdroid_hostServices_ptr->free)(mesh->apVertices);
            }
            if (mesh->apTexVertices != NULL) {
                (*rdroid_hostServices_ptr->free)(mesh->apTexVertices);
            }
            face = mesh->aFaces;
            if (face != NULL) {
                for (faceIdx = 0; faceIdx < mesh->numFaces; faceIdx++) {
                    rdFace_FreeEntry(face);
                    face = face + 1;
                }
                (*rdroid_hostServices_ptr->free)(mesh->aFaces);
            }
            if (mesh->aVertColors != NULL) {
                (*rdroid_hostServices_ptr->free)(mesh->aVertColors);
            }
            if (mesh->aLightIntensities != NULL) {
                (*rdroid_hostServices_ptr->free)(mesh->aLightIntensities);
            }
            if (mesh->aVertNormals != NULL) {
                (*rdroid_hostServices_ptr->free)(mesh->aVertNormals);
            }
        }
        if (geoSet->aMeshes != NULL) {
            (*rdroid_hostServices_ptr->free)(geoSet->aMeshes);
        }
        geoSet = geoSet + 1;
    }
    if (pModel3->aHierarchyNodes != NULL) {
        (*rdroid_hostServices_ptr->free)(pModel3->aHierarchyNodes);
    }
    for (matIdx = 0; matIdx < pModel3->numMaterials; matIdx++) {
        rdMaterial_Free(pModel3->apMaterials[matIdx]);
    }
    if (pModel3->apMaterials != NULL) {
        (*rdroid_hostServices_ptr->free)(pModel3->apMaterials);
    }
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

// Prototype differ from both jkdf and Indy with 2 additional parameters
// 0x0048f210
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
void rdModel3_SetFogFlags(int flags)
{
    if (flags == 0) {
        rdFace_FogFlags = 0;
        return;
    }
    rdFace_FogFlags = (flags == 1) ? RD_FF_3DO_WHIP_AIM : RD_FF_FOG_ENABLED;
}
