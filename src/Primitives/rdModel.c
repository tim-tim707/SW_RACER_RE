#include "rdModel.h"

#include "globals.h"

#include <Engine/rdLight.h>
#include <Engine/rdMaterial.h>
#include <Engine/rdPuppet.h>
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include <Primitives/rdPrimit2.h>
#include <Primitives/rdPrimit3.h>
#include <Primitives/rdVector.h>
#include <Raster/rdCache.h>
#include <Raster/rdFace.h>
#include <Swr/swrModel.h>
#include <Swr/swrRender.h>

#include <macros.h>

#include <math.h>
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
    int geosetNum;
    unsigned int i;
    rdLight* light;
    rdVector3 delta;

    rdModel3_pCurThing = pThing;
    rdModel3_g_numDrawnAlphaFaces = 0;
    rdModel3_g_numDrawnFaces = 0;
    rdModel3_pCurModel = pThing->data.pModel3;
    if (pThing->frustumCullStatus == 2)
        return 0;

    geosetNum = pThing->geosetNum;
    if (geosetNum == -1)
        geosetNum = rdModel3_pCurModel->curGeoNum;
    rdModel3_pCurGeoSet = &rdModel3_pCurModel->aGeos[geosetNum];

    if (rdModel3_pCurThing->rdFrameNum != rdCache_GetFrameNum() || rdCamera_pCurCamera->canvas->vbuffer->rasterInfo.colorInfo.bpp == 8) {
        rdPuppet_BuildJointMatrices(rdModel3_pCurThing, pPlacement);
    }

    rdroid_g_curLightingMode2 = rdModel3_pCurThing->lightMode;
    if (rdModel3_pCurThing->lightMode >= rdroid_g_curLightingMode)
        rdroid_g_curLightingMode2 = rdroid_g_curLightingMode;

    if (rdroid_g_curLightingMode2 > RD_LIGHTING_LIT) {
        rdModel3_g_numGeoLights = 0;
        for (i = 0; i < (unsigned int)rdCamera_pCurCamera->numLights; i++) {
            light = rdCamera_pCurCamera->lights[i];
            if (light->active != 1)
                continue;
            if (light->type == RD_LIGHT_TYPE_POINT) {
                // positions indexed by slot here, by light->id in rdModel3_DrawMesh
                delta.x = rdCamera_pCurCamera->lightPositions[i].x - pPlacement->scale.x;
                delta.y = rdCamera_pCurCamera->lightPositions[i].y - pPlacement->scale.y;
                delta.z = rdCamera_pCurCamera->lightPositions[i].z - pPlacement->scale.z;
                if (sqrtf(delta.x * delta.x + delta.y * delta.y + delta.z * delta.z) < light->falloffMin + rdModel3_pCurModel->size) {
                    rdModel3_g_apGeoLights[rdModel3_g_numGeoLights++] = light;
                }
            } else if (light->type == RD_LIGHT_TYPE_DIRECTIONAL) {
                rdModel3_g_apGeoLights[rdModel3_g_numGeoLights++] = light;
            }
        }
    }

    rdModel3_DrawHNode(rdModel3_pCurModel->aHierarchyNodes);
    return 1;
}

// 0x0048f180
void rdModel3_DrawHNode(rdModel3HNode* pNode)
{
    rdModel3HNode* child;
    unsigned int i;

    if (pNode->meshIdx != -1) {
        rdModel3_DrawMesh(&rdModel3_pCurGeoSet->aMeshes[pNode->meshIdx], &pNode->meshOrient, &pNode->boneMatrix, pNode->vertexBaseOffset);
    }
    if (pNode->numChildren == 0)
        return;

    child = pNode->pChild;
    for (i = 0; i < (unsigned int)pNode->numChildren; i++) {
        if (rdModel3_pCurThing->paJointAmputationFlags == NULL || rdModel3_pCurThing->paJointAmputationFlags[child->num] == 0) {
            rdModel3_DrawHNode(child);
        }
        child = child->pSibling;
    }
}

// Prototype differ from both jkdf and Indy with 2 additional parameters
// 0x0048f210
void rdModel3_DrawMesh(rdModel3Mesh* pMesh, rdMatrix34* pOrient, rdMatrix34* pOrient2, int numVerts2)
{
    rdMatrix34 viewMat;
    rdMatrix34 invOrient;
    rdVector3 camPos;
    rdVector3 delta;
    rdVector3* aVertices;
    rdVector3* v;
    rdLight* light;
    RdFace* pFace;
    int numVertices;
    int bIsBackFace;
    int bVisible;
    unsigned int i;

    rdModel3_g_pCurMesh = pMesh;
    // sign-extended selector vs zero-extended cache: values >= 0x80 never match
    if ((int)(signed char)pMesh->unk89 != (int)rdModel3_curLightSet) {
        rdModel3_curLightSet = pMesh->unk89;
        if (pMesh->unk89 == 0)
            rdCamera_SetLights(0, 1);
        else
            rdCamera_SetLights(rdModel_CurrentLightIndex, rdModel_CurrentLightNum);
    }
    if (rdModel3_g_pCurMesh->unk84 == 0) {
        rdModel3_g_pCurMesh->unk86 = 0;
        return;
    }

    if (rdModel3_g_pCurMesh->geoMode != RD_GEOMETRY_NONE) {
        aVertices = rdModel3_g_pCurMesh->apVertices;
        numVertices = rdModel3_g_pCurMesh->numVertices;
        rdMatrix_Multiply34(&viewMat, &rdCamera_pCurCamera->view_matrix, pOrient);
        rdMatrix_TransformPointLst34(&viewMat, aVertices, rdModel3_aView, numVertices);
        if (numVerts2 > 0) {
            rdMatrix_Multiply34(&viewMat, &rdCamera_pCurCamera->view_matrix, pOrient2);
            rdMatrix_TransformPointLst34(&viewMat, aVertices, rdModel3_aView, numVerts2);
        }
        rdMatrix_InvertOrthoNorm34(&invOrient, pOrient);

        rdModel3_g_lightingMode = rdModel3_g_pCurMesh->lightMode;
        if (rdModel3_g_pCurMesh->lightMode >= rdroid_g_curLightingMode2)
            rdModel3_g_lightingMode = rdroid_g_curLightingMode2;

        rdModel3_clipSrc.verticesProjected = rdModel3_aView;
        rdModel3_clipDst.verticesProjected = rdModel3_aClippedVerts;
        rdModel3_clipSrc.vertexUVs = rdModel3_g_pCurMesh->apTexVertices;
        rdModel3_clipSrc.paDynamicLight = (float*)rdModel3_g_pCurMesh->aLightIntensities;
        rdModel3_clipSrc.intensities = NULL;

        if (rdModel3_g_lightingMode == RD_LIGHTING_DIFFUSE) {
            rdModel3_g_numMeshLights = 0;
            for (i = 0; i < (unsigned int)rdModel3_g_numGeoLights; i++) {
                light = rdModel3_g_apGeoLights[i];
                delta.x = rdCamera_pCurCamera->lightPositions[light->id].x - pOrient->scale.x;
                delta.y = rdCamera_pCurCamera->lightPositions[light->id].y - pOrient->scale.y;
                delta.z = rdCamera_pCurCamera->lightPositions[light->id].z - pOrient->scale.z;
                if (sqrtf(delta.x * delta.x + delta.y * delta.y + delta.z * delta.z) < light->falloffMin + rdModel3_g_pCurMesh->radius) {
                    rdModel3_apMeshLights[rdModel3_g_numMeshLights] = light;
                    rdMatrix_TransformPoint34(&rdModel3_g_aLocalLightPos[rdModel3_g_numMeshLights], &rdCamera_pCurCamera->lightPositions[light->id], &invOrient);
                    rdModel3_g_numMeshLights++;
                }
            }
        } else if (rdModel3_g_lightingMode == RD_LIGHTING_GOURAUD) {
            rdModel3_g_numMeshLights = 0;
            for (i = 0; i < (unsigned int)rdModel3_g_numGeoLights; i++) {
                light = rdModel3_g_apGeoLights[i];
                if (light->type == RD_LIGHT_TYPE_DIRECTIONAL) {
                    rdModel3_apMeshLights[rdModel3_g_numMeshLights] = light;
                    rdMatrix_TransformVector34(&rdModel3_g_aLocalLightPos[rdModel3_g_numMeshLights], &rdCamera_pCurCamera->lightPositions[light->id], &invOrient);
                    rdVector_Normalize3Acc_2(&rdModel3_g_aLocalLightPos[rdModel3_g_numMeshLights]);
                    rdModel3_g_numMeshLights++;
                } else if (light->type == RD_LIGHT_TYPE_POINT) {
                    delta.x = rdCamera_pCurCamera->lightPositions[light->id].x - pOrient->scale.x;
                    delta.y = rdCamera_pCurCamera->lightPositions[light->id].y - pOrient->scale.y;
                    delta.z = rdCamera_pCurCamera->lightPositions[light->id].z - pOrient->scale.z;
                    if (sqrtf(delta.x * delta.x + delta.y * delta.y + delta.z * delta.z) < light->falloffMin + rdModel3_g_pCurMesh->radius) {
                        rdModel3_apMeshLights[rdModel3_g_numMeshLights] = light;
                        rdMatrix_TransformPoint34(&rdModel3_g_aLocalLightPos[rdModel3_g_numMeshLights], &rdCamera_pCurCamera->lightPositions[light->id], &invOrient);
                        rdModel3_g_numMeshLights++;
                    }
                }
            }
            // faithful: the camera's light list is passed with the mesh-local positions
            rdLight_CalcVertexIntensities(rdCamera_pCurCamera->lights, rdModel3_g_aLocalLightPos, rdCamera_pCurCamera->numLights, rdModel3_g_pCurMesh->aVertNormals, rdModel3_g_pCurMesh->apVertices, rdModel3_g_pCurMesh->aVertColors, rdModel3_g_pCurMesh->aLightIntensities, rdModel3_g_pCurMesh->numVertices, rdCamera_pCurCamera->attenuationMin);
        }

        camPos = rdCamera_camMatrix.scale;
        rdMatrix_TransformPoint34(&rdModel3_g_localCamera, &camPos, &invOrient);

        pFace = pMesh->aFaces;
        for (i = 0; i < (unsigned int)pMesh->numFaces; i++, pFace++) {
            v = &rdModel3_g_pCurMesh->apVertices[pFace->aVertIdxs[0]];
            bIsBackFace = (rdModel3_g_localCamera.x - v->x) * pFace->normal.x + (rdModel3_g_localCamera.z - v->z) * pFace->normal.z + (rdModel3_g_localCamera.y - v->y) * pFace->normal.y <= 0.0f;
            if (rdModel3_g_pCurMesh->unk86 > 1)
                bIsBackFace = !bIsBackFace;

            // RD_FF_MIRRORED faces are drawn from the back instead of the front
            if (bIsBackFace)
                bVisible = (pFace->flags & RD_FF_MIRRORED) != 0;
            else
                bVisible = (pFace->flags & RD_FF_MIRRORED) == 0;
            if ((pFace->flags & RD_FF_DOUBLE_SIDED) != 0 || (rdroid_g_curRenderOptions2 == RDROID_BACKFACE_CULLING_ENABLED && (pFace->flags & RD_FF_MIRRORED) != 0)) {
                bVisible = 1;
            }
            if (bVisible || numVerts2 > 0)
                rdModel3_DrawFace(pFace, bIsBackFace, &pMesh->meshColor, pMesh->uvOffsetU, pMesh->uvOffsetV);
        }
    }

    rdModel3_g_pCurMesh->unk84--;
    if (rdModel3_g_pCurMesh->unk84 == 0)
        rdModel3_g_pCurMesh->unk86 = 0;
}

// 0x0048f700
int rdModel3_DrawFace(RdFace* pFace, int bIsBackFace, rdVector4* pMeshColor, float uvOffsetU, float uvOffsetV)
{
    RdCacheProcEntry* entry;
    rdVector3 normal;
    rdVector4 faceLight;
    rdVector3* projected;
    unsigned int i;
    unsigned int next;
    float zNear;
    char procFlags;

    entry = rdCache_GetProcEntry();
    if (entry == NULL)
        return 0;

    entry->lightingMode = pFace->lightingMode;
    if (rdModel3_g_lightingMode < pFace->lightingMode)
        entry->lightingMode = rdModel3_g_lightingMode;
    rdModel3_clipDst.verticesOrig = entry->aVertices;
    rdModel3_clipDst.vertexUVs = entry->aUVCoords;
    rdModel3_clipDst.paDynamicLight = (float*)entry->aVertColors;
    rdModel3_clipSrc.numVertices = pFace->numVertices;
    rdModel3_clipSrc.vertexPosIdx = pFace->aVertIdxs;
    rdModel3_clipSrc.vertexUVIdx = pFace->aTexIdxs;

    if (rdCamera_pCurCamera->canvas->vbuffer->rasterInfo.colorInfo.bpp == 8) {
        rdPrimit3_NoClipFace((rdGeoMode_t)pFace->geometryMode, entry->lightingMode, &rdModel3_clipSrc, &rdModel3_clipDst, &pFace->texVertOffset);
    } else {
        rdClip_Face3T_Maybe(rdCamera_pCurCamera->pClipFrustum, &rdModel3_clipSrc, &rdModel3_clipDst, &pFace->texVertOffset);
    }
    if (rdModel3_clipDst.numVertices < 3)
        return 0;

    entry->extraLight = pFace->extraLight;
    if (entry->lightingMode == RD_LIGHTING_DIFFUSE) {
        if (bIsBackFace) {
            normal.x = -pFace->normal.x;
            normal.y = -pFace->normal.y;
            normal.z = -pFace->normal.z;
            rdLight_CalcFaceIntensity(rdCamera_pCurCamera->lights, rdModel3_g_aLocalLightPos, rdCamera_pCurCamera->numLights, (rdFace*)pFace, &normal, rdModel3_g_pCurMesh->apVertices, rdCamera_pCurCamera->attenuationMin, &faceLight);
        } else {
            rdLight_CalcFaceIntensity(rdCamera_pCurCamera->lights, rdModel3_g_aLocalLightPos, rdCamera_pCurCamera->numLights, (rdFace*)pFace, &pFace->normal, rdModel3_g_pCurMesh->apVertices, rdCamera_pCurCamera->attenuationMin, &faceLight);
        }
        entry->extraLight.x = faceLight.x + entry->extraLight.x;
        entry->extraLight.y = faceLight.y + entry->extraLight.y;
        entry->extraLight.z = faceLight.z + entry->extraLight.z;
        entry->extraLight.w = faceLight.w + entry->extraLight.w;
    }

    rdCamera_pCurCamera->fnProjectLst(rdModel3_clipDst.verticesOrig, rdModel3_clipDst.verticesProjected, rdModel3_clipDst.numVertices);

    if ((rdroid_g_curRenderOptions & RDROID_USE_AMBIENT_CAMERA_LIGHT) != 0) {
        entry->extraLight.x = rdCamera_pCurCamera->ambientColor.x + entry->extraLight.x;
        entry->extraLight.y = rdCamera_pCurCamera->ambientColor.y + entry->extraLight.y;
        entry->extraLight.z = rdCamera_pCurCamera->ambientColor.z + entry->extraLight.z;
        entry->extraLight.w = rdCamera_pCurCamera->ambientColor.w + entry->extraLight.w;
    }

    if (pMeshColor->w != 1.0f) {
        entry->extraLight.w = entry->extraLight.w * pMeshColor->w * 0.5f;
        for (i = 0; i < rdModel3_clipDst.numVertices; i++)
            entry->aVertColors[i].w = entry->aVertColors[i].w * pMeshColor->w * 0.5f;
    }

    entry->matCelNum = pFace->matCelNum;
    procFlags = rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS;
    if (entry->lightingMode >= RD_LIGHTING_GOURAUD)
        procFlags |= rdCache_ProcFaceFLAGS_INTENSITIES;
    entry->flags = rdFace_FogFlags | pFace->flags;
    if ((pFace->flags & RD_FF_NEAR_PLANE) != 0) {
        zNear = rdCamera_pCurCamera->pClipFrustum->zNear;
        for (i = 0; i < rdModel3_clipDst.numVertices; i++)
            entry->aVertices[i].z = zNear;
    }
    if (pMeshColor->w != 1.0f)
        entry->flags |= RD_FF_TEX_TRANSLUCENT;
    entry->pMaterial = pFace->pMaterial;
    entry->uv_offset.x = uvOffsetU;
    entry->uv_offset.y = uvOffsetV;

    if (rdCamera_pCurCamera->canvas->vbuffer->rasterInfo.colorInfo.bpp != 8) {
        rdModel3_g_numDrawnFaces++;
        rdCache_AddProcFace(rdModel3_clipDst.numVertices, procFlags | rdCache_ProcFaceFLAGS_INTENSITIES);
        return 1;
    }

    projected = rdModel3_clipDst.verticesOrig;
    for (i = 0; i < rdModel3_clipDst.numVertices; i++) {
        next = (i < rdModel3_clipDst.numVertices - 1) ? i + 1 : 0;
        rdPrimit2_DrawClippedLine(rdCamera_pCurCamera->canvas, (int)projected[i].x, (int)projected[i].y, (int)projected[next].x, (int)projected[next].y, 0, -1);
    }
    return 0;
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
