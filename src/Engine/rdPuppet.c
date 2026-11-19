#include "rdPuppet.h"

#include "globals.h"

#include <Engine/rdClip.h>

#include <macros.h>

// void __cdecl rdPuppet_BuildJointMatrices(RdThing* prdThing, const RdMatrix* pPlacement)
// 0x00493310
void rdPuppet_BuildJointMatrices(void* prdThing, rdMatrix34* pPlacement)
{
    HANG("TODO");
}

static float rdClip_ClampLight(float value)
{
    // NaN compares unordered and lands on the low bound, as the x87 FCOM/C0 test does
    if (!(value >= 0.0f))
        return 0.0f;
    if (value > 1.0f)
        return 1.0f;
    return value;
}

// 0x00493b80
void rdClip_Face3T_Maybe(rdClipFrustum* pFrustum, rdMeshinfo* pSrc, rdMeshinfo* pDst, rdVector2* pTexOffset)
{
    rdVector4* srcLight;
    rdVector4* intensity;
    rdVector4* dstLight;
    rdVector2* dstUV;
    int posIdx;
    int uvIdx;
    unsigned int i;

    rdClip_face3TSrcLights = (rdVector4*)pSrc->paDynamicLight;
    rdClip_face3TDstLights = (rdVector4*)pDst->paDynamicLight;
    // faithful: with no per-face-vertex intensities nothing is gathered into pDst
    if (pSrc->intensities != NULL) {
        rdClip_face3TIntensities = (rdVector4*)pSrc->intensities;
        for (i = 0; i < pSrc->numVertices; i++) {
            posIdx = pSrc->vertexPosIdx[i];
            uvIdx = pSrc->vertexUVIdx[i];
            srcLight = &rdClip_face3TSrcLights[posIdx];
            intensity = &rdClip_face3TIntensities[i];
            dstLight = &rdClip_face3TDstLights[i];
            dstUV = &pDst->vertexUVs[i];

            dstLight->x = rdClip_ClampLight(srcLight->x + intensity->x);
            *dstUV = pSrc->vertexUVs[uvIdx];
            dstLight->y = rdClip_ClampLight(srcLight->y + intensity->y);
            pDst->verticesProjected[i] = pSrc->verticesProjected[posIdx];
            dstLight->z = rdClip_ClampLight(srcLight->z + intensity->z);
            dstUV->x = pTexOffset->x + dstUV->x;
            dstUV->y = dstUV->y + pTexOffset->y;
            dstLight->w = rdClip_ClampLight(srcLight->w + intensity->w);
        }
    }

    if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
        pDst->numVertices = rdClip_Face3TTestFrustum_Maybe(pFrustum, pSrc);
        if (pDst->numVertices != 0)
            pDst->numVertices = rdClip_Face3TClipPlane_Maybe(pFrustum, pSrc, pDst);
    } else {
        pDst->numVertices = rdClip_Face3TOrtho(pFrustum, pDst->verticesProjected, pDst->vertexUVs, rdClip_face3TDstLights, pSrc->numVertices);
    }
}
