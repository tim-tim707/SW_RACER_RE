#include "rdParticle.h"

#include "globals.h"

#include <Engine/rdClip.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>

// 0x00494330
int rdParticle_Draw(RdThing* pParticle, rdMatrix34* pOrient)
{
    RdParticle* particle;
    RdCacheProcEntry* entry;
    RdLightMode lightingMode;
    rdMatrix34 viewMat;
    rdVector3 viewPos;
    rdVector4 ambient;
    rdVector3* v;
    unsigned int i;

    particle = pParticle->data.pParticle;
    rdMatrix_TransformPoint34(&viewPos, &pOrient->scale, &rdCamera_pCurCamera->view_matrix);
    if (pParticle->frustumCullStatus == 2)
        return 0;

    rdMatrix_Multiply34(&viewMat, &rdCamera_pCurCamera->view_matrix, pOrient);
    if ((rdroid_g_curRenderOptions & RDROID_USE_AMBIENT_CAMERA_LIGHT) != 0) {
        ambient = rdCamera_pCurCamera->ambientColor;
    } else {
        ambient.x = 0.0f;
        ambient.y = 0.0f;
        ambient.z = 0.0f;
        ambient.w = 0.0f;
    }
    lightingMode = particle->lightningMode;
    rdMatrix_TransformPointLst34(&viewMat, particle->aVerticies, rdParticle_aTransformedVertices, particle->numVertices);

    for (i = 0; i < (unsigned int)particle->numVertices; i++) {
        entry = rdCache_GetAlphaProcEntry();
        if (entry == NULL)
            return 0;

        v = &rdParticle_aTransformedVertices[i];
        rdParticle_aFaceVertices[0].x = v->x - particle->sizeHalf;
        rdParticle_aFaceVertices[0].y = v->y;
        rdParticle_aFaceVertices[0].z = v->z - particle->sizeHalf;
        rdParticle_aFaceVertices[1].x = v->x + particle->sizeHalf;
        rdParticle_aFaceVertices[1].y = v->y;
        rdParticle_aFaceVertices[1].z = v->z - particle->sizeHalf;
        rdParticle_aFaceVertices[2].x = v->x + particle->sizeHalf;
        rdParticle_aFaceVertices[2].y = v->y;
        rdParticle_aFaceVertices[2].z = v->z + particle->sizeHalf;
        rdParticle_aFaceVertices[3].x = v->x - particle->sizeHalf;
        rdParticle_aFaceVertices[3].y = v->y;
        rdParticle_aFaceVertices[3].z = v->z + particle->sizeHalf;
        if (rdClip_Face3S(rdCamera_pCurCamera->pClipFrustum, rdParticle_aFaceVertices, 4) != 4)
            continue;

        rdCamera_pCurCamera->fnProjectLst(entry->aVertices, rdParticle_aFaceVertices, 4);
        entry->flags = 0;
        entry->extraLight = ambient;
        entry->lightingMode = lightingMode;
        entry->pMaterial = particle->pMaterial;
        entry->matCelNum = particle->aVertMatCelNums[i];
        entry->aUVCoords[0].x = 0.0f;
        entry->aUVCoords[0].y = 0.0f;
        entry->aUVCoords[1].x = 1.0f;
        entry->aUVCoords[1].y = 0.0f;
        entry->aUVCoords[2].x = 1.0f;
        entry->aUVCoords[2].y = 1.0f;
        entry->aUVCoords[3].x = 0.0f;
        entry->aUVCoords[3].y = 1.0f;
        // faithful: overwrites the camera ambient stored just above
        entry->extraLight = particle->aExtraLights[i];
        rdCache_AddAlphaProcFace(4, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
    }
    return 1;
}
