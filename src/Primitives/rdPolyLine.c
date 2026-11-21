#include "rdPolyLine.h"

#include "globals.h"

#include <General/stdMath.h>
#include <Primitives/rdMatrix.h>
#include <Primitives/rdPrimit3.h>
#include <Raster/rdCache.h>

#include <math.h>

// 0x00493e80
int rdPolyLine_Draw(RdThing* thing, rdMatrix34* matrix)
{
    RdPolyline* polyline;
    rdMatrix34 viewMat;
    rdPrimit3 idxInfo;
    rdVector3 tipLocal;
    rdVector3 tip;
    float dx;
    float dz;
    float len;
    float angle;
    float sinAngle;
    float cosAngle;
    float tipRadiusNeg;
    float baseRadiusNeg;
    float baseRadius;
    float lenSin;
    float lenCos;

    polyline = thing->data.pPolyline;
    idxInfo.aVertLights = NULL;
    idxInfo.aVertIntensities = NULL;
    idxInfo.aVertices = rdPolyLine_aVerticesCache;
    rdMatrix_Multiply34(&viewMat, &rdCamera_pCurCamera->view_matrix, matrix);
    tipLocal.x = 0.0f;
    tipLocal.y = polyline->length;
    tipLocal.z = 0.0f;
    rdMatrix_TransformPoint34(&tip, &tipLocal, &viewMat);

    // tip cap; the cap is lifted 0.001 off the line end
    rdPolyLine_aVerticesCache[0].x = tip.x - polyline->tipRadius;
    rdPolyLine_aVerticesCache[0].y = tip.y + 0.001f;
    rdPolyLine_aVerticesCache[0].z = tip.z - polyline->tipRadius;
    rdPolyLine_aVerticesCache[1].x = tip.x + polyline->tipRadius;
    rdPolyLine_aVerticesCache[1].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[1].z = tip.z - polyline->tipRadius;
    rdPolyLine_aVerticesCache[2].x = tip.x + polyline->tipRadius;
    rdPolyLine_aVerticesCache[2].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[2].z = tip.z + polyline->tipRadius;
    rdPolyLine_aVerticesCache[3].x = tip.x - polyline->tipRadius;
    rdPolyLine_aVerticesCache[3].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[3].z = tip.z + polyline->tipRadius;
    idxInfo.aTexVertices = polyline->apTipUVs;
    rdPolyLine_DrawFace(thing, &polyline->tipFace, rdPolyLine_aVerticesCache, &idxInfo);

    // base cap (faithful: also drawn with the tip face and tip UVs)
    rdPolyLine_aVerticesCache[0].x = viewMat.scale.x - polyline->baseRadius;
    rdPolyLine_aVerticesCache[0].y = viewMat.scale.y + 0.001f;
    rdPolyLine_aVerticesCache[0].z = viewMat.scale.z - polyline->baseRadius;
    rdPolyLine_aVerticesCache[1].x = viewMat.scale.x + polyline->baseRadius;
    rdPolyLine_aVerticesCache[1].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[1].z = viewMat.scale.z - polyline->baseRadius;
    rdPolyLine_aVerticesCache[2].x = viewMat.scale.x + polyline->baseRadius;
    rdPolyLine_aVerticesCache[2].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[2].z = viewMat.scale.z + polyline->baseRadius;
    rdPolyLine_aVerticesCache[3].x = viewMat.scale.x - polyline->baseRadius;
    rdPolyLine_aVerticesCache[3].y = rdPolyLine_aVerticesCache[0].y;
    rdPolyLine_aVerticesCache[3].z = viewMat.scale.z + polyline->baseRadius;
    idxInfo.aTexVertices = polyline->apTipUVs;
    rdPolyLine_DrawFace(thing, &polyline->tipFace, rdPolyLine_aVerticesCache, &idxInfo);

    // edge quad, rotated about view Y to face from base to tip
    dx = tip.x - viewMat.scale.x;
    dz = tip.z - viewMat.scale.z;
    len = sqrtf(dx * dx + dz * dz);
    angle = stdMath_ArcSin3(-dx / len);
    if (dz < 0.0f) {
        if (dx <= 0.0f)
            angle = -(angle + 180.0f);
        else
            angle = 180.0f - angle;
    }
    stdMath_SinCosFast(angle, &sinAngle, &cosAngle);

    tipRadiusNeg = -polyline->tipRadius;
    baseRadiusNeg = -polyline->baseRadius;
    baseRadius = polyline->baseRadius;
    lenSin = len * sinAngle;
    lenCos = len * cosAngle;
    rdPolyLine_aVerticesCache[0].x = (polyline->tipRadius * cosAngle - lenSin) + viewMat.scale.x;
    rdPolyLine_aVerticesCache[0].y = tip.y;
    rdPolyLine_aVerticesCache[0].z = polyline->tipRadius * sinAngle + lenCos + viewMat.scale.z;
    rdPolyLine_aVerticesCache[1].x = (tipRadiusNeg * cosAngle - lenSin) + viewMat.scale.x;
    rdPolyLine_aVerticesCache[1].y = tip.y;
    rdPolyLine_aVerticesCache[1].z = tipRadiusNeg * sinAngle + lenCos + viewMat.scale.z;
    rdPolyLine_aVerticesCache[2].x = baseRadiusNeg * cosAngle + viewMat.scale.x;
    rdPolyLine_aVerticesCache[2].y = viewMat.scale.y;
    rdPolyLine_aVerticesCache[2].z = baseRadiusNeg * sinAngle + viewMat.scale.z;
    rdPolyLine_aVerticesCache[3].x = baseRadius * cosAngle + viewMat.scale.x;
    rdPolyLine_aVerticesCache[3].y = viewMat.scale.y;
    rdPolyLine_aVerticesCache[3].z = baseRadius * sinAngle + viewMat.scale.z;
    idxInfo.aTexVertices = polyline->apEdgeUVs;
    rdPolyLine_DrawFace(thing, &polyline->edgeFace, rdPolyLine_aVerticesCache, &idxInfo);
    return 1;
}

// 0x004941d0
void rdPolyLine_DrawFace(RdThing* pLine, RdFace* pFace, rdVector3* aVertices, rdPrimit3* pIdxInfo)
{
    RdCacheProcEntry* entry;
    RdLightMode lightMode;
    rdPrimit3 clipped;
    char procFlags;

    entry = rdCache_GetProcEntry();
    if (entry == NULL)
        return;

    clipped.aVertices = rdPolyLine_aClipVertices;
    clipped.unknown2 = (int)entry->aVertices;
    clipped.aTexVertices = entry->aUVCoords;
    clipped.aVertLights = entry->aVertColors;
    pIdxInfo->numVertices = pFace->numVertices;
    pIdxInfo->aVertIdxs = pFace->aVertIdxs;
    pIdxInfo->aTexVertIdxs = pFace->aTexIdxs;

    lightMode = rdroid_g_curLightingMode;
    if (pFace->lightingMode <= lightMode)
        lightMode = pFace->lightingMode;
    if (lightMode >= pLine->lightMode)
        lightMode = pLine->lightMode;
    entry->lightingMode = lightMode;

    rdPrimit3_ClipFace(rdCamera_pCurCamera->pClipFrustum, pFace->geometryMode, lightMode, pIdxInfo, &clipped, &pFace->texVertOffset);
    if (clipped.numVertices < 3)
        return;

    rdCamera_pCurCamera->fnProjectLst((rdVector3*)clipped.unknown2, clipped.aVertices, clipped.numVertices);
    entry->extraLight = pFace->extraLight;
    if ((rdroid_g_curRenderOptions & RDROID_USE_AMBIENT_CAMERA_LIGHT) != 0) {
        entry->extraLight.x = rdCamera_pCurCamera->ambientColor.x + entry->extraLight.x;
        entry->extraLight.y = rdCamera_pCurCamera->ambientColor.y + entry->extraLight.y;
        entry->extraLight.z = rdCamera_pCurCamera->ambientColor.z + entry->extraLight.z;
        entry->extraLight.w = rdCamera_pCurCamera->ambientColor.w + entry->extraLight.w;
    }
    procFlags = rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS;
    if (entry->lightingMode >= RD_LIGHTING_GOURAUD)
        procFlags |= rdCache_ProcFaceFLAGS_INTENSITIES;
    entry->matCelNum = pLine->matCelNum;
    entry->flags = pFace->flags;
    entry->pMaterial = pFace->pMaterial;
    rdCache_AddProcFace(clipped.numVertices, procFlags);
}
