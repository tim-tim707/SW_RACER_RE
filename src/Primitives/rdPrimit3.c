#include "rdPrimit3.h"

#include <macros.h>

// 0x004910a0
void rdPrimit3_ClipFace(rdClipFrustum* pFrustrum, RdGeometryMode geoMode, RdLightMode lightMode, rdPrimit3* pSrc, rdPrimit3* pDest, rdVector2* pTexVertOffset)
{
    HANG("TODO");
}

static float rdPrimit3_ClampIntensity(float value)
{
    if (!(value >= 0.0f))
        return 0.0f;
    if (value > 1.0f)
        return 1.0f;
    return value;
}

// Gouraud: per-vertex light = dynamic light (+ static intensity on rgb, when present), clamped.
static void rdPrimit3_CopyVertexLight(rdMeshinfo* src, rdMeshinfo* dst, unsigned int i)
{
    float* dynamicLight = &src->paDynamicLight[src->vertexPosIdx[i] * 4];
    float* out = &dst->paDynamicLight[i * 4];
    int k;

    if (src->intensities == NULL) {
        for (k = 0; k < 4; k++)
            out[k] = rdPrimit3_ClampIntensity(dynamicLight[k]);
        return;
    }
    for (k = 0; k < 3; k++)
        out[k] = rdPrimit3_ClampIntensity(dynamicLight[k] + src->intensities[i * 4 + k]);
    out[3] = rdPrimit3_ClampIntensity(dynamicLight[3]);
}

// 0x00491ac0
void rdPrimit3_NoClipFace(rdGeoMode_t geoMode, int lightMode, rdMeshinfo* _vertexSrc, rdMeshinfo* _vertexDst, rdVector2* idkIn)
{
    unsigned int i;

    switch (geoMode) {
    case RD_GEOMETRY_NONE:
    case RD_GEOMETRY_VERTEX:
    case RD_GEOMETRY_WIREFRAME:
        for (i = 0; i < _vertexSrc->numVertices; i++)
            _vertexDst->verticesProjected[i] = _vertexSrc->verticesProjected[_vertexSrc->vertexPosIdx[i]];
        break;
    case RD_GEOMETRY_SOLID:
        if (lightMode < RD_LIGHTING_NONE || lightMode > RD_LIGHTING_GOURAUD)
            return;
        for (i = 0; i < _vertexSrc->numVertices; i++) {
            _vertexDst->verticesProjected[i] = _vertexSrc->verticesProjected[_vertexSrc->vertexPosIdx[i]];
            if (lightMode == RD_LIGHTING_GOURAUD)
                rdPrimit3_CopyVertexLight(_vertexSrc, _vertexDst, i);
        }
        break;
    case RD_GEOMETRY_FULL:
        if (lightMode < RD_LIGHTING_NONE || lightMode > RD_LIGHTING_GOURAUD)
            return;
        for (i = 0; i < _vertexSrc->numVertices; i++) {
            _vertexDst->verticesProjected[i] = _vertexSrc->verticesProjected[_vertexSrc->vertexPosIdx[i]];
            _vertexDst->vertexUVs[i] = _vertexSrc->vertexUVs[_vertexSrc->vertexUVIdx[i]];
            _vertexDst->vertexUVs[i].x = idkIn->x + _vertexDst->vertexUVs[i].x;
            _vertexDst->vertexUVs[i].y = _vertexDst->vertexUVs[i].y + idkIn->y;
            if (lightMode == RD_LIGHTING_GOURAUD)
                rdPrimit3_CopyVertexLight(_vertexSrc, _vertexDst, i);
        }
        break;
    default:
        return;
    }
    _vertexDst->numVertices = _vertexSrc->numVertices;
}
