#include "rdCache.h"

#include "engine_config.h"
#include "globals.h"
#include "Platform/std3D.h"

#include <General/stdEffect.h>

#include <float.h>
#include <macros.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

// 0x0048db40
void rdCache_Startup(void)
{
    // Zero the leading RDCACHE_MAX_VERTICES *bytes* of the HW vertex scratch
    // buffer (a dword-at-a-time clear in the original; the count is in bytes,
    // not vertices).
    int* hwVertexData = (int*)rdCache_aHWVertices;
    for (unsigned int i = 0; i < RDCACHE_MAX_VERTICES / sizeof(int); i++)
        hwVertexData[i] = 0;
    rdCache_frameNum = 0;
}

// 0x0048db60
void rdCache_AdvanceFrame(void)
{
    rdCache_drawnFaces = 0;
    rdCache_frameNum = rdCache_frameNum + 1;
}

// 0x0048db80
int rdCache_GetFrameNum(void)
{
    return rdCache_frameNum;
}

// 0x0048db90
int rdCache_GetDrawnFacesNum(void)
{
    return rdCache_drawnFaces;
}

// 0x0048dba0
RdCacheProcEntry* rdCache_GetProcEntry(void)
{
    if ((unsigned int)rdCache_numProcFaces >= RDCACHE_MAX_TRIS)
        rdCache_Flush();
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedVertices < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedTexVertices < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedIntensities < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    RdCacheProcEntry* entry = rdCache_aProcFaces + rdCache_numProcFaces;
    entry->aVertices = rdCache_aVertices + rdCache_numUsedVertices;
    entry->aUVCoords = rdCache_aTexVertices + rdCache_numUsedTexVertices;
    entry->aVertColors = rdCache_aVertIntensities + rdCache_numUsedIntensities;
    return entry;
}

// 0x0048dc40
RdCacheProcEntry* rdCache_GetAlphaProcEntry(void)
{
    if ((unsigned int)rdCache_numAlphaProcFaces >= RDCACHE_MAX_TRIS) {
        rdCache_Flush();
        rdCache_FlushAlpha();
    }
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedAlphaVertices < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedAlphaTexVertices < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    if (RDCACHE_MAX_VERTICES - rdCache_numUsedAlphaIntensities < RDCACHE_MIN_FREE_VERTICES)
        return NULL;
    RdCacheProcEntry* entry = rdCache_aAlphaProcFaces + rdCache_numAlphaProcFaces;
    entry->aVertices = rdCache_aAlphaVertices + rdCache_numUsedAlphaVertices;
    entry->aUVCoords = rdCache_aAlphaTexVertices + rdCache_numUsedAlphaTexVertices;
    entry->unk1 = 0;
    entry->aVertColors = rdCache_aAlphaVertIntensities + rdCache_numUsedAlphaIntensities;
    return entry;
}

// 0x0048dce0
void rdCache_Flush(void)
{
    if (rdCache_numProcFaces != 0) {
        std3D_StartScene();
        switch (rdroid_g_curGeometryMode) {
        case RD_GEOMETRY_NONE:
            break;
        case RD_GEOMETRY_VERTEX:
        case RD_GEOMETRY_WIREFRAME:
            rdCache_SendWireframeFaceListToHardware(rdCache_numProcFaces, rdCache_aProcFaces);
            break;
        default:
            rdCache_SendFaceListToHardware(rdCache_numProcFaces, rdCache_aProcFaces);
        }
        rdCache_drawnFaces += rdCache_numProcFaces;
        rdCache_numProcFaces = 0;
        rdCache_numUsedVertices = 0;
        rdCache_numUsedTexVertices = 0;
        rdCache_numUsedIntensities = 0;
        std3D_EndScene();
    }
}

// 0x0048dd80
size_t rdCache_FlushAlpha(void)
{
    size_t numFaces = rdCache_numAlphaProcFaces;

    if (rdCache_numAlphaProcFaces != 0) {
        switch (rdroid_g_curGeometryMode) {
        case RD_GEOMETRY_NONE:
            break;
        case RD_GEOMETRY_VERTEX:
        case RD_GEOMETRY_WIREFRAME:
            rdCache_SendWireframeFaceListToHardware(rdCache_numAlphaProcFaces, rdCache_aAlphaProcFaces);
            break;
        default:
            rdCache_SendFaceListToHardware(rdCache_numAlphaProcFaces, rdCache_aAlphaProcFaces);
        }
        rdCache_numAlphaProcFaces = 0;
        rdCache_drawnFaces += numFaces;
        rdCache_numUsedAlphaVertices = 0;
        rdCache_numUsedAlphaTexVertices = 0;
        rdCache_numUsedAlphaIntensities = 0;
    }
    return numFaces;
}

// OpenJKDF2 Modified
// 0x0048de10
int rdCache_AddProcFace(unsigned int nbVertices, char flags)
{
    if ((unsigned int)rdCache_numProcFaces < RDCACHE_MAX_TRIS) {
        RdCacheProcEntry* entry = rdCache_aProcFaces + rdCache_numProcFaces;
        float minZ = FLT_MAX;
        entry->numVertices = nbVertices;
        if (nbVertices != 0) {
            rdVector3* vertex = entry->aVertices;
            unsigned int remaining = nbVertices;
            do {
                if (vertex->z < minZ)
                    minZ = vertex->z;
                vertex++;
                remaining--;
            } while (remaining != 0);
        }
        entry->distance = minZ;
        if (flags & rdCache_ProcFaceFLAGS_VERTICES)
            rdCache_numUsedVertices += nbVertices;
        if (flags & rdCache_ProcFaceFLAGS_UVS)
            rdCache_numUsedTexVertices += nbVertices;
        if (flags & rdCache_ProcFaceFLAGS_INTENSITIES)
            rdCache_numUsedIntensities += nbVertices;
        rdCache_numProcFaces++;
        return 1;
    }
    return 0;
}

// 0x0048dea0
size_t rdCache_AddAlphaProcFace(int numVertices, char flags)
{
    if ((unsigned int)rdCache_numAlphaProcFaces < RDCACHE_MAX_TRIS) {
        RdCacheProcEntry* entry = rdCache_aAlphaProcFaces + rdCache_numAlphaProcFaces;
        float minZ = FLT_MAX;
        entry->numVertices = numVertices;
        if (numVertices != 0) {
            rdVector3* vertex = entry->aVertices;
            int remaining = numVertices;
            do {
                if (vertex->z < minZ)
                    minZ = vertex->z;
                vertex++;
                remaining--;
            } while (remaining != 0);
        }
        entry->distance = minZ;
        if (flags & rdCache_ProcFaceFLAGS_VERTICES)
            rdCache_numUsedAlphaVertices += numVertices;
        if (flags & rdCache_ProcFaceFLAGS_UVS)
            rdCache_numUsedAlphaTexVertices += numVertices;
        if (flags & rdCache_ProcFaceFLAGS_INTENSITIES)
            rdCache_numUsedAlphaIntensities += numVertices;
        rdCache_numAlphaProcFaces++;
        return 1;
    }
    return 0;
}

// 0x0048df30
void rdCache_SendFaceListToHardware(size_t numPolys, RdCacheProcEntry* aPolys)
{
    RdCacheProcEntry* poly;
    RdMaterial* material;
    LPDIRECT3DTEXTURE2 texture;
    D3DTLVERTEX* hw;
    rdVector3* v;
    rdVector4* c;
    RdFaceFlag flags;
    Std3DRenderState renderState;
    RdLightMode lightingMode;
    size_t polysDone;
    unsigned int i;
    int indexCount;
    int baseVertex;
    int fanFirst;
    int fanMid;
    int fanLast;
    int numTris;
    int k;
    int32_t zBits;
    float approx;
    float rhw;
    float r;
    float g;
    float b;
    float a;
    float scaled;

    std3D_SetProjection(rdCamera_pCurCamera->fov, rdCamera_pCurCamera->screenAspectRatio, rdCamera_pCurCamera->pClipFrustum->zNear, rdCamera_pCurCamera->pClipFrustum->zFar);
    stdEffect_GetFadeFactor();

    polysDone = 0;
    poly = aPolys;
    while (polysDone < numPolys) {
        flags = poly->flags;
        renderState = STD3D_RS_UNKNOWN_1 | STD3D_RS_UNKNOWN_2 | STD3D_RS_UNKNOWN_10;
        if ((flags & RD_FF_TEX_TRANSLUCENT) != 0)
            renderState |= STD3D_RS_BLEND_MODULATE;
        if ((flags & RD_FF_TEX_CLAMP_X) != 0)
            renderState |= STD3D_RS_TEX_CLAMP_U;
        if ((flags & RD_FF_TEX_CLAMP_Y) != 0)
            renderState |= STD3D_RS_TEX_CLAMP_V;
        if ((flags & RD_FF_TEX_FILTER_NEAREST) == 0)
            renderState |= STD3D_RS_TEX_MAGFILTER_LINEAR;
        if ((flags & RD_FF_ZWRITE_DISABLED) != 0)
            renderState |= STD3D_RS_ZWRITE_DISABLED;
        if ((flags & (RD_FF_FOG_ENABLED | RD_FF_3DO_WHIP_AIM)) != 0)
            renderState |= STD3D_RS_FOG_ENABLED;

        material = poly->pMaterial;
        if (material == NULL) {
            texture = NULL;
        } else {
            if (material->formatType != STDCOLOR_FORMAT_RGB)
                renderState |= STD3D_RS_BLEND_MODULATEALPHA;
            rdCache_AddToTextureCache(material->aTextures, material->formatType);
            texture = material->aTextures->pD3DCachedTex;
        }

        indexCount = 0;
        rdCache_numHWVertices = 0;
        rdCache_currentZNear = rdCamera_pCurCamera->pClipFrustum->zNear;
        // batch consecutive polys sharing material and flags into one draw
        for (;;) {
            rdCache_currentVertices = poly->aVertices;
            rdCache_currenVertexColors = poly->aVertColors;
            baseVertex = rdCache_numHWVertices;
            lightingMode = poly->lightingMode;
            if (poly->lightingMode >= rdroid_g_curLightingMode)
                lightingMode = rdroid_g_curLightingMode;

            for (i = 0; i < (unsigned int)poly->numVertices; i++) {
                hw = &rdCache_aHWVertices[rdCache_numHWVertices];
                v = &rdCache_currentVertices[i];
                c = &rdCache_currenVertexColors[i];
                hw->sx = v->x;
                hw->sy = v->y;

                // 1/z: bit-trick seed refined by one Newton step
                rhw = 0.0f;
                if (v->z != 0.0f) {
                    memcpy(&zBits, &v->z, sizeof(zBits));
                    zBits = 0x7f000000 - zBits;
                    memcpy(&approx, &zBits, sizeof(approx));
                    rhw = (2.0f - v->z * approx) * approx;
                }
                if (v->z == rdCache_currentZNear)
                    hw->sz = 0.0f;
                else
                    hw->sz = 1.0f - rhw * rdCache_currentZNear;
                hw->rhw = rhw;

                if ((flags & RD_FF_3DO_WHIP_AIM) != 0) {
                    if (!(v->z > fogStart)) {
                        hw->specular = 0xffffffff;
                    } else if (!(v->z < fogEnd)) {
                        hw->specular = 0xffffff;
                    } else {
                        scaled = (1.0f - (v->z - fogStart) * oneOverFogRange) * 255.0f;
                        hw->specular = ((uint32_t)lrintf(scaled) << 24) | 0xffffff;
                    }
                }

                if (lightingMode > RD_LIGHTING_NONE && lightingMode <= RD_LIGHTING_DIFFUSE) {
                    r = c->x;
                    g = c->y;
                    b = c->z;
                    a = c->w;
                } else if (lightingMode == RD_LIGHTING_GOURAUD) {
                    r = poly->extraLight.x + c->x;
                    g = poly->extraLight.y + c->y;
                    b = poly->extraLight.z + c->z;
                    a = c->w;
                    if (poly->extraLight.w != 1.0f)
                        a = a + poly->extraLight.w;
                } else {
                    r = 1.0f;
                    g = 1.0f;
                    b = 1.0f;
                    // faithful: unlit faces take alpha from the first vertex of the poly
                    a = rdCache_currenVertexColors->w;
                }
                if (r > 1.0f)
                    r = 1.0f;
                if (g > 1.0f)
                    g = 1.0f;
                if (b > 1.0f)
                    b = 1.0f;
                if (a > 1.0f)
                    a = 1.0f;

                if ((flags & RD_FF_TEX_TRANSLUCENT) != 0) {
                    hw->color = (((((uint32_t)lrintf(a * 255.0f) << 8) | (uint32_t)lrintf(r * 255.0f)) << 8 | (uint32_t)lrintf(g * 255.0f)) << 8) | (uint32_t)lrintf(b * 255.0f);
                } else {
                    hw->color = ((((uint32_t)lrintf(r * 255.0f) | 0xffffff00u) << 8 | (uint32_t)lrintf(g * 255.0f)) << 8) | (uint32_t)lrintf(b * 255.0f);
                }
                hw->tu = poly->aUVCoords[i].x + poly->uv_offset.x;
                hw->tv = poly->aUVCoords[i].y + poly->uv_offset.y;
                rdCache_numHWVertices++;
            }

            if ((unsigned int)poly->numVertices <= 3) {
                rdCache_aVertIndices[indexCount] = (WORD)baseVertex;
                rdCache_aVertIndices[indexCount + 1] = (WORD)(baseVertex + 1);
                rdCache_aVertIndices[indexCount + 2] = (WORD)(baseVertex + 2);
                indexCount += 3;
            } else {
                // zig-zag triangulation of the polygon
                numTris = poly->numVertices - 2;
                fanFirst = 0;
                fanMid = 1;
                fanLast = poly->numVertices - 1;
                for (k = 0; k < numTris; k++) {
                    rdCache_aVertIndices[indexCount] = (WORD)(fanFirst + baseVertex);
                    rdCache_aVertIndices[indexCount + 1] = (WORD)(fanMid + baseVertex);
                    rdCache_aVertIndices[indexCount + 2] = (WORD)(fanLast + baseVertex);
                    indexCount += 3;
                    if ((k & 1) == 0)
                        fanFirst = fanMid++;
                    else
                        fanFirst = fanLast--;
                }
            }

            poly++;
            polysDone++;
            if ((unsigned int)(poly->numVertices * 3 - 6 + indexCount) >= std3D_g_maxVertices || polysDone >= numPolys || material != poly->pMaterial || flags != poly->flags) {
                break;
            }
        }
        std3D_DrawRenderList(texture, renderState, rdCache_aHWVertices, rdCache_numHWVertices, rdCache_aVertIndices, indexCount);
    }
}

// 0x0048e4c0
void rdCache_SendWireframeFaceListToHardware(int numPolys, RdCacheProcEntry* aPolys)
{
    int* hwVertexData = (int*)rdCache_aHWVertices;
    RdCacheProcEntry* poly;
    unsigned int remaining;
    unsigned int i;

    // same byte-count clear as rdCache_Startup
    for (i = 0; i < RDCACHE_MAX_VERTICES / sizeof(int); i++)
        hwVertexData[i] = 0;
    std3D_SetWireframeRenderState();

    poly = aPolys;
    for (remaining = (unsigned int)numPolys; remaining != 0; remaining--, poly++) {
        // FRNDINT under stdPlatfom_FPU3, whose rounding control is toward +infinity
        for (i = 0; i < (unsigned int)poly->numVertices; i++) {
            rdCache_aHWVertices[i].sx = ceilf(poly->aVertices[i].x);
            rdCache_aHWVertices[i].sy = ceilf(poly->aVertices[i].y);
            rdCache_aHWVertices[i].color = 0xffffffff;
        }
        if (rdroid_g_curGeometryMode == RD_GEOMETRY_VERTEX) {
            std3D_DrawPointList(rdCache_aHWVertices, poly->numVertices);
        } else if (rdroid_g_curGeometryMode == RD_GEOMETRY_WIREFRAME) {
            rdCache_aHWVertices[i].sx = ceilf(poly->aVertices[0].x);
            rdCache_aHWVertices[i].sy = ceilf(poly->aVertices[0].y);
            rdCache_aHWVertices[i].color = 0xffffffff;
            std3D_DrawLineStrip(rdCache_aHWVertices, poly->numVertices + 1);
        }
    }
}

// 0x0048e5f0
void rdCache_AddToTextureCache(tSystemTexture* pTexture, StdColorFormatType format)
{
    if (pTexture->pD3DCachedTex == NULL) {
        std3D_AddToTextureCache(pTexture, format);
        return;
    }
    std3D_UpdateFrameCount(pTexture);
}

// 0x0048e640
int rdCache_ProcFaceCompare(RdCacheProcEntry* pEntry1, RdCacheProcEntry* pEntry2)
{
    if (pEntry1->pMaterial == pEntry2->pMaterial)
        return pEntry2->matCelNum - pEntry1->matCelNum;
    return (int)(pEntry2->pMaterial - pEntry1->pMaterial);
}
