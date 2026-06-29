#include "rdCache.h"

#include "globals.h"
#include "Platform/std3D.h"

#include <float.h>
#include <macros.h>

// 0x0048db40
void rdCache_Startup(void)
{
    int* hwVertexData = (int*)rdCache_aHWVertices;
    for (int i = 0; i < 0x5000; i++)
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
    if ((unsigned int)rdCache_numProcFaces >= 0x400)
        rdCache_Flush();
    if (0x14000U - rdCache_numUsedVertices < 0x50)
        return NULL;
    if (0x14000U - rdCache_numUsedTexVertices < 0x50)
        return NULL;
    if (0x14000U - rdCache_numUsedIntensities < 0x50)
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
    HANG("TODO");
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
    if ((unsigned int)rdCache_numProcFaces < 0x400) {
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
        if (flags & 1)
            rdCache_numUsedVertices += nbVertices;
        if (flags & 2)
            rdCache_numUsedTexVertices += nbVertices;
        if (flags & 4)
            rdCache_numUsedIntensities += nbVertices;
        rdCache_numProcFaces++;
        return 1;
    }
    return 0;
}

// 0x0048dea0
size_t rdCache_AddAlphaProcFace(int numVertices, char flags)
{
    HANG("TODO");
}

// 0x0048df30
void rdCache_SendFaceListToHardware(size_t numPolys, RdCacheProcEntry* aPolys)
{
    HANG("TODO");
}

// 0x0048e4c0
void rdCache_SendWireframeFaceListToHardware(int numPolys, RdCacheProcEntry* aPolys)
{
    HANG("TODO");
}

// 0x0048e5f0
void rdCache_AddToTextureCache(tSystemTexture* pTexture, StdColorFormatType format)
{
    HANG("TODO");
}

// !! TODO: Size and access do not match !!
// 0x0048e640
int rdCache_ProcFaceCompare(RdCacheProcEntry* pEntry1, RdCacheProcEntry* pEntry2)
{
    HANG("TODO");
}
