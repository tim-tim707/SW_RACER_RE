#include "rdCache.h"

#include <macros.h>

// 0x0048db40
void rdCache_Startup(void)
{
    HANG("TODO");
}

// 0x0048db60
void rdCache_AdvanceFrame(void)
{
    HANG("TODO");
}

// 0x0048db80
int rdCache_GetFrameNum(void)
{
    HANG("TODO");
}

// 0x0048db90
int rdCache_GetDrawnFacesNum(void)
{
    HANG("TODO");
}

// 0x0048dba0
RdCacheProcEntry* rdCache_GetProcEntry(void)
{
    HANG("TODO");
}

// 0x0048dc40
RdCacheProcEntry* rdCache_GetAlphaProcEntry(void)
{
    HANG("TODO");
}

// 0x0048dce0
void rdCache_Flush(void)
{
    HANG("TODO");
}

// 0x0048dd80
size_t rdCache_FlushAlpha(void)
{
    HANG("TODO");
}

// OpenJKDF2 Modified
// 0x0048de10
int rdCache_AddProcFace(unsigned int nbVertices, char flags)
{
    HANG("TODO");
}

// 0x0038dea0
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
