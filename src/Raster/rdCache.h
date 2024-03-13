#ifndef RDCACHE_H
#define RDCACHE_H

#include "types.h"

#define rdCache_Startup_ADDR (0x0048db40)
#define rdCache_AdvanceFrame_ADDR (0x0048db60)
#define rdCache_GetFrameNum_ADDR (0x0048db80)
#define rdCache_GetDrawnFacesNum_ADDR (0x0048db90)
#define rdCache_GetProcEntry_ADDR (0x0048dba0)
#define rdCache_GetAlphaProcEntry_ADDR (0x0048dc40)
#define rdCache_Flush_ADDR (0x0048dce0)
#define rdCache_FlushAlpha_ADDR (0x0048dd80)
#define rdCache_AddProcFace_ADDR (0x0048de10)
#define rdCache_AddAlphaProcFace_ADDR (0x0048dea0)
#define rdCache_SendFaceListToHardware_ADDR (0x0048df30)
#define rdCache_SendWireframeFaceListToHardware_ADDR (0x0048e4c0)
#define rdCache_AddToTextureCache_ADDR (0x0048e5f0)
#define rdCache_ProcFaceCompare_ADDR (0x0048e640)

void rdCache_Startup(void);
void rdCache_AdvanceFrame(void);
int rdCache_GetFrameNum(void);
int rdCache_GetDrawnFacesNum(void);
RdCacheProcEntry* rdCache_GetProcEntry(void);
RdCacheProcEntry* rdCache_GetAlphaProcEntry(void);
void rdCache_Flush(void);
size_t rdCache_FlushAlpha(void);
int rdCache_AddProcFace(unsigned int nbVertices, char flags);
size_t rdCache_AddAlphaProcFace(int numVertices, char flags);
// Suspiciously more like:
// void __cdecl rdModel3K_sub_4E2700(rdModel3Mesh* pMesh, void* a2)
// than the original SendFaceListToHardware. But its in the middle of rdCache :/
void rdCache_SendFaceListToHardware(size_t numPolys, RdCacheProcEntry* aPolys);
void rdCache_SendWireframeFaceListToHardware(int numPolys, RdCacheProcEntry* aPolys);
void rdCache_AddToTextureCache(tSystemTexture* pTexture, StdColorFormatType format);
// !! TODO: Size and access do not match !!
int rdCache_ProcFaceCompare(RdCacheProcEntry* pEntry1, RdCacheProcEntry* pEntry2);

#endif // RDCACHE_H
