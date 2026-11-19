#include "rdSprite.h"

#include "globals.h"

#include <Primitives/rdMatrix.h>
#include <Primitives/rdPrimit3.h>
#include <Raster/rdCache.h>

#include <stdint.h>

// int __cdecl rdSprite_Draw(RdThing* prdThing, const RdMatrix* orient)
// 0x004945e0
int rdSprite_Draw(swrUI_Unk3* pThing, rdMatrix34* orient)
{
    RdThing* thing;
    rdSprite3* sprite;
    RdCacheProcEntry* entry;
    rdPrimit3 dst;
    rdPrimit3 src;
    rdVector3 viewPos;
    RdLightMode lightingMode;
    int cullStatus;
    unsigned int i;

    thing = (RdThing*)pThing;
    sprite = thing->data.pSprite3;
    rdMatrix_TransformPoint34(&viewPos, &orient->scale, &rdCamera_pCurCamera->view_matrix);
    cullStatus = thing->frustumCullStatus;
    if (cullStatus == 2)
        return 0;
    entry = rdCache_GetAlphaProcEntry();
    if (entry == NULL)
        return 0;

    rdSprite_aFaceVerts[0].x = viewPos.x + (sprite->offset.x - sprite->widthHalf);
    rdSprite_aFaceVerts[0].y = viewPos.y + sprite->offset.y;
    rdSprite_aFaceVerts[0].z = viewPos.z + (sprite->offset.z - sprite->heightHalf);
    rdSprite_aFaceVerts[1].x = viewPos.x + (sprite->widthHalf + sprite->offset.x);
    rdSprite_aFaceVerts[1].y = viewPos.y + sprite->offset.y;
    rdSprite_aFaceVerts[1].z = viewPos.z + (sprite->offset.z - sprite->heightHalf);
    rdSprite_aFaceVerts[2].x = viewPos.x + (sprite->widthHalf + sprite->offset.x);
    rdSprite_aFaceVerts[2].y = viewPos.y + sprite->offset.y;
    rdSprite_aFaceVerts[2].z = viewPos.z + (sprite->offset.z + sprite->heightHalf);
    rdSprite_aFaceVerts[3].x = viewPos.x + (sprite->offset.x - sprite->widthHalf);
    rdSprite_aFaceVerts[3].y = viewPos.y + sprite->offset.y;
    rdSprite_aFaceVerts[3].z = viewPos.z + (sprite->offset.z + sprite->heightHalf);

    src.numVertices = sprite->face.numVertices;
    src.aVertIdxs = sprite->face.aVertIdxs;
    src.aTexVertIdxs = sprite->face.aTexIdxs;
    src.aVertices = rdSprite_aFaceVerts;
    src.aTexVertices = sprite->aTexVerts;
    src.aVertLights = NULL;
    src.aVertIntensities = NULL;
    dst.aVertices = rdSprite_aClippedVerts;
    dst.unknown2 = (int)(intptr_t)entry->aVertices;
    dst.aTexVertices = entry->aUVCoords;
    dst.aVertLights = entry->aVertColors;

    // faithful: SETGE/DEC/AND keeps only a negative lighting mode, so this is RD_LIGHTING_NONE
    lightingMode = rdroid_g_curLightingMode < 0 ? rdroid_g_curLightingMode : RD_LIGHTING_NONE;
    entry->lightingMode = lightingMode;
    if (cullStatus != 0) {
        rdPrimit3_ClipFace(rdCamera_pCurCamera->pClipFrustum, sprite->face.geometryMode, lightingMode, &src, &dst, &sprite->face.texVertOffset);
    } else {
        rdPrimit3_NoClipFace((rdGeoMode_t)sprite->face.geometryMode, lightingMode, (rdMeshinfo*)&src, (rdMeshinfo*)&dst, &sprite->face.texVertOffset);
    }
    if (dst.numVertices < 3)
        return 0;

    for (i = 0; i < dst.numVertices; i++)
        entry->aVertColors[i] = sprite->face.extraLight;
    rdCamera_pCurCamera->fnProjectLst((rdVector3*)(intptr_t)dst.unknown2, dst.aVertices, dst.numVertices);

    entry->extraLight = sprite->face.extraLight;
    if ((rdroid_g_curRenderOptions & RDROID_USE_AMBIENT_CAMERA_LIGHT) != 0) {
        entry->extraLight.x = rdCamera_pCurCamera->ambientColor.x + entry->extraLight.x;
        entry->extraLight.y = rdCamera_pCurCamera->ambientColor.y + entry->extraLight.y;
        entry->extraLight.z = rdCamera_pCurCamera->ambientColor.z + entry->extraLight.z;
        entry->extraLight.w = rdCamera_pCurCamera->ambientColor.w + entry->extraLight.w;
    }
    entry->matCelNum = thing->matCelNum;
    entry->flags = sprite->face.flags | RD_FF_TEX_TRANSLUCENT | RD_FF_TEX_CLAMP_X | RD_FF_TEX_CLAMP_Y | RD_FF_ZWRITE_DISABLED;
    entry->pMaterial = sprite->face.pMaterial;
    entry->lightingMode = rdroid_g_curLightingMode;
    if (rdroid_g_curLightingMode >= sprite->face.lightingMode)
        entry->lightingMode = sprite->face.lightingMode;
    rdCache_AddAlphaProcFace(dst.numVertices, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
    return 1;
}
