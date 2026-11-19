#include "rdThing.h"

#include "globals.h"
#include "rdCanvas.h"

#include <Primitives/rdMatrix.h>
#include <Primitives/rdModel.h>
#include <Primitives/rdParticle.h>
#include <Primitives/rdPolyLine.h>
#include <Primitives/rdSprite.h>

#include <macros.h>

#include <stdint.h>

// 0x00490b70
RdThing* rdThing_New(SithThing* pThing)
{
    RdThing* prdThing;

    prdThing = (RdThing*)(*rdroid_hostServices_ptr->alloc)(sizeof(RdThing));
    if (prdThing == NULL)
        return NULL;
    rdThing_NewEntry(prdThing, pThing);
    return prdThing;
}

// 0x00490ba0
void rdThing_NewEntry(RdThing* prdThing, SithThing* pThing)
{
    prdThing->data.pModel3 = NULL;
    prdThing->type = RD_THING_NONE;
    prdThing->pPuppet = NULL;
    prdThing->bSkipBuildingJoints = 0;
    prdThing->rdFrameNum = 0;
    prdThing->geosetNum = -1;
    prdThing->matCelNum = -1;
    prdThing->paJointMatrices = NULL;
    prdThing->desiredGeoMode = RD_GEOMETRY_FULL;
    prdThing->desiredLightMode = RD_LIGHTING_GOURAUD;
    prdThing->geoMode = RD_GEOMETRY_FULL;
    prdThing->lightMode = RD_LIGHTING_GOURAUD;
    prdThing->pThing = pThing;
}

// 0x00490bf0
void rdThing_Free(RdThing* pThing)
{
    if (pThing != NULL) {
        rdThing_FreeEntry(pThing);
        (*rdroid_hostServices_ptr->free)(pThing);
    }
}

// 0x00490c10
void rdThing_FreeEntry(RdThing* pThing)
{
    if (pThing->type == RD_THING_MODEL3) {
        if (pThing->paJointMatrices != NULL) {
            (*rdroid_hostServices_ptr->free)(pThing->paJointMatrices);
            pThing->paJointMatrices = NULL;
        }
        if (pThing->apTweakedAngles != NULL) {
            (*rdroid_hostServices_ptr->free)(pThing->apTweakedAngles);
            pThing->apTweakedAngles = NULL;
        }
        if (pThing->paJointAmputationFlags != NULL) {
            (*rdroid_hostServices_ptr->free)(pThing->paJointAmputationFlags);
            pThing->paJointAmputationFlags = NULL;
        }
    }
    if (pThing->pPuppet != NULL) {
        rdCanvas_Free((rdCanvas*)pThing->pPuppet);
        pThing->pPuppet = NULL;
    }
}

// int __cdecl rdThing_Draw(RdThing* prdThing, const RdMatrix* pOrient)
// 0x00490c80
int rdThing_Draw(swrUI_Unk3* pThing, rdMatrix34* pOrient, int bMirrorX, int screenWidth)
{
    rdCamera_bMirrorX = bMirrorX;
    rdCamera_screen_width = screenWidth;
    if (rdroid_g_curGeometryMode == RD_GEOMETRY_NONE)
        return 0;

    switch (pThing->unk0) {
    case RD_THING_MODEL3:
        return rdModel3_Draw((RdThing*)pThing, pOrient);
    case RD_THING_SPRITE3:
        return rdSprite_Draw(pThing, pOrient);
    case RD_THING_PARTICLE:
        return rdParticle_Draw((RdThing*)pThing, pOrient);
    case RD_THING_POLYLINE:
        return rdPolyLine_Draw((RdThing*)pThing, pOrient);
    case RD_THING_NONE:
    case RD_THING_CAMERA:
    case RD_THING_LIGHT:
        return 0;
    default:
        // faithful: out-of-range types return the thing pointer itself
        return (int)(intptr_t)pThing;
    }
}

// 0x00490d10
int rdThing_AccumulateMatrices(RdThing* prdThing, rdModel3HNode* pNode, rdMatrix34* pPlacement)
{
    rdMatrix34 nodeMatrix;
    rdVector3 negParentPivot;
    rdModel3HNode* child;
    unsigned int i;

    rdMatrix_BuildTranslate34(&nodeMatrix, &pNode->pivot);
    rdMatrix_PostMultiply34(&nodeMatrix, &prdThing->paJointMatrices[pNode->num]);
    if (pNode->pParent != NULL) {
        negParentPivot.x = -pNode->pParent->pivot.x;
        negParentPivot.y = -pNode->pParent->pivot.y;
        negParentPivot.z = -pNode->pParent->pivot.z;
        rdMatrix_PostTranslate34(&nodeMatrix, &negParentPivot);
    }
    rdMatrix_Multiply34(&prdThing->paJointMatrices[pNode->num], pPlacement, &nodeMatrix);

    child = pNode->pChild;
    for (i = 0; i < (unsigned int)pNode->numChildren; i++) {
        if (prdThing->paJointAmputationFlags[child->num] == 0) {
            rdThing_AccumulateMatrices(prdThing, child, &prdThing->paJointMatrices[pNode->num]);
        }
        child = child->pSibling;
    }
    return pNode->numChildren;
}
