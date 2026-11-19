#include "rdThing.h"

#include "globals.h"
#include "rdCanvas.h"

#include <Primitives/rdMatrix.h>

#include <macros.h>

// 0x00490b70
RdThing* rdThing_New(SithThing* pThing)
{
    HANG("TODO");
}

// 0x00490ba0
void rdThing_NewEntry(RdThing* prdThing, SithThing* pThing)
{
    HANG("TODO");
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
int rdThing_Draw(swrUI_Unk3* param_1, rdMatrix34* identity, void* param_3, int screen_width)
{
    HANG("TODO");
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
