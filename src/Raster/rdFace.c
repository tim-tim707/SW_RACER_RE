#include "rdFace.h"

#include "globals.h"

// 0x004923c0
int rdFace_NewEntry(RdFace* pFace)
{
    pFace->num = 0;
    pFace->flags = 0;
    pFace->numVertices = 0;
    pFace->aVertIdxs = NULL;
    pFace->aTexIdxs = NULL;
    pFace->pMaterial = NULL;
    pFace->matCelNum = -1;
    (pFace->normal).x = 0.0;
    (pFace->normal).y = 0.0;
    (pFace->normal).z = 0.0;
    (pFace->texVertOffset).x = 0.0;
    (pFace->texVertOffset).y = 0.0;
    (pFace->extraLight).x = 0.0;
    (pFace->extraLight).y = 0.0;
    (pFace->extraLight).z = 0.0;
    (pFace->extraLight).w = 0.0;
    return 1;
}

// 0x00492410
void rdFace_FreeEntry(RdFace* pFace)
{
    if (pFace->aVertIdxs != NULL)
    {
        (*rdroid_hostServices_ptr->free)(pFace->aVertIdxs);
    }
    if (pFace->aTexIdxs != NULL)
    {
        (*rdroid_hostServices_ptr->free)(pFace->aTexIdxs);
    }
}
