#include "rdFace.h"

#include "globals.h"

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
