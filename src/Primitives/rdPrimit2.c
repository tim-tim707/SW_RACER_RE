#include "types.h"

#include <Engine/rdClip.h>
#include <Win95/stdDisplay.h>

// 0x00490e10
int rdPrimit2_DrawClippedLine(rdCanvas* pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask)
{
    unsigned int uVar1;
    stdVBuffer* vbuffer;
    int iVar2;
    int iVar3;
    int iVar4;
    unsigned int uVar5;
    int iVar6;
    bool bVar7;
    int local_18;
    int local_14;
    unsigned int local_10;

    iVar2 = rdClip_Line2(pCanvas, &x1, &y1, &x2, &y2);
    if (iVar2 != 0)
    {
        vbuffer = pCanvas->vbuffer;
        if ((vbuffer->format).format.r_bits == 8)
        {
            local_18 = y2 - y1;
            local_14 = x2 - x1;
            local_10 = 0x80000000;
            iVar2 = (((local_14 < 1) - 1) & 2) - 1;
            iVar3 = (((local_18 < 1) - 1) & 2) - 1;
            if (iVar2 < 0)
            {
                local_18 = -local_18;
            }
            if (0 < iVar3)
            {
                local_14 = -local_14;
            }
            if ((mask & 0x80000000) != 0)
            {
                vbuffer->surface_lock_alloc[x1 + (vbuffer->format).width_in_pixels * y1] = (char)color16;
            }
            uVar5 = 0;
            while ((x1 != x2 || (y1 != y2)))
            {
                local_10 = local_10 >> 1;
                if (local_10 == 0)
                {
                    local_10 = 0x80000000;
                }
                uVar1 = uVar5 + local_18;
                uVar5 = uVar5 + local_14;
                if ((int)((uVar1 ^ (int)uVar1 >> 0x1f) - ((int)uVar1 >> 0x1f)) < (int)((uVar5 ^ (int)uVar5 >> 0x1f) - ((int)uVar5 >> 0x1f)))
                {
                    x1 = x1 + iVar2;
                    uVar5 = uVar1;
                }
                else
                {
                    y1 = y1 + iVar3;
                }
                if ((mask & local_10) != 0)
                {
                    pCanvas->vbuffer->surface_lock_alloc[x1 + (pCanvas->vbuffer->format).width_in_pixels * y1] = (char)color16;
                }
            }
        }
        else
        {
            bVar7 = vbuffer->bSurfaceLocked == 1;
            if (bVar7)
            {
                stdDisplay_VBufferLock(vbuffer);
            }
            local_18 = y2 - y1;
            local_14 = x2 - x1;
            local_10 = 0x80000000;
            iVar2 = (((local_14 < 1) - 1) & 2) - 1;
            iVar3 = (((local_18 < 1) - 1) & 2) - 1;
            if (iVar2 < 0)
            {
                local_18 = -local_18;
            }
            if (0 < iVar3)
            {
                local_14 = -local_14;
            }
            if ((mask & 0x80000000) != 0)
            {
                *(uint16_t*)(pCanvas->vbuffer->surface_lock_alloc + (pCanvas->vbuffer->format.width_in_pixels * y1 + x1) * 2) = color16;
            }
            uVar5 = 0;
            iVar4 = x1;
            iVar6 = y1;
            while ((iVar4 != x2 || (iVar6 != y2)))
            {
                local_10 = local_10 >> 1;
                if (local_10 == 0)
                {
                    local_10 = 0x80000000;
                }
                uVar1 = uVar5 + local_18;
                uVar5 = uVar5 + local_14;
                if ((int)((uVar1 ^ (int)uVar1 >> 0x1f) - ((int)uVar1 >> 0x1f)) < (int)((uVar5 ^ (int)uVar5 >> 0x1f) - ((int)uVar5 >> 0x1f)))
                {
                    iVar4 = iVar4 + iVar2;
                    uVar5 = uVar1;
                }
                else
                {
                    iVar6 = iVar6 + iVar3;
                }
                if ((mask & local_10) != 0)
                {
                    *(uint16_t*)(pCanvas->vbuffer->surface_lock_alloc + (pCanvas->vbuffer->format.width_in_pixels * iVar6 + iVar4) * 2) = color16;
                }
            }
            if (bVar7)
            {
                stdDisplay_VBufferUnlock(pCanvas->vbuffer);
            }
        }
        return 1;
    }
    return 0;
}
