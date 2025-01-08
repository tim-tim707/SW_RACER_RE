#include "rdMatrixStack.h"
#include "globals.h"

#include <macros.h>

// 0x00445150
void rdMatrixStack44_Init(void)
{
    rdMatrixStack44_size = 0;
    rdMatrixStack44[0].vA.x = 1.0;
    rdMatrixStack44[0].vA.y = 0.0;
    rdMatrixStack44[0].vA.z = 0.0;
    rdMatrixStack44[0].vA.w = 0.0;
    rdMatrixStack44[0].vB.x = 0.0;
    rdMatrixStack44[0].vB.y = 1.0;
    rdMatrixStack44[0].vB.z = 0.0;
    rdMatrixStack44[0].vB.w = 0.0;
    rdMatrixStack44[0].vC.x = 0.0;
    rdMatrixStack44[0].vC.y = 0.0;
    rdMatrixStack44[0].vC.z = 1.0;
    rdMatrixStack44[0].vC.w = 0.0;
    rdMatrixStack44[0].vD.x = 0.0;
    rdMatrixStack44[0].vD.y = 0.0;
    rdMatrixStack44[0].vD.z = 0.0;
    rdMatrixStack44[0].vD.w = 1.0;
    return;
}

// 0x00445200
void rdMatrixStack44_Push(rdMatrix44* mat)
{
    int new_size;
    int new_size_next;
    int size;

    size = rdMatrixStack44_size;
    if (rdMatrixStack44_size < 0x20)
    {
        new_size = rdMatrixStack44_size + 1;
        new_size_next = rdMatrixStack44_size + 2;
        rdMatrixStack44_size = new_size;
        rdMatrixStack44[new_size_next].vA.x = rdMatrixStack44[new_size].vB.x * (mat->vA).y + (mat->vA).w * rdMatrixStack44[new_size].vD.x + rdMatrixStack44[new_size].vC.x * (mat->vA).z + (mat->vA).x * rdMatrixStack44[new_size].vA.x;
        rdMatrixStack44[size + 2].vA.y = rdMatrixStack44[new_size].vB.y * (mat->vA).y + rdMatrixStack44[new_size].vC.y * (mat->vA).z + rdMatrixStack44[new_size].vD.y * (mat->vA).w + (mat->vA).x * rdMatrixStack44[new_size].vA.y;
        rdMatrixStack44[size + 2].vA.z = rdMatrixStack44[new_size].vD.z * (mat->vA).w + rdMatrixStack44[new_size].vC.z * (mat->vA).z + rdMatrixStack44[new_size].vB.z * (mat->vA).y + (mat->vA).x * rdMatrixStack44[new_size].vA.z;
        rdMatrixStack44[size + 2].vA.w = rdMatrixStack44[new_size].vD.w * (mat->vA).w + rdMatrixStack44[new_size].vB.w * (mat->vA).y + rdMatrixStack44[new_size].vC.w * (mat->vA).z + (mat->vA).x * rdMatrixStack44[new_size].vA.w;
        rdMatrixStack44[size + 2].vB.x = (mat->vB).y * rdMatrixStack44[new_size].vB.x + (mat->vB).z * rdMatrixStack44[new_size].vC.x + (mat->vB).w * rdMatrixStack44[new_size].vD.x + rdMatrixStack44[new_size].vA.x * (mat->vB).x;
        rdMatrixStack44[size + 2].vB.y = (mat->vB).x * rdMatrixStack44[new_size].vA.y + (mat->vB).y * rdMatrixStack44[new_size].vB.y + (mat->vB).w * rdMatrixStack44[new_size].vD.y + (mat->vB).z * rdMatrixStack44[new_size].vC.y;
        rdMatrixStack44[size + 2].vB.z = (mat->vB).z * rdMatrixStack44[new_size].vC.z + (mat->vB).y * rdMatrixStack44[new_size].vB.z + (mat->vB).w * rdMatrixStack44[new_size].vD.z + (mat->vB).x * rdMatrixStack44[new_size].vA.z;
        rdMatrixStack44[size + 2].vB.w = (mat->vB).x * rdMatrixStack44[new_size].vA.w + (mat->vB).y * rdMatrixStack44[new_size].vB.w + (mat->vB).w * rdMatrixStack44[new_size].vD.w + (mat->vB).z * rdMatrixStack44[new_size].vC.w;
        rdMatrixStack44[size + 2].vC.x = (mat->vC).w * rdMatrixStack44[new_size].vD.x + (mat->vC).z * rdMatrixStack44[new_size].vC.x + (mat->vC).y * rdMatrixStack44[new_size].vB.x + rdMatrixStack44[new_size].vA.x * (mat->vC).x;
        rdMatrixStack44[size + 2].vC.y = (mat->vC).z * rdMatrixStack44[new_size].vC.y + (mat->vC).w * rdMatrixStack44[new_size].vD.y + (mat->vC).y * rdMatrixStack44[new_size].vB.y + (mat->vC).x * rdMatrixStack44[new_size].vA.y;
        rdMatrixStack44[size + 2].vC.z = (mat->vC).w * rdMatrixStack44[new_size].vD.z + (mat->vC).y * rdMatrixStack44[new_size].vB.z + (mat->vC).z * rdMatrixStack44[new_size].vC.z + (mat->vC).x * rdMatrixStack44[new_size].vA.z;
        rdMatrixStack44[size + 2].vC.w = (mat->vC).z * rdMatrixStack44[new_size].vC.w + (mat->vC).w * rdMatrixStack44[new_size].vD.w + (mat->vC).y * rdMatrixStack44[new_size].vB.w + (mat->vC).x * rdMatrixStack44[new_size].vA.w;
        rdMatrixStack44[size + 2].vD.x = (mat->vD).z * rdMatrixStack44[new_size].vC.x + (mat->vD).y * rdMatrixStack44[new_size].vB.x + (mat->vD).w * rdMatrixStack44[new_size].vD.x + rdMatrixStack44[new_size].vA.x * (mat->vD).x;
        rdMatrixStack44[size + 2].vD.y = (mat->vD).x * rdMatrixStack44[new_size].vA.y + (mat->vD).z * rdMatrixStack44[new_size].vC.y + (mat->vD).y * rdMatrixStack44[new_size].vB.y + (mat->vD).w * rdMatrixStack44[new_size].vD.y;
        rdMatrixStack44[size + 2].vD.z = (mat->vD).w * rdMatrixStack44[new_size].vD.z + (mat->vD).x * rdMatrixStack44[new_size].vA.z + (mat->vD).y * rdMatrixStack44[new_size].vB.z + (mat->vD).z * rdMatrixStack44[new_size].vC.z;
        rdMatrixStack44[size + 2].vD.w = (mat->vD).y * rdMatrixStack44[new_size].vB.w + (mat->vD).x * rdMatrixStack44[new_size].vA.w + (mat->vD).z * rdMatrixStack44[new_size].vC.w + (mat->vD).w * rdMatrixStack44[new_size].vD.w;
    }
    return;
}

// 0x00445500
void rdMatrixStack44_Peek(rdMatrix44* out)
{
    (out->vA).x = rdMatrixStack44[rdMatrixStack44_size].vA.x;
    (out->vA).y = rdMatrixStack44[rdMatrixStack44_size].vA.y;
    (out->vA).z = rdMatrixStack44[rdMatrixStack44_size].vA.z;
    (out->vA).w = rdMatrixStack44[rdMatrixStack44_size].vA.w;
    (out->vB).x = rdMatrixStack44[rdMatrixStack44_size].vB.x;
    (out->vB).y = rdMatrixStack44[rdMatrixStack44_size].vB.y;
    (out->vB).z = rdMatrixStack44[rdMatrixStack44_size].vB.z;
    (out->vB).w = rdMatrixStack44[rdMatrixStack44_size].vB.w;
    (out->vC).x = rdMatrixStack44[rdMatrixStack44_size].vC.x;
    (out->vC).y = rdMatrixStack44[rdMatrixStack44_size].vC.y;
    (out->vC).z = rdMatrixStack44[rdMatrixStack44_size].vC.z;
    (out->vC).w = rdMatrixStack44[rdMatrixStack44_size].vC.w;
    (out->vD).x = rdMatrixStack44[rdMatrixStack44_size].vD.x;
    (out->vD).y = rdMatrixStack44[rdMatrixStack44_size].vD.y;
    (out->vD).z = rdMatrixStack44[rdMatrixStack44_size].vD.z;
    (out->vD).w = rdMatrixStack44[rdMatrixStack44_size].vD.w;
    return;
}

// 0x00445630
void rdMatrixStack44_Pop(void)
{
    if (0 < rdMatrixStack44_size)
    {
        rdMatrixStack44_size = rdMatrixStack44_size + -1;
    }
    return;
}

// 0x0044b660
rdMatrix44* rdMatrix44_ringBuffer_Get(void)
{
    rdMatrix44_ringBufferIndex = rdMatrix44_ringBufferIndex + 1;
    if (0xbff < rdMatrix44_ringBufferIndex)
    {
        rdMatrix44_ringBufferIndex = 0;
    }
    return rdMatrix44_ringBuffer + rdMatrix44_ringBufferIndex;
}

// 0x0044b690
void SetModelMVPAndTranslation(const rdMatrix44* mvp, const rdVector3* translation)
{
    HANG("TODO");
}

// 0x0044b750
void __cdecl rdMatrixStack34_Push(const rdMatrix34* mat)
{
    int iVar1;

    rdMatrixStack34_modified = true;
    if (rdMatrixStack34_size < 0x20)
    {
        iVar1 = rdMatrixStack34_size + 1;
        rdMatrixStack34_size = iVar1;
        rdMatrixStack34[iVar1].rvec.x = (mat->rvec).x;
        rdMatrixStack34[iVar1].rvec.y = (mat->rvec).y;
        rdMatrixStack34[iVar1].rvec.z = (mat->rvec).z;
        rdMatrixStack34[iVar1].lvec.x = (mat->lvec).x;
        rdMatrixStack34[iVar1].lvec.y = (mat->lvec).y;
        rdMatrixStack34[iVar1].lvec.z = (mat->lvec).z;
        rdMatrixStack34[iVar1].uvec.x = (mat->uvec).x;
        rdMatrixStack34[iVar1].uvec.y = (mat->uvec).y;
        rdMatrixStack34[iVar1].uvec.z = (mat->uvec).z;
        rdMatrixStack34[iVar1].scale.x = (mat->scale).x;
        rdMatrixStack34[iVar1].scale.y = (mat->scale).y;
        rdMatrixStack34[iVar1].scale.z = (mat->scale).z;
    }
    return;
}

// 0x0044b7e0
void rdMatrixStack34_PushMultiply(const rdMatrix34* a1)
{
    HANG("TODO");
}

// 0x0044b9b0
void rdMatrixStack34_Peek(rdMatrix34* a1)
{
    HANG("TODO");
}

// 0x0044bab0
void rdMatrixStack34_Pop()
{
    HANG("TODO");
}

// 0x0044bb40
void rdMatrixStack34_Init()
{
    HANG("TODO");
}

// 0x0044bc20
void rdMatrixStack34_PrecomputeMVPMatrices()
{
    HANG("TODO");
}
