#include "swrViewport.h"

#include <globals.h>
#include <macros.h>
#include <Primitives/rdMatrix.h>

// 0x00428B40
void swrViewport_SetCameraIndex(short a1, swrViewport* mesh)
{
    HANG("TODO");
}

// 0x00429540
void swrViewport_UpdateCameras()
{
    HANG("TODO");
}

// 0x004318c0 HOOK
int swrViewport_GetNumViewports()
{
    return 4;
}

// 0x004318d0 HOOK
swrViewport* swrViewport_Get(int index)
{
    return &swrViewport_array[index];
}

// 0x00431900 HOOK
void swrViewport_ExtractViewTransform(swrViewport* param_1, rdVector3* translation, rdVector3* rotation)
{
    swrTranslationRotation tmp;
    rdMatrix_ExtractTransform(&param_1->clipMat, &tmp);
    translation->x = tmp.translation.x;
    translation->y = tmp.translation.y;
    translation->z = tmp.translation.z;
    rotation->x = tmp.yaw_roll_pitch.x;
    rotation->y = tmp.yaw_roll_pitch.y;
    rotation->z = tmp.yaw_roll_pitch.z;
}

// 0x00431950 HOOK
void swrViewport_SetMat3(swrViewport* a1, const rdMatrix44* a2)
{
    a1->unk_mat3 = *a2;
    rdMatrix_Multiply44(&a1->model_matrix, &a1->unk_mat1, &a1->unk_mat3);
}

// 0x00431a00 HOOK
void swrViewport_SetRootNode(swrViewport* a1, swrModel_Node* a2)
{
    a1->model_root_node = a2;
}

// 0x00431a10 HOOK
void swrViewport_SetNodeFlags(swrViewport* a1, int flag, int value)
{
    switch (flag)
    {
    case 3:
        a1->unk164 = value;
        break;
    case 4:
        a1->node_flags1_any_match_for_rendering = value;
        break;
    case 5:
        a1->unk160 = value;
        break;
    case 6:
        a1->node_flags1_exact_match_for_rendering = value;
        break;
    }
}

// 0x00482EE0
void swrViewport_UpdateUnknown(swrViewport*)
{
    HANG("TODO");
}

// 0x00482f10
void swrViewport_UpdateClipMatrix(swrViewport* model)
{
    HANG("TODO");
}

// 0x004830E0
void swrViewport_ScaleViewport(swrViewport* a1)
{
    HANG("TODO");
}

// 0x004831D0
void swrViewport_SetViewport(int a1, int a2, int a3, int a4, int a5)
{
    HANG("TODO");
}

// 0x00483230
void swrViewport_Enable(int, int)
{
    HANG("TODO");
}

// 0x00483270
void swrViewport_Init(int)
{
    HANG("TODO");
}

// 0x00483590
void swrViewport_SetCameraParameters(int, float, float, float, float, float)
{
    HANG("TODO");
}

// 0x00483fc0
void swrViewport_SetRootNodeForAllViewports(swrModel_Node* unk)
{
    HANG("TODO");
}

// 0x00483ff0
void swrViewport_SetNodeFlagsForAllViewports(int flag, int value)
{
    HANG("TODO");
}

// 0x00483750
void swrViewport_UpdateViewTransforms(int)
{
    HANG("TODO");
}

// 0x00483A90
void swrViewport_Render(int x)
{
    HANG("TODO");
}

// 0x00483BB0
void swrViewport_SetCurrent(int)
{
    HANG("TODO");
}

// 0x00483CB0
void RenderAll()
{
    HANG("TODO");
}