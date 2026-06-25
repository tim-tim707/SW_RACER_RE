#include "swrViewport.h"

#include <globals.h>
#include <macros.h>
#include <General/stdMath.h>
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

// 0x004318c0
int swrViewport_GetNumViewports()
{
    return 4;
}

// 0x004318d0
swrViewport* swrViewport_Get(int index)
{
    return &swrViewport_array[index];
}

// 0x00431900
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

// 0x00431950
void swrViewport_SetMat3(swrViewport* a1, const rdMatrix44* a2)
{
    a1->unk_mat3 = *a2;
    rdMatrix_Multiply44(&a1->model_matrix, &a1->unk_mat1, &a1->unk_mat3);
}

// 0x00431a00
void swrViewport_SetRootNode(swrViewport* a1, swrModel_Node* a2)
{
    a1->model_root_node = a2;
}

// 0x00431a10
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
void swrViewport_UpdateUnknown(swrViewport* viewport)
{
    viewport->unk154 = ((45.0 / viewport->fov_y_degrees - 1.0) * viewport->unk150 + 1.0) * viewport->unk148;
}

// 0x00482f10
void swrViewport_ComputeClipMatrix(swrViewport* unk)
{
    float aspect = ((float)(unk->viewport_x2 - unk->viewport_x1) * unk->aspect_ratio) / (float)(unk->viewport_y2 - unk->viewport_y1);
    float angle = 3.0;
    if (0.01 <= aspect) {
        angle = stdMath_Tan(unk->fov_y_degrees * 0.5);
        angle = stdMath_ArcTan2(angle, aspect);
        angle = angle + angle;
    }
    float nearC = unk->near_clipping;
    float farC = unk->far_clipping;
    float top = stdMath_Tan(angle * 0.5) * nearC;
    float right = top * aspect;
    unk->clipMat.vA.y = 0.0;
    unk->clipMat.vA.z = 0.0;
    unk->clipMat.vA.w = 0.0;
    unk->clipMat.vB.x = 0.0;
    unk->clipMat.vB.z = 0.0;
    unk->clipMat.vB.w = 0.0;
    unk->clipMat.vD.x = 0.0;
    unk->clipMat.vD.y = 0.0;
    unk->clipMat.vD.w = 0.0;
    unk->clipMat.vC.w = -1.0;
    unk->clipMat.vA.x = (nearC + nearC) / (right + right);
    unk->clipMat.vB.y = (nearC + nearC) / (top + top);
    unk->clipMat.vC.x = (-right + right) / (right + right);
    unk->clipMat.vC.y = (-top + top) / (top + top);
    unk->clipMat.vC.z = -((farC + nearC) / (farC - nearC));
    unk->clipMat.vD.z = (farC * nearC * -2.0) / (farC - nearC);
    swrViewport_UpdateUnknown(unk);
}

// TODO: body deferred -- Ghidra lost the float args (reads uninitialized regs); needs runtime verification.
// 0x004830E0
void swrViewport_ComputeScreenRect(swrViewport* a1)
{
    HANG("TODO");
}

// 0x004831D0
void swrViewport_SetViewport(int viewportIndex, int x1, int y1, int x2, int y2)
{
    if (swrViewport_force320x240 != 0) {
        x1 = 0;
        x2 = 0x140;
        y1 = 0;
        y2 = 0xf0;
    }
    swrViewport_array[viewportIndex].viewport_x1 = x1;
    swrViewport_array[viewportIndex].viewport_y1 = y1;
    swrViewport_array[viewportIndex].viewport_x2 = x2;
    swrViewport_array[viewportIndex].viewport_y2 = y2;
    swrViewport_ComputeScreenRect(&swrViewport_array[viewportIndex]);
    swrViewport_ComputeClipMatrix(&swrViewport_array[viewportIndex]);
}

// 0x00483230
void swrViewport_Enable(int viewportIndex, int cameraIndex)
{
    unsigned int flags = swrViewport_array[viewportIndex].flag;
    swrViewport_array[viewportIndex].unkCameraIndex = cameraIndex;
    if (cameraIndex < 0)
        swrViewport_array[viewportIndex].flag = flags & ~1u;
    else
        swrViewport_array[viewportIndex].flag = flags | 1;
}

// 0x00483270
void swrViewport_Init(int)
{
    HANG("TODO");
}

// 0x00483590
void swrViewport_SetCameraParameters(int viewportIndex, float fovY, float aspect, float nearClip, float farClip, float param6)
{
    if (swrConfig_VIDEO_DRAWDISTANCE == 3)
        farClip = farClip * 1.5;
    if (swrConfig_VIDEO_DRAWDISTANCE == 1)
        farClip = farClip * 0.4;
    if (0.0 < fovY)
        swrViewport_array[viewportIndex].fov_y_degrees = fovY;
    if (0.0 < aspect)
        swrViewport_array[viewportIndex].aspect_ratio = aspect;
    if (0.0 < nearClip)
        swrViewport_array[viewportIndex].near_clipping = nearClip;
    if (0.0 < farClip)
        swrViewport_array[viewportIndex].far_clipping = farClip;
    if (0.0 <= param6)
        swrViewport_array[viewportIndex].unk13c = param6;
    swrViewport_UpdateUnknown(&swrViewport_array[viewportIndex]);
}

// 0x00483fc0
void swrViewport_SetRootNodeForAllViewports(swrModel_Node* unk)
{
    for (swrViewport* a1 = swrViewport_array; a1 < swrViewport_array + 4; a1++)
        swrViewport_SetRootNode(a1, unk);
}

// 0x00483ff0
void swrViewport_SetNodeFlagsForAllViewports(int flag, int value)
{
    for (swrViewport* a1 = swrViewport_array; a1 < swrViewport_array + 4; a1++)
        swrViewport_SetNodeFlags(a1, flag, value);
}

// 0x00483750
void swrViewport_Setup(int)
{
    HANG("TODO");
}

// 0x00483A90
void swrViewport_Render(int x)
{
    HANG("TODO");
}

// 0x00483BB0
void swrViewport_Activate(int)
{
    HANG("TODO");
}
