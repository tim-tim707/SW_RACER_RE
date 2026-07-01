#include "swrViewport.h"

#include <globals.h>
#include <macros.h>
#include <swr.h>
#include <General/stdMath.h>
#include <Primitives/rdMatrix.h>
#include <Swr/swrModel.h>
#include <Unknown/rdMatrixStack.h>

// 0x00428B40
void swrViewport_SetCameraIndex(short a1, swrViewport* mesh)
{
    if (mesh != NULL) {
        if (swrModel_MeshGetBehavior((swrModel_Mesh*)mesh) != (swrModel_Behavior*)0xffffffff) {
            int behavior = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)mesh);
            *(unsigned int*)&unkCameraArray[behavior].flags &= ~1u;
        }
        if (a1 == -1) {
            unkCameraArrayIndex = -1;
            return;
        }
        swrViewport_SetRootNode_Maybe(mesh, a1);
        *(unsigned int*)&unkCameraArray[unkCameraArrayIndex].flags |= 1u;
        swrViewport_cameraApplied = 0;
    }
}

// Deferred: decoded, but it calls swrCam_CamState_GetOffsetTransform /
// swrCam_CamState_ApplyToViewport and BuildLookAtTransform, which are not
// reimplemented yet, so a real body would not link into dinput_hook.
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

// 0x00431b90
void swrViewport_SetRootNode_Maybe(swrViewport* viewport, int cameraIndex)
{
    viewport->unkCameraIndex = cameraIndex;
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

// 0x004830E0
void swrViewport_ComputeScreenRect(swrViewport* a1)
{
    // Scale the pixel viewport rect into the rasterizer's fixed-point space:
    // logical 320x240 maps to screen pixels (screenWidth/320, screenHeight/240),
    // stored as a center/half-extent pair (x1/y1 = 2*half + 8, x2/y2 = 2*center).
    double scaleX = swrDisplay_screenWidth * 0.003125;
    double scaleY = swrDisplay_screenHeight * 0.004166666666666667;
    int sx1 = (int)(a1->viewport_x1 * scaleX);
    int sy1 = (int)(a1->viewport_y1 * scaleY);
    int sx2 = (int)(a1->viewport_x2 * scaleX);
    int sy2 = (int)(a1->viewport_y2 * scaleY);
    a1->viewport_scaled_x1 = (short)((sx2 - sx1) * 2 + 8);
    a1->viewport_scaled_x2 = (short)((sx2 + sx1) * 2);
    a1->viewport_scaled_y1 = (short)((sy2 - sy1) * 2 + 8);
    a1->viewport_scaled_y2 = (short)((sy2 + sy1) * 2);
    if (swrViewport_force320x240 != 0) {
        a1->viewport_scaled_x1 = 0x500;
        a1->viewport_scaled_y1 = 0x3c0;
        a1->viewport_scaled_x2 = (swrViewport_force320x240Quadrant & 1) ? 0 : 0x500;
        a1->viewport_scaled_y2 = (swrViewport_force320x240Quadrant & 2) ? 0 : 0x3c0;
    }
    a1->unk14 = 0x92;
    a1->unk1c = 0x36c;
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
void swrViewport_Init(int viewportIndex)
{
    swrViewport* vp = &swrViewport_array[viewportIndex];
    int* scaledRect = (int*)&vp->viewport_scaled_x1;

    vp->flag &= ~1u;
    vp->unkCameraIndex = -1;
    vp->unk8 = -1;
    vp->unkc = -1;
    scaledRect[0] = swrViewport_defaultScaledRect[0];
    scaledRect[1] = swrViewport_defaultScaledRect[1];
    scaledRect[2] = swrViewport_defaultScaledRect[2];
    scaledRect[3] = swrViewport_defaultScaledRect[3];
    vp->viewport_x1 = 0;
    vp->viewport_y1 = 0;
    vp->viewport_x2 = 0x140;
    vp->viewport_y2 = 0xf0;
    rdMatrix_SetIdentity44(&vp->unk_mat1);
    rdMatrix_SetIdentity44(&vp->model_matrix);
    rdMatrix_SetIdentity44(&vp->unk_mat3);
    rdMatrix_SetIdentity44(&vp->clipMat);
    vp->unk130 = 0x10;
    vp->fov_y_degrees = 90.0;
    vp->aspect_ratio = 1.0;
    vp->unk13c = -1.0;
    vp->near_clipping = 5.0;
    vp->far_clipping = 5000.0;
    vp->unk148 = 1.0;
    vp->unk14c = 0;
    vp->unk150 = 1.0;
    vp->unk154 = 1.0;
    vp->node_flags1_exact_match_for_rendering = 6;
    vp->node_flags1_any_match_for_rendering = -1;
    vp->unk160 = 0;
    vp->unk164 = -1;
    vp->model_root_node = NULL;
    swrViewport_ComputeScreenRect(vp);
    swrViewport_ComputeClipMatrix(vp);
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
void swrViewport_Setup(int viewportIndex)
{
    swrViewport* vp = &swrViewport_array[viewportIndex];
    rdMatrix44 worldMatrix;
    rdMatrix44 viewMatrix;
    rdMatrix44 mvpMatrix;
    rdVector3 translation;

    swrViewport_ComputeScreenRect(vp);
    swrViewport_ComputeClipMatrix(vp);
    rdMatrix_Copy44(&worldMatrix, &vp->model_matrix);
    translation.x = worldMatrix.vD.x;
    translation.y = worldMatrix.vD.y;
    translation.z = worldMatrix.vD.z;
    worldMatrix.vD.x = 0.0;
    worldMatrix.vD.y = 0.0;
    worldMatrix.vD.z = 0.0;
    rdMatrix_BuildViewMatrix(&viewMatrix, &worldMatrix);
    rdMatrix_Multiply44(&mvpMatrix, &viewMatrix, &vp->clipMat);
    SetModelMVPAndTranslation(&mvpMatrix, &translation);
    if (vp->unk13c > 0.0)
        vp->unk130 = (short)(65536.0 / vp->unk13c);
}

// Deferred: decoded, but the scene path it calls (rdModel_BuildAndDrawScene /
// rdModel_SetupSceneFogAndLights_Maybe) is not reimplemented yet, so a real body
// would not link into dinput_hook (the reimpl set must stay call-closed).
// 0x00483A90
void swrViewport_Render(int x)
{
    HANG("TODO");
}

// 0x00483BB0
void swrViewport_Activate(int viewportIndex)
{
    swrViewport_active = &swrViewport_array[viewportIndex];
    swrViewport_Setup(viewportIndex);
    swr_noop3();
}
