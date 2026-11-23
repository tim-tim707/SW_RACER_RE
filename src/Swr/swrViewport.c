#include "swrViewport.h"

#include <globals.h>
#include <macros.h>
#include <swr.h>
#include <General/stdMath.h>
#include <Primitives/rdMatrix.h>
#include <Swr/swrModel.h>
#include <Swr/swrRender.h>
#include <Unknown/rdMatrixStack.h>
#include <Swr/swrObj.h>
#include <Swr/swrText.h>
#include <Swr/swrCam.h>
#include <engine_config.h>

// 0x00428B40
void swrViewport_SetCameraIndex(short a1, swrViewport* mesh)
{
    if (mesh != NULL) {
        if (swrModel_MeshGetBehavior((swrModel_Mesh*)mesh) != (swrModel_Behavior*)0xffffffff) {
            int behavior = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)mesh);
            unkCameraArray[behavior].flags &= ~1u;
        }
        if (a1 == -1) {
            unkCameraArrayIndex = -1;
            return;
        }
        // the camera index is stored in the mesh behavior slot
        swrModel_MeshSetBehavior((swrModel_Mesh*)mesh, (swrModel_Behavior*)(int)a1);
        unkCameraArray[unkCameraArrayIndex].flags |= 1u;
        swrViewport_cameraApplied = 0;
    }
}

// 0x00428bd0
void swrViewport_SetActiveCamera(short cameraIndex)
{
    if (unkCameraArrayIndex != -1)
        unkCameraArray[unkCameraArrayIndex].flags &= ~1u;
    if (cameraIndex == -1) {
        unkCameraArrayIndex = -1;
        return;
    }
    unkCameraArrayIndex = cameraIndex;
    currentUnkCameraStructPtr = &unkCameraArray[unkCameraArrayIndex];
    currentUnkCameraStructPtr->flags |= 1u;
    swrViewport_cameraApplied = 0;
}

// 0x00429540
void swrViewport_UpdateCameras()
{
    swrCamera_unk* cam;
    swrViewport* viewport;
    swrViewport* active;
    swrTranslationRotation lookFrom;
    rdMatrix44 rotation;
    rdMatrix44 source;
    rdMatrix44 view;
    rdVector3 offset;
    rdVector3 ypr;
    rdVector3 lookAt;
    float spread;
    int cameraIndex;
    int i;
    short v;

    for (i = 0; i < SWR_NUM_CAMERAS; i++) {
        unkCameraArray[i].flags &= ~swrCamera_FLAG_IN_VIEWPORT;
    }
    viewport = NULL;
    for (v = 0; v < swrViewport_GetNumViewports(); v++) {
        viewport = swrViewport_Get(v);
        if (viewport != NULL) {
            cameraIndex = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)viewport);
            if ((swrModel_NodeGetFlags((swrModel_Node*)viewport) & swrViewport_FLAGS_CAMERA_VALID) != 0 && cameraIndex >= 0 && cameraIndex < SWR_NUM_CAMERAS) {
                unkCameraArray[cameraIndex].flags |= swrCamera_FLAG_IN_VIEWPORT;
            }
        }
    }

    for (i = 0; i < SWR_NUM_CAMERAS; i++) {
        cam = &unkCameraArray[i];
        if (cam->behaviorType == 0 || (cam->flags & (swrCamera_FLAG_ACTIVE | swrCamera_FLAG_IN_VIEWPORT)) == 0) {
            continue;
        }
        // lightningpirate's CE freecam NOPs this matrix store (0x00429602-0x0042963d)
        if (cam->sourceType == 0) {
            cam->transform = *(rdMatrix44*)cam->matrixSource;
        } else if (cam->sourceType == 1) {
            rdMatrix_SetTransform44(&cam->transform, (swrTranslationRotation*)cam->matrixSource);
        } else {
            swrCam_CamState_GetOffsetTransform(cam->sourceType, (swrModel_NodeTransformed*)cam->matrixSource, &cam->transform);
        }
        offset = cam->posOffset;
        if (offset.x != 0.0f || offset.y != 0.0f || offset.z != 0.0f) {
            rdMatrix_Multiply3(&offset, &offset, &cam->transform);
            cam->transform.vD.x = offset.x + cam->transform.vD.x;
            cam->transform.vD.y = offset.y + cam->transform.vD.y;
            cam->transform.vD.z = offset.z + cam->transform.vD.z;
        }
        ypr = cam->rotationYPR;
        if (ypr.x != 0.0f || ypr.y != 0.0f || ypr.z != 0.0f) {
            rdMatrix_SetRotation44(&rotation, ypr.x, ypr.y, ypr.z);
            rdMatrix_Multiply44Acc(&cam->transform, &rotation);
        }
        if (cam->behaviorType != 2 && cam->behaviorType != 3 && cam->behaviorType != 4) {
            continue;
        }
        rdMatrix_ExtractTransform(&cam->transform, &lookFrom);
        if (cam->offsetMode == 1) {
            lookAt.x = cam->localOffset.x + ((rdVector3*)cam->offsetSource)->x;
            lookAt.y = cam->localOffset.y + ((rdVector3*)cam->offsetSource)->y;
            lookAt.z = cam->localOffset.z + ((rdVector3*)cam->offsetSource)->z;
        } else {
            if (cam->offsetMode == 0) {
                source = *(rdMatrix44*)cam->offsetSource;
            } else {
                swrCam_CamState_GetOffsetTransform(cam->offsetMode, (swrModel_NodeTransformed*)cam->offsetSource, &source);
            }
            lookAt.x = cam->localOffset.x + source.vD.x;
            lookAt.y = cam->localOffset.y + source.vD.y;
            lookAt.z = cam->localOffset.z + source.vD.z;
            if (cam->behaviorType == 4) {
                // look further along the source's forward axis the steeper it points
                spread = source.vB.z < 0.0f ? -source.vB.z : source.vB.z;
                lookAt.x = (spread * SWR_CAM_LOOKAHEAD_SCALE - -1.0) * source.vB.x + lookAt.x;
                lookAt.y = (spread * SWR_CAM_LOOKAHEAD_SCALE - -1.0) * source.vB.y + lookAt.y;
                lookAt.z = (spread * SWR_CAM_LOOKAHEAD_SCALE - -1.0) * source.vB.z + lookAt.z;
            }
        }
        rdMatrix_BuildLookAtTransform((rdVector3*)&cam->transform.vD, &lookAt, &cam->transform, &lookFrom, lookFrom.yaw_roll_pitch.z);
        if (cam->behaviorType == 3) {
            if (cam->sourceType == 0) {
                *(rdMatrix44*)cam->matrixSource = cam->transform;
            } else if (cam->sourceType == 1) {
                ((swrTranslationRotation*)cam->matrixSource)->yaw_roll_pitch = lookFrom.yaw_roll_pitch;
            }
        }
    }

    if (swrViewport_GetNumViewports() == 0) {
        active = swrViewport_active;
        if (unkCameraArrayIndex == -1) {
            swrCam_CamState_ApplyToViewport(active);
        } else {
            if (swrViewport_cameraApplied == 0) {
                swrViewport_cameraApplied = 1;
            }
            view = unkCameraArray[unkCameraArrayIndex].transform;
            if (active == NULL) {
                return;
            }
            swrViewport_SetMat3(active, &view);
        }
        if (active != NULL) {
            swrViewport_ExtractViewTransform(active, &swrViewport_viewTranslation, &swrViewport_viewRotation);
        }
        return;
    }
    for (i = 0; i < swrViewport_GetNumViewports(); i++) {
        viewport = swrViewport_Get(i);
        if (viewport == NULL) {
            continue;
        }
        cameraIndex = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)viewport);
        if ((swrModel_NodeGetFlags((swrModel_Node*)viewport) & swrViewport_FLAGS_CAMERA_VALID) == 0) {
            continue;
        }
        if (cameraIndex == -1) {
            swrCam_CamState_ApplyToViewport(viewport);
        } else {
            if (swrViewport_cameraApplied == 0) {
                swrViewport_cameraApplied = 1;
            }
            view = unkCameraArray[cameraIndex].transform;
            swrViewport_SetMat3(viewport, &view);
        }
    }
    // the last swrViewport_Get result, NULL when the last index had no viewport
    if (viewport != NULL) {
        swrViewport_ExtractViewTransform(viewport, &swrViewport_viewTranslation, &swrViewport_viewRotation);
    }
}

// Projects a world (or camera-relative) point through the current model MVP into
// viewport pixel coordinates. Writes the pixel x/y (or a -1000 sentinel when the
// point is behind the near plane or falls outside the +/-8px padded viewport box),
// the perspective-divided depth (outZ) and raw clip w (outDepth).
// 0x0042b710
void swrViewport_ProjectToScreen(swrViewport* viewport, rdVector4* worldPos, float* outScreenX, float* outScreenY, float* outZ, float* outDepth, int pointIsCameraRelative)
{
    rdMatrix44 mvp;
    rdVector4 relativePos;
    rdVector4 clip;
    int halfW;
    int halfH;
    float scaleX;
    float scaleY;
    float centerX;
    float centerY;
    float screenX;
    float screenY;

    mvp = rdMatrix44_model_MVP;
    halfW = (int)viewport->viewport_scaled_x1 / 2;
    halfH = (int)viewport->viewport_scaled_y1 / 2;
    scaleX = (float)halfW * 0.5f;
    scaleY = (float)halfH * 0.5f;
    centerX = (float)((int)viewport->viewport_scaled_x2 / 4) - scaleX;
    centerY = (float)((int)viewport->viewport_scaled_y2 / 4) - scaleY;
    *outScreenX = -1000.0f;
    *outScreenY = -1000.0f;
    if (pointIsCameraRelative == 0) {
        relativePos.x = worldPos->x - rdVector_model_translation.x;
        relativePos.y = worldPos->y - rdVector_model_translation.y;
        relativePos.z = worldPos->z - rdVector_model_translation.z;
        worldPos = &relativePos;
    }
    rdMatrix_TransformPoint44(&clip, worldPos, &mvp);
    if ((GameSettingFlags & 0x4000) != 0) {
        clip.x = -clip.x;
    }
    if (0.01 < clip.w) { // retail compares against a double
        screenX = (clip.x / clip.w + 1.0f) * scaleX + centerX;
        screenY = (1.0f - clip.y / clip.w) * scaleY + centerY;
        *outZ = clip.z / clip.w;
        *outDepth = clip.w;
        // keep the point only if it lands inside the viewport rect padded by 8px
        if (centerX - 8.0f < screenX && screenX < (centerX + (float)halfW) + 8.0f &&
            centerY - 8.0f < screenY && screenY < (centerY + (float)halfH) + 8.0f) {
            *outScreenX = screenX;
            *outScreenY = screenY;
        }
    }
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
    if (0.01f <= aspect) {
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

// 0x00431ba0
void swrViewport_ResetRenderState(void)
{
    swrViewport_viewTranslation.x = 0.0f;
    swrViewport_viewTranslation.y = 0.0f;
    swrViewport_viewTranslation.z = 0.0f;
    swrViewport_viewRotation.x = 0.0f;
    swrViewport_viewRotation.y = 0.0f;
    swrViewport_viewRotation.z = 0.0f;
    swrViewport_cameraResetWord = 0;
    swrRender_frameClearFlags = 0;
    swrViewport_renderStateUnkE2 = 2;
    GameSettingFlags = GAME_SETTING_UNK_1 | GAME_SETTING_STEREO_PAN;
    swrViewport_renderStateUnkE8 = 1.0f;
    swrViewport_renderStateUnkE4 = 1.0f;
    swrViewport_sceneInitArg = 0;
    swrViewport_renderStateUnkF0 = 1;
    swrViewport_renderStateUnkF4 = 30;
    swrViewport_renderStateUnkF6 = 0;
    swrViewport_renderStateUnkF8 = 0;
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
        farClip = farClip * 1.5f;
    if (swrConfig_VIDEO_DRAWDISTANCE == 1)
        farClip = farClip * 0.4f;
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

// 0x00483be0
void swrRace_DrawDebugPosition(int debugLevel)
{
    char text[64];
    double comp;
    rdVector4* pos = &swrViewport_array[1].model_matrix.vD;

    if (debugLevel <= 1)
        return;
    sprintf(text, swrText_Translate(g_pTxtDebugPosFormat), (int)pos->x, (int)pos->y, (int)pos->z);
    swrText_CreateColorlessFormattedEntry1(4, 0x11d, 0xd6, text);
    comp = swrRace_GetLapProgressIfAvailable();
    if (0.0 < comp) {
        sprintf(text, swrText_Translate(g_pTxtDebugCompFormat), comp);
        swrText_CreateColorlessFormattedEntry1(4, 300, 0xc2, text);
    }
}

// 0x00483ca0
void swrRace_RebuildViewport1Scene_Maybe(void)
{
    rdModel_BuildSceneNoDraw_Maybe(&swrViewport_array[1]);
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
    swrViewport_SetModelMVPAndTranslation(&mvpMatrix, &translation);
    if (vp->unk13c > 0.0)
        vp->unk130 = (short)(65536.0 / vp->unk13c);
}

// In splitscreen, shows swrModel_Node2 (and Node4) only in viewport 1 and Node1/Node3 only in the
// others, then draws the viewport's scene.
// 0x00483A90
void swrViewport_Render(int x)
{
    if (swrObjJdge_splitscreenActive != 0) {
        if (x == 1) {
            if (swrModel_Node1 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node1, 2, -4, 0x10, 3);
            if (swrModel_Node3 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node3, 2, -4, 0x10, 3);
            if (swrModel_Node2 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node2, 2, 3, 0x10, 2);
            if (swrModel_Node4 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node4, 2, 3, 0x10, 2);
        } else {
            if (swrModel_Node1 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node1, 2, 3, 0x10, 2);
            if (swrModel_Node3 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node3, 2, 3, 0x10, 2);
            if (swrModel_Node2 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node2, 2, -4, 0x10, 3);
            if (swrModel_Node4 != NULL)
                swrModel_NodeModifyFlags(swrModel_Node4, 2, -4, 0x10, 3);
        }
    }
    rdModel_SetupSceneFogAndLights(&swrRender_displayListCursor);
    rdModel_BuildAndDrawScene(&swrRender_displayListCursor, &swrViewport_array[x]);
}

// 0x00483BB0
void swrViewport_Activate(int viewportIndex)
{
    swrViewport_active = &swrViewport_array[viewportIndex];
    swrViewport_Setup(viewportIndex);
    swr_noop3();
}

// 0x00482e20
void swrViewport_AdvanceFrameParity(void)
{
    swrViewport_frameTriple++;
    if (swrViewport_frameTriple > 2)
        swrViewport_frameTriple = 0;
    swrViewport_frameParity = 1 - swrViewport_frameParity;
}
