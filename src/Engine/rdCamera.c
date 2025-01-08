#include "rdCamera.h"

#include "types.h"
#include "globals.h"
#include "rdCanvas.h"
#include "rdLight.h"

#include <macros.h>
#include <General/stdMath.h>
#include <Primitives/rdMatrix.h>

// 0x00409af0
void rdCamera_Shutdown(void)
{
    rdCanvas_Free(rdCanvas_main_ptr);
    rdCamera_Free(rdCamera_main_ptr);
}

// 0x0048fad0
rdCamera* rdCamera_New(float fov, float x, float y, float z, float aspectRatio)
{
    rdCamera* out = (*rdroid_hostServices_ptr->alloc)(sizeof(rdCamera));
    if (out == NULL)
        return NULL;

    if (rdCamera_NewEntry(out, fov, x, y, z, aspectRatio))
        return out;

    return NULL;
}

// 0x0048fb20
int rdCamera_NewEntry(rdCamera* camera, float fov, float a3, float zNear, float zFar, float aspectRatio)
{
    rdClipFrustum* clipFrustum;

    clipFrustum = (rdClipFrustum*)(*rdroid_hostServices_ptr->alloc)(100);
    camera->pClipFrustum = clipFrustum;
    if (clipFrustum != NULL)
    {
        if (fov < 5.0)
        {
            fov = 5.0;
        }
        else if (179.0 < fov)
        {
            fov = 179.0;
        }
        camera->fov = fov;
        clipFrustum->bFarClip = a3;
        clipFrustum->zNear = zNear;
        clipFrustum->zFar = zFar;
        camera->screenAspectRatio = aspectRatio;
        camera->orthoScale = 1.0;
        camera->canvas = NULL;
        camera->numLights = 0;
        camera->attenuationMin = 0.2;
        camera->attenuationMax = 0.1;

        clipFrustum->leftPlaneNormal = (rdVector3){ 0, 0, 0 };
        clipFrustum->rightPlaneNormal = (rdVector3){ 0, 0, 0 };
        clipFrustum->topPlaneNormal = (rdVector3){ 0, 0, 0 };
        clipFrustum->bottomPlaneNormal2 = (rdVector3){ 0, 0, 0 };

        rdCamera_SetProjectType(camera, rdCameraProjectType_Perspective);
        return 1;
    }
    return 0;
}

// 0x0048fc10
void rdCamera_Free(rdCamera* camera)
{
    if (camera != NULL)
    {
        rdCamera_FreeEntry(camera);
        rdroid_hostServices_ptr->free(camera);
    }
}

// 0x0048fc30
void rdCamera_FreeEntry(rdCamera* camera)
{
    if (camera->pClipFrustum)
    {
        rdroid_hostServices_ptr->free(camera->pClipFrustum);
    }
}

// 0x0048fc50 TODO: crashes on release build, runs fine on debug build
int rdCamera_SetCanvas(rdCamera* camera, rdCanvas* canvas)
{
    camera->canvas = canvas;
    rdCamera_BuildFOV(camera);
    return 1;
}

// 0x0048fc70
int rdCamera_SetCurrent(rdCamera* camera)
{
    if (rdCamera_pCurCamera != camera)
    {
        rdCamera_pCurCamera = camera;
    }
    return 1;
}

// 0x0048fc90
int rdCamera_SetProjectType(rdCamera* camera, rdCameraProjectType type)
{
    camera->projectType = type;

    if (type == rdCameraProjectType_Ortho)
    {
        if (camera->screenAspectRatio == 1.0)
        {
            camera->fnProject = rdCamera_OrthoProjectSquare;
            camera->fnProjectLst = rdCamera_OrthoProjectSquareLst;
        }
        else
        {
            camera->fnProject = rdCamera_OrthoProject;
            camera->fnProjectLst = rdCamera_OrthoProjectLst;
        }
    }
    else if (type == rdCameraProjectType_Perspective)
    {
        if (camera->screenAspectRatio == 1.0)
        {
            camera->fnProject = rdCamera_PerspProjectSquare;
            camera->fnProjectLst = rdCamera_PerspProjectSquareLst;
        }
        else
        {
            camera->fnProject = rdCamera_PerspProject;
            camera->fnProjectLst = rdCamera_PerspProjectLst;
        }
    }

    if (camera->canvas)
        rdCamera_BuildFOV(camera);

    return 1;
}

// 0x0048fd10 TODO: crashes on release build, works fine on debug build
int rdCamera_UpdateProject(rdCamera* camera, float aspectRatio)
{
    camera->screenAspectRatio = aspectRatio;
    if (camera->projectType == rdCameraProjectType_Ortho)
    {
        if (aspectRatio == 1.0)
        {
            camera->fnProject = rdCamera_OrthoProjectSquare;
            camera->fnProjectLst = rdCamera_OrthoProjectSquareLst;
            rdCamera_BuildFOV(camera);
            return 1;
        }
        camera->fnProject = rdCamera_OrthoProject;
        camera->fnProjectLst = rdCamera_OrthoProjectLst;
    }
    else if (camera->projectType == rdCameraProjectType_Perspective)
    {
        if (aspectRatio == 1.0)
        {
            camera->fnProject = rdCamera_PerspProjectSquare;
            camera->fnProjectLst = rdCamera_PerspProjectSquareLst;
            rdCamera_BuildFOV(camera);
            return 1;
        }
        camera->fnProject = rdCamera_PerspProject;
        camera->fnProjectLst = rdCamera_PerspProjectLst;
        rdCamera_BuildFOV(camera);
        return 1;
    }
    rdCamera_BuildFOV(camera);
    return 1;
}

// 0x0048fdc0
int rdCamera_BuildFOV(rdCamera* camera)
{
    HANG("TODO: the struct layout seems wrong, the members are shifted.");
    float fVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    rdCanvas* canvas;
    rdClipFrustum* clipFrustrum;

    canvas = camera->canvas;
    if (canvas == NULL)
    {
        return 0;
    }
    if (camera->projectType == rdCameraProjectType_Ortho)
    {
        fVar1 = (float)(canvas->widthMinusOne - canvas->xStart) * 0.5;
        fVar2 = (float)(canvas->heightMinusOne - canvas->yStart) * 0.5;
        camera->pClipFrustum->orthoLeftPlane = -(fVar1 / camera->orthoScale);
        camera->pClipFrustum->orthoTopPlane = (fVar2 / camera->orthoScale) / camera->screenAspectRatio;
        camera->pClipFrustum->orthoRightPlane = fVar1 / camera->orthoScale;
        camera->pClipFrustum->orthoBottomPlane = -(fVar2 / camera->orthoScale) / camera->screenAspectRatio;
        camera->fov_y = 0.0;
        camera->pClipFrustum->topPlane = 0.0;
        camera->pClipFrustum->bottomPlane = 0.0;
        camera->pClipFrustum->leftPlane = 0.0;
        camera->pClipFrustum->rightPlane = 0.0;
    }
    else if (camera->projectType == rdCameraProjectType_Perspective)
    {
        fVar1 = (float)(canvas->widthMinusOne - canvas->xStart) * 0.5;
        fVar2 = (float)(canvas->heightMinusOne - canvas->yStart) * 0.5;
        fVar4 = stdMath_FastTan(camera->fov * 0.5);
        fVar4 = fVar1 / fVar4;
        clipFrustrum = camera->pClipFrustum;
        camera->fov_y = fVar4;
        fVar3 = fVar4 / clipFrustrum->zNear;
        camera->ambientLight = fVar3;
        camera->unk = (int)(1.0 / (fVar4 / clipFrustrum->zFar - fVar3));
        clipFrustrum->orthoRightPlane = camera->screenAspectRatio / (fVar2 / fVar4);
        camera->pClipFrustum->topPlane = -fVar1 / camera->fov_y;
        camera->pClipFrustum->orthoBottomPlane = (-fVar2 / camera->fov_y) / camera->screenAspectRatio;
        camera->pClipFrustum->bottomPlane = fVar1 / camera->fov_y;
        camera->pClipFrustum->leftPlane = ((fVar2 - -1.0) / camera->fov_y) / camera->screenAspectRatio;
        camera->pClipFrustum->rightPlane = -(fVar1 - -1.0) / camera->fov_y;
        rdCamera_BuildClipFrustum(camera, camera->pClipFrustum, fVar1 + fVar1, fVar2 + fVar2);
        return 1;
    }
    return 1;
}

// 0x0048ffc0
int rdCamera_BuildClipFrustum(rdCamera* camera, rdClipFrustum* outClip, float width, float height)
{
    HANG("TODO: Looks like rdCamera_BuildClipFrustum but clip frustum is different");
    return 0;
}

// 0x00490060
void rdCamera_Update(rdMatrix34* orthoProj)
{
    rdMatrix_InvertOrtho34(&rdCamera_pCurCamera->view_matrix, orthoProj);
    memcpy(&rdCamera_camMatrix, orthoProj, sizeof(rdCamera_camMatrix));
    rdMatrix_ExtractAngles34(&rdCamera_camMatrix, &rdCamera_camRotation);
}

// 0x004900a0
void rdCamera_OrthoProject(rdVector3* out, rdVector3* v)
{
    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = -(v->z * rdCamera_pCurCamera->orthoScale) * rdCamera_pCurCamera->screenAspectRatio + rdCamera_pCurCamera->canvas->screen_width_half;
    out->z = v->y * rdCamera_pCurCamera->orthoScale;
}

// 0x004900e0
void rdCamera_OrthoProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices)
{
    for (unsigned int i = 0; i < num_vertices; i++)
    {
        rdCamera_OrthoProject(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

// 0x00490160
void rdCamera_OrthoProjectSquare(rdVector3* out, rdVector3* v)
{
    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * rdCamera_pCurCamera->orthoScale;
    out->z = v->y;
}

// 0x004901a0
void rdCamera_OrthoProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices)
{
    for (unsigned int i = 0; i < num_vertices; i++)
    {
        rdCamera_OrthoProjectSquare(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

// 0x00490210
void rdCamera_PerspProject(rdVector3* out, rdVector3* v)
{
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - (rdCamera_pCurCamera->fov_y / v->y) * v->z;
    out->z = v->y;
}

// 0x00490250
void rdCamera_PerspProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices)
{
    for (unsigned int i = 0; i < num_vertices; i++)
    {
        rdCamera_PerspProject(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

// 0x004902d0
void rdCamera_PerspProjectSquare(rdVector3* out, rdVector3* v)
{
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * (rdCamera_pCurCamera->fov_y / v->y);
    out->z = v->y;
}

// 0x00490310
void rdCamera_PerspProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices)
{
    for (unsigned int i = 0; i < num_vertices; i++)
    {
        rdCamera_PerspProjectSquare(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

// 0x004903a0
void rdCamera_SetAmbientLight(rdCamera* camera, rdVector4* v)
{
    (camera->unk2).x = v->x;
    (camera->unk2).y = v->y;
    (camera->unk2).z = v->z;
    (camera->unk2).w = v->w;
}

// 0x004903d0
void rdCamera_SetAttenuation(rdCamera* camera, float minVal, float maxVal)
{
    rdLight* light;
    uint32_t i;
    rdLight** lights;

    camera->attenuationMin = minVal;
    i = 0;
    camera->attenuationMax = maxVal;
    if (camera->numLights != 0)
    {
        lights = camera->lights;
        do
        {
            light = *lights;
            if (light->falloffMin == 0.0)
            {
                light->falloffMin = camera->attenuationMin * 40.0;
            }
            if (light->falloffMax == 0.0)
            {
                light->falloffMax = camera->attenuationMax * 50.0;
            }
            i = i + 1;
            lights = lights + 1;
        } while (i < (uint32_t)camera->numLights);
    }
    return;
}

// 0x00490450
int rdCamera_AddLight(rdCamera* camera, rdLight* light, rdVector3* lightPos)
{
    rdVector3* pos;
    float fVar2;

    if (128 < camera->numLights) // max number of lights
    {
        return 0;
    }
    light->id = camera->numLights;
    camera->lights[camera->numLights] = light;
    pos = camera->lightPositions + camera->numLights;
    pos->x = lightPos->x;
    pos->y = lightPos->y;
    pos->z = lightPos->z;
    if (light->falloffMin == 0.0)
    {
        fVar2 = rdLight_GetIntensity(&light->color);
        light->falloffMin = (fVar2 / camera->attenuationMin);
    }
    if (light->falloffMax == 0.0)
    {
        fVar2 = rdLight_GetIntensity(&light->color);
        light->falloffMax = (fVar2 / camera->attenuationMax);
    }
    camera->numLights = camera->numLights + 1;
    return 1;
}

// 0x004904f0
int rdCamera_ClearLights(rdCamera* camera)
{
    camera->numLights = 0;
    return 1;
}
