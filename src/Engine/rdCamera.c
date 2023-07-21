#include "rdCamera.h"

#include "globals.h"

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

// 0x0048fdc0
int rdCamera_BuildFOV(rdCamera* camera)
{
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
        camera->pClipFrustum->orthoLeft = -(fVar1 / camera->orthoScale);
        camera->pClipFrustum->orthoTop = (fVar2 / camera->orthoScale) / camera->screenAspectRatio;
        camera->pClipFrustum->orthoRight = fVar1 / camera->orthoScale;
        camera->pClipFrustum->orthoBottom = -(fVar2 / camera->orthoScale) / camera->screenAspectRatio;
        camera->fov_y = 0.0;
        camera->pClipFrustum->farTop = 0.0;
        camera->pClipFrustum->bottom = 0.0;
        camera->pClipFrustum->farLeft = 0.0;
        camera->pClipFrustum->right = 0.0;
    }
    else if (camera->projectType == rdCameraProjectType_Perspective)
    {
        fVar1 = (float)(canvas->widthMinusOne - canvas->xStart) * 0.5;
        fVar2 = (float)(canvas->heightMinusOne - canvas->yStart) * 0.5;
        fVar4 = stdMath_FastTan(camera->fov * 0.5);
        fVar4 = fVar1 / fVar4;
        clipFrustrum = camera->pClipFrustum;
        camera->fov_y = fVar4;
        fVar3 = fVar4 / (clipFrustrum->v).y;
        camera->ambientLight = fVar3;
        camera->numLights = (int)(1.0 / (fVar4 / (clipFrustrum->v).z - fVar3));
        clipFrustrum->farTop = camera->screenAspectRatio / (fVar2 / fVar4);
        camera->pClipFrustum->farLeft = -fVar1 / camera->fov_y;
        camera->pClipFrustum->bottom = (-fVar2 / camera->fov_y) / camera->screenAspectRatio;
        camera->pClipFrustum->right = fVar1 / camera->fov_y;
        camera->pClipFrustum->nearTop = ((fVar2 - -1.0) / camera->fov_y) / camera->screenAspectRatio;
        camera->pClipFrustum->nearLeft = -(fVar1 - -1.0) / camera->fov_y;
        rdCamera_BuildClipFrustum_Unk(camera, camera->pClipFrustum, fVar1 + fVar1, fVar2 + fVar2);
        return 1;
    }
    return 1;
}

// 0x0048ffc0
int rdCamera_BuildClipFrustum_Unk(rdCamera* camera, rdClipFrustum* outClip, float width, float height)
{
    hang("TODO: Looks like rdCamera_BuildClipFrustum but clip frustum is different");
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
    for (int i = 0; i < num_vertices; i++)
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
    for (int i = 0; i < num_vertices; i++)
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
    for (int i = 0; i < num_vertices; i++)
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
    for (int i = 0; i < num_vertices; i++)
    {
        rdCamera_PerspProjectSquare(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}
