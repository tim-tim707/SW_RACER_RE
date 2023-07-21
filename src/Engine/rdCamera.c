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

// 0x0048ffc0
int rdCamera_BuildClipFrustum_Unk(rdCamera* camera, rdClipFrustum* outClip, float width, float height)
{
    hang("TODO: Looks like rdCamera_BuildClipFrustum but clip frustum is different");
    return 0;
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
