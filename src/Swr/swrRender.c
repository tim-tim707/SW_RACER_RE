#include "swrRender.h"

#include "globals.h"
#include "swrModel.h"

#include <swr.h>

#include <Engine/rdCamera.h>
#include <Engine/rdMaterial.h>
#include <Raster/rdFace.h>
#include <Engine/rdThing.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdVector.h>
#include <Primitives/rdModel.h>
#include <Unknown/rdMatrixStack.h>
#include <engine_config.h>
#include <stdPlatform.h>
#include <Win95/DirectX.h>
#include <Win95/stdDisplay.h>
#include <Engine/rdCanvas.h>
#include <Engine/rdLight.h>
#include <Engine/rdroid.h>
#include <Swr/swrUI.h>
#include <macros.h>

#include <string.h>

// 0x00409290
void rdModel3Mesh_CalculateSurfaceNormals(rdModel3Mesh* mesh)
{
    unsigned int faceIndex;
    RdFace* face;
    int cur;
    int prev = 0;
    int next = 0;

    face = mesh->aFaces;
    for (faceIndex = 0; faceIndex < (unsigned int)mesh->numFaces; faceIndex++, face++) {
        // find a vertex whose neighbours are not collinear with it
        for (cur = 0; cur < (int)face->numVertices; cur++) {
            prev = cur - 1;
            if (prev < 0)
                prev = face->numVertices - 1;
            next = (unsigned int)(cur + 1) % face->numVertices;
            if (!rdMath_PointsCollinear(&mesh->apVertices[face->aVertIdxs[cur]], &mesh->apVertices[face->aVertIdxs[next]], &mesh->apVertices[face->aVertIdxs[prev]]))
                break;
        }
        if (cur < (int)face->numVertices)
            rdMath_CalcSurfaceNormal(&face->normal, &mesh->apVertices[face->aVertIdxs[cur]], &mesh->apVertices[face->aVertIdxs[next]], &mesh->apVertices[face->aVertIdxs[prev]]);
    }
}

// 0x00409380
void rdFace_ConfigureFogStartEnd(int16_t start, int16_t end)
{
    float scaledStart;
    float range;

    scaledStart = (float)start * zNearEpsilon;
    if (scaledStart < 1.0f)
        fogStart = rdCamera_pCurCamera->pClipFrustum->zNear / (1.0f - scaledStart);
    else
        fogStart = rdCamera_pCurCamera->pClipFrustum->zFar;
    if (!(fogStart < rdCamera_pCurCamera->pClipFrustum->zFar)) {
        rdModel3_SetFogFlags(0);
        return;
    }
    range = rdCamera_pCurCamera->pClipFrustum->zFar - fogStart;
    oneOverFogRange = 1.0f / range;
    // `end` is ignored: the fog end is always placed 1.7 x range past the start
    fogEnd = fogStart - range * -0.7;
    if (fogStart < rdCamera_pCurCamera->pClipFrustum->zNear)
        fogStart = rdCamera_pCurCamera->pClipFrustum->zNear;
}

// Set the fog color from 0-255 component values, then push it (with the current
// fogStart/fogEnd range) to the D3D fog state. Alpha is stored in fogColor.w but not
// forwarded to Direct3d_ConfigFog.
// 0x00409450
void Direct3d_ConfigFog2(short r, short g, short b, short a)
{
    fogColor.x = (float)(int)r * oneOver255f;
    fogColor.y = (float)(int)g * oneOver255f;
    fogColor.z = (float)(int)b * oneOver255f;
    fogColor.w = (float)(int)a * oneOver255f;
    Direct3d_ConfigFog(fogColor.x, fogColor.y, fogColor.z, fogStart, fogEnd);
}

// Enable/disable fog. mode==0 clears all fog flags (and returns 0); otherwise the
// hardware-supported fog flags are applied and returned.
// 0x004094E0
int rdFace_SetFogEnabled(int mode)
{
    if (mode == 0) {
        rdModel3_SetFogFlags(0);
        return mode;
    }
    uint32_t flags = rdFace_FogFlagsSupportedByHardware;
    rdModel3_SetFogFlags(rdFace_FogFlagsSupportedByHardware);
    return flags;
}

// Push light slot `light_index` from the staging arrays into the active cameras: direction into
// rdCamera_main_ptr's light position, color into the current camera's light, plus ambient. A
// second light (secondary bank) is activated when num_lights > 1, otherwise it is disabled.
// 0x00409510
void rdCamera_SetLights(int light_index, int num_lights)
{
    rdCamera_main_ptr->lightPositions[0].x = lightDirection1[light_index].x;
    rdCamera_main_ptr->lightPositions[0].y = lightDirection1[light_index].y;
    rdCamera_main_ptr->lightPositions[0].z = lightDirection1[light_index].z;
    rdCamera_pCurCamera->lights[0]->color = lightColor1[light_index];
    rdCamera_pCurCamera->lights[0]->active = 1;
    rdCamera_SetAmbientLight(rdCamera_pCurCamera, &lightAmbientColor[light_index]);
    if (num_lights > 1) {
        rdCamera_main_ptr->lightPositions[1].x = lightDirection2[light_index].x;
        rdCamera_main_ptr->lightPositions[1].y = lightDirection2[light_index].y;
        rdCamera_main_ptr->lightPositions[1].z = lightDirection2[light_index].z;
        rdCamera_pCurCamera->lights[1]->color = lightColor2[light_index];
        rdCamera_pCurCamera->lights[1]->active = 1;
    } else {
        rdCamera_pCurCamera->lights[1]->active = 0;
    }
}

// Set primary-bank light `light_index`: direction from the raw position, color + ambient from
// 0-255 components scaled to 0..1 (w = 1.0). The return is the internal light_index*16 byte
// offset left in EAX; callers ignore it.
// 0x00409600
float* SetLightColorsAndDirection(int light_index, short ambient_r, short ambient_g, short ambient_b, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    lightDirection1[light_index].x = (float)(int)pos_x;
    lightDirection1[light_index].y = (float)(int)pos_y;
    lightDirection1[light_index].z = (float)(int)pos_z;
    lightColor1[light_index].x = (float)(int)light_r * oneOver255f;
    lightColor1[light_index].y = (float)(int)light_g * oneOver255f;
    lightColor1[light_index].z = (float)(int)light_b * oneOver255f;
    lightColor1[light_index].w = 1.0f;
    lightAmbientColor[light_index].x = (float)(int)ambient_r * oneOver255f;
    lightAmbientColor[light_index].y = (float)(int)ambient_g * oneOver255f;
    lightAmbientColor[light_index].z = (float)(int)ambient_b * oneOver255f;
    lightAmbientColor[light_index].w = 1.0f;
    return (float*)(light_index * 0x10);
}

// Copy the primary light (slot 0)'s direction/color/ambient x,y,z into slot `light_index`.
// 0x00409700
int SetLightColorsAndDirectionFromPrimaryLight(short light_index)
{
    lightDirection1[light_index].x = lightDirection1[0].x;
    lightDirection1[light_index].y = lightDirection1[0].y;
    lightDirection1[light_index].z = lightDirection1[0].z;
    lightColor1[light_index].x = lightColor1[0].x;
    lightColor1[light_index].y = lightColor1[0].y;
    lightColor1[light_index].z = lightColor1[0].z;
    lightAmbientColor[light_index].x = lightAmbientColor[0].x;
    lightAmbientColor[light_index].y = lightAmbientColor[0].y;
    lightAmbientColor[light_index].z = lightAmbientColor[0].z;
    return 0xc;
}

// Set secondary-bank light `light_index`: direction from the raw position, color from 0-255
// components (the secondary bank has no ambient term). Return is the vestigial index offset.
// 0x00409750
float* SetAlternativeLightColorsAndDirection(int light_index, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    lightDirection2[light_index].x = (float)(int)pos_x;
    lightDirection2[light_index].y = (float)(int)pos_y;
    lightDirection2[light_index].z = (float)(int)pos_z;
    lightColor2[light_index].x = (float)(int)light_r * oneOver255f;
    lightColor2[light_index].y = (float)(int)light_g * oneOver255f;
    lightColor2[light_index].z = (float)(int)light_b * oneOver255f;
    lightColor2[light_index].w = 1.0f;
    return (float*)(light_index * 0x10);
}

// 0x00409800
int swrRender_InitScene(swrMainDisplaySettings* settings)
{
    rdVector3 light1Pos;
    rdVector3 light2Pos;
    rdVector4 ambient;
    StdVideoMode mode;

    stdDisplay_Update();
    swrUI_UpdateProgressBar(26);
    stdDisplay_BackBufferFill((uint8_t)backBufferClearColor[0], (uint8_t)backBufferClearColor[1], (uint8_t)backBufferClearColor[2], NULL);
    swrUI_UpdateProgressBar(28);
    swrDisplay_screenWidth = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth;
    swrDisplay_screenHeight = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight;
    rdCanvas_main_ptr = rdCanvas_New(0, &stdDisplay_g_backBuffer, 0, 0, swrDisplay_screenWidth, swrDisplay_screenHeight);
    rdSetGeometryMode(settings->geometryMode);
    rdSetLightingMode(settings->lightMode);
    rdSetRenderOptions(RDDROID_BACKFACE_CULLING_ENABLED);
    swrUI_UpdateProgressBar(29);
    rdCamera_main_ptr = rdCamera_New(75.0f, 0.0f, 0.08f, 15.0f, 1.0f);
    rdCamera_SetCanvas(rdCamera_main_ptr, rdCanvas_main_ptr);
    swrUI_UpdateProgressBar(30);
    rdCamera_SetCurrent(rdCamera_main_ptr);
    rdCamera_mat = rdMatrix34_identity;
    swrRender_initSceneUnusedPos.x = -1000.0f;
    swrRender_initSceneUnusedPos.y = -2000.0f;
    swrRender_initSceneUnusedPos.z = 8000.0f;
    swrRender_initSceneUnusedVec.x = 0.0f;
    swrRender_initSceneUnusedVec.y = 0.0f;
    swrRender_initSceneUnusedVec.z = 0.0f;
    rdCamera_Update(&rdCamera_mat);
    swrUI_UpdateProgressBar(32);
    if (stdDisplay_CopyCurrentVideoMode(&mode) != 0)
        return 0;
    rdCamera_UpdateProject(rdCamera_main_ptr, mode.aspectRatio);
    rdCamera_SetAttenuation(rdCamera_main_ptr, 0.4f, 0.8f);
    swrUI_UpdateProgressBar(34);
    rdCamera_SetCanvas(rdCamera_main_ptr, rdCanvas_main_ptr);
    rdCamera_ClearLights(rdCamera_main_ptr);
    rdLight_NewEntry(&rdLight_1);
    rdLight_NewEntry(&rdLight_2);
    rdLight_1.type = RD_LIGHT_TYPE_DIRECTIONAL;
    rdLight_2.type = RD_LIGHT_TYPE_DIRECTIONAL;
    rdLight_1.color.x = 1.0f;
    rdLight_2.color.x = 1.0f;
    rdLight_1.color.z = 0.0f;
    rdLight_1.color.y = 0.0f;
    rdLight_2.color.z = 0.0f;
    rdLight_2.color.y = 0.0f;
    light1Pos.x = 0.0f;
    light2Pos.x = 0.0f;
    light1Pos.y = 100.0f;
    light2Pos.y = 100.0f;
    light1Pos.z = -20.0f;
    light2Pos.z = -20.0f;
    swrUI_UpdateProgressBar(36);
    rdCamera_AddLight(rdCamera_main_ptr, &rdLight_1, &light1Pos);
    rdCamera_AddLight(rdCamera_main_ptr, &rdLight_2, &light2Pos);
    ambient.x = 0.0f;
    ambient.y = 0.0f;
    ambient.z = 0.5f;
    ambient.w = 1.0f;
    rdCamera_SetAmbientLight(rdCamera_main_ptr, &ambient);
    swrUI_UpdateProgressBar(38);
    swrRender_sceneInitialized = 1;
    // the EXE returns whatever swrUI_UpdateProgressBar left in EAX; no caller reads it
    return 1;
}

// 0x00432B80
void rdModel3Mesh_ApplySwrModelColors(rdModel3Mesh* rdmesh, swrModel_Mesh* mesh)
{
    rdVector4* vertColors = rdmesh->aVertColors;
    rdVector4* lightIntensities = rdmesh->aLightIntensities;
    int numVertices = rdmesh->numVertices;
    swrModel_MeshMaterial* meshMaterial = mesh->mesh_material;
    swrModel_Material* material;
    float color[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
    float value;
    int i, k;

    if (meshMaterial == NULL)
        return;
    material = meshMaterial->material;
    if (material != NULL) {
        if (rdmesh->colorFlags & RDMESH_COLOR_PRIM_RGB) {
            color[0] = (float)material->primitive_color[0] * (1.0f / 255.0f);
            color[1] = (float)material->primitive_color[1] * (1.0f / 255.0f);
            color[2] = (float)material->primitive_color[2] * (1.0f / 255.0f);
        }
        if (rdmesh->colorFlags & RDMESH_COLOR_PRIM_ALPHA)
            color[3] = (float)material->primitive_color[3] * (1.0f / 255.0f);
    }

    if ((meshMaterial->type & swrModel_MESH_MATERIAL_VTX_NORMALS_MASK) == 0 && (rdmesh->colorFlags & RDMESH_COLOR_VERTEX_ALPHA_ONLY) == 0) {
        // baked vertex colors, tinted by the primitive color
        for (i = 0; i < numVertices; i++) {
            for (k = 0; k < 4; k++) {
                value = (float)(&mesh->vertices[i].v.r)[k] * color[k] * (1.0f / 255.0f);
                (&vertColors[i].x)[k] = value;
                (&lightIntensities[i].x)[k] = value;
            }
        }
        return;
    }
    for (i = 0; i < numVertices; i++) {
        vertColors[i].x = lightIntensities[i].x = color[0];
        vertColors[i].y = lightIntensities[i].y = color[1];
        vertColors[i].z = lightIntensities[i].z = color[2];
        vertColors[i].w = lightIntensities[i].w = color[3];
        if (rdmesh->colorFlags & RDMESH_COLOR_VERTEX_ALPHA_ONLY) {
            value = (float)mesh->vertices[i].v.a * color[3] * (1.0f / 255.0f);
            vertColors[i].w = value;
            lightIntensities[i].w = value;
        }
    }
}

static int rdModel_ClampConvertIndex(int idx, int numVertices)
{
    // faithful: only idx > numVertices (unsigned) is rejected, idx == numVertices passes
    if ((unsigned int)idx > (unsigned int)numVertices)
        return 0;
    return idx;
}

static void rdModel_InitConvertFace(RdFace* face, int num, RdFaceFlag flags, RdLightMode lightMode, int* aVertIdxs, int* aTexIdxs, RdMaterial* pMaterial)
{
    rdFace_NewEntry(face);
    face->lightingMode = lightMode;
    face->aVertIdxs = aVertIdxs;
    face->num = num;
    face->flags = flags;
    face->geometryMode = RD_GEOMETRY_FULL;
    face->numVertices = 3;
    face->aTexIdxs = aTexIdxs;
    face->pMaterial = pMaterial;
}

static void rdModel_SetConvertFaceIndices(RdFace* face, int a, int b, int c)
{
    face->aVertIdxs[0] = a;
    face->aVertIdxs[1] = b;
    face->aVertIdxs[2] = c;
    face->aTexIdxs[0] = a;
    face->aTexIdxs[1] = b;
    face->aTexIdxs[2] = c;
}

static int rdModel_UsesPrimitiveColor(const uint8_t* combine)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (combine[i] == N64_CCMUX_PRIMITIVE || combine[i + 8] == N64_CCMUX_PRIMITIVE)
            return 1;
    }
    return 0;
}

// 0x00432D30
void rdModel_ConvertSwrModelMesh(Gfx* display_list, rdModel3Mesh* result, swrModel_Mesh* mesh, RdFaceFlag material_flags)
{
    RdFace faces[RDMODEL_CONVERT_MAX_FACES];
    swrModel_MeshMaterial* meshMaterial;
    swrModel_MaterialTexture* texture;
    swrModel_Material* material;
    RdMaterial* pMaterial;
    RdLightMode lightMode;
    Vtx* vtx;
    Gfx* cmd;
    rdVector3* normal;
    int* indexBuf;
    uint32_t renderMode;
    uint8_t texWrap;
    uint8_t colorFlags;
    float uScale;
    float vScale;
    float uDiv;
    float vDiv;
    int clampUV;
    int hasNormals;
    int numVertices;
    int vertexBase;
    int numFaces;
    int indexBytes;
    int done;
    int i;

    done = 0;
    hasNormals = 0;
    clampUV = 0;
    numFaces = 0;
    uScale = 1.0f;
    vScale = 1.0f;
    pMaterial = NULL;
    colorFlags = 0;
    lightMode = RD_LIGHTING_LIT;
    renderMode = 0;
    meshMaterial = mesh->mesh_material;

    if (meshMaterial != NULL) {
        material = meshMaterial->material;
        texture = meshMaterial->material_texture;
        if (texture == NULL) {
            pMaterial = rdMaterial_GetOrCreateDefaultMaterial(meshMaterial);
        } else {
            pMaterial = texture->loaded_material;
            if (texture->specs[0] != NULL) {
                texWrap = ((uint8_t*)&texture->specs[0]->flags)[3];
                if ((texWrap & swrModel_TEXWRAP_S_MIRROR) != 0)
                    uScale = 2.0f;
                if ((texWrap & swrModel_TEXWRAP_T_MIRROR) != 0)
                    vScale = 2.0f;
                if ((texWrap & swrModel_TEXWRAP_S_CLAMP) != 0 && (texWrap & swrModel_TEXWRAP_T_CLAMP) != 0)
                    clampUV = 1;
            }
        }

        if (material != NULL) {
            renderMode = material->render_mode_1 | material->render_mode_2;
            // color mux bytes of both cycles, then alpha mux bytes of both cycles
            if (rdModel_UsesPrimitiveColor((const uint8_t*)&material->color_combine_mode_cycle1))
                colorFlags = RDMESH_COLOR_PRIM_RGB;
            if (rdModel_UsesPrimitiveColor((const uint8_t*)&material->alpha_combine_mode_cycle1)) {
                colorFlags |= RDMESH_COLOR_PRIM_ALPHA;
                material_flags |= RD_FF_TEX_TRANSLUCENT;
            }

            // the full render-mode words below are the specific N64 modes the PC port special-cases
            if (rdMaterial_a_alpha_ice03_rgb != pMaterial) {
                if ((renderMode & (N64_RM_Z_CMP | N64_RM_Z_UPD)) == 0)
                    material_flags |= RD_FF_ZWRITE_DISABLED;
                if (renderMode == 0xc81049f8 || renderMode == 0xc8104b50) {
                    material_flags |= RD_FF_ZWRITE_DISABLED | RD_FF_DOUBLE_SIDED;
                } else if (renderMode == 0xc1841c8) {
                    if (pMaterial != NULL)
                        rdMaterial_InvertTextureAlphaR4G4B4A4(pMaterial);
                    material_flags |= RD_FF_NEAR_PLANE | RD_FF_ZWRITE_DISABLED | RD_FF_DOUBLE_SIDED;
                } else if (rdMaterial_b_alpha_waterfall_ctr_rgb != pMaterial && rdMaterial_b_alpha_waterfall_edge_rgb != pMaterial) {
                    if (renderMode == 0xc81041d8 || renderMode == 0xc81049d8) {
                        material_flags |= RD_FF_ZWRITE_DISABLED | RD_FF_DOUBLE_SIDED;
                    } else if (renderMode == 0xf0a2008) {
                        material_flags |= RD_FF_ZWRITE_DISABLED;
                    } else if (renderMode == 0xc184950) {
                        material_flags |= RD_FF_ZWRITE_DISABLED;
                        colorFlags |= RDMESH_COLOR_VERTEX_ALPHA_ONLY;
                    } else if (renderMode != 0xc180079 && rdMaterial_mg_engturbine_rgb != pMaterial && renderMode != 0xc8104340 && (renderMode & N64_RM_ZMODE_XLU) == 0 && pMaterial != NULL) {
                        if (pMaterial->formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA)
                            rdMaterial_RemoveTextureAlphaR5G5B5A1(pMaterial);
                        if (pMaterial->formatType == STDCOLOR_FORMAT_RGBA)
                            rdMaterial_RemoveTextureAlphaR4G4B4A4(pMaterial);
                    }
                }
            }

            if (renderMode == 0xf0a2008)
                clampUV = 1;
            if (clampUV != 0)
                material_flags |= RD_FF_TEX_CLAMP_X | RD_FF_TEX_CLAMP_Y;
        }

        if (renderMode != 0xc81041c8 && (meshMaterial->type & swrModel_MESH_MATERIAL_VTX_NORMALS_MASK) != 0) {
            hasNormals = 1;
            lightMode = RD_LIGHTING_GOURAUD;
        }
    }

    vtx = mesh->vertices;
    numVertices = (int16_t)mesh->num_vertices;
    result->numVertices = numVertices;
    result->apVertices = swrModel_AllocMaterial((unsigned int)meshMaterial, numVertices * sizeof(rdVector3));
    result->numTexVertices = numVertices;
    result->apTexVertices = swrModel_AllocMaterial((unsigned int)meshMaterial, numVertices * sizeof(rdVector2));
    result->aVertColors = swrModel_AllocMaterial((unsigned int)meshMaterial, numVertices * sizeof(rdVector4));
    result->aLightIntensities = swrModel_AllocMaterial((unsigned int)meshMaterial, numVertices * sizeof(rdVector4));
    result->aVertNormals = swrModel_AllocMaterial((unsigned int)meshMaterial, numVertices * sizeof(rdVector3));
    result->geoMode = RD_GEOMETRY_FULL;
    result->lightMode = lightMode;
    result->colorFlags = colorFlags;
    rdVector_Set4(&result->meshColor, 1.0f, 1.0f, 1.0f, 1.0f);

    if (numVertices != 0) {
        // N64 texture coordinates are s10.5 fixed point over a 2x-mirrored page when the wrap mode mirrors
        uDiv = uScale * 4096.0f;
        vDiv = vScale * 4096.0f;
        for (i = 0; i < numVertices; i++, vtx++) {
            result->apVertices[i].x = (float)(int16_t)SWAP16(vtx->v.x);
            result->apVertices[i].y = (float)(int16_t)SWAP16(vtx->v.y);
            result->apVertices[i].z = (float)(int16_t)SWAP16(vtx->v.z);
            result->apTexVertices[i].x = (float)(int16_t)SWAP16(vtx->v.u) / uDiv;
            result->apTexVertices[i].y = (float)(int16_t)SWAP16(vtx->v.v) / vDiv;
            if (hasNormals == 0) {
                result->aVertColors[i].x = (float)vtx->v.r * (1.0f / 255.0f);
                result->aVertColors[i].y = (float)vtx->v.g * (1.0f / 255.0f);
                result->aVertColors[i].z = (float)vtx->v.b * (1.0f / 255.0f);
                result->aVertColors[i].w = (float)vtx->v.a * (1.0f / 255.0f);
            } else {
                result->aVertColors[i].x = 1.0f;
                result->aVertColors[i].y = 1.0f;
                result->aVertColors[i].z = 1.0f;
                result->aVertColors[i].w = 1.0f;
                normal = &result->aVertNormals[i];
                normal->x = (float)vtx->n.nx * (1.0f / 128.0f);
                normal->y = (float)vtx->n.ny * (1.0f / 128.0f);
                normal->z = (float)vtx->n.nz * (1.0f / 128.0f);
                rdVector_Normalize3Acc_2(normal);
            }
            result->aLightIntensities[i] = result->aVertColors[i];
        }
    }

    if (clampUV != 0) {
        for (i = 0; i < numVertices; i++) {
            result->apTexVertices[i].x = result->apTexVertices[i].x - 1.0f;
            result->apTexVertices[i].y = result->apTexVertices[i].y - 1.0f;
        }
    }

    indexBytes = 0;
    cmd = display_list;
    do {
        if (cmd->type == GFX_OP_TRI1)
            indexBytes += 2 * 3 * sizeof(int);
        else if (cmd->type == GFX_OP_TRI2)
            indexBytes += 2 * 2 * 3 * sizeof(int);
        else if (cmd->type == GFX_OP_END_DL)
            done = 1;
        cmd++;
    } while (done == 0);
    indexBuf = swrModel_AllocMaterial((unsigned int)meshMaterial, indexBytes);

    // faithful: vertexBase starts as the clampUV flag until the first gSPVertex sets it
    vertexBase = clampUV;
    done = 0;
    cmd = display_list;
    do {
        if (cmd->type == GFX_OP_TRI1) {
            int a = rdModel_ClampConvertIndex(((int8_t)cmd->gSP1Triangle.index0 >> 1) + vertexBase, numVertices);
            int b = rdModel_ClampConvertIndex(((int8_t)cmd->gSP1Triangle.index1 >> 1) + vertexBase, numVertices);
            int c = rdModel_ClampConvertIndex(((int8_t)cmd->gSP1Triangle.index2 >> 1) + vertexBase, numVertices);
            rdModel_InitConvertFace(&faces[numFaces], numFaces, material_flags, lightMode, indexBuf, indexBuf + 3, pMaterial);
            rdModel_SetConvertFaceIndices(&faces[numFaces], a, b, c);
            indexBuf += 6;
            numFaces++;
        } else if (cmd->type == GFX_OP_VERTEX) {
            rdModel_lastVertexLoad = cmd->gSPVertex.vertex_offset - mesh->vertex_base_offset;
            vertexBase = ((int)rdModel_lastVertexLoad - (int)mesh->vertices) / (int)sizeof(Vtx);
        } else if (cmd->type == GFX_OP_TRI2) {
            int a = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index0 >> 1) + vertexBase, numVertices);
            int b = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index1 >> 1) + vertexBase, numVertices);
            int c = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index2 >> 1) + vertexBase, numVertices);
            int d = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index3 >> 1) + vertexBase, numVertices);
            int e = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index4 >> 1) + vertexBase, numVertices);
            int f = rdModel_ClampConvertIndex(((int8_t)cmd->gSP2Triangles.index5 >> 1) + vertexBase, numVertices);
            // faithful: both triangles get the same face num
            for (i = 0; i < 2; i++) {
                rdModel_InitConvertFace(&faces[numFaces + i], numFaces, material_flags, lightMode, indexBuf, indexBuf + 3, pMaterial);
                indexBuf += 6;
            }
            rdModel_SetConvertFaceIndices(&faces[numFaces], a, b, c);
            rdModel_SetConvertFaceIndices(&faces[numFaces + 1], d, e, f);
            numFaces += 2;
        } else if (cmd->type == GFX_OP_END_DL) {
            done = 1;
        }
        cmd++;
    } while (done == 0);

    result->numFaces = numFaces;
    result->aFaces = swrModel_AllocMaterial((unsigned int)meshMaterial, numFaces * sizeof(RdFace));
    for (i = 0; i < numFaces; i++) {
        rdFace_NewEntry(&result->aFaces[i]);
        result->aFaces[i].num = faces[i].num;
        result->aFaces[i].flags = faces[i].flags;
        result->aFaces[i].geometryMode = faces[i].geometryMode;
        result->aFaces[i].lightingMode = faces[i].lightingMode;
        result->aFaces[i].numVertices = faces[i].numVertices;
        result->aFaces[i].aVertIdxs = faces[i].aVertIdxs;
        result->aFaces[i].aTexIdxs = faces[i].aTexIdxs;
        result->aFaces[i].pMaterial = faces[i].pMaterial;
    }
}

// 0x0044C440
char rdModel_ApplyNodeSettings(char flags, short light_index)
{
    char applied = 0;

    if ((flags & swrModel_NODEFLAGS5_NO_FRUSTUM_CULL) != 0 && rdModel_frustumCullEnabled != 0) {
        rdModel_frustumCullEnabled = 0;
        applied = swrModel_NODEFLAGS5_NO_FRUSTUM_CULL;
    }
    if ((flags & swrModel_NODEFLAGS5_MIRRORED) != 0) {
        rdModel_mirroredWinding = rdModel_mirroredWinding == 0;
        applied |= swrModel_NODEFLAGS5_MIRRORED;
    }
    if ((flags & swrModel_NODEFLAGS5_LIGHT_INDEX) != 0 && rdModel_LightSelected == 0) {
        rdModel_LightSelected = 1;
        rdModel_LightingEnabled = 1;
        rdModel_CurrentLightIndex = light_index + 1;
        rdModel_CurrentLightNum = numEnabledLights[light_index];
        applied |= swrModel_NODEFLAGS5_LIGHT_INDEX;
    }
    return applied;
}

// 0x0044C4C0
void rdModel_RevertNodeSettings(char state)
{
    if ((state & swrModel_NODEFLAGS5_MIRRORED) != 0)
        rdModel_mirroredWinding = rdModel_mirroredWinding == 0;
    if ((state & swrModel_NODEFLAGS5_NO_FRUSTUM_CULL) != 0)
        rdModel_frustumCullEnabled = 1;
    if ((state & swrModel_NODEFLAGS5_LIGHT_INDEX) != 0) {
        rdModel_LightSelected = 0;
        rdModel_LightingEnabled = 0;
        rdCamera_SetLights(0, 1);
    }
}

// One clip axis of AABBFrustumTest: `side` is -1/0/1 for a corner below/inside/above the
// clip range, `allInside` stays nonzero while every corner was inside, `commonSide` stays
// -1/1 while every corner was outside on the same side (-2 = no corner seen yet).
static void AABBFrustumTest_AccumulateAxis(int16_t side, int16_t* allInside, int16_t* commonSide)
{
    if (side == 0) {
        if (*allInside != 0)
            *allInside = 1;
        *commonSide = 0;
        return;
    }
    *allInside = 0;
    if (*commonSide == -side)
        *commonSide = 0;
    else if (*commonSide == -2)
        *commonSide = side;
}

static int16_t AABBFrustumTest_ClassifySymmetric(float c, float w)
{
    if (w > 0.0f) {
        if (c > w)
            return 1;
        if (c < -w)
            return -1;
        return 0;
    }
    if (c > -w)
        return 1;
    if (c < w)
        return -1;
    return 0;
}

// Returns 0 = outside the frustum, 1 = intersecting, 2 = fully inside (only with full_test).
// 0x0044c510
int16_t AABBFrustumTest(float* aabb, bool full_test)
{
    // per clip row: each min/max component times its matrix column
    float rowX[6];
    float rowY[6];
    float rowZ[6];
    float rowW[6];
    int16_t insideX, insideY, insideZ;
    int16_t sideX, sideY, sideZ;
    int16_t sideDepth;
    int offX, offY, offZ;
    float w;
    int corner;

    if (!(aabb[0] <= aabb[3]) || !(aabb[1] <= aabb[4]) || !(aabb[2] <= aabb[5]))
        return 0;

    rowX[0] = PrecomputedMVPMatrix.vA.x * aabb[0];
    rowX[3] = PrecomputedMVPMatrix.vA.x * aabb[3];
    rowX[1] = PrecomputedMVPMatrix.vB.x * aabb[1];
    rowX[4] = PrecomputedMVPMatrix.vB.x * aabb[4];
    rowX[2] = PrecomputedMVPMatrix.vC.x * aabb[2];
    rowX[5] = PrecomputedMVPMatrix.vC.x * aabb[5];
    rowY[0] = PrecomputedMVPMatrix.vA.y * aabb[0];
    rowY[3] = PrecomputedMVPMatrix.vA.y * aabb[3];
    rowY[1] = PrecomputedMVPMatrix.vB.y * aabb[1];
    rowY[4] = PrecomputedMVPMatrix.vB.y * aabb[4];
    rowY[2] = PrecomputedMVPMatrix.vC.y * aabb[2];
    rowY[5] = PrecomputedMVPMatrix.vC.y * aabb[5];
    rowZ[0] = PrecomputedMVPMatrix.vA.z * aabb[0];
    rowZ[3] = PrecomputedMVPMatrix.vA.z * aabb[3];
    rowZ[1] = PrecomputedMVPMatrix.vB.z * aabb[1];
    rowZ[4] = PrecomputedMVPMatrix.vB.z * aabb[4];
    rowZ[2] = PrecomputedMVPMatrix.vC.z * aabb[2];
    rowZ[5] = PrecomputedMVPMatrix.vC.z * aabb[5];
    rowW[0] = PrecomputedMVPMatrix.vA.w * aabb[0];
    rowW[3] = PrecomputedMVPMatrix.vA.w * aabb[3];
    rowW[1] = PrecomputedMVPMatrix.vB.w * aabb[1];
    rowW[4] = PrecomputedMVPMatrix.vB.w * aabb[4];
    rowW[2] = PrecomputedMVPMatrix.vC.w * aabb[2];
    rowW[5] = PrecomputedMVPMatrix.vC.w * aabb[5];

    if (full_test) {
        insideX = -1;
        insideY = -1;
        insideZ = -1;
    } else {
        insideX = 0;
        insideY = 0;
        insideZ = 0;
    }
    sideX = -2;
    sideY = -2;
    sideZ = -2;

    for (corner = 0; corner < 8; corner++) {
        offZ = (corner & 1) * 3 + 2;
        offY = ((corner >> 1) & 1) * 3 + 1;
        offX = ((corner >> 2) & 1) * 3;
        w = rowW[offY] + rowW[offX] + rowW[offZ] + PrecomputedMVPMatrix.vD.w;
        if (insideX != 0 || sideX != 0)
            AABBFrustumTest_AccumulateAxis(AABBFrustumTest_ClassifySymmetric(rowX[offY] + rowX[offX] + rowX[offZ] + PrecomputedMVPMatrix.vD.x, w), &insideX, &sideX);
        if (insideY != 0 || sideY != 0)
            AABBFrustumTest_AccumulateAxis(AABBFrustumTest_ClassifySymmetric(rowY[offY] + rowY[offX] + rowY[offZ] + PrecomputedMVPMatrix.vD.y, w), &insideY, &sideY);
        if (insideZ != 0 || sideZ != 0) {
            // depth only clips against the far plane; w <= 0 counts as behind the camera
            if (!(w > 0.0f))
                sideDepth = -1;
            else if (rowZ[offY] + rowZ[offX] + rowZ[offZ] + PrecomputedMVPMatrix.vD.z > w)
                sideDepth = 1;
            else
                sideDepth = 0;
            AABBFrustumTest_AccumulateAxis(sideDepth, &insideZ, &sideZ);
        }
    }

    if (insideX != 0 && insideY != 0 && insideZ != 0)
        return 2;
    if (sideX == 0 && sideY == 0 && sideZ == 0)
        return 1;
    return 0;
}

// Appends one scene hierarchy node per mesh of a mesh group under the root node, oriented by
// `orient`, and returns the first appended node.
static rdModel3HNode* rdModel_AppendMeshGroupHNodes(const rdMatrix34* orient, int numMeshes, int resetVertexBase)
{
    rdModel3HNode* nodes = swr_rootModel_ptr->aHierarchyNodes;
    int first = swr_rootModel_ptr->numHNodes;
    int end = first + numMeshes;
    rdModel3HNode* hnode;
    int i;

    nodes->numChildren = end - 1;
    if (&nodes[first - 1] == swr_rootModel_ptr->aHierarchyNodes)
        nodes[first - 1].pChild = &nodes[first];
    else
        nodes[first - 1].pSibling = &nodes[first];
    hnode = &nodes[first];
    for (i = first; i < end; i++, hnode++) {
        hnode->num = i;
        hnode->meshIdx = -1;
        memcpy(hnode->aName, "Unknown", 8);
        hnode->pParent = swr_rootModel_ptr->aHierarchyNodes;
        hnode->pSibling = i < end - 1 ? hnode + 1 : NULL;
        hnode->pChild = NULL;
        hnode->numChildren = 0;
        if (resetVertexBase)
            hnode->vertexBaseOffset = 0;
        hnode->type = 1;
        hnode->meshOrient = *orient;
    }
    swr_rootModel_ptr->numHNodes = end;
    return &nodes[first];
}

static RdFaceFlag rdModel_MeshMaterialFaceFlags(const swrModel_MeshMaterial* material)
{
    if (material == NULL || (material->type & swrModel_MESH_MATERIAL_FRONT_FACING) != 0)
        return 0;
    return (material->type & swrModel_MESH_MATERIAL_MIRRORED) != 0 ? RD_FF_MIRRORED : RD_FF_DOUBLE_SIDED;
}

// Converts a mesh's N64 display list into the next free root-model mesh and returns it.
static rdModel3Mesh* rdModel_ConvertMeshIntoRoot(swrModel_Mesh* mesh, rdModel3HNode* hnode, RdFaceFlag faceFlags, int resetCounters)
{
    Gfx* displayList = mesh->vertex_display_list;
    int meshIndex = swrModel_AllocRootMeshIndex((unsigned int)displayList);
    rdModel3Mesh* result = &rdModel_rootGeoSet->aMeshes[meshIndex];

    result->geoMode = RD_GEOMETRY_SOLID;
    hnode->meshIdx = meshIndex;
    result->num = meshIndex;
    result->name[0] = 'a';
    result->name[1] = 'e';
    result->name[2] = 's';
    if (resetCounters) {
        result->unk84 = 0;
        result->unk86 = 0;
    }
    rdModel_ConvertSwrModelMesh(displayList, result, mesh, faceFlags);
    // faithful: the source display list pointer is parked (unaligned) in the name after the tag
    memcpy(&result->name[10], &mesh->vertex_display_list, sizeof(Gfx*));
    mesh->converted_mesh = result;
    result->radius = rdVector_Dist3((rdVector3*)&mesh->aabb[0], (rdVector3*)&mesh->aabb[3]) * 0.5f;
    rdModel3Mesh_CalculateSurfaceNormals(result);
    return result;
}

// 0x0044ca00
void rdModel_AddMeshGroupToScene(swrModel_NodeMeshGroup* node)
{
    // faithful: the UV offsets and face flags are not reset per mesh, so an untextured or
    // double-sided mesh inherits them from the meshes before it in the group
    float uOffset = 0.0f;
    float vOffset = 0.0f;
    RdFaceFlag faceFlags = 0;
    const rdMatrix34* orient;
    rdModel3HNode* hnode;
    swrModel_Mesh* mesh;
    swrModel_MeshMaterial* material;
    swrModel_MaterialTexture* texture;
    rdModel3Mesh* converted;
    rdModel3Mesh* result;
    int16_t visibility;
    int i;

    if (rdModel_nodeTransformsEnabled != 0 && rdMatrixStack34_modified != 0)
        rdMatrixStack34_PrecomputeMVPMatrices();
    node->cached_model_matrix = PrecomputedModelMatrixPtr;
    node->cached_mvp_matrix = PrecomputedMVPMatrixPtr;
    if (rdModel_frustumCullEnabled == 0)
        visibility = 2;
    else
        visibility = AABBFrustumTest(node->aabb, true);
    if (visibility == 0)
        return;

    if (rdModel_nodeTransformsEnabled != 0) {
        rdMatrixStack34_mvpComputed = 0;
        orient = &rdMatrixStack34[rdMatrixStack34_size];
    } else {
        // faithful: with node transforms off, the node itself is read as the orientation
        orient = (const rdMatrix34*)node;
    }
    hnode = rdModel_AppendMeshGroupHNodes(orient, node->node.num_children, 1);

    for (i = 0; i < (int)node->node.num_children; i++, hnode++) {
        mesh = node->node.children.meshes[i];
        if (visibility != 2 && AABBFrustumTest(mesh->aabb, false) == 0)
            continue;
        converted = mesh->converted_mesh;
        // faithful: the call also pushes mesh->mesh_material, which the callee ignores
        rdModel_SetForceFlatNormals_Maybe(GameSettingFlags & GAME_SETTING_UNK_2000);
        material = mesh->mesh_material;
        faceFlags |= rdModel_MeshMaterialFaceFlags(material);
        if ((GameSettingFlags & GAME_SETTING_UNTEXTURED) == 0 && material != NULL && material->material_texture != NULL) {
            texture = material->material_texture;
            uOffset = (float)material->texture_offset[0] / (float)texture->res[0];
            vOffset = (float)material->texture_offset[1] / (float)texture->res[1];
            // faithful: both calls push two more (ignored) arguments
            if (texture->specs[0] == NULL)
                rdModel_SetCurrentMaterial(rdMaterial_GetOrCreateDefaultMaterial(material));
            else
                rdModel_SetCurrentMaterial(texture->loaded_material);
        } else {
            // faithful: passes the mesh, not its material
            rdModel_SetCurrentMaterial(rdMaterial_GetOrCreateDefaultMaterial(mesh));
        }

        if (strncmp(converted->name, "aes", 3) == 0) {
            hnode->meshIdx = converted->num;
            hnode->vertexBaseOffset = 0;
            result = converted;
            if (rdModel_CurrentMaterialSet != 0)
                rdModel3Mesh_ApplyMaterialToAllFaces(converted);
        } else {
            result = rdModel_ConvertMeshIntoRoot(mesh, hnode, faceFlags, 0);
        }

        result->unk84++;
        result->unk86++;
        result->uvOffsetU = 1.0f - uOffset;
        result->uvOffsetV = 1.0f - vOffset;
        result->unk89 = rdModel_LightingEnabled != 0 ? 1 : 0;
        if (rdroid_g_curRenderOptions2 != 0)
            result->unk89 = 0;
        rdModel_CurrentMaterialSet = 0;
        if (result->colorFlags != 0)
            rdModel3Mesh_ApplySwrModelColors(result, mesh);

        if (converted != NULL && mesh->vertex_base_offset != 0) {
            if (mesh->referenced_node == NULL)
                swrModel_ComputeNodeRenderMatrix(hnode, mesh->vertex_base_offset);
            else
                swrModel_CopyNodeRenderMatrix((swrModel_NodeMeshGroup*)mesh->referenced_node, hnode, mesh->vertex_base_offset);
        }
    }
}

// 0x0044ceb0
void rdModel_AddMeshGroupToScene2(swrModel_NodeMeshGroup* node)
{
    const rdMatrix34* orient;
    rdModel3HNode* hnode;
    swrModel_Mesh* mesh;
    swrModel_MeshMaterial* material;
    swrModel_MaterialTexture* texture;
    rdModel3Mesh* converted;
    int i;

    if (rdModel_nodeTransformsEnabled != 0 && rdMatrixStack34_modified != 0)
        rdMatrixStack34_PrecomputeMVPMatrices();
    node->cached_model_matrix = PrecomputedModelMatrixPtr;
    node->cached_mvp_matrix = PrecomputedMVPMatrixPtr;
    if (rdModel_nodeTransformsEnabled != 0) {
        rdMatrixStack34_mvpComputed = 0;
        orient = &rdMatrixStack34[rdMatrixStack34_size];
    } else {
        // faithful: with node transforms off, the node itself is read as the orientation
        orient = (const rdMatrix34*)node;
    }
    if (node->node.num_children == 0)
        return;
    hnode = rdModel_AppendMeshGroupHNodes(orient, node->node.num_children, 0);

    for (i = 0; i < (int)node->node.num_children; i++, hnode++) {
        mesh = node->node.children.meshes[i];
        converted = mesh->converted_mesh;
        if (converted == NULL)
            continue;
        // faithful: the call also pushes mesh->mesh_material, which the callee ignores
        rdModel_SetForceFlatNormals_Maybe(GameSettingFlags & GAME_SETTING_UNK_2000);
        material = mesh->mesh_material;
        texture = material != NULL ? material->material_texture : NULL;
        // faithful: both calls push two more (ignored) arguments
        if ((GameSettingFlags & GAME_SETTING_UNTEXTURED) == 0 && texture != NULL && texture->specs[0] != NULL)
            rdModel_SetCurrentMaterial(texture->loaded_material);
        else
            rdModel_SetCurrentMaterial(NULL);

        if (strncmp(converted->name, "aes", 3) == 0)
            hnode->meshIdx = converted->num;
        else
            rdModel_ConvertMeshIntoRoot(mesh, hnode, rdModel_MeshMaterialFaceFlags(material), 1);
    }
}

// 0x0044d1e0
void NodeTransformedWithPivot_ApplyTransform(rdMatrix34* inout_transform, const rdMatrix34* transform, const rdVector3* pivot)
{
    float* translation;
    int i;

    translation = &inout_transform->scale.x;
    for (i = 0; i < 3; i++) {
        translation[i] = translation[i] - (&transform->rvec.x)[i] * pivot->x - (&transform->lvec.x)[i] * pivot->y - pivot->z * (&transform->uvec.x)[i] + (&pivot->x)[i];
    }
}

// 0x0044d240
void rdModel_AddTransformedNodeToScene(int a1, rdMatrix34* transform, swrModel_Node* node)
{
    int overflow;
    int numChildren;
    int i;
    swrModel_Node* child;
    uint32_t required;

    rdModel_sceneNodeDepth++;
    if (rdModel_sceneNodeDepth > RDMODEL_SCENE_MAX_DEPTH) {
        overflow = 1;
    } else {
        overflow = 0;
        if (rdModel_nodeTransformsEnabled != 0)
            rdMatrixStack34_PushMultiply(transform);
    }
    numChildren = swrModel_NodeGetNumChildren(node);
    for (i = 0; i < numChildren; i++) {
        child = node->children.nodes[i];
        if (child == NULL)
            continue;
        required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
        if ((swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
            rdModel_AddNodeToScene(child);
    }
    if (!overflow && rdModel_nodeTransformsEnabled != 0)
        rdMatrixStack34_Pop();
    rdModel_sceneNodeDepth--;
}

// 0x0044d310
void rdModel_NodeTransformedComputedToScene(swrModel_NodeTransformedComputed* node)
{
    // rotation rows and scale are uninitialized in the original for orientation_option > 3
    rdMatrix34 transform = { 0 };
    rdMatrix34 peeked;
    rdVector3 toNode;
    rdVector3 up;
    float scale = 1.0f;
    swrModel_Node* child;
    uint32_t required;
    int numChildren;
    int overflow;
    int i;

    if (rdModel_nodeTransformsEnabled == 0) {
        transform = rdMatrix34_identity;
    } else {
        if (node->orientation_option == 0) {
            rdMatrixStack34_Peek(&transform);
        } else {
            rdMatrixStack34_Peek(&peeked);
            transform.scale = peeked.scale;
            toNode.x = peeked.scale.x - rdModel_CurrentViewport->model_matrix.vD.x;
            toNode.y = peeked.scale.y - rdModel_CurrentViewport->model_matrix.vD.y;
            toNode.z = peeked.scale.z - rdModel_CurrentViewport->model_matrix.vD.z;
            rdVector_Normalize3Acc(&toNode);
            if (node->orientation_option == 1) {
                rdVector_Scale3(&up, node->up_vector.x, &peeked.rvec);
                rdVector_Scale3Add3(&up, &up, node->up_vector.y, &peeked.lvec);
                rdVector_Scale3Add3(&transform.uvec, &up, node->up_vector.z, &peeked.uvec);
                scale = rdVector_Normalize3Acc(&transform.uvec);
                rdVector_Cross3(&transform.rvec, &toNode, &transform.uvec);
                rdVector_Normalize3Acc(&transform.rvec);
                rdVector_Cross3(&transform.lvec, &transform.uvec, &transform.rvec);
            } else {
                transform.lvec = toNode;
                if (node->orientation_option == 2) {
                    scale = rdVector_Len3(&peeked.uvec);
                    rdVector_Cross3(&transform.rvec, &transform.lvec, (rdVector3*)&rdModel_CurrentViewport->model_matrix.vC);
                    rdVector_Normalize3Acc(&transform.rvec);
                    rdVector_Cross3(&transform.uvec, &transform.rvec, &transform.lvec);
                } else if (node->orientation_option == 3) {
                    rdVector_Scale3(&up, node->up_vector.x, &peeked.rvec);
                    rdVector_Scale3Add3(&up, &up, node->up_vector.y, &peeked.lvec);
                    rdVector_Scale3Add3(&up, &up, node->up_vector.z, &peeked.uvec);
                    scale = rdVector_Normalize3Acc(&up);
                    rdVector_Cross3(&transform.rvec, &transform.lvec, &up);
                    rdVector_Normalize3Acc(&transform.rvec);
                    rdVector_Cross3(&transform.uvec, &transform.rvec, &transform.lvec);
                }
            }
            transform.rvec.x *= scale;
            transform.rvec.y *= scale;
            transform.rvec.z *= scale;
            transform.lvec.x *= scale;
            transform.lvec.y *= scale;
            transform.lvec.z *= scale;
            transform.uvec.x *= scale;
            transform.uvec.y *= scale;
            transform.uvec.z *= scale;
        }
        if (node->follow_model_position == 1) {
            transform.scale.x = rdModel_CurrentViewport->model_matrix.vD.x;
            transform.scale.y = rdModel_CurrentViewport->model_matrix.vD.y;
            transform.scale.z = rdModel_CurrentViewport->model_matrix.vD.z;
        }
    }

    rdModel_sceneNodeDepth++;
    if (rdModel_sceneNodeDepth > RDMODEL_SCENE_MAX_DEPTH) {
        overflow = 1;
    } else {
        overflow = 0;
        rdMatrixStack34_Push(&transform);
    }
    numChildren = swrModel_NodeGetNumChildren(&node->node);
    for (i = 0; i < numChildren; i++) {
        child = node->node.children.nodes[i];
        if (child == NULL)
            continue;
        required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
        if ((swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
            rdModel_AddNodeToScene(child);
    }
    if (!overflow)
        rdMatrixStack34_Pop();
    rdModel_sceneNodeDepth--;
}

// 0x0044d740
int NodeLODSelector_FindLODIndex(swrModel_NodeLODSelector* node)
{
    int numChildren;
    int i;

    numChildren = swrModel_NodeGetNumChildren(&node->node);
    if (numChildren <= 0)
        return -1;
    if (rdModel_nodeTransformsEnabled == 0)
        return 0;
    // LOD is selected for a fixed viewing distance of 10
    if (10.0f < node->lod_distances[0])
        return -1;
    for (i = 1; i < 8; i++) {
        if (node->lod_distances[i] == -1.0f || !(node->lod_distances[i] < 10.0f))
            break;
    }
    if (i - 1 >= numChildren)
        return -1;
    return i - 1;
}

// 0x0044d7c0
void rdModel_AddNodeToScene(swrModel_Node* a1)
{
    rdMatrix34 pivotTransform;
    rdMatrix34* transform;
    swrModel_Node* child;
    uint32_t required;
    int nodeType;
    int numChildren;
    int selected;
    int prevCounter;
    char state;
    int i;

    if (a1 == NULL)
        return;
    required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
    if ((swrModel_NodeGetFlags1Or2(a1, 2) & required) != required)
        return;
    if ((rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(a1, 2)) == 0)
        return;

    prevCounter = rdModel_sceneNodeYieldCounter++;
    if (prevCounter > 10) {
        rdModel_sceneNodeYieldCounter = 0;
        swr_noop2();
    }

    nodeType = swrModel_NodeGetFlags(a1);
    state = rdModel_ApplyNodeSettings((char)a1->flags_5, a1->light_index);
    switch (nodeType) {
    case NODE_MESH_GROUP:
        rdModel_AddMeshGroupToScene((swrModel_NodeMeshGroup*)a1);
        break;
    case NODE_BASIC:
        numChildren = swrModel_NodeGetNumChildren(a1);
        for (i = 0; i < numChildren; i++) {
            child = a1->children.nodes[i];
            required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
            if (child != NULL && (swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
                rdModel_AddNodeToScene(child);
        }
        break;
    case NODE_SELECTOR:
        numChildren = swrModel_NodeGetNumChildren(a1);
        selected = ((swrModel_NodeSelector*)a1)->selected_child_node;
        if (selected == -2)
            break;
        if (selected == -1) {
            for (i = 0; i < numChildren; i++) {
                child = a1->children.nodes[i];
                required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
                if (child != NULL && (swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
                    rdModel_AddNodeToScene(child);
            }
            break;
        }
        if (selected < 0 || selected >= numChildren)
            break;
        child = a1->children.nodes[selected];
        required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
        if (child != NULL && (swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
            rdModel_AddNodeToScene(child);
        break;
    case NODE_LOD_SELECTOR:
        selected = NodeLODSelector_FindLODIndex((swrModel_NodeLODSelector*)a1);
        if (selected == -1)
            break;
        child = a1->children.nodes[selected];
        required = rdModel_CurrentViewport->node_flags1_exact_match_for_rendering;
        if (child != NULL && (swrModel_NodeGetFlags1Or2(child, 2) & required) == required && (rdModel_CurrentViewport->node_flags1_any_match_for_rendering & swrModel_NodeGetFlags1Or2(child, 2)) != 0)
            rdModel_AddNodeToScene(child);
        break;
    case NODE_TRANSFORMED:
        rdModel_AddTransformedNodeToScene(0, &((swrModel_NodeTransformed*)a1)->transform, a1);
        break;
    case NODE_TRANSFORMED_WITH_PIVOT:
        if ((int)swrModel_NodeGetNumChildren(a1) <= 0)
            break;
        if (a1->flags_3 & swrModel_NODEFLAGS3_USE_PIVOT) {
            pivotTransform = ((swrModel_NodeTransformedWithPivot*)a1)->transform;
            NodeTransformedWithPivot_ApplyTransform(&pivotTransform, &((swrModel_NodeTransformedWithPivot*)a1)->transform, &((swrModel_NodeTransformedWithPivot*)a1)->pivot);
            transform = &pivotTransform;
        } else {
            transform = &((swrModel_NodeTransformedWithPivot*)a1)->transform;
        }
        rdModel_AddTransformedNodeToScene(1, transform, a1);
        break;
    case NODE_TRANSFORMED_COMPUTED:
        rdModel_NodeTransformedComputedToScene((swrModel_NodeTransformedComputed*)a1);
        break;
    default:
        break;
    }
    rdModel_RevertNodeSettings(state);
}

// 0x0044dae0
void rdModel_AddNodeToScene2(swrModel_Node* a1)
{
    uint32_t nodeType;
    int numChildren;
    char state;
    int i;

    if (a1 == NULL)
        return;
    nodeType = swrModel_NodeGetFlags(a1);
    state = rdModel_ApplyNodeSettings((char)a1->flags_5, a1->light_index);
    if (nodeType & NODE_HAS_CHILDREN) {
        numChildren = swrModel_NodeGetNumChildren(a1);
        for (i = 0; i < numChildren; i++) {
            if (a1->children.nodes[i] != NULL)
                rdModel_AddNodeToScene2(a1->children.nodes[i]);
        }
    } else if (nodeType & NODE_MESH_GROUP) {
        // faithful: bit test against the NODE_MESH_GROUP value, not an equality check
        rdModel_AddMeshGroupToScene2((swrModel_NodeMeshGroup*)a1);
    }
    rdModel_RevertNodeSettings(state);
}

// Inlined at the top of rdModel_BuildAndDrawScene and rdModel_BuildSceneNoDraw_Maybe.
static void rdModel_CreateRootModel(void)
{
    rdModel3HNode* root;

    swr_rootModel_ptr = (RdModel3*)stdPlatform_Alloc(sizeof(RdModel3));
    rdModel3_NewEntry(swr_rootModel_ptr);
    swr_rootModel_ptr->num = 0;
    swr_rootModel_ptr->apMaterials = NULL;
    swr_rootModel_ptr->numMaterials = 0;
    swr_rootModel_ptr->numGeos = 1;
    rdModel_rootGeoSet = &swr_rootModel_ptr->aGeos[swr_rootModel_ptr->curGeoNum];
    swrModel_ResetRootMeshCounts();
    rdModel_rootGeoSet->aMeshes = (rdModel3Mesh*)stdPlatform_Alloc(RDMODEL_ROOT_MAX_MESHES * sizeof(rdModel3Mesh));
    memset(rdModel_rootGeoSet->aMeshes, 0, RDMODEL_ROOT_MAX_MESHES * sizeof(rdModel3Mesh));

    swr_rootModelThing_ptr = rdThing_New(NULL);
    swr_rootModelThing_ptr->type = RD_THING_MODEL3;
    swr_rootModelThing_ptr->bSkipBuildingJoints = 1;
    swr_rootModelThing_ptr->data.pModel3 = swr_rootModel_ptr;
    swr_rootModelThing_ptr->geosetNum = -1;
    swr_rootModelThing_ptr->geoMode = RD_GEOMETRY_FULL;
    swr_rootModelThing_ptr->desiredGeoMode = RD_GEOMETRY_FULL;
    swr_rootModelThing_ptr->paJointAmputationFlags = NULL;
    swr_rootModelThing_ptr->apTweakedAngles = NULL;

    swr_rootModel_ptr->aHierarchyNodes = (rdModel3HNode*)stdPlatform_Alloc(RDMODEL_ROOT_MAX_MESHES * sizeof(rdModel3HNode));
    root = swr_rootModel_ptr->aHierarchyNodes;
    root->num = 0;
    memcpy(root->aName, "ROOT", 5);
    root->pParent = NULL;
    root->pSibling = NULL;
    root->pChild = NULL;
    root->numChildren = 0;
    root->type = 1;
    root->meshIdx = -1;
    root->meshOrient = rdMatrix34_identity;
}

// 0x0044db70
void rdModel_BuildAndDrawScene(Gfx** displayListCursor, swrViewport* viewport)
{
    int i;

    rdModel_displayListCursor = *displayListCursor;
    rdModel_CurrentViewport = viewport;
    if (swr_rootModel_ptr == NULL && swr_rootModelThing_ptr == NULL)
        rdModel_CreateRootModel();
    swr_rootModel_ptr->numHNodes = 1;
    rdModel3_SetRootMaterials(swr_rootModel_ptr);
    rdModel_sceneNodeDepth = 0;
    rdMatrixStack34_Init();
    rdModel_sceneBuildCount++;
    memset(rdModel_sceneStatCounters, 0, sizeof(rdModel_sceneStatCounters));
    swr_rootThing_ptr = NULL;
    rdModel_mirroredWinding = (GameSettingFlags & GAME_SETTING_MIRROR) != 0;
    rdModel_AddNodeToScene(viewport->model_root_node);
    for (i = 1; i < (int)(sizeof(rdModel_sceneStatCounters) / sizeof(rdModel_sceneStatCounters[0])); i++)
        rdModel_sceneStatCounters[0] += rdModel_sceneStatCounters[i];
    rdThing_Draw((swrUI_Unk3*)swr_rootModelThing_ptr, &rdMatrix34_identity, (GameSettingFlags & GAME_SETTING_MIRROR) != 0, swrDisplay_screenWidth);
    *displayListCursor = rdModel_displayListCursor;
}

// 0x0044de10
void rdModel_BuildSceneNoDraw_Maybe(swrViewport* viewport)
{
    rdModel_CurrentViewport = viewport;
    if (swr_rootModel_ptr == NULL && swr_rootModelThing_ptr == NULL)
        rdModel_CreateRootModel();
    swr_rootModel_ptr->numHNodes = 1;
    rdModel3_SetRootMaterials(swr_rootModel_ptr);
    rdModel_sceneNodeDepth = 0;
    rdModel_AddNodeToScene2(viewport->model_root_node);
}

// 0x0044e000
void rdModel_SetupSceneFogAndLights(Gfx** displayListCursor)
{
    Gfx* cursor;

    memcpy(rdModel_sceneState, rdModel_sceneStateDefaults, sizeof(rdModel_sceneState));
    rdModel_sceneStateUnusedA = -1;
    rdModel_sceneStateUnusedB = -1;
    rdModel_sceneStateUnusedC = -1;
    rdModel_sceneStateUnusedD = 0;
    rdModel_sceneStateUnusedE = 0;
    cursor = *displayListCursor;
    if ((GameSettingFlags & GAME_SETTING_FOG_DISABLED) == 0) {
        rdFace_SetFogEnabled(1);
        rdFace_ConfigureFogStartEnd(fogStartInt16, fogEndInt16);
        Direct3d_ConfigFog2(fogColorInt16[0], fogColorInt16[1], fogColorInt16[2], fogColorInt16[3]);
        rdCamera_SetLights(0, 1);
        *displayListCursor = cursor;
        return;
    }
    rdFace_SetFogEnabled(0);
    rdCamera_SetLights(0, 1);
    *displayListCursor = cursor;
}

// 0x0044e0c0
void rdModel_SetFogEnabled(int enable)
{
    if (enable != 0) {
        GameSettingFlags = GameSettingFlags & ~GAME_SETTING_FOG_DISABLED;
        return;
    }
    GameSettingFlags = GameSettingFlags | GAME_SETTING_FOG_DISABLED;
}

// 0x0044E0E0
void SetFogParameters(int fogStart_, int fogEnd_, int fogColorR, int fogColorG, int fogColorB, int fogColorA)
{
    // a negative component leaves that field unchanged
    if (fogStart_ >= 0) {
        fogStartInt16 = (int16_t) fogStart_;
    }
    if (fogEnd_ >= 0) {
        fogEndInt16 = (int16_t) fogEnd_;
    }
    if (fogColorR >= 0) {
        fogColorInt16[0] = (int16_t) fogColorR;
    }
    if (fogColorG >= 0) {
        fogColorInt16[1] = (int16_t) fogColorG;
    }
    if (fogColorB >= 0) {
        fogColorInt16[2] = (int16_t) fogColorB;
    }
    if (fogColorA >= 0) {
        fogColorInt16[3] = (int16_t) fogColorA;
    }
}

// Primary light (slot 0) from short[3] ambient/color/position arrays; position negated to a direction.
// 0x0044E140
void SetPrimaryLightColorsAndDirection(short* ambient_color, short* light_color, short* light_position)
{
    SetLightColorsAndDirection(0, ambient_color[0], ambient_color[1], ambient_color[2], light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
}

// Secondary light `light_index` (stored at slot light_index+1) from short[3] arrays.
// 0x0044E190
void SetSecondaryLightColorsAndDirection(unsigned int light_index, short* ambient_color, short* light_color, short* light_position)
{
    if ((int)light_index >= 0 && (int)light_index < 0xc) {
        SetLightColorsAndDirection(light_index + 1, ambient_color[0], ambient_color[1], ambient_color[2], light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
    }
}

// Copy the primary light into slot index+1 and record numEnabledLights[index] = 1.
// 0x0044E1F0
void SetLightColorsAndDirectionFromPrimraryLight2(unsigned int index)
{
    if ((int)index >= 0 && (int)index < 0xc) {
        SetLightColorsAndDirectionFromPrimaryLight((short)index + 1);
        numEnabledLights[index] = 1;
    }
}

// Secondary-bank light `light_index`: light_type2 == 0 -> just record it (numEnabledLights = 1);
// otherwise record numEnabledLights = 2 and set slot light_index+1 from the color/position arrays.
// 0x0044E220
void SetAlternativeLightColorsAndDirection2(int light_index, BOOL light_type2, short* light_color, short* light_position)
{
    if (light_index >= 0 && light_index < 0xc) {
        if (light_type2 == 0) {
            numEnabledLights[light_index] = 1;
            return;
        }
        numEnabledLights[light_index] = 2;
        SetAlternativeLightColorsAndDirection(light_index + 1, light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
    }
}

// 0x0044E290
void rdProcEntry_SetCurrentColor(int a1, int a2, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    rdProcEntry_CurrentColor.x = (float) r * oneOver255f;
    rdProcEntry_CurrentColor.y = (float) g * oneOver255f;
    rdProcEntry_CurrentColor.z = (float) b * oneOver255f;
    rdProcEntry_CurrentColor.w = (float) a * oneOver255f;
}

// Float-input primary/secondary light. Normalizes light_position to a length-120 direction
// (straight down when the position is near-zero), truncates the float ambient/color/direction
// to shorts, and dispatches to SetPrimary (a1 == -1) or SetSecondary. Return unused (vestigial).
// 0x00483840
float* SetLightColorsAndDirection2(int a1, rdVector3* ambient_color, rdVector3* light_color, rdVector3* light_position)
{
    float dir_x;
    float dir_y;
    float dir_z;
    float len = rdVector_Len3(light_position);
    if (len < 0.01f) {
        dir_x = 0.0f;
        dir_y = 0.0f;
        dir_z = -1.0f;
    } else {
        float scale = 120.0f / len;
        dir_x = light_position->x * scale;
        dir_y = light_position->y * scale;
        dir_z = light_position->z * scale;
    }
    short ambient[3] = { (short)(int)ambient_color->x, (short)(int)ambient_color->y, (short)(int)ambient_color->z };
    short color[3] = { (short)(int)light_color->x, (short)(int)light_color->y, (short)(int)light_color->z };
    short direction[3] = { (short)(int)dir_x, (short)(int)dir_y, (short)(int)dir_z };
    if (a1 == -1) {
        SetPrimaryLightColorsAndDirection(ambient, color, direction);
    } else {
        SetSecondaryLightColorsAndDirection(a1, ambient, color, direction);
    }
    return NULL;
}

// Float-input secondary-bank variant: when light_type2 is set, normalize light_position the same
// way and truncate the float color to shorts; then defer to SetAlternative...2. Return unused.
// 0x00483960
float* SetAlternativeLightColorsAndDirection3(int light_index, BOOL light_type2, float* light_color, rdVector3* light_position)
{
    short color[3] = { 0, 0, 0 };
    short direction[3] = { 0, 0, 0 };
    if (light_type2 != 0) {
        float dir_x;
        float dir_y;
        float dir_z;
        float len = rdVector_Len3(light_position);
        if (len < 0.01f) {
            dir_x = 0.0f;
            dir_y = 0.0f;
            dir_z = -1.0f;
        } else {
            float scale = 120.0f / len;
            dir_x = light_position->x * scale;
            dir_y = light_position->y * scale;
            dir_z = light_position->z * scale;
        }
        color[0] = (short)(int)light_color[0];
        color[1] = (short)(int)light_color[1];
        color[2] = (short)(int)light_color[2];
        direction[0] = (short)(int)dir_x;
        direction[1] = (short)(int)dir_y;
        direction[2] = (short)(int)dir_z;
    }
    SetAlternativeLightColorsAndDirection2(light_index, light_type2, color, direction);
    return NULL;
}

// Guarded wrapper: copy the primary light into slot a1+1 unless a1 == -1.
// 0x00483A40
int SetLightColorsAndDirectionFromPrimaryLight3(unsigned int a1)
{
    if (a1 != 0xffffffff) {
        SetLightColorsAndDirectionFromPrimraryLight2(a1);
    }
    return a1;
}

// 0x00483A60
short SetClearColor(short r, short g, short b)
{
    backBufferClearColor[0] = r;
    backBufferClearColor[1] = g;
    backBufferClearColor[2] = b;
    return r;
}

// 0x00433680
void rdModel_SetForceFlatNormals_Maybe(int enable)
{
    if (enable != 0)
        rdModel_flatNormalsClearFlag = 0;
}
