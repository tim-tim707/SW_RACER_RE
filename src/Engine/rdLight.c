#include "rdLight.h"

#include "globals.h"

#include <Primitives/rdMath.h>
#include <Primitives/rdVector.h>
#include <macros.h>

#include <math.h>

// 0x00490510
int rdLight_NewEntry(rdLight* light)
{
    light->type = 2;
    light->active = 1;
    (light->direction).x = 0.0;
    (light->direction).y = 0.0;
    (light->direction).z = 0.0;
    light->color = (rdVector4){ 1, 1, 1, 0 };
    light->falloffMin = 0.0;
    light->falloffMax = 0.0;
    return 1;
}

// 0x00490550
void rdLight_CalcVertexIntensities(rdLight** apLights, rdVector3* aLightPos, int numLights, rdVector3* aVertexNormal, rdVector3* aVertices, rdVector4* aVertexColors, rdVector4* aLightColors, int numVertices, float scalar)
{
    rdVector3 toLight;
    rdVector4* out;
    rdVector3* normal;
    rdLight* light;
    float dot;
    float dist;
    float falloff;
    int v, l;

    for (v = numVertices - 1; v >= 0; v--) {
        out = &aLightColors[v];
        normal = &aVertexNormal[v];
        out->x = rdCamera_pCurCamera->ambientColor.x;
        out->y = rdCamera_pCurCamera->ambientColor.y;
        out->z = rdCamera_pCurCamera->ambientColor.z;
        out->w = 1.0f;
        for (l = numLights - 1; l >= 0; l--) {
            light = apLights[l];
            if (light->type == RD_LIGHT_TYPE_DIRECTIONAL) {
                dot = normal->x * aLightPos[l].x + normal->y * aLightPos[l].y + normal->z * aLightPos[l].z;
                if (dot > 0.0f) {
                    out->x = light->color.x * dot + out->x;
                    out->y = light->color.y * dot + out->y;
                    out->z = light->color.z * dot + out->z;
                }
            } else if (light->type == RD_LIGHT_TYPE_POINT) {
                toLight.x = aLightPos[l].x - aVertices[v].x;
                toLight.y = aLightPos[l].y - aVertices[v].y;
                toLight.z = aLightPos[l].z - aVertices[v].z;
                dist = sqrtf(toLight.x * toLight.x + toLight.y * toLight.y + toLight.z * toLight.z);
                if (dist < light->falloffMin) {
                    rdVector_Normalize3Acc_2(&toLight);
                    dot = normal->x * toLight.x + normal->y * toLight.y + normal->z * toLight.z;
                    if (dot > 0.0f) {
                        falloff = dist * scalar;
                        out->x = (light->color.x - falloff) * dot + out->x;
                        out->y = (light->color.y - falloff) * dot + out->y;
                        out->z = (light->color.z - falloff) * dot + out->z;
                    }
                }
            }
            // faithful: the vertex color is multiplied in once per light, not once per vertex
            out->x = aVertexColors[v].x * out->x;
            out->y = aVertexColors[v].y * out->y;
            out->z = aVertexColors[v].z * out->z;
            out->w = aVertexColors[v].w * out->w;
        }
    }
}

// 0x00490750
void rdLight_CalcFaceIntensity(rdLight** meshLights, rdVector3* localLightPoses, int numLights, rdFace* face, rdVector3* faceNormal, rdVector3* vertices, float scalar, void* outInfos)
{
    rdVector4* out = (rdVector4*)outInfos;
    rdVector3 toLight;
    rdVector3* vertex;
    rdLight* light;
    float dot;
    float dist;
    float falloff;
    int l;

    out->x = 0.0f;
    out->y = 0.0f;
    out->z = 0.0f;
    out->w = 0.0f;
    for (l = 0; l < numLights; l++) {
        light = meshLights[l];
        if (light->active == 0)
            continue;
        if (light->type == RD_LIGHT_TYPE_DIRECTIONAL) {
            toLight = localLightPoses[l];
            rdVector_Normalize3Acc_2(&toLight);
            dot = faceNormal->y * toLight.y + faceNormal->z * toLight.z + faceNormal->x * toLight.x;
            if (dot > 0.0f) {
                out->x = light->color.x * dot + out->x;
                out->y = light->color.y * dot + out->y;
                out->z = light->color.z * dot + out->z;
            }
        } else if (light->type == RD_LIGHT_TYPE_POINT) {
            // the face's first vertex stands in for the whole face
            vertex = &vertices[face->vertexPosIdx[0]];
            toLight.x = localLightPoses[l].x - vertex->x;
            toLight.y = localLightPoses[l].y - vertex->y;
            toLight.z = localLightPoses[l].z - vertex->z;
            dist = rdMath_DistancePointToPlane(&localLightPoses[l], faceNormal, vertex);
            if (dist < light->falloffMin) {
                rdVector_Normalize3Acc_2(&toLight);
                dot = faceNormal->y * toLight.y + faceNormal->z * toLight.z + faceNormal->x * toLight.x;
                if (dot > 0.0f) {
                    falloff = dist * scalar;
                    out->x = (light->color.x - falloff) * dot + out->x;
                    out->y = (light->color.y - falloff) * dot + out->y;
                    out->z = (light->color.z - falloff) * dot + out->z;
                }
            }
        }
    }
}

// 0x00490930
float rdLight_GetIntensity(const rdVector4* pLight)
{
    return (pLight->y + pLight->z + pLight->x) * 0.3333333;
}
