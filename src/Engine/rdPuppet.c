#include "rdPuppet.h"

#include "globals.h"

#include <Engine/rdClip.h>
#include <Engine/rdThing.h>
#include <General/stdMath.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <engine_config.h>

// 0x00493310
void rdPuppet_BuildJointMatrices(RdThing* prdThing, rdMatrix34* pPlacement)
{
    RdModel3* pModel;
    RdPuppet* pPuppet;
    RdPuppetTrack* pTrack;
    RdKeyframe* pKeyframe;
    RdKeyframeNode* pKFNode;
    RdKeyframeNodeEntry* pEntry;
    rdModel3HNode* pNode;
    rdVector3* pTweak;
    rdVector3 pos;
    rdVector3 rot;
    rdVector3 entryPos;
    rdVector3 entryRot;
    rdVector3 lowPos;
    rdVector3 lowRot;
    float weight;
    float lowWeight;
    float scale;
    float dt;
    int highPri;
    int lowPri;
    int pri;
    int last;
    int next;
    int done;
    unsigned int nodeIdx;
    unsigned int i;
    int t;

    pModel = prdThing->data.pModel3;
    pPuppet = prdThing->pPuppet;
    if (prdThing->bSkipBuildingJoints != 0)
        return;

    if (pPuppet == NULL || pPuppet->unknown != 0) {
        for (i = 0; i < (unsigned int)pModel->numHNodes; i++)
            prdThing->paJointMatrices[i] = pModel->aHierarchyNodes[i].meshOrient;
    } else {
        for (t = 0; t < RDPUPPET_MAX_TRACKS; t++) {
            pTrack = &pPuppet->aTracks[t];
            if (pTrack->status == 0)
                continue;
            pKeyframe = pTrack->pKFTrack;
            for (i = 0; i < (unsigned int)pKeyframe->numJoints; i++) {
                pKFNode = &pKeyframe->aNodes[i];
                if (pKFNode->numEntries == 0)
                    continue;
                last = pKFNode->numEntries - 1;
                // faithful: reads the cursor by nodeNum but writes it back by keyframe node index
                next = pTrack->aNodes[pKFNode->nodeNum];
                if (next == last)
                    continue;
                next++;
                if (pTrack->curFrame < pKFNode->aEntries[next].frame)
                    continue;
                done = 0;
                do {
                    if (next == last)
                        done = 1;
                    else if (pTrack->curFrame < pKFNode->aEntries[next + 1].frame)
                        done = 1;
                    else
                        next++;
                } while (!done);
                pTrack->aNodes[i] = next;
            }
        }

        for (nodeIdx = 0; nodeIdx < (unsigned int)pModel->numHNodes; nodeIdx++) {
            pNode = &pModel->aHierarchyNodes[nodeIdx];
            highPri = 0;
            lowPri = 0;
            weight = 0.0f;
            lowWeight = 0.0f;
            pos.x = pos.y = pos.z = 0.0f;
            rot.x = rot.y = rot.z = 0.0f;
            lowPos.x = lowPos.y = lowPos.z = 0.0f;
            lowRot.x = lowRot.y = lowRot.z = 0.0f;

            for (t = 0; t < RDPUPPET_MAX_TRACKS; t++) {
                pTrack = &pPuppet->aTracks[t];
                pKeyframe = pTrack->pKFTrack;
                if (pKeyframe == NULL)
                    continue;
                if ((pNode->type & pKeyframe->type) != 0)
                    pri = pTrack->hi;
                else
                    pri = pTrack->lo;
                if ((pTrack->status & RDPUPPET_TRACK_PLAYING) == 0)
                    continue;
                // faithful: the keyframe node is read before the numJoints bounds check
                pKFNode = &pKeyframe->aNodes[pNode->num];
                if (pKFNode->numEntries == 0)
                    continue;
                if (pri < lowPri)
                    continue;
                if (pri < highPri && !(weight < 1.0f))
                    continue;
                if ((unsigned int)pNode->num >= (unsigned int)pKeyframe->numJoints)
                    continue;

                pEntry = &pKFNode->aEntries[pTrack->aNodes[pNode->num]];
                dt = pTrack->curFrame - pEntry->frame;
                if ((pEntry->flags & RDKEYFRAME_ENTRY_TRANSLATE) != 0) {
                    entryPos.x = pEntry->dpos.x * dt + pEntry->pos.x;
                    entryPos.y = pEntry->dpos.y * dt + pEntry->pos.y;
                    entryPos.z = pEntry->dpos.z * dt + pEntry->pos.z;
                } else {
                    entryPos = pEntry->pos;
                }
                if ((pEntry->flags & RDKEYFRAME_ENTRY_ROTATE) != 0) {
                    entryRot.x = pEntry->drot.x * dt + pEntry->rot.x;
                    entryRot.y = pEntry->drot.y * dt + pEntry->rot.y;
                    entryRot.z = pEntry->drot.z * dt + pEntry->rot.z;
                } else {
                    entryRot = pEntry->rot;
                }

                entryPos.x = entryPos.x - pNode->pos.x;
                entryPos.y = entryPos.y - pNode->pos.y;
                entryPos.z = entryPos.z - pNode->pos.z;
                entryRot.x = stdMath_NormalizeAngleAcute(entryRot.x - pNode->pyr.x);
                entryRot.y = stdMath_NormalizeAngleAcute(entryRot.y - pNode->pyr.y);
                entryRot.z = stdMath_NormalizeAngleAcute(entryRot.z - pNode->pyr.z);

                if (pTrack->playSpeed < 1.0f) {
                    entryPos.x = pTrack->playSpeed * entryPos.x;
                    entryPos.y = pTrack->playSpeed * entryPos.y;
                    entryPos.z = pTrack->playSpeed * entryPos.z;
                    entryRot.x = pTrack->playSpeed * entryRot.x;
                    entryRot.y = pTrack->playSpeed * entryRot.y;
                    entryRot.z = pTrack->playSpeed * entryRot.z;
                }

                if (pri == highPri) {
                    pos.x = pos.x + entryPos.x;
                    pos.y = pos.y + entryPos.y;
                    pos.z = pos.z + entryPos.z;
                    rot.x = rot.x + entryRot.x;
                    rot.y = rot.y + entryRot.y;
                    rot.z = rot.z + entryRot.z;
                    weight = weight + pTrack->playSpeed;
                } else if (pri > highPri) {
                    lowPos = pos;
                    lowRot = rot;
                    lowWeight = weight;
                    lowPri = highPri;
                    pos = entryPos;
                    rot = entryRot;
                    weight = pTrack->playSpeed;
                    highPri = pri;
                } else if (pri > lowPri) {
                    lowPos = entryPos;
                    lowRot = entryRot;
                    lowWeight = pTrack->playSpeed;
                    lowPri = pri;
                } else {
                    lowPos.x = lowPos.x + entryPos.x;
                    lowPos.y = lowPos.y + entryPos.y;
                    lowPos.z = lowPos.z + entryPos.z;
                    lowRot.x = lowRot.x + entryRot.x;
                    lowRot.y = lowRot.y + entryRot.y;
                    lowRot.z = lowRot.z + entryRot.z;
                    lowWeight = lowWeight + pTrack->playSpeed;
                }
            }

            if (weight < 1.0f && lowWeight > 0.0f) {
                if (lowWeight > 1.0f) {
                    scale = 1.0f / lowWeight;
                    lowPos.x = scale * lowPos.x;
                    lowPos.y = scale * lowPos.y;
                    lowPos.z = scale * lowPos.z;
                    lowRot.x = scale * lowRot.x;
                    lowRot.y = scale * lowRot.y;
                    lowRot.z = scale * lowRot.z;
                }
                scale = 1.0f - weight;
                pos.x = scale * lowPos.x + pos.x;
                pos.y = scale * lowPos.y + pos.y;
                pos.z = scale * lowPos.z + pos.z;
                rot.x = scale * lowRot.x + rot.x;
                rot.y = scale * lowRot.y + rot.y;
                rot.z = scale * lowRot.z + rot.z;
            } else if (weight > 1.0f) {
                scale = 1.0f / weight;
                pos.x = scale * pos.x;
                pos.y = scale * pos.y;
                pos.z = scale * pos.z;
                rot.x = scale * rot.x;
                rot.y = scale * rot.y;
                rot.z = scale * rot.z;
            }

            rot.x = stdMath_NormalizeAngleAcute(rot.x);
            rot.y = stdMath_NormalizeAngleAcute(rot.y);
            rot.z = stdMath_NormalizeAngleAcute(rot.z);
            pos.x = pNode->pos.x + pos.x;
            pos.y = pNode->pos.y + pos.y;
            pos.z = pNode->pos.z + pos.z;
            rot.x = pNode->pyr.x + rot.x;
            rot.y = pNode->pyr.y + rot.y;
            rot.z = pNode->pyr.z + rot.z;
            rdMatrix_BuildRotation34(&prdThing->paJointMatrices[nodeIdx], &rot, &pos);

            pTweak = &prdThing->apTweakedAngles[nodeIdx];
            if (pTweak->x != 0.0f || pTweak->y != 0.0f || pTweak->z != 0.0f)
                rdMatrix_PreRotate34(&prdThing->paJointMatrices[nodeIdx], pTweak);
        }
    }

    rdThing_AccumulateMatrices(prdThing, pModel->aHierarchyNodes, pPlacement);
    prdThing->rdFrameNum = rdCache_GetFrameNum();
}

static float rdClip_ClampLight(float value)
{
    // NaN compares unordered and lands on the low bound, as the x87 FCOM/C0 test does
    if (!(value >= 0.0f))
        return 0.0f;
    if (value > 1.0f)
        return 1.0f;
    return value;
}

// 0x00493b80
void rdPrimit3_ClipFace3T(rdClipFrustum* pFrustum, rdMeshinfo* pSrc, rdMeshinfo* pDst, rdVector2* pTexOffset)
{
    rdVector4* srcLight;
    rdVector4* intensity;
    rdVector4* dstLight;
    rdVector2* dstUV;
    int posIdx;
    int uvIdx;
    unsigned int i;

    rdClip_face3TSrcLights = (rdVector4*)pSrc->paDynamicLight;
    rdClip_face3TDstLights = (rdVector4*)pDst->paDynamicLight;
    // faithful: with no per-face-vertex intensities nothing is gathered into pDst
    if (pSrc->intensities != NULL) {
        rdClip_face3TIntensities = (rdVector4*)pSrc->intensities;
        for (i = 0; i < pSrc->numVertices; i++) {
            posIdx = pSrc->vertexPosIdx[i];
            uvIdx = pSrc->vertexUVIdx[i];
            srcLight = &rdClip_face3TSrcLights[posIdx];
            intensity = &rdClip_face3TIntensities[i];
            dstLight = &rdClip_face3TDstLights[i];
            dstUV = &pDst->vertexUVs[i];

            dstLight->x = rdClip_ClampLight(srcLight->x + intensity->x);
            *dstUV = pSrc->vertexUVs[uvIdx];
            dstLight->y = rdClip_ClampLight(srcLight->y + intensity->y);
            pDst->verticesProjected[i] = pSrc->verticesProjected[posIdx];
            dstLight->z = rdClip_ClampLight(srcLight->z + intensity->z);
            dstUV->x = pTexOffset->x + dstUV->x;
            dstUV->y = dstUV->y + pTexOffset->y;
            dstLight->w = rdClip_ClampLight(srcLight->w + intensity->w);
        }
    }

    if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
        pDst->numVertices = rdClip_Face3TTestFrustum(pFrustum, pSrc);
        if (pDst->numVertices != 0)
            pDst->numVertices = rdClip_Face3TClipNear(pFrustum, pSrc, pDst);
    } else {
        pDst->numVertices = rdClip_Face3TOrtho(pFrustum, pDst->verticesProjected, pDst->vertexUVs, rdClip_face3TDstLights, pSrc->numVertices);
    }
}
