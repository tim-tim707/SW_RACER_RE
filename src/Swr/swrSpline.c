#include "swrSpline.h"

#include "swrLoader.h"
#include "types_enums.h"
#include "macros.h"
#include "engine_config.h"
#include "swrAssetBuffer.h"
#include "globals.h"
#include "swr.h"
#include "swrModel.h"
#include "swrObj.h"

#include <Primitives/rdMatrix.h>
#include <Primitives/rdVector.h>

// 0x00446fc0
void swrSpline_LoadSpline(int index, unsigned short** b)
{
    swrLoader_OpenBlock(swrLoader_TYPE_SPLINE_BLOCK);
    int spline_count;
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, 0, &spline_count, sizeof(int));
    spline_count = SWAP32(spline_count);

    if (index < 0 || index >= spline_count)
    {
        *b = NULL;
        return;
    }

    unsigned int indices_bound[2];
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, index * 4 + 4, indices_bound, sizeof(indices_bound));
    indices_bound[0] = SWAP32(indices_bound[0]);
    indices_bound[1] = SWAP32(indices_bound[1]);

    const unsigned int spline_size = indices_bound[1] - indices_bound[0];
    swrSpline* spline = (swrSpline*)swrAssetBuffer_GetBuffer();
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, indices_bound[0], spline, spline_size);

    *b = (unsigned short*)spline;
    // the on-disk 4-byte slot at offset 0xc is repurposed as the runtime
    // pointer to the control point array, which follows the 0x10 byte header.
    spline->control_points = (swrSplineControlPoint*)((char*)spline + sizeof(swrSpline));

    spline->type = SWAP16(spline->type);
    // note: unk1 is intentionally left un-swapped, matching the original
    spline->num_control_points = SWAP32(spline->num_control_points);
    spline->num_segments = SWAP32(spline->num_segments);

    for (int i = 0; i < (int)spline->num_control_points; i++)
    {
        swrSplineControlPoint* cp = &spline->control_points[i];

        cp->next_count = SWAP16(cp->next_count);
        cp->prev_count = SWAP16(cp->prev_count);
        cp->next1 = SWAP16(cp->next1);
        cp->next2 = SWAP16(cp->next2);
        cp->prev1 = SWAP16(cp->prev1);
        cp->prev2 = SWAP16(cp->prev2);
        cp->prev3 = SWAP16(cp->prev3);
        cp->prev4 = SWAP16(cp->prev4);

        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->position.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->rotation.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->handle1.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->handle2.x + j);

        cp->progress = SWAP16(cp->progress);
        for (int j = 0; j < 8; j++)
            cp->unk_set[j] = SWAP16(cp->unk_set[j]);
        // note: cp->unk is intentionally left un-swapped, matching the original
    }

    swrAssetBuffer_SetBuffer((char*)spline + spline_size);
    swrLoader_CloseBlock(swrLoader_TYPE_SPLINE_BLOCK);
}

// 0x004472e0
char* swrSpline_LoadSplineById(char* splineBuffer)
{
    swrSpline_LoadSpline((int)splineBuffer, (unsigned short**)&splineBuffer);
    return splineBuffer;
}

// 0x0044e5a0
void swrSpline_GetControlPointPosition(swrSpline* spline, int index, rdVector3* out)
{
    rdVector3* position = &spline->control_points[index].position;
    out->x = position->x;
    out->y = position->y;
    out->z = position->z;
}

// 0x0044e5e0
int swrSpline_getControlPointIdFromProgress(swrSpline* spline, int progress, int startIndex)
{
    for (int i = startIndex; i < (int)spline->num_control_points; i++) {
        if ((short)spline->control_points[i].progress == progress)
            return i;
    }
    return -1;
}

// 0x0044e620
int swrSpline_getControlPoint(void* cursor, int level)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    int branch = c->branchFlags;
    if (branch == 0)
        return c->nodeLookahead[level];
    if (level != 0)
        branch >>= (level & 0x1f);
    swrSplineControlPoint* cp = &c->spline->control_points[c->nodeLookahead[level]];
    return (short)cp->unk_set[branch];
}

// Cubic interpolation kernel. Builds the {t^3, t^2, t, 1} basis, multiplies it by the
// spline-type basis matrix, and writes the components selected by mask
// (swrSpline_INTERP_FLAGS) into out[0..11] (3 floats each).
// 0x0044e660
void swrSpline_Interpolate(void* spline, unsigned char mask, float t, int* nodeIndices, float* out)
{
    swrSpline* s = (swrSpline*)spline;
    swrSplineControlPoint* cp = s->control_points;
    rdVector4 tvec;
    rdVector4 basis;

    tvec.z = t;
    tvec.y = t * t;
    tvec.w = 1.0f;
    tvec.x = tvec.y * t;

    float* p0;
    float* p1;
    float* p2;
    float* p3;
    if (s->type == SPLINE_TYPE_BSPLINE) {
        rdMatrix_Multiply4(&basis, &tvec, &rdMatrix_unk5);
        p0 = &cp[nodeIndices[0]].position.x;
        p1 = &cp[nodeIndices[1]].position.x;
        p2 = &cp[nodeIndices[2]].position.x;
        p3 = &cp[nodeIndices[3]].position.x;
    } else {
        rdMatrix_Multiply4(&basis, &tvec, &rdMatrix_unk6);
        p0 = &cp[nodeIndices[0]].position.x;
        p1 = &cp[nodeIndices[0]].handle2.x;
        p2 = &cp[nodeIndices[1]].handle1.x;
        p3 = &cp[nodeIndices[1]].position.x;
    }

    if (mask & SPLINE_INTERP_POSITION) {
        out[0] = p0[0] * basis.x + p2[0] * basis.z + p1[0] * basis.y + p3[0] * basis.w;
        out[1] = p1[1] * basis.y + p2[1] * basis.z + p0[1] * basis.x + p3[1] * basis.w;
        out[2] = p1[2] * basis.y + p2[2] * basis.z + p0[2] * basis.x + p3[2] * basis.w;
    }
    if (mask & SPLINE_INTERP_UP) {
        if (s->type == SPLINE_TYPE_BEZIER_FLAT) {
            out[11] = 1.0f;
            out[9] = 0.0f;
            out[10] = 0.0f;
        } else {
            float* r0 = &cp[nodeIndices[0]].rotation.x;
            float* r1 = &cp[nodeIndices[1]].rotation.x;
            float* r2 = &cp[nodeIndices[2]].rotation.x;
            float* r3 = &cp[nodeIndices[3]].rotation.x;
            out[9] = r3[0] * basis.w + r0[0] * basis.x + r2[0] * basis.z + r1[0] * basis.y;
            out[10] = r1[1] * basis.y + r2[1] * basis.z + r0[1] * basis.x + r3[1] * basis.w;
            out[11] = r3[2] * basis.w + r1[2] * basis.y + r2[2] * basis.z + r0[2] * basis.x;
        }
    }
    if (mask & SPLINE_INTERP_TANGENT) {
        rdMatrix_Multiply4(&basis, &tvec, s->type == SPLINE_TYPE_BSPLINE ? &rdMatrix_unk3 : &rdMatrix_unk4);
        out[3] = p0[0] * basis.x + p2[0] * basis.z + p1[0] * basis.y + p3[0] * basis.w;
        out[4] = p1[1] * basis.y + p2[1] * basis.z + p0[1] * basis.x + p3[1] * basis.w;
        out[5] = p1[2] * basis.y + p2[2] * basis.z + p0[2] * basis.x + p3[2] * basis.w;
    }
    if (mask & SPLINE_INTERP_NORMAL) {
        rdMatrix_Multiply4(&basis, &tvec, s->type == SPLINE_TYPE_BSPLINE ? &rdMatrix_unk1 : &rdMatrix_unk2);
        out[6] = p0[0] * basis.x + p2[0] * basis.z + p1[0] * basis.y + p3[0] * basis.w;
        out[7] = p1[1] * basis.y + p2[1] * basis.z + p0[1] * basis.x + p3[1] * basis.w;
        out[8] = p1[2] * basis.y + p2[2] * basis.z + p0[2] * basis.x + p3[2] * basis.w;
    }
}

// Step the cursor one control point along the graph: direction 1 advances (next link),
// direction 2 retreats (prev link). Shifts the node lookahead window and tracks the
// branch taken in branchFlags; sets endFlag/startFlag at a dead end.
// 0x0044eaa0
void swrSpline_CursorStep(void* spline, int direction, void* cursor)
{
    swrSpline* s = (swrSpline*)spline;
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    swrSplineControlPoint* cp = s->control_points;

    if ((short)direction == 1) {
        c->startFlag = 0;
        if (c->endFlag == 0) {
            int lead = (s->type == SPLINE_TYPE_BSPLINE) ? c->nodeLookahead[3] : c->nodeLookahead[1];
            int nextCount = (short)cp[lead].next_count;
            if (nextCount == 0) {
                direction = -1;
                c->endFlag = 1;
                c->segmentT = 1.0f;
            } else {
                int branch = (c->branchSelector < nextCount) ? c->branchSelector : (c->branchSelector % nextCount);
                direction = (short)(&cp[lead].next1)[branch];
                int hist = c->branchFlags >> 1;
                c->branchFlags = (s->type == SPLINE_TYPE_BSPLINE) ? (hist | (branch << 2)) : (hist | branch);
            }
        }
        if (c->endFlag == 0) {
            c->nodeLookahead[0] = c->nodeLookahead[1];
            if (s->type != SPLINE_TYPE_BSPLINE) {
                c->nodeLookahead[1] = direction;
                return;
            }
            c->nodeLookahead[1] = c->nodeLookahead[2];
            c->nodeLookahead[2] = c->nodeLookahead[3];
            c->nodeLookahead[3] = direction;
        }
    } else {
        c->endFlag = 0;
        if (c->startFlag == 0) {
            int tail = c->nodeLookahead[0];
            int prevCount = (short)cp[tail].prev_count;
            if (prevCount == 0) {
                direction = -1;
                c->startFlag = 1;
                c->segmentT = 0.0f;
            } else {
                int branch = c->branchSelector;
                direction = (short)(&cp[tail].prev1)[(branch < prevCount) ? branch : (branch % prevCount)];
                c->branchFlags = (s->type == SPLINE_TYPE_BSPLINE) ? ((c->branchFlags & 3) << 1) : 0;
                if (tail != (short)cp[direction].next1)
                    c->branchFlags |= 1;
            }
        }
        if (c->startFlag == 0) {
            if (s->type == SPLINE_TYPE_BSPLINE) {
                c->nodeLookahead[3] = c->nodeLookahead[2];
                c->nodeLookahead[2] = c->nodeLookahead[1];
            }
            int old = c->nodeLookahead[0];
            c->nodeLookahead[0] = direction;
            c->nodeLookahead[1] = old;
        }
    }
}

// Advance the cursor parameter by velocity * dt, crossing segment boundaries (stepping
// the cursor) as needed, then evaluate position + tangent + up into out and cache the
// tangent length.
// 0x0044ec40
void swrSpline_CursorEvaluate(void* cursor, float* out)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;

    if ((c->velocity > 0.0f && c->endFlag == 0) || (c->velocity < 0.0f && c->startFlag == 0)) {
        float step = c->velocity * (float)swrRace_deltaTimeSecs;
        c->segmentT += step;
        if (step >= 0.0f) {
            if (step > 0.0f)
                c->startFlag = 0;
        } else {
            c->endFlag = 0;
        }
    }

    while (c->segmentT >= 1.0f) {
        if (c->endFlag != 0)
            break;
        c->segmentT -= 1.0f;
        swrSpline_CursorStep(c->spline, 1, c);
    }
    while (c->segmentT < 0.0f) {
        if (c->startFlag != 0)
            break;
        c->segmentT += 1.0f;
        swrSpline_CursorStep(c->spline, 2, c);
    }
    if (c->segmentT < 0.0f)
        c->segmentT = 0.0f;
    if (c->segmentT > 1.0f)
        c->segmentT = 1.0f;

    swrSpline_Interpolate(c->spline, SPLINE_INTERP_POSITION | SPLINE_INTERP_TANGENT | SPLINE_INTERP_UP, c->segmentT, c->nodeLookahead, out);
    c->tangentLength = rdVector_Len3((rdVector3*)(out + 3));
}

// Evaluate the cursor's current point into a position + orientation matrix, building the
// basis from the path tangent (forward) and the interpolated up vector.
// 0x0044ed80
void swrSpline_EvaluateToMatrix(void* cursor, rdMatrix44* out)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    rdVector3 right;
    rdVector3 upAxis;
    rdVector3 oldTranslation;
    rdVector3 sample[4]; // position, tangent, normal (unused here), up

    swrSpline_CursorEvaluate(c, &sample[0].x);
    float tangentLen = rdVector_Len3(&sample[1]);
    if (tangentLen < (float)0.0001) {
        // tangent collapses at a segment endpoint; sample just inside the segment instead
        float t = (0.5f <= c->segmentT) ? 0.999f : 0.001f;
        swrSpline_Interpolate(c->spline, SPLINE_INTERP_TANGENT, t, c->nodeLookahead, &sample[0].x);
    }
    rdVector_Cross3(&right, &sample[1], &sample[3]);
    rdVector_Cross3(&upAxis, &right, &sample[1]);
    rdVector_Normalize3Acc(&right);
    rdVector_Normalize3Acc(&upAxis);
    rdVector_Normalize3Acc(&sample[1]);
    out->vA.w = 0.0f;
    out->vB.w = 0.0f;
    out->vC.w = 0.0f;
    out->vD.w = 1.0f;
    rdMatrix_SetColumn(out, 0, &right);
    rdMatrix_SetColumn(out, 1, &sample[1]);
    rdMatrix_SetColumn(out, 2, &upAxis);
    rdMatrix_GetColumn(out, 3, &oldTranslation); // original reads the old translation (unused)
    rdMatrix_SetColumn(out, 3, &sample[0]);
}

// 0x0044eeb0
void swrSpline_EvaluateAtOffset(void* cursor, rdMatrix44* out, float t)
{
    swrSplineCursor tmp = *(swrSplineCursor*)cursor;
    tmp.segmentT += t;
    tmp.velocity = 0.0f;
    swrSpline_EvaluateToMatrix(&tmp, out);
}

// 0x0044eef0
void swrSpline_CursorSeek(void* cursor, int nodeIndex)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    swrSpline* s = c->spline;
    swrSplineControlPoint* cp = s->control_points;

    c->nodeLookahead[0] = nodeIndex;
    c->nodeLookahead[1] = nodeIndex;
    c->nodeLookahead[2] = nodeIndex;
    c->nodeLookahead[3] = nodeIndex;
    if (cp[nodeIndex].next_count != 0) {
        int n1 = cp[nodeIndex].next1;
        c->nodeLookahead[1] = n1;
        if (s->type == SPLINE_TYPE_BSPLINE && cp[n1].next_count != 0) {
            int n2 = cp[n1].next1;
            c->nodeLookahead[2] = n2;
            if (cp[n2].next_count != 0)
                c->nodeLookahead[3] = cp[n2].next1;
        }
    }
}

// Active track's total spline length, cached by swrSpline_TraceProgress during bake.
// 0x0047e870
float swrSpline_GetTrackLength(void)
{
    return swrSpline_trackLength;
}

// 0x0047e880
void* swrSpline_CursorInit(void* cursor, swrSpline* spline)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    c->spline = spline;
    c->velocity = 0.0f;
    c->tangentLength = 0.0f;
    c->segmentT = 0.0f;
    c->endFlag = 0;
    c->startFlag = 0;
    c->branchSelector = 0;
    c->branchFlags = 0;
    swrSpline_CursorSeek(c, 0);
    return c;
}

// Seed the cursor to a track-progress value (progress / 10 selects the band/node, the
// remainder becomes the segment parameter) and fill its node lookahead chain.
// 0x0047e8b0
void swrSpline_CursorSeekToProgress(void* cursor, int progress)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    swrSpline* s = c->spline;
    swrSplineControlPoint* cp = s->control_points;
    int band = progress / 10;

    if (band < (int)s->num_control_points) {
        c->nodeLookahead[0] = band;
        int n1 = cp[band].next1;
        c->nodeLookahead[1] = n1;
        if (s->type != SPLINE_TYPE_BEZIER_FLAT) {
            int n2 = cp[n1].next1;
            c->nodeLookahead[2] = n2;
            c->nodeLookahead[3] = cp[n2].next1;
        }
        c->branchFlags = 0;
        c->segmentT = ((float)progress - (float)band * 10.0f) * 0.1f;
        return;
    }

    for (int node = 0; node < (int)s->num_control_points; node++) {
        for (int slot = 0; slot < 8; slot++) {
            if ((short)cp[node].unk_set[slot] != band)
                continue;
            c->nodeLookahead[0] = node;
            c->branchFlags = slot;
            c->segmentT = ((float)progress - (float)band * 10.0f) * 0.1f;
            int n1 = (&cp[node].next1)[slot & 1];
            c->nodeLookahead[1] = n1;
            if (s->type != SPLINE_TYPE_BEZIER_FLAT) {
                int n2 = (&cp[n1].next1)[(slot >> 1) & 1];
                c->nodeLookahead[2] = n2;
                c->nodeLookahead[3] = (&cp[n2].next1)[(slot >> 2) & 1];
            }
            return;
        }
    }
}

// 0x0047ea20
void swrSpline_BakeSampleTrackMesh(void* cursor, float samplesPerNode, swrModel_Node* trackModel, unsigned short* order)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    rdMatrix44 m;
    // origin, direction, length
    float ray[7];
    int ambiguous = 0;

    ray[3] = 0.0f;
    ray[4] = 0.0f;
    ray[5] = -1.0f;
    ray[6] = 5000.0f;
    swrSpline_EvaluateToMatrix(c, &m);
    ray[0] = m.vD.x;
    ray[1] = m.vD.y;
    ray[2] = m.vD.z;
    swrModel_SetRaycastIgnoreFacing(1);
    swrModel_Mesh* mesh = (swrModel_Mesh*)swrModel_CollideRayWithModel((swrModel_NodeTransformed*)trackModel, ray);
    if (mesh == NULL) {
        ray[5] = 1.0f;
        mesh = (swrModel_Mesh*)swrModel_CollideRayWithModel((swrModel_NodeTransformed*)trackModel, ray);
    }
    swrModel_SetRaycastIgnoreFacing(0);

    int node = swrSpline_getControlPoint(c, 0);
    int sample = (int)(((float)node + c->segmentT) * samplesPerNode);
    unsigned short pathOrder = order[node];
    swrSpline_sampleMeshes[sample] = mesh;
    if (mesh != NULL) {
        if (mesh->splineSampleIndex == 0) {
            mesh->splineSampleIndex = (uint16_t)sample;
        } else {
            int anchorNode = (int)((float)(short)mesh->splineSampleIndex / samplesPerNode);
            if (pathOrder != order[anchorNode])
                ambiguous = 1;
        }
    }
    if (ambiguous) {
        swrModel_Behavior* behavior = swrModel_MeshGetBehavior(mesh);
        if (behavior == NULL) {
            swrModel_MeshSetBehavior(mesh, &swrSpline_ambiguousMeshBehavior);
            return;
        }
        behavior->unk1 |= swrModel_BEHAVIOR_SPLINE_AMBIGUOUS;
    }
}

// 0x0047eb60
void swrSpline_ProjectPoint(void* cursor, rdVector3* point)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    rdMatrix44 m;
    int moved = 0;

    swrSpline_EvaluateToMatrix(c, &m);
    int done;
    do {
        done = 1;
        // advance while the sample point is behind the target along the path tangent (vB)
        if (m.vD.z * m.vB.z + m.vD.y * m.vB.y + m.vD.x * m.vB.x < m.vB.x * point->x + m.vB.y * point->y + m.vB.z * point->z) {
            float prevT = c->segmentT;
            c->segmentT += 0.01f;
            swrSpline_EvaluateToMatrix(c, &m);
            done = (prevT == c->segmentT); // clamped at the path end -> stop
            moved = 1;
        }
    } while (!done);

    if (!moved) {
        // target is behind the start sample: retreat by fine steps instead
        c->segmentT -= 0.01f;
        swrSpline_EvaluateToMatrix(c, &m);
        do {
            done = 1;
            if (m.vB.x * point->x + m.vB.y * point->y + m.vB.z * point->z < m.vD.z * m.vB.z + m.vD.y * m.vB.y + m.vD.x * m.vB.x) {
                float prevT = c->segmentT;
                c->segmentT -= 0.01f;
                swrSpline_EvaluateToMatrix(c, &m);
                if (prevT != c->segmentT)
                    done = 0;
            }
        } while (!done);
        c->segmentT += 0.01f;
        swrSpline_EvaluateToMatrix(c, &m);
    }
}

// 0x0047ece0
void swrSpline_ValidateSampleTrackMesh(void* cursor, float samplesPerNode)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    swrSplineCursor anchorBuf;
    rdMatrix44 sampleMat;
    rdMatrix44 anchorMat;
    rdVector3 behind;

    void* anchor = swrSpline_CursorInit(&anchorBuf, c->spline);
    int node = swrSpline_getControlPoint(c, 0);
    swrModel_Mesh* mesh = swrSpline_sampleMeshes[(int)(((float)node + c->segmentT) * samplesPerNode)];
    if (mesh == NULL)
        return;
    swrModel_Behavior* behavior = swrModel_MeshGetBehavior(mesh);
    if (behavior != NULL && (behavior->unk1 & swrModel_BEHAVIOR_SPLINE_AMBIGUOUS) != 0)
        return;
    if (mesh->splineSampleIndex == 0)
        return;

    swrSpline_CursorSeekToProgress(anchor, (short)mesh->splineSampleIndex);
    swrSpline_EvaluateToMatrix(c, &sampleMat);
    behind.x = sampleMat.vD.x - sampleMat.vB.x * 0.5f;
    behind.y = sampleMat.vD.y - sampleMat.vB.y * 0.5f;
    behind.z = sampleMat.vD.z - sampleMat.vB.z * 0.5f;
    swrSpline_ProjectPoint(anchor, &behind);
    swrSpline_EvaluateToMatrix(anchor, &anchorMat);
    if (rdVector_DistSquared3((rdVector3*)&sampleMat.vD, (rdVector3*)&anchorMat.vD) > 4.0f) {
        // stripped debug print: the node ids are fetched and discarded
        swrSpline_getControlPoint(c, 0);
        swrSpline_getControlPoint(c, 1);
        swrSpline_getControlPoint(anchor, 0);
        swrSpline_getControlPoint(anchor, 1);
    }
}

// 0x0047ee20
void swrSpline_ForEachSample(swrSpline* spline, float step, void* arg3, void* arg4, void* callback)
{
    void (*cb)(void*, float, void*, void*) = (void (*)(void*, float, void*, void*))callback;
    swrSplineControlPoint* cp = spline->control_points;
    float inc = 1.0f / step;
    swrSplineCursor cursor;
    swrSplineCursor* c = (swrSplineCursor*)swrSpline_CursorInit(&cursor, spline);

    for (int node = 0; node < (int)spline->num_control_points; node++) {
        swr_noop4();
        c->nodeLookahead[0] = node;
        c->branchFlags = 0;
        for (int i = 0; i < (short)cp[node].next_count; i++) {
            c->branchFlags = (c->branchFlags & ~1u) | (i != 0 ? 1u : 0u);
            int n1 = (short)(&cp[c->nodeLookahead[0]].next1)[i];
            c->nodeLookahead[1] = n1;
            if (spline->type == SPLINE_TYPE_BEZIER_FLAT) {
                c->segmentT = 0.0f;
                do {
                    cb(c, step, arg3, arg4);
                    c->segmentT += inc;
                } while (c->segmentT < 1.0f);
            } else if ((short)cp[n1].next_count > 0) {
                for (int j = 0; j < (short)cp[c->nodeLookahead[1]].next_count; j++) {
                    c->branchFlags = (c->branchFlags & ~2u) | (j != 0 ? 2u : 0u);
                    int n2 = (short)(&cp[c->nodeLookahead[1]].next1)[j];
                    c->nodeLookahead[2] = n2;
                    if (n2 != c->nodeLookahead[0] && (short)cp[n2].next_count > 0) {
                        for (int k = 0; k < (short)cp[c->nodeLookahead[2]].next_count; k++) {
                            c->branchFlags = (c->branchFlags & ~4u) | (k != 0 ? 4u : 0u);
                            int n3 = (short)(&cp[c->nodeLookahead[2]].next1)[k];
                            c->nodeLookahead[3] = n3;
                            if (n3 != c->nodeLookahead[1]) {
                                c->segmentT = 0.0f;
                                do {
                                    cb(c, step, arg3, arg4);
                                    c->segmentT += inc;
                                } while (c->segmentT < 1.0f);
                            }
                        }
                    }
                }
            }
        }
    }
}

// 0x0047f060
void swrSpline_TraceProgress(void* cursor, float segmentLength, unsigned short* order, short* counter)
{
    swrSplineCursor* c = (swrSplineCursor*)cursor;
    swrSplineCursor walk;
    rdMatrix44 m;
    rdVector3 prevPos;
    int isStart = 0;
    int done = 0;
    float startProgress;
    float endProgress;
    int node;
    int prevNode;

    int first = swrSpline_getControlPoint(c, 0);
    if (!(swrSpline_progressTable[first].x <= 0.0f))
        return;
    if (c->branchFlags == 0) {
        isStart = 1;
        startProgress = 0.0f;
    } else {
        startProgress = swrSpline_progressTable[c->nodeLookahead[0]].x;
    }
    swrSpline_progressTable[first].x = startProgress;

    float tStep = 1.0f / segmentLength;
    walk = *c;
    walk.segmentT = 0.0f;
    float length = 0.0f;
    swrSpline_EvaluateToMatrix(&walk, &m);
    prevPos.x = m.vD.x;
    prevPos.y = m.vD.y;
    prevPos.z = m.vD.z;
    int nodeCount = 0;
    node = -1;
    do {
        float t = 0.0f;
        nodeCount++;
        int i = 1;
        while ((float)i < segmentLength) {
            t += tStep;
            swrSpline_EvaluateAtOffset(&walk, &m, t);
            length = rdVector_Dist3(&prevPos, (rdVector3*)&m.vD) + length;
            i++;
            prevPos.x = m.vD.x;
            prevPos.y = m.vD.y;
            prevPos.z = m.vD.z;
        }
        walk.segmentT = 1.0f;
        swrSpline_EvaluateToMatrix(&walk, &m);
        prevNode = node;
        node = swrSpline_getControlPoint(&walk, 0);
        if (prevNode == node) {
            // the path dead-ends: an open track's finish
            done = 1;
            endProgress = 1.0f;
            if (swrSpline_finishNodeIdx == -2) {
                swrSpline_finishMatrix = m;
                swrSpline_finishNodeIdx = node;
            } else {
                swrSpline_finishNodeIdx = -3;
            }
        } else {
            length = rdVector_Dist3(&prevPos, (rdVector3*)&m.vD) + length;
            prevPos.x = m.vD.x;
            prevPos.y = m.vD.y;
            prevPos.z = m.vD.z;
            if (swrSpline_progressTable[node].x < 0.0f) {
                walk.segmentT = 0.0f;
                swrSpline_progressTable[node].x = length;
            } else {
                // reached a node another path already traced
                endProgress = swrSpline_progressTable[node].x;
                done = 1;
            }
        }
    } while (!done);

    if (endProgress == 0.0f)
        endProgress = 1.0f;
    if (isStart)
        swrSpline_trackLength = length;

    // remap the raw arc lengths onto [startProgress, endProgress]
    walk = *c;
    for (int i = 0; i < nodeCount; i++) {
        node = swrSpline_getControlPoint(&walk, 0);
        order[node] = *counter;
        float f = (swrSpline_progressTable[node].x - startProgress) / length;
        float progress = f * endProgress + (1.0f - f) * startProgress;
        swrSpline_progressTable[node].x = progress;
        if (i != 0)
            swrSpline_progressTable[prevNode].y = progress - swrSpline_progressTable[prevNode].x;
        prevNode = node;
        walk.segmentT = 1.0f;
        swrSpline_EvaluateToMatrix(&walk, &m);
        walk.segmentT = 0.0f;
    }
    swrSpline_progressTable[prevNode].y = endProgress - swrSpline_progressTable[prevNode].x;
    (*counter)++;
}

// 0x0047f450
void swrSpline_TracePathProgress(void* cursor, float segmentLength, unsigned short* order, short* counter)
{
    swrSpline_TraceProgress(cursor, segmentLength, order, counter);
}

// 0x0047f470
void swrSpline_BuildProgressTable(swrSpline* spline, float segmentLength, unsigned short* order)
{
    swrSplineControlPoint* cp = spline->control_points;
    swrSplineCursor cursor;
    short counter;

    for (int i = 0; i < (int)spline->num_segments; i++) {
        order[i] = 0xffff;
        swrSpline_progressTable[i].x = -1.0f;
    }
    counter = 0;
    swrSplineCursor* c = (swrSplineCursor*)swrSpline_CursorInit(&cursor, spline);
    for (int progress = 0; progress < (int)spline->num_control_points; progress++) {
        swr_noop4();
        c->nodeLookahead[0] = swrSpline_getControlPointIdFromProgress(c->spline, progress, 0);
        while (c->nodeLookahead[0] != -1) {
            c->branchFlags = 0;
            for (int i = 0; i < (short)cp[c->nodeLookahead[0]].next_count; i++) {
                c->branchFlags = (c->branchFlags & ~1u) | (i != 0 ? 1u : 0u);
                int n1 = (short)(&cp[c->nodeLookahead[0]].next1)[i];
                c->nodeLookahead[1] = n1;
                if (spline->type == SPLINE_TYPE_BEZIER_FLAT) {
                    swrSpline_TracePathProgress(c, segmentLength, order, &counter);
                    continue;
                }
                for (int j = 0; j < (short)cp[c->nodeLookahead[1]].next_count; j++) {
                    c->branchFlags = (c->branchFlags & ~2u) | (j != 0 ? 2u : 0u);
                    int n2 = (short)(&cp[c->nodeLookahead[1]].next1)[j];
                    c->nodeLookahead[2] = n2;
                    if (n2 == c->nodeLookahead[0])
                        continue;
                    for (int k = 0; k < (short)cp[c->nodeLookahead[2]].next_count; k++) {
                        c->branchFlags = (c->branchFlags & ~4u) | (k != 0 ? 4u : 0u);
                        int n3 = (short)(&cp[c->nodeLookahead[2]].next1)[k];
                        c->nodeLookahead[3] = n3;
                        if (n3 != c->nodeLookahead[1])
                            swrSpline_TracePathProgress(c, segmentLength, order, &counter);
                    }
                }
            }
            c->nodeLookahead[0] = swrSpline_getControlPointIdFromProgress(c->spline, progress, c->nodeLookahead[0] + 1);
        }
    }
}

// 0x0047f6c0
void swrSpline_ResetNodeProgress(int nodeIndex)
{
    for (int i = 0; i < SWR_SPLINE_SAMPLES_PER_NODE; i++)
        swrSpline_sampleMeshes[nodeIndex * SWR_SPLINE_SAMPLES_PER_NODE + i] = NULL;
    swrSpline_progressTable[nodeIndex].x = 0.0f;
    swrSpline_progressTable[nodeIndex].y = 0.0f;
}

// 0x0047eb50
int swrSpline_ProjectPointStub(void* cursor, int* out)
{
    // projection compiled out of retail
    *out = 0;
    return 0;
}

// Returns the .rdata sample-spacing constant at 0x004adf40 (0.0f in retail).
// 0x0047f800
float swrSpline_GetSampleSpacing(void)
{
    return 0.0f;
}

// 0x00480170
int swrSpline_CollectNearbyPoints(swrSpline* spline, float* center, float range, int maxPoints, rdVector2* outPoints, float density)
{
    swrSplineCursor cursor;
    rdMatrix44 m;
    rdVector3 nodePos;
    rdVector3 nextPos;
    int count = 0;
    int skip;

    if (spline->type != SPLINE_TYPE_BEZIER_FLAT)
        return 0;
    float step = 1.0f / density;
    swrSplineCursor* c = (swrSplineCursor*)swrSpline_CursorInit(&cursor, spline);
    swrSplineControlPoint* cp = spline->control_points;
    skip = 0;
    for (int node = 0; node < (int)spline->num_control_points; node++) {
        c->nodeLookahead[0] = node;
        int nextCount = (short)cp[node].next_count;
        if (track_spline_variant != 0) {
            // track variants mask out the control-point range of an alternate path
            skip = 0;
            if (node == 1)
                nextCount = 1;
            else if (track_spline_variant == 1)
                skip = node >= 0x63 && node <= 0x71;
            else if (track_spline_variant == 2)
                skip = node >= 0x67 && node <= 0x73;
            else if (track_spline_variant == 3)
                skip = node >= 0x84 && node <= 0x90;
        }
        if (skip)
            continue;
        c->branchFlags = 0;
        swrSpline_GetControlPointPosition(spline, node, &nodePos);
        // dx/dy start as the node's offset but are overwritten by the last sample of each branch,
        // which the next branch's reject test then reads
        float dx = nodePos.x - center[0];
        float dy = nodePos.y - center[1];
        if (nextCount <= 0)
            continue;
        float negRange = -range;
        for (int i = 0; i < nextCount; i++) {
            c->branchFlags = (c->branchFlags & ~1u) | (i != 0 ? 1u : 0u);
            int next = (short)(&cp[c->nodeLookahead[0]].next1)[i];
            c->nodeLookahead[1] = next;
            swrSpline_GetControlPointPosition(spline, next, &nextPos);
            float nextDx = nextPos.x - center[0];
            float nextDy = nextPos.y - center[1];
            // skip segments whose ends both lie past the same edge of the box
            if (dx < negRange && nextDx < negRange)
                continue;
            if (dx > range && nextDx > range)
                continue;
            if (dy < negRange && nextDy < negRange)
                continue;
            if (dy > range && nextDy > range)
                continue;
            c->segmentT = 0.0f;
            rdVector2* out = &outPoints[count];
            do {
                swrSpline_EvaluateToMatrix(c, &m);
                dx = m.vD.x - center[0];
                dy = m.vD.y - center[1];
                if (dx < range && -dx < range && dy < range && -dy < range) {
                    // counted even past maxPoints; only the first maxPoints are stored
                    if (count < maxPoints) {
                        out->x = dx;
                        out->y = dy;
                    }
                    count++;
                    out++;
                }
                c->segmentT = step + c->segmentT;
            } while (c->segmentT < 1.0f);
        }
    }
    return count;
}

// 0x0047f6f0
void swrSpline_Build(swrSpline* spline, struct swrModel_Node* trackModel)
{
    unsigned short order[SWR_SPLINE_MAX_SEGMENTS];
    int i;

    swrSpline_finishNodeIdx = -1;
    if (spline == NULL || (int)spline->num_segments > SWR_SPLINE_MAX_SEGMENTS)
        return;
    if (spline->control_points[0].prev_count == 0) {
        swrSpline_finishNodeIdx = -2;
        for (i = 0; i < (int)spline->num_control_points; i++) {
            swr_noop4();
            // -3 is never stored in retail, so this reset is dead
            if (swrSpline_finishNodeIdx == -3 && spline->control_points[i].next_count == 0)
                swrSpline_ResetNodeProgress(i);
        }
    } else {
        for (i = 0; i < (int)spline->num_control_points; i++) {
            swr_noop4();
            if (spline->control_points[i].next_count == 0)
                swrSpline_ResetNodeProgress(i);
        }
    }
    swrSpline_BuildProgressTable(spline, 100.0f, order);
    swrSpline_ForEachSample(spline, 10.0f, trackModel, order, swrSpline_BakeSampleTrackMesh);
    if (swrSpline_validateSampleMeshes != 0)
        swrSpline_ForEachSample(spline, 10.0f, NULL, NULL, swrSpline_ValidateSampleTrackMesh);
}

// 0x00480480
void swr_SetFixedDeltaTime(double seconds)
{
    swr_fixedDeltaTimeSecs = seconds;
}
