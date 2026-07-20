#ifndef SWRSPLINE_H
#define SWRSPLINE_H

#include "types.h"

#define swrSpline_LoadSpline_ADDR (0x00446fc0)

#define swrSpline_LoadSplineById_ADDR (0x004472e0)

// Runtime cursor primitives. A "cursor" is a 0x30 byte walker tracking a
// position moving along the spline graph (the swrObjJdge embeds one at +0x34):
//   [0] spline   [1] velocity   [2] segment t   [3] tangent length
//   [4..7] 4 node lookahead window   [8] end flag   [9] start flag
//   [10] branch selector   [0xb] branch flag bits
#define swrSpline_getControlPointIdFromProgress_ADDR (0x0044e5e0)
#define swrSpline_getControlPoint_ADDR (0x0044e620)
#define swrSpline_Interpolate_ADDR (0x0044e660)
#define swrSpline_CursorStep_ADDR (0x0044eaa0)
#define swrSpline_CursorEvaluate_ADDR (0x0044ec40)
#define swrSpline_EvaluateToMatrix_ADDR (0x0044ed80)
#define swrSpline_EvaluateAtOffset_ADDR (0x0044eeb0)
#define swrSpline_CursorSeek_ADDR (0x0044eef0)

// Graph traversal, post-load baking, and point projection (control points form
// a directed graph keyed by a per-node "progress" band; baking assigns
// arc-length progress and tessellates each segment).
#define swrSpline_GetTrackLength_ADDR (0x0047e870)
#define swrSpline_CursorInit_ADDR (0x0047e880)
#define swrSpline_CursorSeekToProgress_ADDR (0x0047e8b0)
#define swrSpline_BakeSampleTrackMesh_ADDR (0x0047ea20)
#define swrSpline_ProjectPointStub_ADDR (0x0047eb50)
#define swrSpline_ProjectPoint_ADDR (0x0047eb60)
#define swrSpline_ValidateSampleTrackMesh_ADDR (0x0047ece0)
#define swrSpline_ForEachSample_ADDR (0x0047ee20)
#define swrSpline_TraceProgress_ADDR (0x0047f060)
#define swrSpline_BuildProgressTable_ADDR (0x0047f470)
#define swrSpline_ResetNodeProgress_ADDR (0x0047f6c0)
#define swrSpline_Build_ADDR (0x0047f6f0)
#define swrSpline_GetSampleSpacing_ADDR (0x0047f800)
#define swrSpline_CollectNearbyPoints_ADDR (0x00480170)
#define swr_SetFixedDeltaTime_ADDR (0x00480480)

void swrSpline_LoadSpline(int index, unsigned short** b);

char* swrSpline_LoadSplineById(char* splineBuffer);

// Scan control points from startIndex for one whose progress field equals
// progress; returns its index or -1.
int swrSpline_getControlPointIdFromProgress(swrSpline* spline, int progress, int startIndex);

// Resolve the node index at lookahead level (0..3), honoring the cursor branch
// flag bits.
int swrSpline_getControlPoint(void* cursor, int level);

// Core cubic interpolation kernel. Builds the {t^3, t^2, t, 1} basis, applies
// the spline-type basis matrices, and writes the components selected by mask
// (swrSpline_INTERP_FLAGS) into out.
void swrSpline_Interpolate(void* spline, unsigned char mask, float t, int* nodeIndices, float* out);

// Step the cursor to the next (direction 1) or previous (direction 2) control
// point, shifting the lookahead window and tracking branch selection.
void swrSpline_CursorStep(void* spline, int direction, void* cursor);

// Advance the cursor parameter by its velocity, crossing segment boundaries,
// then evaluate position + tangent + up into out.
void swrSpline_CursorEvaluate(void* cursor, float* out);

// Evaluate the cursor's current point into a position+orientation matrix (the
// path tangent becomes the forward axis).
void swrSpline_EvaluateToMatrix(void* cursor, rdMatrix44* out);

// Advance the cursor parameter by t, then evaluate it into a matrix.
void swrSpline_EvaluateAtOffset(void* cursor, rdMatrix44* out, float t);

// Seed the cursor to nodeIndex and fill its 4 level lookahead chain.
void swrSpline_CursorSeek(void* cursor, int nodeIndex);

// Return the active track's total spline length (cached in a global during bake).
float swrSpline_GetTrackLength(void);

// Initialize a cursor for spline (zeroes it then seeks to the start). Returns
// the cursor.
void* swrSpline_CursorInit(void* cursor, swrSpline* spline);

// Seed the cursor to a track-progress value: progress / 10 selects the band/node and
// the remainder becomes the segment parameter, then fill the node lookahead chain.
void swrSpline_CursorSeekToProgress(void* cursor, int progress);

// Retired/compiled-out projection: writes 0 to the out-slot and returns 0 unconditionally
// (the swrRace 0xf4..0x100 block it feeds is therefore always zero in retail).
int swrSpline_ProjectPointStub(void* cursor, int* out);

// ForEachSample callback (10 samples/node, from swrSpline_Build): raycasts down (then up)
// 5000 units from the spline sample (facing check disabled), stores the hit track mesh into
// the baked sample->mesh table (spline_progress_values scratch region), stamps mesh
// splineSampleIndex with the first sample that hit it, and marks meshes shared between
// traversal orders as spline-ambiguous (behavior unk1 bit 8; assigns the static behavior
// @0x4c7be8 if the mesh has none).
void swrSpline_BakeSampleTrackMesh(void* cursor, float samplesPerNode, swrModel_Node* trackModel, unsigned short* order);

// Optional debug pass over the baked sample->mesh table (gated on the global at 0xe259a0 in
// swrSpline_Build): re-seeks a cursor to each mesh's anchor sample and distance-checks it;
// the mismatch branch is a stripped debug print.
void swrSpline_ValidateSampleTrackMesh(void* cursor, float samplesPerNode);

// Advance the cursor to the point on the spline nearest the given world point
// (used to map a world position back to a spline parameter / progress).
void swrSpline_ProjectPoint(void* cursor, rdVector3* point);

// Walk every segment, subdivide it into fixed steps, and invoke callback per
// sample.
void swrSpline_ForEachSample(swrSpline* spline, float step, void* arg3, void* arg4, void* callback);

// Trace one graph path, integrating arc length to assign each visited node a
// normalized progress value.
void swrSpline_TraceProgress(void* cursor, float segmentLength, unsigned short* order, short* counter);

// Walk all graph paths and build the per-node progress table.
void swrSpline_BuildProgressTable(swrSpline* spline, float segmentLength, unsigned short* order);

// Clear the runtime progress/state arrays for one node index.
void swrSpline_ResetNodeProgress(int nodeIndex);

// Top level post-load processing (called by LoadTrackSpline): resets junction nodes, builds
// the arc-length progress table (100-unit tracing), then bakes the 10-samples-per-node
// sample->track-mesh table against the track model (+ an optional debug validation pass).
void swrSpline_Build(swrSpline* spline, struct swrModel_Node* trackModel);

// Returns the .rdata sample-spacing constant (0.0f in retail).
float swrSpline_GetSampleSpacing(void);

// Returns the integrated track/spline length (swrSpline_trackLength, set by swrSpline_TraceProgress).
float swrSpline_GetTrackLength(void);

// Sample every spline segment near `center` (within +/- range on each axis), writing each hit as an
// (x,y) offset from center into outPoints (up to maxPoints); `density` controls the sample spacing.
// Returns the number of points found. Used to draw the track outline on the in-race minimap.
int swrSpline_CollectNearbyPoints(swrSpline* spline, float* center, float range, int maxPoints, rdVector2* outPoints, float density);

// Stores the fixed delta time in seconds into its global.
void swr_SetFixedDeltaTime(double seconds);

#endif // SWRSPLINE_H
