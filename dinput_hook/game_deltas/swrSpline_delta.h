#pragma once

char *swrSpline_LoadSplineById_delta(char *splineBuffer);

// Choke point for every spline evaluation. swrSpline_Interpolate trusts the cursor completely, so
// a cursor whose spline went away faults at address 0, and one left pointing into a reloaded asset
// buffer faults on garbage. Skip the evaluation and name the caller instead of taking the process
// down.
void swrSpline_EvaluateToMatrix_delta(void *cursor, void *out);
// Seeding a cursor to a progress band that matches no node leaves its node window untouched, so
// a cursor reused across tracks keeps indices from the previous (possibly longer) spline.
void swrSpline_CursorSeekToProgress_delta(void *cursor, int progress);

// True if this cursor can actually be evaluated: a spline with a control-point array and a
// plausible count. Use instead of a bare `cursor->spline != NULL` before starting anything that
// waits for the path to finish.
bool spline_cursor_has_usable_spline(const void *cursor);
