#pragma once

#include "types.h"

// Render smoothing for the fixed-timestep sim: the world only moves on ticks, so when render
// outruns the sim, everything a tick writes and the render only reads -- scene node matrices,
// racer / engine / cockpit transforms, cameras, keyframed animations, HUD sprites and dial, material
// colours, the race clock text -- is swapped to its value at the frame's display time for the render,
// then restored before the next tick so the sim never sees it.

extern bool swr_fixedTimestepSmoothing;// render smoothing on (default on)
// How far ahead of the last tick the display is shown, in ticks: 0 interpolates (smooth, one tick
// behind), 1 extrapolates (no added latency, overshoots on turns and bumps). Jitter grows with the
// square of it.
extern float swr_fixedTimestepPrediction;
extern int swr_fixedTimestep_smoothedNodes;// poses given a display value last frame (readout)

// After a frame's batch of `ticks` sim ticks (>= 1): shift curr -> prev for the racers and mark the
// scene for capture. Scene nodes are captured at render time (smoothing_render_root), the only
// point where a scene root is known to be live: teardown can leave someRootNode's children
// dangling while it is no longer drawn.
void smoothing_capture(int ticks);
// Display values for alpha = fraction of a tick elapsed since the last one, in [0, 1). Call after
// swrViewport_UpdateCameras, so the cameras copy the true poses.
void smoothing_apply(float alpha);
// Camera display poses; call right after swrViewport_UpdateCameras (which copies cMan's tick-rate
// camera into each viewport).
void smoothing_apply_cameras();
// From the viewport render hook, before traversing `root`: captures (if ticks ran this frame) and
// writes the display pose of every transformed node under it. Once per root per frame.
void smoothing_render_root(swrModel_Node *root);
// Race-time text: the tick formats the clock into a text entry, so its digits step at the sim rate.
// swrText_CreateTimeEntry's delta notes each entry; entries whose time advanced at real-time rate
// across the last two captures are running clocks and get re-formatted at the frame's display time.
void smoothing_tick_begin();
void smoothing_note_time_entry(int index, float seconds, int fracScale, int fracDigits,
                               const char *screenText);
// Put the true tick values back. Call after phase 2.
void smoothing_restore();
// Drop all history (disengage, pause): the next tick starts fresh with no prev.
void smoothing_reset();
