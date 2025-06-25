#include "swrSpline_delta.h"

#include <macros.h>

extern "C" {
#include <Swr/swrSpline.h>
}

#include "../hook_helper.h"
#include "../custom_tracks.h"

extern FILE *hook_log;

// 0x004472e0
char *swrSpline_LoadSplineById_delta(char *splineBuffer) {
    const bool is_custom_track = prepare_loading_custom_track_spline((SPLINEID *) &splineBuffer);

    char *res = hook_call_original(swrSpline_LoadSplineById, splineBuffer);

    if (is_custom_track)
        finalize_loading_custom_track_spline(*(swrSpline **) res);
    return res;
}
