#include "swrSpline_delta.h"

#include <macros.h>

extern "C" {
#include <Swr/swrSpline.h>
}

#include "tracks_delta.h"

#include "../hook_helper.h"

extern FILE *hook_log;

// 0x004472e0
char *swrSpline_LoadSplineById_delta(char *splineBuffer) {
    fprintf(hook_log, "spline id load: %d\n", (int) splineBuffer);
    fflush(hook_log);
    const bool is_custom_track = prepare_loading_custom_track_spline((SPLINEID*)&splineBuffer);

    char *res = hook_call_original(swrSpline_LoadSplineById, splineBuffer);

    if (is_custom_track)
        finalize_loading_custom_track_spline(*(swrSpline**)res);
    return res;
}
