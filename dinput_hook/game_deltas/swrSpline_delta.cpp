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
    if ((int) splineBuffer >= CUSTOM_SPLINE_MODELID_BEGIN) {
        return NULL;
    }

    char *res = hook_call_original(swrSpline_LoadSplineById, splineBuffer);

    return res;
}
