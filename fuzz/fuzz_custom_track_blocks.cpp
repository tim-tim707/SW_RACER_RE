// Custom-track block files are untrusted input: any downloaded track ships its own.
#include "custom_track_blocks.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_spline_block((const char *) data, size);
    parse_model_block((const char *) data, size);
    return 0;
}
