#pragma once

// Per-frame performance breakdown for the FPS overlay, so a player can tell (and screenshot)
// whether their machine is CPU- or GPU-limited.
//
// CPU = time from the start of a frame to the swap call, i.e. everything the game + renderer did
// on the CPU. Wait = time spent inside the swap (the driver blocking until the GPU catches up, or
// vsync). GPU = a GL_TIME_ELAPSED query spanning the frame's command stream, read back a few
// frames late so it never stalls.

struct PerfStats {
    float cpu_ms = 0.0f;
    float wait_ms = 0.0f;
    float gpu_ms = 0.0f;// 0 until the first query result arrives
    int n64_draws = 0;  // N64-path meshes actually drawn last frame (culled ones excluded)
    int hd_draws = 0;   // glTF replacement models drawn last frame
};

void perf_frame_before_swap();
void perf_frame_after_swap();
void perf_frame_begin();// after the frame-rate limiter, so its sleep counts as neither CPU nor wait
void perf_count_n64_draw();
void perf_count_hd_draw();
const PerfStats &perf_stats();
const char *perf_gl_renderer();// GL_RENDERER string, e.g. "Intel(R) UHD Graphics 620"
