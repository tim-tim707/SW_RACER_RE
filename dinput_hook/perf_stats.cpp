//
// Per-frame performance breakdown -- see perf_stats.h.
//
#include "perf_stats.h"

#include <glad/glad.h>

#include <chrono>

// Results are read this many frames after their query ends, so the read never waits on the GPU.
#define PERF_QUERY_RING (4)
// Exponential smoothing weight per frame; ~0.5 s time constant at 60 fps keeps the numbers readable.
#define PERF_SMOOTHING (0.03f)

using perf_clock = std::chrono::steady_clock;

static PerfStats g_stats;
static perf_clock::time_point g_frame_start;
static perf_clock::time_point g_before_swap;
static bool g_frame_started = false;

static GLuint g_queries[PERF_QUERY_RING] = {};
static bool g_query_pending[PERF_QUERY_RING] = {};
static int g_query_index = 0;
static bool g_query_open = false;

static int g_n64_draws = 0;
static int g_hd_draws = 0;

static float ms_between(perf_clock::time_point a, perf_clock::time_point b) {
    return std::chrono::duration<float, std::milli>(b - a).count();
}

static void smooth(float &value, float sample) {
    value = value == 0.0f ? sample : value + (sample - value) * PERF_SMOOTHING;
}

void perf_frame_before_swap() {
    g_before_swap = perf_clock::now();
    if (g_query_open) {
        glEndQuery(GL_TIME_ELAPSED);
        g_query_open = false;
        g_query_pending[g_query_index] = true;
    }
}

void perf_frame_after_swap() {
    const perf_clock::time_point now = perf_clock::now();
    if (g_frame_started) {
        smooth(g_stats.cpu_ms, ms_between(g_frame_start, g_before_swap));
        smooth(g_stats.wait_ms, ms_between(g_before_swap, now));
    }
    g_stats.n64_draws = g_n64_draws;
    g_stats.hd_draws = g_hd_draws;
    g_n64_draws = 0;
    g_hd_draws = 0;
}

void perf_frame_begin() {
    if (g_query_open)// a skipped present never reached before_swap; keep the query running
        return;
    if (g_queries[0] == 0)
        glGenQueries(PERF_QUERY_RING, g_queries);
    // The slot about to be reused ended PERF_QUERY_RING - 1 frames ago.
    g_query_index = (g_query_index + 1) % PERF_QUERY_RING;
    if (g_query_pending[g_query_index]) {
        GLint available = 0;
        glGetQueryObjectiv(g_queries[g_query_index], GL_QUERY_RESULT_AVAILABLE, &available);
        if (available) {
            GLuint64 ns = 0;
            glGetQueryObjectui64v(g_queries[g_query_index], GL_QUERY_RESULT, &ns);
            smooth(g_stats.gpu_ms, (float) (ns / 1.0e6));
        }
        g_query_pending[g_query_index] = false;
    }
    glBeginQuery(GL_TIME_ELAPSED, g_queries[g_query_index]);
    g_query_open = true;

    g_frame_start = perf_clock::now();
    g_frame_started = true;
}

void perf_count_n64_draw() {
    g_n64_draws++;
}

void perf_count_hd_draw() {
    g_hd_draws++;
}

const PerfStats &perf_stats() {
    return g_stats;
}

const char *perf_gl_renderer() {
    const GLubyte *renderer = glGetString(GL_RENDERER);
    return renderer ? (const char *) renderer : "unknown";
}
