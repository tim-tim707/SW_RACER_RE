#pragma once

// Shadow verification: `shadow <pattern>` in reimpl_config.txt.
//
// Every call to a shadowed function runs retail, rolls memory back, runs our body on the same
// inputs, and compares return registers plus every byte either body wrote. Retail's result is kept,
// so the game (and a lockstep replay) stays on retail's path while each reimpl is checked on real
// gameplay inputs. Mismatches go to shadow.log with the function, frame, arguments and the bytes.
//
// Writes are found with page protection: the game's writable data (the EXE's sections and the heap
// regions its globals point into) is made read-only for the duration of each call, and a vectored
// exception handler records each page's first write. Callees of a shadowed function run retail in
// both runs, so each function is checked in isolation.
//
// Extra reimpl_config.txt keys:
//   shadow_limit <n>         compare at most n calls per function (0 = all)
//   shadow_every <n>         compare every n-th call only (spreads a budget over the whole race)
//   shadow_budget_ms <ms>    at most this much comparison time per frame (live play); each
//                            function is compared once per round, rounds cycle through all of them
//   shadow_frames <a> [b]    compare only in lockstep frames a..b (jump to a mismatch on replay)
//   shadow_anytime           shadow outside a lockstep race too (logged as "live N" frames)
//   shadow_off               start with comparisons paused (Debug > Verification turns them on)
//   shadow_unsafe            also shadow names that suggest input/sound/render/menu/file effects
//   shadow_trace             log each comparison before it runs
//   shadow_no_heap_segments  leave the game's heap out of the protected set
//   shadow_heap_windows      protect only 16 KB behind each pointer argument into the game heap
//   shadow_heap_lock         hold every Win32 heap's lock during a comparison (deadlock-prone)
//   shadow_regions <0|1|2>   protect nothing / module data only / module data + game memory
//   shadow_no_layout_cache   re-walk the memory map on every comparison (slower, for debugging)
// Only functions without effects outside memory can be shadowed: input polling, sound, rendering
// and file I/O would happen twice. shadow_watchdog.txt records where the game thread stopped if a
// comparison ever stalls.

#ifdef __cplusplus
extern "C" {
#endif

// Called by init_hooks() before and after the hook table is installed.
void shadow_init(void);
void shadow_resolve(void);

// Called once per frame from swrRace_IncrementFrameTimer: resets the per-frame budget.
void shadow_frame_tick(void);
// A race scene finished loading: rebuild the region map now rather than on the first comparison.
void shadow_race_loaded(void);

// Writes the per-function summary to shadow.log. Called when a lockstep run stops.
void shadow_report(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <cstdint>

// Read-out and controls for the Verification window (Debug > Verification).
struct ShadowStatus {
    int installed;// functions with a working shadow entry (from reimpl_config.txt at launch)
    bool enabled;
    bool anytime;
    double budget_ms;
    uint32_t every;
    uint64_t compared;
    uint32_t mismatches;
    uint32_t quirks;// known retail quirks, not counted as mismatches
    double total_ms;
    double last_frame_ms;
    double worst_frame_ms;
    uint32_t over_budget_frames;
    uint32_t rounds;
    int foreign_waits;
};

struct ShadowFunctionStats {
    const char *name;
    bool ready;
    bool disabled;// stack-cleanup mismatch: no longer compared
    uint32_t calls;
    uint32_t compared;
    uint32_t mismatches;
    uint32_t warnings;
    uint32_t unreliable;
    uint32_t quirks;
    int first_frame;
    double avg_ms;
    double max_ms;
};

struct ShadowMismatch {
    const char *function;
    int frame;// recording frame, or the game's own frame count when live
    bool live;
    bool unreliable;
    const char *known;// a known retail quirk's explanation, or null for a real mismatch
    char what[160];// first differing bytes, or the return-value difference
};

void shadow_get_status(ShadowStatus *st);
int shadow_function_count(void);
bool shadow_get_function(int i, ShadowFunctionStats *out);
// Returns how many were ever recorded; the last min(n, 64) are in out[(n - k) % 64].
int shadow_recent_mismatches(const ShadowMismatch **out);
void shadow_set_enabled(bool on);
void shadow_set_anytime(bool on);
void shadow_set_budget_ms(double ms);
void shadow_reset_stats(void);
#endif
