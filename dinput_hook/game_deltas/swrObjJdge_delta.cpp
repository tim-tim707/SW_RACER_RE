#include <macros.h>
#include <cstring>
#include <cstdio>
#include "swrObjJdge_delta.h"
#include "swrRace_delta.h"

extern "C" {
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrText.h>
#include <Swr/swrSprite.h>
#include <Swr/swrViewport.h> // swrViewport_SetActiveCamera_ADDR (pre-race track fly-by restore)
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"
#include "../patch.h"
#include "../imgui_utils.h"// imgui_state cutscene-skip toggles ("Game" settings panel)

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

// Fresh accept/cancel skip edge (defined in swrControl_delta.cpp): 1 for one frame on a genuine
// press, never for a held key -- so a key held from the race-start menu press can't cascade.
extern "C" int g_cutscene_skip_edge;

int fixup_invalid_node_ptrs(swrModel_Node *&node) {
    if (!node)
        return 0;

    switch (node->type) {
        case NODE_MESH_GROUP:
            break;
        case NODE_BASIC:
            break;
        case NODE_SELECTOR:
            break;
        case NODE_LOD_SELECTOR:
            break;
        case NODE_TRANSFORMED:
            break;
        case NODE_TRANSFORMED_WITH_PIVOT:
            break;
        case NODE_TRANSFORMED_COMPUTED:
            break;
        default:
            // this model type is invalid, set it to null.
            node = nullptr;
            return 1;
    }

    int num_removed_nodes = 0;
    if (node->type & NODE_HAS_CHILDREN) {
        for (int i = 0; i < node->num_children; i++)
            num_removed_nodes += fixup_invalid_node_ptrs(node->children.nodes[i]);
    }
    return num_removed_nodes;
}

// TODO hack: this is a workaround for a crash when loading custom tracks. sometimes the scene graph
//  contains nodes with invalid child pointers, this happens after playing a vanilla track and
//  afterwards a custom track. can be reproduced playing "Spice Mine Run" and then "Bowsers Castle 1".
static void reset_lap_tracking(swrScore *scores); // 100-lap support, defined below

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore *scores) {
    // Drop cable nodes from the previous track so freed pointers aren't matched against new meshes.
    swrRace_ClearCableBends();
    const unsigned int x = hook_call_original(swrObjJdge_InitTrack, judge, scores);
    reset_lap_tracking(scores);
    const int num_removed_nodes = fixup_invalid_node_ptrs(swrViewport_array[0].model_root_node);
    if (num_removed_nodes != 0)
    {
        fprintf(hook_log, "[swrObjJdge_InitTrack_delta] HACK: removed %d nodes with an invalid node type.\n", num_removed_nodes);
        fflush(hook_log);
    }
    return x;
}

// --- 100-lap support -------------------------------------------------------------------------
// swrObjJdge_F2 (0x0045ea30) accumulates each frame's elapsed time into a fixed 5-element array
// swrScore::results_P1_Lap1..Lap5 (offsets 0x60..0x70), indexed *directly* by the current lap
// counter swrScore::results_P1_Lap (offset 0x78, read as an int). The vanilla menu caps laps at
// 5, so the index never exceeds 4. With more than 5 laps the index walks off the end of the
// array and corrupts the score struct -- total_time (0x74) at lap index 5, the lap counter
// itself (0x78) at lap index 6, then obj_test_ptr (0x84) at lap index 9 -> crash -- within a
// handful of laps. This is the real "hardcoded 5-lap" limit (the menu wrap is only cosmetic).
//
// Fix: de-index every access to that array inside F2 so it always uses the first slot
// (Lap1, [esi+0x60]). The lap counter (0x78) and total race time (0x74) are left untouched, so
// lap counting, the finish check (lap+1 == num_laps at judge+0x1c8) and the "n / N" HUD all work
// natively for any lap count. Per-lap split data is no longer kept in the score; instead
// swrObjJdge_F2_delta (below) reconstructs each lap's time from the running total at every lap
// boundary, the in-race "LAP TIME" reads are pointed at the live current/last-lap slots (the two
// swrRace_InRaceTimer sites in the table), and the on-track results screen is replaced with a
// best/worst/average summary (swrRace_InRaceEndStatistics_delta). Total time + lap counting are
// unaffected.
//
// Most sites are a 4-byte SIB-indexed memory operand ([esi + reg*4 + 0x60], plus one
// +num_laps*4+0x5c at the finish check). The de-indexed form is 3 bytes, padded with a NOP, so
// instruction boundaries are preserved and no trampoline is needed. We verify the original bytes
// before patching so a mismatched / already-patched / future binary is skipped, never corrupted.
void swrObjJdge_PatchLapTimeOverflow() {
    struct LapTimeSite {
        uint32_t address;
        uint8_t original[4];
        uint8_t patched[4];
    };

    static const LapTimeSite sites[] = {
        {0x0045ebc6, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045ebe4, {0xd9, 0x44, 0x86, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045ebee, {0x8d, 0x4c, 0x86, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]
        {0x0045ec49, {0xd9, 0x44, 0x96, 0x5c}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60] (was +num_laps*4+0x5c)
        {0x0045ed5f, {0x89, 0x5c, 0x86, 0x60}, {0x89, 0x5e, 0x60, 0x90}}, // mov [esi+0x60],ebx
        {0x0045eda8, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045edb3, {0xd9, 0x44, 0x96, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045edbd, {0x8d, 0x4c, 0x96, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]

        // swrRace_InRaceTimer (0x00460950) in-race "LAP TIME" reads, indexed by current lap:
        // point the current-lap read at Lap1 (slot 0, where F2 now writes the live accumulator) and
        // the just-completed-lap read at Lap2 (slot 1, which swrObjJdge_F2_delta fills with the last
        // lap's time) so the readout ticks and the lap-complete flash shows the real last-lap time
        // instead of 00.000 / out-of-bounds garbage.
        {0x00460aec, {0xd9, 0x44, 0x85, 0x60}, {0xd9, 0x45, 0x60, 0x90}}, // fld [ebp+0x60] (current lap)
        {0x00460af6, {0xd9, 0x44, 0x85, 0x5c}, {0xd9, 0x45, 0x64, 0x90}}, // fld [ebp+0x64] (last lap)
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const LapTimeSite &site: sites) {
        uint8_t *code = (uint8_t *) site.address;
        if (std::memcmp(code, site.original, 4) != 0) {
            if (std::memcmp(code, site.patched, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchLapTimeOverflow] unexpected bytes at %p; aborting patch. "
                    ">5 laps will corrupt memory / crash.\n",
                    (void *) code);
            fflush(hook_log);
            return;
        }

        // Route the write through the owner-tagged journal (revertible, overlap-checked) instead
        // of a raw VirtualProtect+memcpy. The verify above guarantees WriteMemory snapshots the
        // stock bytes, so UndoOwner("lap_time_overflow") restores the original binary exactly.
        if (WriteMemory("lap_time_overflow", code, site.patched, 4))
            patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchLapTimeOverflow] de-indexed %d/%d lap-time sites; >5 laps now safe.\n",
            patched, total);
    fflush(hook_log);
}

// --- 1hr+ race-time support ------------------------------------------------------------------
// swrObjJdge_F2 caps the running race time (and each lap slot) at 3000.0s == 50:00 every frame:
//   if (total >= 3000.0f) total = 3000.0f;   // at 0x0045ed94 (total) and 0x0045edc8 (lap slot)
// using a shared threshold constant 3000.0f at 0x004ad264 (referenced only by these two compares).
// So the in-game timer pins at 50:00.000 and a longer race shows ~50:00.0xx. Raise the threshold
// and both clamp values to 24h so the time keeps accumulating; the time formatter
// (swrText_CreateTimeEntryPrecise) already prints minutes unbounded (MM:SS.mmm, e.g. 72:34.567),
// so every total-time readout (in-race timer, results summary, hangar results) follows.
void swrObjJdge_PatchRaceTimeCap() {
    const float kCap = 86400.0f; // 24h; effectively no cap for any real race, keeps ms precision
    uint8_t cap_bytes[4];
    std::memcpy(cap_bytes, &kCap, 4);

    static const uint8_t old_3000[4] = {0x00, 0x80, 0x3b, 0x45}; // 3000.0f

    struct CapSite {
        uint32_t address;
        bool executable; // .text immediate vs .rdata constant
    };
    static const CapSite sites[] = {
        {0x004ad264, false}, // shared threshold constant (.rdata), used by both fcom compares
        {0x0045ed97, true},  // total_time clamp immediate: mov [esi+0x74], 3000.0f
        {0x0045edca, true},  // lap-slot clamp immediate:  mov [ecx], 3000.0f
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const CapSite &site: sites) {
        uint8_t *p = (uint8_t *) site.address;
        if (std::memcmp(p, old_3000, 4) != 0) {
            if (std::memcmp(p, cap_bytes, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchRaceTimeCap] unexpected bytes at %p; skipping (timer stays "
                    "capped at 50:00).\n",
                    (void *) p);
            fflush(hook_log);
            return;
        }

        // Journaled write (see PatchLapTimeOverflow): the verify above pins the snapshot to the
        // stock 3000.0f, so UndoOwner("race_time_cap") restores the original cap.
        if (WriteMemory("race_time_cap", p, cap_bytes, 4))
            patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchRaceTimeCap] raised race-time cap %d/%d sites (50:00 -> 24h).\n",
            patched, total);
    fflush(hook_log);
}

// --- hours in time displays ------------------------------------------------------------------
// The stock time formatters (swrText_CreateTimeEntry @0x00450670 -> centiseconds, and
// swrText_CreateTimeEntryPrecise @0x00450760 -> milliseconds) split the time only into
// minutes:seconds.fraction, with the minutes field unbounded -- so a 1h12m race renders as
// "72:34.567". Reimplement both to break out an hours field once the time reaches an hour
// ("1:12:34.567"). Under one hour the output is byte-for-byte the vanilla layout, so lap times,
// records and short totals are unchanged. The time arrives as the 3rd argument, a float passed as
// its raw bits (callers pass *(int*)&seconds); screenText is the leading ~format-code prefix.
// Formats a time (seconds) into out as H:MM:SS.frac (>=1h), M:SS.frac (>=1m) or SS.frac, with
// frac_digits of a frac_scale-th fraction (100 = centiseconds, 1000 = milliseconds). The hours
// field only appears past an hour; under an hour the layout matches stock exactly.
static void format_time_str(float t, int frac_scale, int frac_digits, char *out, int out_size) {
    if (t < 0.0f)
        t = 0.0f;
    int total_sec = (int) t;
    int frac = (int) ((t - (float) total_sec) * (float) frac_scale);
    if (frac >= frac_scale) { // guard against float edge cases, matching the stock carry
        frac -= frac_scale;
        total_sec++;
    }
    const int h = total_sec / 3600;
    const int m = (total_sec / 60) % 60;
    const int s = total_sec % 60;
    if (h > 0)
        snprintf(out, out_size, "%d:%02d:%02d.%0*d", h, m, s, frac_digits, frac);
    else if (m > 0)
        snprintf(out, out_size, "%d:%02d.%0*d", m, s, frac_digits, frac);
    else
        snprintf(out, out_size, "%02d.%0*d", s, frac_digits, frac);
}

static void format_time_with_hours(int x, int y, int time_bits, int r, int g, int b, int a,
                                   char *screenText, int frac_scale, int frac_digits) {
    float t;
    std::memcpy(&t, &time_bits, sizeof(t));
    char tstr[32];
    format_time_str(t, frac_scale, frac_digits, tstr, sizeof(tstr));
    char body[96];
    snprintf(body, sizeof(body), "%s%s", screenText ? screenText : "", tstr);
    swrText_CreateTextEntry1(x, y, r, g, b, a, body);
}

void swrText_CreateTimeEntry_delta(int x, int y, int unused, int r, int g, int b, int a,
                                   char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 100, 2); // centiseconds
}

void swrText_CreateTimeEntryPrecise_delta(int x, int y, int unused, int r, int g, int b, int a,
                                          char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 1000, 3); // milliseconds
}

// --- 100-lap lap-time tracking + summary -----------------------------------------------------
// Because the de-index collapses the score's 5-slot per-lap array, we reconstruct each lap's time
// from the racer's running total_time (swrScore+0x74) at every lap boundary. This needs no per-lap
// storage in the score -- only a running best / worst (+ their lap numbers) per racer, plus the
// last completed lap time (mirrored into the score's Lap2 slot so the patched in-race readout can
// show it). swrScore field offsets:
#define SCORE_STRIDE     0x88
#define SCORE_POSITION   0x5c // short
#define SCORE_LAP1       0x60 // float, slot 0 (F2's live current-lap accumulator after de-index)
#define SCORE_LAP2       0x64 // float, slot 1 (we mirror the last completed lap time here)
#define SCORE_TOTAL_TIME 0x74 // float
#define SCORE_CUR_LAP    0x78 // int, completed-lap count for this racer
#define JDGE_NUM_RACERS  0x1bc // swrObjJdge::num_players (total racers, local + AI); 0x1ac is planetId
#define JDGE_NUM_LAPS    0x1c8

#define LAP_RACER_MAX 24
// The vanilla on-track results screen has exactly 5 per-lap rows (the score's 5-slot per-lap
// array). g_lapTimes only feeds that screen, and only on the <=5-lap path, so it needs no more
// than these 5 slots -- a >5-lap race uses the best/worst/avg summary instead and never reads it.
#define VANILLA_RESULTS_LAPS 5

static const char *g_lapScores = nullptr; // == DAT_00e28960 (scores base), captured at InitTrack
static float g_bestLap[LAP_RACER_MAX];
static int g_bestLapNum[LAP_RACER_MAX];
static float g_worstLap[LAP_RACER_MAX];
static int g_worstLapNum[LAP_RACER_MAX];
static float g_lastLap[LAP_RACER_MAX];
static float g_prevTotal[LAP_RACER_MAX];
static int g_prevLap[LAP_RACER_MAX];
static bool g_lapFinished[LAP_RACER_MAX];
// Per-lap times for the first VANILLA_RESULTS_LAPS laps, kept so the <=5-lap vanilla results screen
// (which reads the 5-slot per-lap array the de-index collapsed) can be refilled with real times.
static float g_lapTimes[LAP_RACER_MAX][VANILLA_RESULTS_LAPS];

static void reset_lap_tracking(swrScore *scores) {
    g_lapScores = (const char *) scores;
    for (int i = 0; i < LAP_RACER_MAX; i++) {
        g_bestLap[i] = 1.0e9f;
        g_bestLapNum[i] = 0;
        g_worstLap[i] = 0.0f;
        g_worstLapNum[i] = 0;
        g_lastLap[i] = 0.0f;
        g_prevTotal[i] = 0.0f;
        g_prevLap[i] = 0;
        g_lapFinished[i] = false;
        for (int j = 0; j < VANILLA_RESULTS_LAPS; j++)
            g_lapTimes[i][j] = 0.0f;
    }
}

// Wraps swrObjJdge_F2: runs the (de-indexed, crash-safe) original, then reconstructs per-lap times
// from each racer's total_time so we can report best / worst / average for any lap count.
void swrObjJdge_F2_delta(swrObjJdge *jdge) {
    hook_call_original(swrObjJdge_F2, jdge);

    if (!g_lapScores)
        return;

    int numRacers = *(int *) ((char *) jdge + JDGE_NUM_RACERS);
    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    if (numRacers > LAP_RACER_MAX)
        numRacers = LAP_RACER_MAX;

    for (int r = 0; r < numRacers; r++) {
        char *sc = (char *) g_lapScores + r * SCORE_STRIDE;
        const int lap = *(int *) (sc + SCORE_CUR_LAP);
        const float total = *(float *) (sc + SCORE_TOTAL_TIME);

        if (lap > g_prevLap[r]) {
            const float lapTime = total - g_prevTotal[r];
            const int completedIdx = g_prevLap[r]; // 0-based index of the lap that just finished
            const int lapNum = completedIdx + 1;   // 1-based number for display
            if (lapTime > 0.0f) {
                if (completedIdx < VANILLA_RESULTS_LAPS)
                    g_lapTimes[r][completedIdx] = lapTime; // for the <=5 vanilla results refill
                g_lastLap[r] = lapTime;
                if (lapTime < g_bestLap[r]) {
                    g_bestLap[r] = lapTime;
                    g_bestLapNum[r] = lapNum;
                }
                if (lapTime > g_worstLap[r]) {
                    g_worstLap[r] = lapTime;
                    g_worstLapNum[r] = lapNum;
                }
            }
            g_prevTotal[r] = total;
            g_prevLap[r] = lap;
        }

        if (!g_lapFinished[r] && lap < numLaps) {
            // Mirror the last completed lap time into slot 1 so the patched in-race "LAP TIME"
            // flash (which now reads slot 1) shows it instead of garbage.
            *(float *) (sc + SCORE_LAP2) = g_lastLap[r];
        } else if (!g_lapFinished[r] && numLaps > 0 && lap >= numLaps) {
            // On finish, overwrite the de-indexed lap slots so the records save in
            // swrRace_ResultsMenu (min over Lap1..Lap_n) records the real best lap rather than the
            // de-indexed 0.0; the sentinel in Lap2 makes its min loop stop after Lap1.
            g_lapFinished[r] = true;
            if (g_bestLapNum[r] > 0) {
                *(float *) (sc + SCORE_LAP1) = g_bestLap[r];
                *(float *) (sc + SCORE_LAP2) = -1.0f;
            }
        }
    }
}

// On-track end-of-race results. For <=5 laps the score's 5 per-lap slots fit, so refill them from
// the reconstructed lap times (the de-index dropped per-lap storage) and defer to the original
// screen -- it looks exactly like vanilla. For >5 laps a per-lap list can't fit (the vanilla layout
// stacks one row per lap off the top of the screen), so show a compact best/worst/average/total
// summary in the same left-label / time-column style.
void swrRace_InRaceEndStatistics_delta(void *jdge, void *score) {
    if (!g_lapScores) {
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    const int r = (int) (((char *) score - g_lapScores) / SCORE_STRIDE);

    if (numLaps <= 5) {
        if (r >= 0 && r < LAP_RACER_MAX) {
            for (int i = 0; i < numLaps && i < VANILLA_RESULTS_LAPS; i++)
                *(float *) ((char *) score + SCORE_LAP1 + i * 4) = g_lapTimes[r][i];
        }
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    // >5 laps: hide the results-screen sprites the vanilla screen would lay out, then draw the
    // summary. These are UI sprites, not racers: the original swrRace_InRaceEndStatistics
    // (0x00462320) single-player branch hides sprite IDs 0..0x12 (loop `while (i < 0x13)`) -- the
    // per-lap row sprites it would otherwise show. We mirror that exact range so none show through
    // our summary. (The vanilla 2-player splitscreen branches instead clear 0xf..0x12 / 0x13..0x16;
    // the >5-lap summary path only runs single-player.) Times are formatted here (hour-aware) and
    // drawn left-aligned so they sit in a clean column instead of right-aligning over the labels.
    const short kResultsScreenSprites = 0x13; // == original single-player sprite-hide loop bound
    for (short i = 0; i < kResultsScreenSprites; i++)
        swrSprite_SetVisible(i, 0);

    const float total = *(float *) ((char *) score + SCORE_TOTAL_TIME);
    const int pos = *(short *) ((char *) score + SCORE_POSITION);
    char buf[96];
    char tstr[32];

    swrText_CreateTextEntry1(0xa0, 0x14, -1, -1, -1, -1, swrText_Translate((char *) "~cResults"));

    const int label_x = 0x2d; // 45
    const int time_x = 0x82;  // 130
    const int lapn_x = 0xd2;  // 210
    int y = 0x48;             // 72

    if (r >= 0 && r < LAP_RACER_MAX && g_bestLapNum[r] > 0) {
        const float avg = (numLaps > 0) ? total / (float) numLaps : 0.0f;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sBest");
        format_time_str(g_bestLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_bestLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sWorst");
        format_time_str(g_worstLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_worstLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sAverage");
        format_time_str(avg, 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        y += 0xe;
    }

    swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sTotal");
    format_time_str(total, 1000, 3, tstr, sizeof(tstr));
    snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
    swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
    y += 0x16;

    snprintf(buf, sizeof(buf), "~cFinished %d laps - position %d", numLaps, pos);
    swrText_CreateTextEntry1(0xa0, y, -1, -1, -1, -1, buf);
}

// #97 follow-up: keep finished racers placed above still-racing ones at any race length.
// swrObjJdge_UpdateStandings ranks a finished racer by (10000 - total_time) and a still-racing one
// by progress (lap + fraction, below ~num_laps). Vanilla pinned total_time at the 50:00 (3000s)
// clamp, so the finished key stayed >= 7000 and always beat the progress keys. PatchRaceTimeCap
// raised that clamp to 24h, so a race past ~2h46m (total_time > 10000s, reachable in a long
// 125-lap race) drives a finished racer's key negative and sorts it BELOW a still-racing pod.
// Widening the key would cost finish-time precision (the unfinished band must stay at progress for
// the original's gap math), so instead: let the original compute the gap / rival-arrow displays,
// then re-assign the finishing positions finished-first -- finished racers (ordered by total_time)
// always above still-racing ones (ordered by progress), comparing total_time directly so the order
// keeps full precision. A no-op for any race the original already ordered correctly.
typedef void swrObjJdge_UpdateStandings_t(swrObjJdge *jdge);
typedef float swrObjJdge_GetRacerProgress_t(swrScore *score);

void swrObjJdge_UpdateStandings_delta(swrObjJdge *jdge) {
    hook_call_original((swrObjJdge_UpdateStandings_t *) swrObjJdge_UpdateStandings_ADDR, jdge);

    int numRacers = jdge->num_players;
    if (numRacers > 20)
        numRacers = 20;// swrScoresPtr is swrScore[20]

    swrObjJdge_GetRacerProgress_t *getRacerProgress =
        (swrObjJdge_GetRacerProgress_t *) swrObjJdge_GetRacerProgress_ADDR;
    float progress[20];
    for (int i = 0; i < numRacers; i++)
        progress[i] = getRacerProgress(&swrScoresPtr[i]);

    for (int i = 0; i < numRacers; i++) {
        swrScore *a = &swrScoresPtr[i];
        bool finishedA = (a->flag & 2) != 0;
        int place = 1;
        for (int j = 0; j < numRacers; j++) {
            if (j == i)
                continue;
            swrScore *b = &swrScoresPtr[j];
            bool finishedB = (b->flag & 2) != 0;
            bool bAhead;
            if (finishedA != finishedB)
                bAhead = finishedB;// a finished racer always outranks a still-racing one
            else if (finishedA)
                bAhead = b->results_P1_total_time <
                         a->results_P1_total_time;// both finished: faster first
            else
                bAhead = progress[j] > progress[i];// both racing: more progress first
            if (bAhead)
                place++;
        }
        *(short *) &a->results_P1_Position = (short) place;
    }
}

// Cutscene auto-skip ("Game" settings panel): fast-forward the end credits. ScrollCredits ends a
// section by clearing the judge with 'Fini' (next section) or 'Abrt' (leave credits) once it has
// scrolled off the top; 'Abrt' is the exit the final section uses, so firing it now drops straight
// out of the whole credits sequence. Default off.
typedef void(__cdecl *swrObjJdge_ScrollCreditsFn)(swrObjJdge *);

void swrObjJdge_ScrollCredits_delta(swrObjJdge *jdge) {
    if (imgui_state.skip_credits) {
        swrObjJdge_Clear(jdge, 'Abrt');
        return;
    }
    hook_call_original((swrObjJdge_ScrollCreditsFn) swrObjJdge_ScrollCredits_ADDR, jdge);
}

// Pre-race intro handling ("Game" settings panel): the race manager plays two intro stages before
// the 3-2-1-GO countdown -- flag nibble 4 = the track fly-by sweep, nibble 5 = the pod orbit /
// binder ignition (camera mode 7, ~9s). This delta owns both the dormant-sweep restore and the
// per-stage skip (see the state 4/5 block below); the skip_prerace_camera toggle auto-skips the
// orbit. The live race (nibble 1) and menus are untouched.
typedef void(__cdecl *swrViewport_SetActiveCameraFn)(short);

void swrObjJdge_F0_delta(swrObjJdge *jdge) {
    const int state = jdge->flag & 0xf;

    // Restore the dormant pre-race track fly-by. swrObjJdge_SetupTrackEnvironment already loads a
    // per-track cinematic camera spline (SPLINEID_*_track*came) into jdge->cam_spline, seeds the
    // fly-by cursor at jdge->unk134_mat, and registers its output as camera index 5 -- it just ends
    // by zeroing jdge->camSweepState (so F0/F2 never walk the cursor) and never points the viewport
    // at camera 5. Re-enabling both during the pre-race state (nibble 4) plays the sweep: F2 walks
    // the cam-spline, F0 holds state 4 until the spline ends, then advances to the pod orbit. We
    // capture the active camera entering the sweep and restore it on the way out so the race view
    // returns. Takes precedence over the orbit skip below (opposite intents). Default off.
    static int prevState = -1;
    static short savedCamera = -1;
    if (imgui_state.restore_prerace_track_sweep) {
        if (state == 4 && prevState != 4 && jdge->cam_spline != NULL) {
            savedCamera = (short) unkCameraArrayIndex;
            jdge->camSweepState = jdge->cam_spline;// non-null gate (F0/F2 only test != 0)
            ((swrViewport_SetActiveCameraFn) swrViewport_SetActiveCamera_ADDR)(5);
        } else if (state != 4 && prevState == 4 && savedCamera != 5) {
            jdge->camSweepState = NULL;
            ((swrViewport_SetActiveCameraFn) swrViewport_SetActiveCamera_ADDR)(savedCamera);
            savedCamera = -1;
        }
    }
    prevState = state;

    // Pre-race intro skip = one stage per press. The game skips state 4 (track sweep) and state 5
    // (pod orbit / binder ignition) whenever accept is down -- KeyDownForPlayer1Or2(0x201) OR
    // swrControl_acceptPressedEdge -- and state 4's skip jumps straight PAST the orbit to the
    // countdown (swrObjJdge_StartPostRaceSequence). Two problems: a key held from the race-start
    // menu press keeps that accept "down" (the in-race bitset re-latches it as a fresh press on the
    // first race frame), so it cascades through every stage; and even a deliberate skip in state 4
    // loses the orbit. So neutralize the game's own accept-skip in both states and drive the advance
    // ourselves on a fresh skip edge only: state 4 ends the sweep (the game then advances to the
    // orbit), state 5 raises the accept edge (-> countdown). The skip_prerace_camera toggle
    // auto-skips just the orbit. 0x201 mirrors the game's KeyDownForPlayer1Or2(0x201) skip check
    // (pause bit 0x200 | action bit 0x1).
    if (state == 4 || state == 5) {
        const uint32_t PRERACE_SKIP_INPUT_BITS = 0x201;
        inRaceLocalPlayerInputBitset1[0] &= ~PRERACE_SKIP_INPUT_BITS;
        swrControl_acceptPressedEdge = 0;
        const bool skipStage =
                g_cutscene_skip_edge || (state == 5 && imgui_state.skip_prerace_camera);
        if (skipStage) {
            if (state == 4)
                jdge->camSweepState = NULL;// end the sweep -> the game advances to the orbit
            else
                swrControl_acceptPressedEdge = 1;// orbit -> countdown via the game's own teardown
        }
    }

    hook_call_original(swrObjJdge_F0, jdge);
}
