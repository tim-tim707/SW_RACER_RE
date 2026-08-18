#include "swrMain_delta.h"

#include <chrono>

extern "C" {
#include <Main/swrMain.h>// swrMain_RunFrame_ADDR, swrMain_UpdateInRaceLoopSfx_ADDR
#include <Swr/swrRace.h> // swrRace_IncrementFrameTimer_ADDR, swrRace_resultsScreenActive, swrRace_dt_raw_d
#include <Swr/swrObj.h>  // GetPauseState_ADDR, updateInRaceInputBitsets_ADDR, swrObjJudge_PollPause_ADDR
#include <Swr/swrText.h> // resetOverlayDrawQueues_ADDR
#include <Swr/swrSound.h>// swrSound_UpdateDelayedSfx_ADDR, swrSound_UpdateMusic_ADDR
#include <Swr/swrEvent.h>// swrEvent_CallAllF0..F3_ADDR
#include <Swr/swrModel.h>// swrModel_UpdateAnimations_ADDR
#include <Swr/swrViewport.h>// swrViewport_UpdateCameras_ADDR
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"

// Toggle + tunables (driven from the ImGui panel; see imgui_utils.cpp).
bool swr_fixedTimestep = false;
float swr_fixedTimestepHz = 60.0f;
int swr_fixedTimestep_lastSteps = 0;

namespace {
typedef void(__cdecl* swrMain_RunFrame_t)(short, short);
typedef void(__cdecl* void_fn_t)(void);
typedef int(__cdecl* int_fn_t)(void);

constexpr int kNumLocalInputSlots = 4;// inRaceLocalPlayerInputBitset* are int[4]

// Cap catch-up sub-steps so a long stall (load spike, breakpoint) can't spiral into a death loop;
// after a hitch we drop the backlog and resync rather than fast-forward through it.
constexpr int kMaxSubSteps = 6;

// swrMain_RunFrame phase-1 (0x00445980) decomposed. The original bundles, in order: a per-frame sfx
// tick, the input edge detector, the frame timer (dt), two sound updates, the pause poll, then --
// only when not paused -- the world sim (model animations + entity F0..F3), and finally the camera
// update. The first spike ran the WHOLE bundle per sub-step, which re-polled input and rebuilt the 2D
// overlay N times (or zero on a tickless frame) -- the root of the picky-input and minimap-flicker
// bugs. Here the once-per-frame parts run once at render cadence and only the world sim repeats on the
// fixed-dt accumulator. Every callee is invoked by its src _ADDR (none are reimplemented/hooked).

std::chrono::steady_clock::time_point s_lastTime;
bool s_haveLast = false;
double s_accum = 0.0;// unspent wall-clock seconds carried between render frames

// frametotal must read as ONE render-frame number for the whole frame. swrSound_Update keeps a looping
// voice (engine, warning beep) alive only while its startFrame == frametotal (or frametotal-1, set by
// playASoundImpl when the sim re-requests it); otherwise it resets the channel. IncrementFrameTimer
// bumps frametotal each tick, so without pinning it the per-tick requests stamp a moving startFrame
// that no longer matches the value swrSound_Update sees -> the loop is reset and restarted every frame
// (the "broken record" stutter). We advance it once per tick-frame and hold it across all the ticks.
unsigned int s_frametotalThisFrame = 0;

// Input is sampled once per render frame (render cadence) but consumed by the sim on a fixed tick.
// Both the just-pressed edges (bitset1) and the held level (bitset3) are OR-accumulated across the
// frames since the last tick, so a tap or brief hold landing on a tickless frame still reaches the
// next tick instead of being missed -- many pod controls (boost/lean) read the HELD bit, not the
// edge, so latching only the edges left those inputs dropping at high FPS / low sim rate. The
// accumulated latch is presented to the FIRST tick only; later ticks in the same frame see the true
// current held (no phantom re-press). updateInRaceInputBitsets derives its edges by diffing against
// bitset3, so after the ticks we restore bitset3 to the true held sampled this frame, or the next
// frame's edge detection would diff against the latched (wrong) value.
int s_pressLatch[kNumLocalInputSlots] = {0, 0, 0, 0};// OR of bitset1 (just-pressed) since last tick
int s_heldLatch[kNumLocalInputSlots] = {0, 0, 0, 0}; // OR of bitset3 (held) since last tick
int s_trueHeld[kNumLocalInputSlots] = {0, 0, 0, 0};  // true bitset3 sampled by the prologue this frame
bool s_haveTrueHeld = false;

// The bitsets are only ONE of the game's two per-frame input representations. swrControl_ProcessInputs
// (run once per render frame by swrMain_GuiAdvance, before our hook) also writes the processed control
// values: the analog axes (throttle/steering/pitch) plus a block of digital BUTTON floats at
// swrRace_PitchInput[1..15] -- boost and thrust among them. The boost charge->fire state machine reads
// those floats per tick, so a single press on a tickless frame is overwritten before any tick sees it
// (the "boost lost between steps" bug). Latch them like the bitsets: max since last tick, present to
// the first tick, restore the true value after. The axes are level signals (steering sign matters) and
// are left untouched -- the tick reads the current value.
constexpr int kNumProcButtons = 15;// swrRace_PitchInput[1..15], set by swrControl_ProcessInputs
float s_btnLatch[kNumProcButtons] = {0};// max of each processed button float since last tick
float s_btnTrue[kNumProcButtons] = {0}; // true processed button floats sampled this frame

// Last-built 2D overlay counts (minimap dots + both text-entry queues, the exact set
// resetOverlayDrawQueues clears). The world sim appends these; phase-2 draws them and zeroes the
// counts while the backing arrays persist. On a tickless frame we restore the counts so phase-2
// redraws the last-built overlay instead of an empty one.
int s_savedMiniMapPositions = 0;
int s_savedTextEntries1Count = 0;
int s_savedTextEntries2Count = 0;

// The 15 processed button floats live at swrRace_PitchInput[1..15] (the axes occupy [-3..0]).
float* procButtons() {
    return &swrRace_PitchInput + 1;
}

void reset_fixed_step_state() {
    s_haveLast = false;
    s_accum = 0.0;
    s_haveTrueHeld = false;
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        s_pressLatch[p] = 0;
        s_heldLatch[p] = 0;
        s_trueHeld[p] = 0;
    }
    for (int i = 0; i < kNumProcButtons; i++) {
        s_btnLatch[i] = 0.0f;
        s_btnTrue[i] = 0.0f;
    }
    s_savedMiniMapPositions = 0;
    s_savedTextEntries1Count = 0;
    s_savedTextEntries2Count = 0;
}

// Phase-1 work that must run exactly once per render frame, independent of how many fixed sim ticks
// we take. Input is edge-detected here: swrControl_ProcessInputs already refreshed the device snapshot
// once this frame (in swrMain_GuiAdvance, before phase-1), so this reads fresh input. The press + held
// bits (bitsets and processed button floats) are OR-accumulated into the latches so a tap/hold
// survives a tickless frame.
void runFrameOncePrologue() {
    ((void_fn_t) swrMain_UpdateInRaceLoopSfx_ADDR)();
    ((void_fn_t) updateInRaceInputBitsets_ADDR)();
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        s_trueHeld[p] = inRaceLocalPlayerInputBitset3[p];
        s_pressLatch[p] |= inRaceLocalPlayerInputBitset1[p];
        s_heldLatch[p] |= inRaceLocalPlayerInputBitset3[p];
    }
    s_haveTrueHeld = true;
    float* btn = procButtons();
    for (int i = 0; i < kNumProcButtons; i++) {
        s_btnTrue[i] = btn[i];
        if (btn[i] > s_btnLatch[i])
            s_btnLatch[i] = btn[i];
    }
    ((void_fn_t) swrSound_UpdateDelayedSfx_ADDR)();
    ((void_fn_t) swrSound_UpdateMusic_ADDR)();
    ((void_fn_t) swrObjJudge_PollPause_ADDR)();
}

// One fixed-dt world-sim tick. resetOverlayDrawQueues first so each tick builds a FRESH 2D overlay
// (only the last tick's survives; otherwise N ticks stack N copies of every minimap dot -> the
// flickering crosses). Advance the frame timer (emits the fixed dt via FastMode; undo its per-tick
// frametotal bump so all ticks share one frame number), present the latched input to the first tick
// (held -> true-current on later ticks so a held control doesn't re-fire its edge), then run the world
// sim -- the only work that integrates against deltaTimeSecs.
void runWorldSimTick(bool firstTick) {
    ((void_fn_t) resetOverlayDrawQueues_ADDR)();
    ((void_fn_t) swrRace_IncrementFrameTimer_ADDR)();
    frametotal = s_frametotalThisFrame;
    float* btn = procButtons();
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        inRaceLocalPlayerInputBitset1[p] = firstTick ? s_pressLatch[p] : 0;
        inRaceLocalPlayerInputBitset3[p] = firstTick ? s_heldLatch[p] : s_trueHeld[p];
    }
    for (int i = 0; i < kNumProcButtons; i++)
        btn[i] = firstTick ? s_btnLatch[i] : s_btnTrue[i];
    ((void_fn_t) swrModel_UpdateAnimations_ADDR)();
    ((void_fn_t) swrEvent_CallAllF0_ADDR)();
    ((void_fn_t) swrEvent_CallAllF1_ADDR)();
    ((void_fn_t) swrEvent_CallAllF2_ADDR)();
    ((void_fn_t) swrEvent_CallAllF3_ADDR)();
}
}// namespace

void __cdecl swrMain_RunFrame_delta(short flags, short phase) {
    // Engage only when the pod is actually being driven on track. This mirrors the game's own "live
    // driving" test in swrControl_UpdateForceFeedback (the gate for the traction/speed/impact force
    // effects): a local player exists, swrRace_resultsScreenActive != 0, and the pod is not respawning
    // or dead. Plus our own toggle and the not-paused / not-stopped guards, so menus / pause / the
    // post-race screens keep vanilla timing.
    const int paused = ((int_fn_t) GetPauseState_ADDR)();
    const int raceSimActive = swrRace_resultsScreenActive;
    const bool haveLocal = currentPlayer_Test != nullptr;
    const bool driving =
        haveLocal && (currentPlayer_Test->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0;

    const bool engage = swr_fixedTimestep && driving && paused == 0 && swrGui_Stopped == 0 &&
                        raceSimActive != 0;

    if (!engage) {
        reset_fixed_step_state();
        hook_call_original((swrMain_RunFrame_t) swrMain_RunFrame_ADDR, flags, phase);
        return;
    }

    // --- simulation phase: once-per-frame prologue, then step the world sim at a fixed dt ---
    if (phase == 0 || phase == 1) {
        const float hz = swr_fixedTimestepHz > 1.0f ? swr_fixedTimestepHz : 1.0f;
        const double dt0 = 1.0 / (double) hz;

        // Measure wall time first so we know whether the sim will tick this frame.
        const auto now = std::chrono::steady_clock::now();
        if (!s_haveLast) {
            s_lastTime = now;
            s_haveLast = true;
        }
        double wall = std::chrono::duration<double>(now - s_lastTime).count();
        s_lastTime = now;
        if (wall > 0.10)// ignore load/hitch spikes rather than catching up across them
            wall = 0.10;
        s_accum += wall;

        // Advance frametotal once per TICK frame and hold it for the whole frame; on a tickless frame
        // it stays put. swrSound_Update keeps a looping voice alive only while its startFrame ==
        // frametotal (or frametotal-1). The sim re-requests those voices on tick frames, stamping the
        // current frametotal -- so frametotal must not move on tickless frames (the loop would age out
        // and reset) nor per-tick (the stamp would not match phase-2's value). One number per frame.
        const bool willTick = s_accum >= dt0;
        s_frametotalThisFrame = willTick ? frametotal + 1 : frametotal;
        frametotal = s_frametotalThisFrame;

        runFrameOncePrologue();

        // Reuse the engine's built-in fixed-dt path: under swr_FastMode, swrRace_IncrementFrameTimer
        // sets deltaTimeSecs = swr_fixedDeltaTimeSecs. It does NOT touch swrRace_dt_raw_d, the un-
        // clamped delta the race/lap clock accumulates (swrObjJdge_F2) -- left alone it keeps the last
        // real frame delta, so the timer would count at hz/render_fps. Pin it to the fixed dt too so
        // the clock advances one real second per second regardless of sim rate. Save/restore all three.
        const int savedFastMode = swr_FastMode;
        const double savedFixedDt = swr_fixedDeltaTimeSecs;
        const double savedRawDt = swrRace_dt_raw_d;
        swr_FastMode = 1;
        swr_fixedDeltaTimeSecs = dt0;
        swrRace_dt_raw_d = dt0;

        int steps = 0;
        while (s_accum >= dt0 && steps < kMaxSubSteps) {
            runWorldSimTick(steps == 0);
            s_accum -= dt0;
            steps++;
        }
        if (steps >= kMaxSubSteps)
            s_accum = 0.0;// give up catching up after a long stall

        swr_FastMode = savedFastMode;
        swr_fixedDeltaTimeSecs = savedFixedDt;
        swrRace_dt_raw_d = savedRawDt;
        swr_fixedTimestep_lastSteps = steps;

        // Restore the true input sampled this frame: bitset3 so the next frame's edge detection
        // (updateInRaceInputBitsets diffs against it) isn't thrown off by the latch we wrote inside the
        // ticks, and the processed button floats so any post-tick reader sees the real values. No-op on
        // a tickless frame (nothing overwrote them).
        if (s_haveTrueHeld) {
            float* btn = procButtons();
            for (int p = 0; p < kNumLocalInputSlots; p++)
                inRaceLocalPlayerInputBitset3[p] = s_trueHeld[p];
            for (int i = 0; i < kNumProcButtons; i++)
                btn[i] = s_btnTrue[i];
        }

        if (steps > 0) {
            // A tick consumed the latched input, and the world sim rebuilt the overlay this frame.
            for (int p = 0; p < kNumLocalInputSlots; p++) {
                s_pressLatch[p] = 0;
                s_heldLatch[p] = 0;
            }
            for (int i = 0; i < kNumProcButtons; i++)
                s_btnLatch[i] = 0.0f;
            s_savedMiniMapPositions = numMiniMapPositions;
            s_savedTextEntries1Count = swrTextEntries1Count;
            s_savedTextEntries2Count = swrTextEntries2Count;
        } else {
            // Render outran the sim: restore the last-built overlay so phase-2 redraws it (no flicker).
            // The backing arrays still hold the last tick's dots/text; only the counts were zeroed.
            numMiniMapPositions = s_savedMiniMapPositions;
            swrTextEntries1Count = s_savedTextEntries1Count;
            swrTextEntries2Count = s_savedTextEntries2Count;
        }

        // Camera follows the pod; update once per render frame after the ticks (render cadence).
        ((void_fn_t) swrViewport_UpdateCameras_ADDR)();
    }

    // --- render phase: once per real frame, straight through to the original render path ---
    if (phase == 0 || phase == 2) {
        hook_call_original((swrMain_RunFrame_t) swrMain_RunFrame_ADDR, flags, (short) 2);
    }
}
