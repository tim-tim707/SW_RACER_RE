#include "swrMain_delta.h"

#include <chrono>

#include <windows.h>// timeGetTime

extern "C" {
#include <Main/swrMain.h>// swrMain_RunFrame_ADDR, swrMain_UpdateInRaceLoopSfx_ADDR
#include <Swr/swrRace.h> // swrRace_IncrementFrameTimer_ADDR, swrRace_resultsScreenActive, swrRace_dt_raw_d
#include <Swr/swrObj.h>  // GetPauseState_ADDR, updateInRaceInputBitsets_ADDR, swrObjJudge_PollPause_ADDR, updatePauseMenu_ADDR
#include <Swr/swrText.h> // resetOverlayDrawQueues_ADDR
#include <Swr/swrSound.h>// swrSound_UpdateDelayedSfx_ADDR, swrSound_UpdateMusic_ADDR
#include <Swr/swrEvent.h>// swrEvent_CallAllF0..F3_ADDR
#include <Swr/swrModel.h>// swrModel_UpdateAnimations_ADDR
#include <Swr/swrViewport.h>// swrViewport_UpdateCameras_ADDR
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"

bool swr_fixedTimestep = false;
float swr_fixedTimestepHz = 60.0f;
int swr_fixedTimestep_lastSteps = 0;
bool swr_fixedTimestepSplitRng = true;
unsigned int swr_fixedTimestep_ticks = 0;
int swr_fixedTimestep_physRandState = 0;
int swr_fixedTimestep_physDrawsLastFrame = 0;
int swr_fixedTimestep_cosDrawsLastFrame = 0;

namespace {
typedef void(__cdecl* swrMain_RunFrame_t)(short, short);
typedef void(__cdecl* void_fn_t)(void);
typedef int(__cdecl* int_fn_t)(void);

constexpr int kNumLocalInputSlots = 4;// inRaceLocalPlayerInputBitset* are int[4]

// Catch-up cap; past it the backlog is dropped rather than fast-forwarded.
constexpr int kMaxSubSteps = 6;

// swrMain_RunFrame phase-1 (0x00445980) decomposed: only the world sim repeats on the fixed-dt
// accumulator; input, sound, pause poll and cameras run once per render frame.

std::chrono::steady_clock::time_point s_lastTime;
bool s_haveLast = false;
double s_accum = 0.0;// unspent wall-clock seconds carried between render frames

// frametotal must read as ONE number for the whole frame: swrSound_Update keeps a looping voice
// alive only while its startFrame == frametotal (or frametotal-1, stamped by playASoundImpl), so a
// per-tick bump makes every loop reset and restart (the "broken record" stutter).
unsigned int s_frametotalThisFrame = 0;

// Input is sampled per render frame but consumed per tick: press/release edges and held level are
// OR-latched across tickless frames and handed to the FIRST tick only. bitset3 is restored after
// the ticks because updateInRaceInputBitsets derives next frame's edges by diffing against it.
int s_pressLatch[kNumLocalInputSlots] = {0, 0, 0, 0};// OR of bitset1 (just-pressed) since last tick
int s_releaseLatch[kNumLocalInputSlots] = {0, 0, 0, 0};// OR of bitset2 (just-released) since last tick
int s_heldLatch[kNumLocalInputSlots] = {0, 0, 0, 0}; // OR of bitset3 (held) since last tick
int s_trueHeld[kNumLocalInputSlots] = {0, 0, 0, 0};  // true bitset3 sampled by the prologue this frame
bool s_haveTrueHeld = false;

// swrControl_ProcessInputs also writes digital button floats (boost, thrust) after the axes; the
// boost state machine reads them per tick, so they get the same latch. Axes are left untouched.
constexpr int kNumProcButtons = 15;// swrRace_PitchInput[1..15], set by swrControl_ProcessInputs
float s_btnLatch[kNumProcButtons] = {0};// max of each processed button float since last tick
float s_btnTrue[kNumProcButtons] = {0}; // true processed button floats sampled this frame

// Last-built 2D overlay counts (the exact set resetOverlayDrawQueues clears). Phase-2 zeroes the
// counts but the backing arrays persist, so restoring them on a tickless frame redraws the overlay.
int s_savedMiniMapPositions = 0;
int s_savedTextEntries1Count = 0;
int s_savedTextEntries2Count = 0;

// swrUtils_Rand (0x004816b0) has one global state shared by sim draws and render-cadence cosmetics
// (weather, minimap, HUD), so the renders-per-tick count would leak into the gameplay stream. While
// engaged, swrUtils_randState holds the physics stream only during ticks; the rest of the frame
// draws from a separate cosmetic stream. Disengaging hands the physics stream back.
constexpr int kCosmeticRandSalt = 0x5f3759df;
bool s_rngSplit = false;
int s_physRandState = 0;
int s_cosRandAfterTicks = 0;// cosmetic state at the last tick bracket, for the draw readout

// swrUtils_Rand's LCG step. Used only to count draws for the readout.
constexpr unsigned int kRandMul = 0x41c64e6d;
constexpr unsigned int kRandInc = 0x3039;
constexpr int kMaxCountedDraws = 4096;

int countRandDraws(int from, int to) {
    unsigned int s = (unsigned int) from;
    for (int n = 0; n <= kMaxCountedDraws; n++) {
        if (s == (unsigned int) to)
            return n;
        s = s * kRandMul + kRandInc;
    }
    return -1;
}

void beginRngSplit() {
    if (s_rngSplit || !swr_fixedTimestepSplitRng)
        return;
    s_physRandState = swrUtils_randState;
    swrUtils_randState ^= kCosmeticRandSalt;
    s_cosRandAfterTicks = swrUtils_randState;
    s_rngSplit = true;
}

void endRngSplit() {
    if (!s_rngSplit)
        return;
    swrUtils_randState = s_physRandState;
    s_rngSplit = false;
}

float* procButtons() {
    return &swrRace_PitchInput + 1;
}

void reset_fixed_step_state() {
    s_haveLast = false;
    s_accum = 0.0;
    s_haveTrueHeld = false;
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        s_pressLatch[p] = 0;
        s_releaseLatch[p] = 0;
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

// swrControl_ProcessInputs already refreshed the device snapshot (in swrMain_GuiAdvance).
void runFrameOncePrologue() {
    ((void_fn_t) swrMain_UpdateInRaceLoopSfx_ADDR)();
    ((void_fn_t) updateInRaceInputBitsets_ADDR)();
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        s_trueHeld[p] = inRaceLocalPlayerInputBitset3[p];
        s_pressLatch[p] |= inRaceLocalPlayerInputBitset1[p];
        s_releaseLatch[p] |= inRaceLocalPlayerInputBitset2[p];
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

// One fixed-dt world-sim tick. resetOverlayDrawQueues first, or N ticks stack N copies of every
// minimap dot. The frame timer emits the fixed dt via FastMode; its per-tick frametotal bump is
// undone so all ticks share one frame number.
void runWorldSimTick(bool firstTick) {
    ((void_fn_t) resetOverlayDrawQueues_ADDR)();
    ((void_fn_t) swrRace_IncrementFrameTimer_ADDR)();
    frametotal = s_frametotalThisFrame;
    float* btn = procButtons();
    for (int p = 0; p < kNumLocalInputSlots; p++) {
        inRaceLocalPlayerInputBitset1[p] = firstTick ? s_pressLatch[p] : 0;
        inRaceLocalPlayerInputBitset2[p] = firstTick ? s_releaseLatch[p] : 0;
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
// swrObjJdge_F0's state machine (flag & 0xf): countdown and racing are the only states the world
// sim should tick in. swrRace_resultsScreenActive stays set through the quit transition into the
// menus (the stale currentPlayer_Test survives it too), so it can't gate on its own.
constexpr int kJdgeStateMask = 0xf;
constexpr int kJdgeStateCountdown = 0;
constexpr int kJdgeStateRacing = 1;

bool race_is_running() {
    const int count = swrEvent_GetEventCount('Jdge');
    for (int i = 0; i < count; i++) {
        swrObjJdge *jdge = (swrObjJdge *) swrEvent_GetItem('Jdge', i);
        if (jdge == nullptr || (jdge->obj.flags & swrObj_FLAG_FREED) != 0)
            continue;
        const int state = jdge->flag & kJdgeStateMask;
        return state == kJdgeStateCountdown || state == kJdgeStateRacing;
    }
    return false;
}
}// namespace

void __cdecl swrMain_RunFrame_delta(short flags, short phase) {
    // Same "live driving" test as swrControl_UpdateForceFeedback, plus not paused / stopped, so
    // menus and post-race screens keep vanilla timing.
    const int paused = ((int_fn_t) GetPauseState_ADDR)();
    const int raceSimActive = swrRace_resultsScreenActive;
    const bool haveLocal = currentPlayer_Test != nullptr;
    const bool driving =
        haveLocal && (currentPlayer_Test->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0;

    const bool engage = swr_fixedTimestep && driving && paused == 0 && swrGui_Stopped == 0 &&
                        raceSimActive != 0 && race_is_running();

    if (!engage) {
        endRngSplit();
        reset_fixed_step_state();
        hook_call_original((swrMain_RunFrame_t) swrMain_RunFrame_ADDR, flags, phase);
        return;
    }

    if (phase == 0 || phase == 1) {
        const float hz = swr_fixedTimestepHz > 1.0f ? swr_fixedTimestepHz : 1.0f;
        const double dt0 = 1.0 / (double) hz;

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

        // frametotal advances once per TICK frame and holds: it must not move on a tickless frame
        // (the looping voice ages out) nor per tick (the stamp stops matching phase-2's value).
        const bool willTick = s_accum >= dt0;
        s_frametotalThisFrame = willTick ? frametotal + 1 : frametotal;
        frametotal = s_frametotalThisFrame;

        if (!swr_fixedTimestepSplitRng)
            endRngSplit();
        beginRngSplit();

        runFrameOncePrologue();

        // Vanilla re-reads the pause state after PollPause: the frame pause is pressed runs the
        // pause menu instead of the world sim. Next frame the gate fails and vanilla takes over.
        if (((int_fn_t) GetPauseState_ADDR)() != 0) {
            ((void_fn_t) updatePauseMenu_ADDR)();
            ((void_fn_t) swrViewport_UpdateCameras_ADDR)();
            swr_systemTimeMs = timeGetTime();
            reset_fixed_step_state();
            if (phase == 0)
                hook_call_original((swrMain_RunFrame_t) swrMain_RunFrame_ADDR, flags, (short) 2);
            return;
        }

        // Under swr_FastMode, swrRace_IncrementFrameTimer sets deltaTimeSecs = swr_fixedDeltaTimeSecs
        // but does NOT touch swrRace_dt_raw_d, the unclamped delta the race/lap clock accumulates
        // (swrObjJdge_F2) -- so that has to be pinned too or the clock counts at hz/render_fps.
        const int savedFastMode = swr_FastMode;
        const double savedFixedDt = swr_fixedDeltaTimeSecs;
        const double savedRawDt = swrRace_dt_raw_d;
        swr_FastMode = 1;
        swr_fixedDeltaTimeSecs = dt0;
        swrRace_dt_raw_d = dt0;

        const int cosRand = swrUtils_randState;
        const int physRandBefore = s_rngSplit ? s_physRandState : swrUtils_randState;
        swrUtils_randState = physRandBefore;

        int steps = 0;
        while (s_accum >= dt0 && steps < kMaxSubSteps) {
            runWorldSimTick(steps == 0);
            s_accum -= dt0;
            steps++;
        }
        if (s_accum >= dt0)
            s_accum = 0.0;// give up catching up after a long stall

        const int physRandAfter = swrUtils_randState;
        swr_fixedTimestep_physRandState = physRandAfter;
        swr_fixedTimestep_ticks += (unsigned int) steps;
        if (steps > 0)
            swr_fixedTimestep_physDrawsLastFrame = countRandDraws(physRandBefore, physRandAfter);
        if (s_rngSplit) {
            s_physRandState = physRandAfter;
            swrUtils_randState = cosRand;
            swr_fixedTimestep_cosDrawsLastFrame = countRandDraws(s_cosRandAfterTicks, cosRand);
            s_cosRandAfterTicks = cosRand;
        } else {
            swr_fixedTimestep_cosDrawsLastFrame = 0;
        }

        swr_FastMode = savedFastMode;
        swr_fixedDeltaTimeSecs = savedFixedDt;
        swrRace_dt_raw_d = savedRawDt;
        // FastMode never advances swr_systemTimeMs; resync it or the first vanilla frame after
        // disengaging (respawn, toggle off) sees the whole engaged span as one unclamped dt_raw_d.
        swr_systemTimeMs = timeGetTime();
        swr_fixedTimestep_lastSteps = steps;

        // Restore the true input sampled this frame, so next frame's edge detection does not diff
        // against the latch. No-op on a tickless frame.
        if (s_haveTrueHeld) {
            float* btn = procButtons();
            for (int p = 0; p < kNumLocalInputSlots; p++)
                inRaceLocalPlayerInputBitset3[p] = s_trueHeld[p];
            for (int i = 0; i < kNumProcButtons; i++)
                btn[i] = s_btnTrue[i];
        }

        if (steps > 0) {
            for (int p = 0; p < kNumLocalInputSlots; p++) {
                s_pressLatch[p] = 0;
                s_releaseLatch[p] = 0;
                s_heldLatch[p] = 0;
            }
            for (int i = 0; i < kNumProcButtons; i++)
                s_btnLatch[i] = 0.0f;
            s_savedMiniMapPositions = numMiniMapPositions;
            s_savedTextEntries1Count = swrTextEntries1Count;
            s_savedTextEntries2Count = swrTextEntries2Count;
        } else {
            // Render outran the sim: the backing arrays still hold the last tick's dots/text, so
            // restoring the counts makes phase-2 redraw them.
            numMiniMapPositions = s_savedMiniMapPositions;
            swrTextEntries1Count = s_savedTextEntries1Count;
            swrTextEntries2Count = s_savedTextEntries2Count;
        }

        ((void_fn_t) swrViewport_UpdateCameras_ADDR)();
    }

    if (phase == 0 || phase == 2) {
        hook_call_original((swrMain_RunFrame_t) swrMain_RunFrame_ADDR, flags, (short) 2);
    }
}
