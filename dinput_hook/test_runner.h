#pragma once

// Unattended scenario runner for automated testing (scripts/run_tests.py). Armed only when
// swr_test_plan.ini exists in the game directory; it is renamed on arm so a crash never leaves a
// normal launch armed. Races each planned track with the local pod on autopilot, logs each race
// to swr_test_results.jsonl, then shuts the game down.

#ifdef __cplusplus
extern "C" {
#endif

// Read the plan. Call once, before the hooks are registered.
void test_runner_Init(void);

// Register the race-end and autopilot detours. Call before init_hooks().
void test_runner_RegisterHooks(void);

// Per-frame service on the game thread, outside the ImGui frame.
void test_runner_Service(void);

// Non-zero while a plan is running: cinematics skip and focus loss doesn't pause the game.
int test_runner_Active(void);

#ifdef __cplusplus
}
#endif
