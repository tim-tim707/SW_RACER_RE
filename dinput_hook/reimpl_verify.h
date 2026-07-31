#ifndef REIMPL_VERIFY_H
#define REIMPL_VERIFY_H

#include <stdio.h>

// Differential self-test for reimplemented functions.
//
// A reimplementation and its retail counterpart are two implementations of the same
// contract, so the cheapest proof of equivalence is to run both over the same inputs
// and compare. That is only possible for functions configured HOOK_MODE_BOTH, where
// neither body has been redirected -- every other mode leaves exactly one of the two
// reachable. Cases whose function is not in that mode are skipped and reported as
// such, because comparing retail against itself would report a meaningless pass.
//
// Enabled by a bare `verify` line in reimpl_config.txt. Results land in
// reimpl_verify.log next to the game, with a one-line summary in hook.log.
//
// Timing matters. This cannot run from init_hooks(): several retail math helpers open
// with `FLDCW [0x00ec8c8x]`, loading the x87 control word from globals the game fills
// in during startup. Called that early they install a garbage control word and the
// next floating-point instruction faults. So the run is driven from the first rendered
// frame instead, by which point the CRT and the game's own init have both completed.
#ifdef __cplusplus
extern "C" {
#endif

// Run every case now. Prefer reimpl_verify_tick() unless you know the game is up.
void reimpl_verify_run(FILE *hook_log);

// Call once per frame. Runs the suite on the first call and does nothing afterwards.
void reimpl_verify_tick(FILE *hook_log);

#ifdef __cplusplus
}
#endif

#endif// REIMPL_VERIFY_H
