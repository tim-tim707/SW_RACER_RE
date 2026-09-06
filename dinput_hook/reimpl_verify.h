#ifndef REIMPL_VERIFY_H
#define REIMPL_VERIFY_H

#include <stdio.h>

// Differential self-test for reimplemented functions: run our body and the retail body over the
// same inputs and compare. Only possible under HOOK_MODE_BOTH, where neither is redirected -- any
// other mode leaves one of the two unreachable, so those cases are skipped and reported as such.
//
// Enabled by a bare `verify` line in reimpl_config.txt. Results land in reimpl_verify.log next to
// the game, with a one-line summary in hook.log.
//
// Cannot run from init_hooks(): several retail math helpers open with `FLDCW [0x00ec8c8x]`, loading
// the x87 control word from globals the game fills in during startup, so called that early they
// install garbage and the next FP instruction faults. Driven from the first rendered frame.
#ifdef __cplusplus
extern "C" {
#endif

// Prefer reimpl_verify_tick() unless you know the game is up.
void reimpl_verify_run(FILE *hook_log);

// Call once per frame. Runs the suite on the first call and does nothing afterwards.
void reimpl_verify_tick(FILE *hook_log);

#ifdef __cplusplus
}
#endif

#endif// REIMPL_VERIFY_H
