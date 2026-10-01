#pragma once

// ASan can't see the game's allocators (asset-buffer bump arena, daAlloc pages), so these hooks
// poison what the game releases: instrumented reads through stale pointers then report.
// No-ops unless ENABLE_ASAN.

#ifdef __cplusplus
extern "C" {
#endif

// Point the ASan report at crashes\asan.<pid> and log that the build is instrumented.
void memsafety_Init(void);

// Register the daAlloc / daFree / asset-buffer poisoning detours. Call before init_hooks().
void memsafety_RegisterHooks(void);

#ifdef __cplusplus
}
#endif
