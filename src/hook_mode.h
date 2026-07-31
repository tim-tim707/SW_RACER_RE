#ifndef HOOK_MODE_H
#define HOOK_MODE_H

#include <stdio.h>
#include <stdint.h>

// Which body actually runs for a reimplemented function.
//
// Every reimplementation is one half of a pair: our compiled body in src/, and the
// retail body in SWEP1RCR.EXE. A single redirect decides which one the game reaches,
// and the direction it points is what these modes select. GenerateHooks.py emits one
// hook_install() call per reimplementation; this is what that call consults.
typedef enum hook_mode
{
    // Redirect OUR body to retail. The reimplementation is dormant: it compiles and
    // links but never executes. This is the default and the shipped behaviour --
    // reimplementations stay reference material until proven equivalent.
    HOOK_MODE_ORIGINAL = 0,
    // Redirect RETAIL to our body. The reimplementation takes over, so every call
    // site in the game reaches our code. Callees left at HOOK_MODE_ORIGINAL still
    // resolve to their retail bodies, so one function can be brought live in
    // isolation against otherwise-untouched surroundings.
    HOOK_MODE_REIMPL = 1,
    // Redirect neither, leaving both bodies intact and independently callable. The
    // game keeps running retail code; a harness can call our symbol directly and
    // reach retail through hook_retail_ptr(), and compare the two.
    HOOK_MODE_BOTH = 2,
} hook_mode;

// Read from the working directory (next to SWEP1RCR.EXE) at first use. Absent file
// means every reimplementation stays dormant, i.e. exactly the shipped behaviour.
#define HOOK_MODE_CONFIG_FILE "reimpl_config.txt"

// Translate a preferred-base retail address (0x004xxxxx) into a live pointer.
uint8_t* hook_retail_ptr(uint32_t retail_addr);

// Resolve the configured mode for one function name. Loads the config on first call.
hook_mode hook_mode_for(const char* function_name);

// Non-zero when the config contains a bare `verify` line, asking for the
// differential self-test to run once at startup.
int hook_verify_requested(void);

// Wire up one reimplementation according to its resolved mode. `force_reimpl` marks
// functions annotated `// 0xADDR HOOK` -- deltas the GL renderer depends on rather
// than equivalence candidates, so they go live regardless of configuration.
void hook_install(const char* function_name, uint32_t reimpl_addr, uint32_t retail_addr, int force_reimpl, FILE* hook_log);

// Log what hook_install() actually did across the whole table.
void hook_mode_log_summary(FILE* hook_log);

#endif // HOOK_MODE_H
