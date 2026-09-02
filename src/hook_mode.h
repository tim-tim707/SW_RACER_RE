#ifndef HOOK_MODE_H
#define HOOK_MODE_H

#include <stdio.h>
#include <stdint.h>

// Which body runs for a reimplemented function: our compiled body in src/, or the retail body in
// SWEP1RCR.EXE. One redirect decides, and its direction is what these modes select.
// GenerateHooks.py emits one hook_install() call per reimplementation.
typedef enum hook_mode
{
    // Redirect OUR body to retail: the reimplementation compiles and links but never executes.
    // The default and shipped behaviour.
    HOOK_MODE_ORIGINAL = 0,
    // Redirect RETAIL to our body. Callees left at HOOK_MODE_ORIGINAL still resolve to their
    // retail bodies, so one function can be brought live in isolation.
    HOOK_MODE_REIMPL = 1,
    // Redirect neither: the game keeps running retail, and a harness can call our symbol directly
    // and reach retail through hook_retail_ptr().
    HOOK_MODE_BOTH = 2,
} hook_mode;

// Read from the working directory at first use. An absent file leaves every reimplementation
// dormant, i.e. the shipped behaviour.
#define HOOK_MODE_CONFIG_FILE "reimpl_config.txt"

// Translate a preferred-base retail address (0x004xxxxx) into a live pointer.
uint8_t* hook_retail_ptr(uint32_t retail_addr);

// Resolve the configured mode for one function name. Loads the config on first call.
hook_mode hook_mode_for(const char* function_name);

// Non-zero when the config contains a bare `verify` line.
int hook_verify_requested(void);

// `force_reimpl` marks functions annotated `// 0xADDR HOOK` -- deltas the GL renderer depends on
// rather than equivalence candidates, so they go live regardless of configuration.
void hook_install(const char* function_name, uint32_t reimpl_addr, uint32_t retail_addr, int force_reimpl, FILE* hook_log);

// Log what hook_install() actually did across the whole table.
void hook_mode_log_summary(FILE* hook_log);

#endif // HOOK_MODE_H
