//
// Mod module registry (modding API, issue #153): a feature as a unit that can be enabled and
// disabled at runtime. A mod's `name` is its journal owner (patch.h), so disable_mod() reverts
// every write the mod tagged with mod_owner(self) via UndoOwner - the author writes only enable().
// Mods without journal entries (runtime-gated hooks) flip their gate in enable()/on_disable().
//
// enable_mod: depends_on all enabled -> enable() -> on false, UndoOwner + report.
// disable_mod: UndoOwner(name) -> on_disable(). Both idempotent, logged to hook.log.
//
#pragma once

#include "patch.h"

typedef int ModId;
#define MOD_ID_INVALID (-1)

typedef struct ModModule {
    // Unique stable id; also the journal owner of the mod's memory writes.
    const char *name;
    const char *version;
    // NULL-terminated names of mods that must be enabled first; may be NULL.
    const char *const *depends_on;
    // Mod-instance state, handed back to the callbacks.
    void *user;
    // Apply the mod. Return false to abort: the journal writes made so far are reverted.
    bool (*enable)(ModId self, void *user);
    // Optional: tear down what the journal cannot revert (GL objects, handles).
    void (*on_disable)(void *user);
} ModModule;

// Register a mod. The registry keeps the pointer, so pass a static ModModule. Returns
// MOD_ID_INVALID (and logs) for a malformed module or a duplicate name.
ModId register_mod(const ModModule *mod);

ModId find_mod(const char *name);
const ModModule *mod_info(ModId id);// NULL for an invalid id
int mod_count(void);
PatchOwner mod_owner(ModId id);// the owner tag for this mod's WriteMemory/PatchPointer calls

bool enable_mod(ModId id);
void disable_mod(ModId id);
// enable_mod / disable_mod by flag; returns the resulting state.
bool set_mod_enabled(ModId id, bool on);
bool mod_enabled(ModId id);
