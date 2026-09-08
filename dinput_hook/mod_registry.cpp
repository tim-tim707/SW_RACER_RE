//
// Mod module registry (modding API, issue #153). See mod_registry.h.
//
#include "mod_registry.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" FILE *hook_log;

namespace {
    struct ModEntry {
        const ModModule *mod;
        bool enabled;
    };

    std::vector<ModEntry> g_mods;

    void log(const char *fmt, ...) {
        if (!hook_log)
            return;
        va_list args;
        va_start(args, fmt);
        vfprintf(hook_log, fmt, args);
        va_end(args);
        fflush(hook_log);
    }

    bool valid(ModId id) {
        return id >= 0 && (size_t) id < g_mods.size();
    }
}// namespace

ModId register_mod(const ModModule *mod) {
    if (!mod || !mod->name || !mod->name[0] || !mod->enable) {
        log("[mods] refused to register a malformed module\n");
        return MOD_ID_INVALID;
    }
    if (find_mod(mod->name) != MOD_ID_INVALID) {
        log("[mods] refused duplicate registration of '%s'\n", mod->name);
        return MOD_ID_INVALID;
    }
    g_mods.push_back(ModEntry{mod, false});
    return (ModId) (g_mods.size() - 1);
}

ModId find_mod(const char *name) {
    if (!name)
        return MOD_ID_INVALID;
    for (size_t i = 0; i < g_mods.size(); i++) {
        if (std::strcmp(g_mods[i].mod->name, name) == 0)
            return (ModId) i;
    }
    return MOD_ID_INVALID;
}

const ModModule *mod_info(ModId id) {
    return valid(id) ? g_mods[id].mod : nullptr;
}

int mod_count(void) {
    return (int) g_mods.size();
}

PatchOwner mod_owner(ModId id) {
    return valid(id) ? g_mods[id].mod->name : nullptr;
}

bool enable_mod(ModId id) {
    if (!valid(id))
        return false;
    ModEntry &e = g_mods[id];
    if (e.enabled)
        return true;

    if (e.mod->depends_on) {
        for (const char *const *req = e.mod->depends_on; *req; req++) {
            const ModId dep = find_mod(*req);
            if (dep == MOD_ID_INVALID || !g_mods[dep].enabled) {
                log("[mods] '%s' not enabled: requires '%s', which is not enabled\n", e.mod->name,
                    *req);
                return false;
            }
        }
    }

    if (!e.mod->enable(id, e.mod->user)) {
        // Whatever the mod journaled before bailing is reverted, so a failed enable leaves stock.
        UndoOwner(e.mod->name);
        log("[mods] '%s' failed to enable (reverted)\n", e.mod->name);
        return false;
    }
    e.enabled = true;
    log("[mods] enabled '%s' %s\n", e.mod->name, e.mod->version ? e.mod->version : "");
    return true;
}

void disable_mod(ModId id) {
    if (!valid(id))
        return;
    ModEntry &e = g_mods[id];
    if (!e.enabled)
        return;

    UndoOwner(e.mod->name);
    if (e.mod->on_disable)
        e.mod->on_disable(e.mod->user);
    e.enabled = false;
    log("[mods] disabled '%s'\n", e.mod->name);
}

bool set_mod_enabled(ModId id, bool on) {
    if (on)
        return enable_mod(id);
    disable_mod(id);
    return false;
}

bool mod_enabled(ModId id) {
    return valid(id) && g_mods[id].enabled;
}
