//
// Created by tly on 02.03.2024.
//

#include "hook_helper.h"
#include "patch.h"
#include "lockstep.h"
#include <iterator>
#include <vector>
#include <filesystem>
#include <map>
#include <optional>
#include <regex>
#include <cassert>

#include <detours.h>

extern "C" {
#include <hook_mode.h>
}

extern "C" FILE *hook_log;

std::map<void *, DebugFunctionInfo> hooks;
std::map<void *, void *> hook_replacements;

extern "C" void hook_generated(FILE *hook_log);

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address) {
    hooks[(void *) original_address] = DebugFunctionInfo{
        .name = function_name,
        .address = hook_address,
        .original_address = (void *) original_address,
        .hook_state = (void *) original_address,
    };
}

extern "C" void patchMemoryAccess(uint32_t address, void *newAddress) {
    assert(address >= SWR_TEXT_ADDR_);
    assert(address < SWR_TEXT_END_ADDR_);

    // Journaled (owner-tracked, revertible) form of the old raw VirtualProtect+poke.
    PatchPointer("patchMemoryAccess", (void *) address, (uint32_t) newAddress);
}

// Detours moves the stock entry to the delta, but our src body of that function would still run for
// any caller that names the symbol (a live reimpl, or delta code). Send those to the delta too, so
// every caller reaches the same code as retail's callers do.
static void route_reimpl_to(void *reimpl, void *delta) {
    uint8_t jmp[5] = {0xE9};
    const int32_t rel = (int32_t) ((uintptr_t) delta - ((uintptr_t) reimpl + sizeof(jmp)));
    memcpy(&jmp[1], &rel, sizeof(rel));
    if (memcmp(reimpl, jmp, sizeof(jmp)) != 0)
        WriteMemory("hook_replace_route", reimpl, jmp, sizeof(jmp));
}

static int delta_owned(uint32_t reimpl_addr) {
    return hook_replacements.contains((void *) reimpl_addr);
}

extern "C" void init_hooks() {
    fprintf(hook_log, "[init_hooks]\n");

    lockstep_vanilla_filter();
    hook_mode_delta_owned = delta_owned;
    hook_generated(hook_log);

    fprintf(hook_log, "[init_hooks]: found %zu hooked functions.\n", hooks.size());
    fflush(hook_log);

    for (auto &[address, info]: hooks) {
        if (hook_replacements.contains(info.address)) {
            auto &replacement = hook_replacements.at(info.address);
            info.address = replacement;
        }
        if (hook_replacements.contains(info.original_address)) {
            auto &replacement = hook_replacements.at(info.original_address);
            void *reimpl = info.original_address;
            std::swap(info.address, info.original_address);
            info.hook_state = info.original_address;
            info.address = replacement;
            route_reimpl_to(reimpl, replacement);
        }

        fprintf(hook_log, "    hooking %s (address=%p original_address=%p)", info.name.c_str(),
                info.address, info.original_address);
        fflush(hook_log);

        DetourTransactionBegin();
        int err = DetourAttach(&info.hook_state, info.address);
        if (err) {
            if (err == ERROR_INVALID_BLOCK) {
                fprintf(hook_log,
                        "\nWarning, function is too small to be hooked, ignored instead\n");
                fflush(hook_log);
                DetourTransactionCommit();
            } else {
                fprintf(hook_log, " FAILED. err %d\n", err);
                fflush(hook_log);
                std::abort();
            }
        } else {
            fprintf(hook_log, " succeeded.\n");
            fflush(hook_log);
            DetourTransactionCommit();
        }
    }
}
