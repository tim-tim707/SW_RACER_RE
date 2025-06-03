//
// Created by tly on 02.03.2024.
//

#pragma once
#include <string>
#include <filesystem>
#include <map>

#include <windows.h>

#include <detours.h>

#ifndef SWR_TEXT_ADDR_
#define SWR_TEXT_ADDR_ 0x00401000
#endif
#ifndef SWR_TEXT_END_ADDR_
#define SWR_TEXT_END_ADDR_ 0x004AB7FF
#endif

struct DebugFunctionInfo {
    std::string name;
    void *address;
    void *original_address;
    void *hook_state;
};

extern "C" FILE *hook_log;

extern std::map<void *, void *> hook_replacements;
extern std::map<void *, DebugFunctionInfo> hooks;

extern "C" void init_hooks();
extern "C" void patchMemoryAccess(uint32_t address, void *newAddress);

auto hook_call_original(auto *func, auto... args) {
    if (!hooks.contains((void *) func)) {
        fprintf(hook_log, "original function is not contained in hooked functions. Aborting\n");
        fflush(hook_log);
        std::abort();
    }

    auto &info = hooks.at((void *) func);
    return ((decltype(func)) info.hook_state)(args...);
}

void hook_replace(auto *func, auto *hook_func) {
    hook_replacements[(void *) func] = (void *) hook_func;
}
