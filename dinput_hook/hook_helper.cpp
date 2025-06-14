//
// Created by tly on 02.03.2024.
//

#include "hook_helper.h"
#include <iterator>
#include <vector>
#include <filesystem>
#include <map>
#include <optional>
#include <regex>
#include <cassert>

#include <detours.h>

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

    DWORD oldProtect;
    VirtualProtect((LPVOID) address, sizeof(void *), PAGE_EXECUTE_READWRITE, &oldProtect);
    *((uint32_t *) address) = uint32_t(newAddress);
    VirtualProtect((LPVOID) address, sizeof(void *), oldProtect, &oldProtect);
}

extern "C" void init_hooks() {
    fprintf(hook_log, "[init_hooks]\n");

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
            std::swap(info.address, info.original_address);
            info.hook_state = info.original_address;
            info.address = replacement;
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
