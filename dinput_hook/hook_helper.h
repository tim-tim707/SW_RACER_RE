//
// Created by tly on 02.03.2024.
//

#pragma once
#include <string>
#include <filesystem>
#include <map>

#include <windows.h>

#include <detours.h>

struct DebugFunctionInfo
{
    std::string name;
    void* address;
    void* original_address;
    void* hook_state;
};

extern std::map<void*, void*> hook_replacements;
extern std::map<void*, DebugFunctionInfo> hooks;

void init_hooks();

auto hook_call_original(auto* func, auto... args)
{
    if (!hooks.contains((void*)func))
        std::abort();

    auto& info = hooks.at((void*)func);
    return ((decltype(func))info.hook_state)(args...);
}

void hook_replace(auto* func, auto* hook_func)
{
    hook_replacements[(void*)func] = (void*)hook_func;
}