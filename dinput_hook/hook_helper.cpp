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

#define PACKAGE
#define PACKAGE_VERSION
#include <bfd.h>

extern "C"
{
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
}
#include <detours.h>

extern "C" FILE* hook_log;

namespace fs = std::filesystem;

const fs::path source_directory = fs::path(__FILE__).parent_path().parent_path() / "src";

std::optional<fs::path> path_in_source_directory(const fs::path& file)
{
    const auto [it_file, it_dir] = std::mismatch(file.begin(), file.end(), source_directory.begin(), source_directory.end());
    if (it_dir != source_directory.end())
        return std::nullopt;

    fs::path relative_path;
    for (auto it = it_file; it != file.end(); it++)
        relative_path /= *it;

    return relative_path;
}

std::string read_file(const fs::path& file, int64_t max_size = INT64_MAX)
{
    std::string file_ = file.generic_string();
    FILE* f = fopen(file_.c_str(), "rb");
    if (fseek(f, 0, SEEK_END) != 0)
        std::abort();

    int64_t l = ftell(f);
    if (l == -1)
        std::abort();

    std::string content(std::min(l, max_size), '\0');

    if (fseek(f, 0, SEEK_SET) != 0)
        std::abort();

    if (fread(content.data(), 1, content.size(), f) != content.size())
        std::abort();

    fclose(f);

    return content;
}

struct DebugFunctionInfo
{
    std::string name;
    fs::path file_in_source_dir;
    int line;
    void* address;
    void* original_address_in_executable;
    void* hook_state;
};

struct CurrentModuleInfo
{
    HMODULE mod;
    MODULEINFO info;
    std::string filename;
};

CurrentModuleInfo find_current_module()
{
    HMODULE current_module = nullptr;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)find_current_module, &current_module);
    if (!current_module)
        std::abort();

    const auto actual_image_base = (uint64_t)current_module;

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), current_module, &info, sizeof(info)))
        std::abort();

    char filename[1024];
    GetModuleFileNameA(current_module, std::data(filename), std::size(filename));

    fprintf(hook_log, "module info: name=%s actual_image_base=%p\n", filename, (const void*)actual_image_base);
    fflush(hook_log);

    return {
        current_module,
        info,
        filename,
    };
}

std::vector<DebugFunctionInfo> find_debug_function_infos()
{
    fprintf(hook_log, "[find_debug_function_infos]\n");
    fflush(hook_log);

    const auto mod_info = find_current_module();

    bfd_init();

    auto handle = bfd_openr(mod_info.filename.c_str(), nullptr);
    if (!handle)
        std::abort();

    // handle->flags |= BFD_DECOMPRESS;

    fprintf(hook_log, "[find_debug_function_infos] bfd handle open.\n");
    fflush(hook_log);

    if (!bfd_check_format(handle, bfd_object) || !bfd_check_format_matches(handle, bfd_object, nullptr))
        std::abort();

    if ((bfd_get_file_flags(handle) & HAS_SYMS) == 0)
        std::abort();

    ssize_t symtab_storage_size = bfd_get_symtab_upper_bound(handle);

    fprintf(hook_log, "[find_debug_function_infos] symtab_storage_size: %d\n", symtab_storage_size);
    fflush(hook_log);

    std::vector<asymbol*> symbols;
    symbols.resize(symtab_storage_size / sizeof(asymbol*));
    ssize_t symcount = bfd_canonicalize_symtab(handle, symbols.data());
    symbols.resize(symcount);

    // find image base symbol
    std::optional<std::int64_t> image_base;
    for (const auto& sym : symbols)
    {
        if (sym->name == std::string_view("___ImageBase"))
        {
            image_base = sym->value;
            fprintf(hook_log, "[find_debug_function_infos] found ImageBase: %llx\n", *image_base);
            fflush(hook_log);
            break;
        }
    }

    if (!image_base)
    {
        fprintf(hook_log, "[find_debug_function_infos] error: ImageBase not found.\n");
        fflush(hook_log);
        std::abort();
    }

    std::vector<DebugFunctionInfo> infos;
    for (const auto& sym : symbols)
    {
        //fprintf(hook_log, "    %s %llx\n", sym->name, sym->value);
        //fflush(hook_log);

        if ((sym->flags & BSF_FUNCTION) == 0)
            continue;

        const char* file = nullptr;
        const char* function = nullptr;
        unsigned int line = 0;
        if (!bfd_find_nearest_line(handle, bfd_asymbol_section(sym), symbols.data(), sym->value, &file, &function, &line))
            continue;

        const auto path_in_source = path_in_source_directory(file);
        if (!path_in_source)
            continue;

        fprintf(hook_log, "    %s:%d: %s %s %llx\n", path_in_source->generic_string().c_str(), line, sym->name, function, sym->value);
        fflush(hook_log);

        if (function != std::string_view(sym->name).substr(1))
            std::abort();

        infos.emplace_back(DebugFunctionInfo{ function, *path_in_source, int(line), (uint8_t*)mod_info.info.lpBaseOfDll + (bfd_asymbol_section(sym)->vma + sym->value - *image_base) });
    }

    bfd_close(handle);

    return infos;
}

struct SourceFile
{
    std::string content;
    std::vector<int64_t> line_offsets;
};

SourceFile read_source_file(const fs::path& file)
{
    SourceFile s;
    s.content = read_file(file);

    std::string::size_type pos = 0;
    while (true)
    {
        s.line_offsets.push_back(pos);
        pos = s.content.find('\n', pos);
        if (pos == std::string::npos)
            break;

        pos++;
    }
    s.line_offsets.push_back(s.content.size());

    return s;
}

void hook_function(uint8_t* hook_addr, uint8_t* hook_dst)
{
    DWORD oldProtect;
    VirtualProtect(hook_addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    uint8_t* rel_addr = hook_dst - (uint32_t)hook_addr - 5;
    hook_addr[0] = 0xe9; // jmp rel32
    hook_addr += 1;
    ((uint32_t*)hook_addr)[0] = (uint32_t)rel_addr;

    VirtualProtect(hook_addr, 5, oldProtect, &oldProtect);
}

void hook_all_functions()
{
    fprintf(hook_log, "[find_debug_function_infos]\n");

    auto funcs = find_debug_function_infos();
    fprintf(hook_log, "[find_debug_function_infos]: found %zu potentially hookable functions.\n", funcs.size());
    fflush(hook_log);

    const static std::regex address_line_regex(R"(\/\/\s+(0x[0-9a-fA-F]+)(\s|.)*)");

    const auto mod_info = find_current_module();

    // open all source files that are needed
    int num_replaced_functions = 0;
    std::map<fs::path, SourceFile> source_file_content;
    std::map<uint64_t, DebugFunctionInfo> hooks;
    for (auto& func : funcs)
    {
        auto it = source_file_content.find(func.file_in_source_dir);
        if (it == source_file_content.end())
            it = source_file_content.emplace(func.file_in_source_dir, read_source_file(source_directory / func.file_in_source_dir)).first;

        const auto& source = it->second;

        bool hook_original = false;
        std::optional<uint64_t> address;
        int i = func.line - 1;
        for (; i >= 0 && i > (func.line - 6); i--)
        {
            const std::string line = source.content.substr(source.line_offsets.at(i), source.line_offsets.at(i + 1) - source.line_offsets.at(i));
            std::smatch match;
            if (std::regex_match(line, match, address_line_regex))
            {
                address = std::stoull(match[1].str(), nullptr, 16);
                hook_original = line.find("HOOK") != std::string::npos;
                break;
            }
        }
        if (!address)
        {
            fprintf(hook_log, "ERROR: iterate_over_symbols did not find address comment for function %s in file %s\n", func.name.c_str(), func.file_in_source_dir.generic_string().c_str());
            fflush(hook_log);
            std::abort();
        }

        if (hooks.contains(*address))
        {
            fprintf(hook_log, "ERROR: hook address clash for function %s in file %s: this address is already assigned to %s.\n", func.name.c_str(), func.file_in_source_dir.generic_string().c_str(), hooks.at(*address).name.c_str());
            fflush(hook_log);
            std::abort();
        }
        auto& info = hooks.emplace(*address, std::move(func)).first->second;
        info.original_address_in_executable = (void*)*address;

        /*if (hook_original)
        {


            hook_function((uint8_t*)info.original_address_in_executable, (uint8_t*)info.address);
        }*/

        fprintf(hook_log, "    hooking %s (address=%p original_address=%p)", info.name.c_str(), info.address, info.original_address_in_executable);
        fflush(hook_log);

        DetourTransactionBegin();

        int err = 0;
        if (hook_original)
        {
            info.hook_state = info.original_address_in_executable;
            err = DetourAttach(&info.hook_state, info.address);
            num_replaced_functions += err == 0;
        }
        else
        {
            info.hook_state = info.address;
            err = DetourAttach(&info.hook_state, info.original_address_in_executable);
        }
        if (err)
        {
            fprintf(hook_log, " FAILED. err %d\n", err);
            fflush(hook_log);
            std::abort();
        }
        else
        {
            fprintf(hook_log, " succeeded.\n");
            fflush(hook_log);
            DetourTransactionCommit();
        }
    }

    fprintf(hook_log, "[hook_all_functions] %d/%zu functions replace the original functions, that is %.2f%%.\n", num_replaced_functions, funcs.size(), double(num_replaced_functions) / funcs.size() * 100);
    fflush(hook_log);
}