#include "shadow.h"

#include "hook_helper.h"
#include "lockstep.h"

#include <windows.h>

#include <detours.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include <hook_mode.h>
}

extern "C" FILE *hook_log;

// The harness's own state: kept out of the protected set (see build_regions).
#define SHADOW_STATE __attribute__((section(".shstate")))

namespace {

constexpr uint32_t kPage = 0x1000;
constexpr int kMaxFns = 4096;
constexpr int kStubSize = 16;
constexpr int kArgDwords = 16;
constexpr int kMaxPages = 4096;
constexpr int kTableSize = 8192;// power of two, > kMaxPages
constexpr size_t kMaxStackWindow = 256 * 1024;
constexpr int kDetailedPerFn = 3;
constexpr int kMaxDiffRuns = 24;
constexpr int kEntryBytes = 16;

// An entry Detours redirected. The bodies are called by putting the original bytes back for the
// duration of the call: a Detours trampoline breaks bodies that branch back into their first
// instructions (loops at the top of a function), and with the entry restored a nested call of the
// same function simply runs that body.
struct Entry {
    uint8_t orig[kEntryBytes];
    uint8_t patched[kEntryBytes];
    int len;// bytes the redirect changed
};

// Layout shared with the asm below: retail_orig must stay first.
struct ShadowFn {
    void *retail_orig;// Detours trampoline, only for calls from other threads
    bool ready;
    Entry retail_entry;
    Entry ours_entry;
    const char *name;
    uint32_t reimpl;
    uint32_t retail;
    hook_ret_kind ret;
    uint32_t calls;
    uint32_t compared;
    uint32_t mismatches;
    uint32_t warnings;
    uint32_t unreliable;
    uint32_t quirks;// differences matching a known retail quirk, not counted as mismatches
    int first_frame;
    bool disabled;
    uint32_t round;// budget mode: the last round this function was compared in
    uint32_t frame_stamp;// budget mode: g_frame of frame_calls
    uint32_t frame_calls;// budget mode: calls so far in frame_stamp
    uint32_t last_frame_calls;// budget mode: calls in the last frame it was called in
    int64_t ticks;// time spent comparing this function
    int64_t max_ticks;// slowest single comparison
};

// Layout shared with the asm below.
struct CallOut {
    uint32_t eax;
    uint32_t edx;
    uint32_t has_st0;// the call left one more value on the x87 stack than it found
    uint8_t st0[10];
    uint8_t pad[6];
    int32_t popped;
    uint8_t fpu[108];// FNSAVE image right after the call; retail's goes back to the caller
};
static_assert(offsetof(CallOut, st0) == 12 && offsetof(CallOut, popped) == 28 && offsetof(CallOut, fpu) == 32,
              "asm offsets");

struct PageEntry {
    uint32_t page;// 0 = empty slot
    uint16_t pool;// index into pre/post pools
    bool dirty_r;
    bool dirty_o;
    bool foreign;
};

struct Region {
    uint32_t lo;
    uint32_t hi;
};

SHADOW_STATE ShadowFn g_fns[kMaxFns];
SHADOW_STATE int g_fn_count = 0;
SHADOW_STATE uint8_t *g_stubs = nullptr;

SHADOW_STATE DWORD g_thread = 0;
SHADOW_STATE int g_depth = 0;
SHADOW_STATE volatile LONG g_heartbeat = 0;
SHADOW_STATE volatile int g_phase = 0;// 0 idle, 1 protecting, 2 retail run, 3 restore, 4 our run, 5 compare/keep
SHADOW_STATE volatile DWORD g_last_foreign_tid = 0, g_last_foreign_eip = 0, g_last_foreign_addr = 0;
SHADOW_STATE volatile const char *g_cur_name = "";
SHADOW_STATE volatile int g_window = 0;// 1 = retail run, 2 = our run
SHADOW_STATE volatile int g_protected = 0;// pages are read-only, from the first protect to the last unprotect
SHADOW_STATE bool g_overflow = false;
SHADOW_STATE int g_foreign = 0;
SHADOW_STATE volatile int g_foreign_waits = 0;
SHADOW_STATE bool g_regions_built = false;
SHADOW_STATE uint32_t g_limit = 0;
SHADOW_STATE uint32_t g_every = 1;
SHADOW_STATE bool g_anytime = false;
SHADOW_STATE bool g_trace = false;
// shadow_budget_ms: per-frame time budget for comparisons (live play). 0 = no budget.
SHADOW_STATE double g_budget_ms = 0.0;
SHADOW_STATE int64_t g_budget_ticks = 0;
SHADOW_STATE int64_t g_frame_ticks = 0;// time spent comparing in the current frame
SHADOW_STATE int64_t g_max_frame_ticks = 0;
SHADOW_STATE uint32_t g_frame = 0;// own frame counter: every swrRace_IncrementFrameTimer
SHADOW_STATE uint32_t g_round = 1;
SHADOW_STATE bool g_frame_had_eligible = false;
SHADOW_STATE bool g_round_compared = false;// the current round compared something
SHADOW_STATE uint32_t g_rounds_done = 0;// rounds that compared something
SHADOW_STATE uint32_t g_over_budget_frames = 0;
SHADOW_STATE bool g_enabled = true;// Verification window: comparisons on/off (entries stay installed)
SHADOW_STATE bool g_allow_unsafe = false;// `shadow_unsafe`: skip the name denylist
// Recent mismatches for the Verification window; the first diff of each is captured here.
SHADOW_STATE ShadowMismatch g_recent[64];
SHADOW_STATE int g_recent_count = 0;// total ever recorded; slot = index % 64
SHADOW_STATE char *g_capture = nullptr;
SHADOW_STATE size_t g_capture_len = 0;
SHADOW_STATE uint32_t g_mismatch_total = 0;
SHADOW_STATE uint32_t g_quirk_total = 0;
SHADOW_STATE int64_t g_last_frame_ticks = 0;
SHADOW_STATE int g_from_frame = -1;// shadow_frames <from> [to]: compare only inside this frame range
SHADOW_STATE int g_to_frame = -1;
SHADOW_STATE bool g_heap_segments = true;
SHADOW_STATE bool g_heap_windows = false;// `shadow_heap_windows`: only 16 KB behind pointer args
SHADOW_STATE bool g_heap_lock = false;
SHADOW_STATE HANDLE g_heaps[64];
SHADOW_STATE DWORD g_heap_count = 0;
SHADOW_STATE int g_region_mode = 2;// 0 none, 1 image only, 2 image + heap
SHADOW_STATE bool g_vanilla_ok = true;

SHADOW_STATE std::vector<Region> g_regions;

SHADOW_STATE PageEntry g_table[kTableSize];
SHADOW_STATE uint32_t g_used[kMaxPages];// table slots in use, in order
SHADOW_STATE int g_used_count = 0;
SHADOW_STATE uint8_t *g_pre = nullptr;
SHADOW_STATE uint8_t *g_post = nullptr;
SHADOW_STATE uint8_t *g_ours = nullptr;
SHADOW_STATE uint8_t *g_stack_ours = nullptr;
SHADOW_STATE uint8_t *g_stack_pre = nullptr;
SHADOW_STATE uint8_t *g_stack_post = nullptr;
SHADOW_STATE uint8_t *g_pool_lo = nullptr;
SHADOW_STATE uint8_t *g_pool_hi = nullptr;

SHADOW_STATE CallOut g_result;
SHADOW_STATE FILE *g_log = nullptr;
SHADOW_STATE LARGE_INTEGER g_qpf;
SHADOW_STATE int64_t g_ticks = 0;
SHADOW_STATE uint64_t g_total_compared = 0;

void log_open() {
    if (!g_log)
        g_log = fopen("shadow.log", "w");
}

bool in_regions(uint32_t page) {
    auto it = std::upper_bound(g_regions.begin(), g_regions.end(), page,
                               [](uint32_t p, const Region &r) { return p < r.lo; });
    if (it == g_regions.begin())
        return false;
    --it;
    return page >= it->lo && page < it->hi;
}

PageEntry *table_find(uint32_t page, bool add) {
    uint32_t h = (page >> 12) * 2654435761u;
    for (int i = 0; i < kTableSize; i++) {
        PageEntry &e = g_table[(h + i) & (kTableSize - 1)];
        if (e.page == page)
            return &e;
        if (e.page == 0) {
            if (!add || g_used_count >= kMaxPages)
                return nullptr;
            e.page = page;
            e.pool = (uint16_t) g_used_count;
            e.dirty_r = e.dirty_o = e.foreign = false;
            g_used[g_used_count++] = (uint32_t) (&e - g_table);
            return &e;
        }
    }
    return nullptr;
}

void table_clear() {
    for (int i = 0; i < g_used_count; i++)
        g_table[g_used[i]].page = 0;
    g_used_count = 0;
}

// Runs made read-only by the last protect_all(PAGE_READONLY), so exactly those are opened again
// (memory can be freed or decommitted in between, and VirtualProtect fails a whole range then).
SHADOW_STATE Region g_locked[16384];
SHADOW_STATE int g_locked_count = 0;

// Layout cache: VirtualQuery walks cost more than the protects, so the last walk's writable runs are
// reused until memory is allocated/freed (hooked below), the map changes, or a protect fails.
SHADOW_STATE volatile LONG g_layout_gen = 1;
SHADOW_STATE bool g_layout_cache = true;// `shadow_no_layout_cache` turns it off
SHADOW_STATE LONG g_run_cache_gen = 0;
SHADOW_STATE uint32_t g_regions_ver = 0;// bumped by every rebuild_regions
SHADOW_STATE uint32_t g_run_cache_ver = 0;
SHADOW_STATE Region g_run_cache[16384];
SHADOW_STATE int g_run_cache_count = 0;

typedef LONG(NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG(NTAPI *NtFreeVirtualMemory_t)(HANDLE, PVOID *, PSIZE_T, ULONG);
SHADOW_STATE NtAllocateVirtualMemory_t g_real_nt_alloc = nullptr;
SHADOW_STATE NtFreeVirtualMemory_t g_real_nt_free = nullptr;

LONG NTAPI layout_nt_alloc(HANDLE p, PVOID *base, ULONG_PTR zero, PSIZE_T size, ULONG type, ULONG prot) {
    LONG st = g_real_nt_alloc(p, base, zero, size, type, prot);
    InterlockedIncrement(&g_layout_gen);
    return st;
}

LONG NTAPI layout_nt_free(HANDLE p, PVOID *base, PSIZE_T size, ULONG type) {
    LONG st = g_real_nt_free(p, base, size, type);
    InterlockedIncrement(&g_layout_gen);
    return st;
}

void hook_layout_changes() {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    g_real_nt_alloc = (NtAllocateVirtualMemory_t) GetProcAddress(nt, "NtAllocateVirtualMemory");
    g_real_nt_free = (NtFreeVirtualMemory_t) GetProcAddress(nt, "NtFreeVirtualMemory");
    if (!g_real_nt_alloc || !g_real_nt_free) {
        g_layout_cache = false;
        return;
    }
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID *) &g_real_nt_alloc, (PVOID) layout_nt_alloc);
    DetourAttach((PVOID *) &g_real_nt_free, (PVOID) layout_nt_free);
    if (DetourTransactionCommit() != NO_ERROR)
        g_layout_cache = false;
}

void protect_all(DWORD prot) {
    DWORD old;
    if (prot != PAGE_READWRITE) {
        g_protected = 1;
        g_locked_count = 0;
        const LONG gen = g_layout_gen;
        if (g_layout_cache && g_run_cache_count > 0 && gen == g_run_cache_gen && g_regions_ver == g_run_cache_ver) {
            bool ok = true;
            for (int i = 0; i < g_run_cache_count && ok; i++) {
                if (VirtualProtect((void *) g_run_cache[i].lo, g_run_cache[i].hi - g_run_cache[i].lo, prot, &old))
                    g_locked[g_locked_count++] = g_run_cache[i];
                else
                    ok = false;
            }
            if (ok && gen == g_layout_gen)
                return;
            for (int i = 0; i < g_locked_count; i++)
                VirtualProtect((void *) g_locked[i].lo, g_locked[i].hi - g_locked[i].lo, PAGE_READWRITE, &old);
            g_locked_count = 0;
        }
        for (const Region &r: g_regions) {
            MEMORY_BASIC_INFORMATION mbi;
            uint32_t a = r.lo;
            while (a < r.hi && VirtualQuery((void *) a, &mbi, sizeof(mbi))) {
                uint32_t end = std::min(r.hi, (uint32_t) mbi.BaseAddress + (uint32_t) mbi.RegionSize);
                bool writable = mbi.State == MEM_COMMIT &&
                                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY);
                if (writable && g_locked_count < (int) (sizeof(g_locked) / sizeof(g_locked[0])) &&
                    VirtualProtect((void *) a, end - a, prot, &old))
                    g_locked[g_locked_count++] = {a, end};
                a = end;
            }
        }
        memcpy(g_run_cache, g_locked, sizeof(Region) * (size_t) g_locked_count);
        g_run_cache_count = g_locked_count;
        g_run_cache_gen = gen;
        g_run_cache_ver = g_regions_ver;
        return;
    }
    for (int i = 0; i < g_locked_count; i++)
        VirtualProtect((void *) g_locked[i].lo, g_locked[i].hi - g_locked[i].lo, PAGE_READWRITE, &old);
    g_locked_count = 0;
    g_protected = 0;
}

LONG CALLBACK shadow_veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || er->NumberParameters < 2 ||
        er->ExceptionInformation[0] != 1)
        return EXCEPTION_CONTINUE_SEARCH;
    uint32_t page = (uint32_t) er->ExceptionInformation[1] & ~(kPage - 1);
    if (!g_protected) {
        // Outside a comparison: a page of ours left read-only by accident is opened, not crashed on.
        MEMORY_BASIC_INFORMATION q;
        DWORD o;
        if (g_regions_built && in_regions(page) && VirtualQuery((void *) page, &q, sizeof(q)) &&
            q.State == MEM_COMMIT && q.Protect == PAGE_READONLY &&
            VirtualProtect((void *) page, kPage, PAGE_READWRITE, &o))
            return EXCEPTION_CONTINUE_EXECUTION;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (!in_regions(page))
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD old;
    if (GetCurrentThreadId() != g_thread) {
        // Another thread: hold it until the comparison is over, so its write lands on retail's state
        // instead of being rolled back. Bounded, in case the game thread is waiting on this one.
        for (int i = 0; i < 50 && g_protected; i++)
            Sleep(1);
        if (!g_protected) {
            g_foreign_waits++;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    PageEntry *e = table_find(page, true);
    if (GetCurrentThreadId() != g_thread || !g_window) {
        // The write is real and must stand: stop tracking this page.
        g_foreign++;
        g_last_foreign_tid = GetCurrentThreadId();
        g_last_foreign_eip = ep->ContextRecord->Eip;
        g_last_foreign_addr = (DWORD) er->ExceptionInformation[1];
        if (e)
            e->foreign = true;
    } else if (!e) {
        g_overflow = true;
    } else {
        if (!e->dirty_r && !e->dirty_o)
            memcpy(g_pre + (size_t) e->pool * kPage, (void *) page, kPage);
        if (g_window == 1)
            e->dirty_r = true;
        else
            e->dirty_o = true;
    }
    VirtualProtect((void *) page, kPage, PAGE_READWRITE, &old);
    return EXCEPTION_CONTINUE_EXECUTION;
}

constexpr uint32_t kHeapWindow = 16 * 1024;

// Allocations seen so far: 0 = ignored, 1 = protected whole, 2 = Win32 heap segment. A heap segment
// is shared with other threads and the kernel (protecting one whole deadlocks the game), so only a
// window behind each pointer argument into one is protected, for that call.
SHADOW_STATE std::vector<std::pair<uint32_t, int>> g_alloc_kind;
SHADOW_STATE std::vector<Region> g_base_regions;
SHADOW_STATE std::vector<Region> g_window_regions;

// Heaps the game itself uses: process heaps whose handle is stored in the EXE's data (its C runtime
// heap). Filled by build_regions before any allocation is classified.
SHADOW_STATE std::vector<uint32_t> *g_game_heaps = nullptr;
constexpr uint32_t kBigBlock = 2 * 1024 * 1024;

int classify_allocation(uint32_t base) {
    MEMORY_BASIC_INFORMATION mbi;
    bool head_readable = VirtualQuery((void *) base, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                         (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) && !(mbi.Protect & PAGE_GUARD);
    bool segment = head_readable && *(uint32_t *) (base + 8) == 0xffeeffeeu;
    if (segment) {
        if (!g_heap_segments)
            return 0;
        // The first segment's base is the heap handle; later segments point back to it at +0x18.
        uint32_t heap = base;
        if (std::find(g_game_heaps->begin(), g_game_heaps->end(), heap) == g_game_heaps->end())
            heap = *(uint32_t *) (base + 0x18);
        if (std::find(g_game_heaps->begin(), g_game_heaps->end(), heap) == g_game_heaps->end())
            return 0;// another module's heap (overlays, drivers, our own CRT)
        if (g_heap_windows)
            return 2;
    }

    // A thread stack: a guard page right below a committed read-write run that reaches the top of
    // the allocation (stacks grow down).
    std::vector<Region> runs;
    std::vector<MEMORY_BASIC_INFORMATION> all;
    uint32_t a = base;
    while (VirtualQuery((void *) a, &mbi, sizeof(mbi)) && (uint32_t) mbi.AllocationBase == base) {
        all.push_back(mbi);
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
            runs.push_back({a, a + (uint32_t) mbi.RegionSize});
        a += (uint32_t) mbi.RegionSize;
    }
    size_t n = all.size();
    if (n >= 2 && all[n - 1].State == MEM_COMMIT && all[n - 1].Protect == PAGE_READWRITE &&
        (all[n - 2].Protect & PAGE_GUARD))
        return 0;
    // Outside the game's heaps, only the game's own big blocks: small private allocations reached
    // from its data are often other modules' (an injected overlay faulted on one).
    uint32_t committed = 0;
    for (const Region &r: runs)
        committed += r.hi - r.lo;
    if (!segment && committed < kBigBlock)
        return 0;
    for (const Region &r: runs) {
        g_base_regions.push_back(r);
        if (g_log)
            fprintf(g_log, "region alloc %08x-%08x (%u KB)\n", r.lo, r.hi, (r.hi - r.lo) / 1024);
    }
    return runs.empty() ? 0 : 1;
}

// Runs already looked up, valid while the layout generation holds.
struct Span {
    uint32_t lo, hi;
};
SHADOW_STATE Span g_spans[256];
SHADOW_STATE int g_span_count = 0;
SHADOW_STATE LONG g_span_gen = 0;

// Heap data reached from a pointer: committed private read-write memory that is not a thread stack
// (stacks carry a guard page) and not our own pools.
void consider_pointer(uint32_t value, bool window) {
    if (g_region_mode < 2)
        return;
    if (value < 0x10000 || value >= 0x7fff0000)
        return;
    if ((uint8_t *) value >= g_pool_lo && (uint8_t *) value < g_pool_hi)
        return;
    if (g_layout_cache) {
        const LONG gen = g_layout_gen;
        if (gen != g_span_gen) {
            g_span_count = 0;
            g_span_gen = gen;
        }
        for (int i = 0; i < g_span_count; i++)
            if (value >= g_spans[i].lo && value < g_spans[i].hi)
                return;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *) value, &mbi, sizeof(mbi)))
        return;
    if (g_layout_cache && g_span_count < 256 && !g_trace) {
        // Cached once nothing is left to do for a pointer into this run: unusable memory, or an
        // allocation already classified as anything but a heap segment (which needs a window).
        uint32_t base = (uint32_t) mbi.AllocationBase;
        int kind = -1;
        for (const auto &k: g_alloc_kind)
            if (k.first == base)
                kind = k.second;
        bool usable = mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE;
        if (!usable || (kind >= 0 && kind != 2))
            g_spans[g_span_count++] = {(uint32_t) mbi.BaseAddress, (uint32_t) mbi.BaseAddress + (uint32_t) mbi.RegionSize};
    }
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.Protect != PAGE_READWRITE) {
        if (window && g_trace && g_log && mbi.State == MEM_COMMIT)
            fprintf(g_log, "skip arg %08x type %lx protect %lx base %08x\n", value, mbi.Type, mbi.Protect,
                    (uint32_t) mbi.AllocationBase);
        return;
    }
    uint32_t base = (uint32_t) mbi.AllocationBase;
    int kind = -1;
    for (const auto &k: g_alloc_kind)
        if (k.first == base)
            kind = k.second;
    if (kind < 0) {
        kind = classify_allocation(base);
        g_alloc_kind.push_back({base, kind});
        if (g_trace && g_log)
            fprintf(g_log, "alloc %08x (from %08x) kind %d\n", base, value, kind);
    }
    if (kind != 2 || !window)
        return;
    uint32_t run_lo = (uint32_t) mbi.BaseAddress, run_hi = run_lo + (uint32_t) mbi.RegionSize;
    uint32_t lo = value & ~(kPage - 1);
    uint32_t hi = std::min(run_hi, (value + kHeapWindow + kPage - 1) & ~(kPage - 1));
    if (lo >= run_lo && hi > lo)
        g_window_regions.push_back({lo, hi});
}

SHADOW_STATE void *g_veh = nullptr;

bool heap_pointer(uint32_t v) {
    MEMORY_BASIC_INFORMATION mbi;
    return v >= 0x10000 && v < 0x7fff0000 && VirtualQuery((void *) v, &mbi, sizeof(mbi)) &&
           mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE;
}

// Pages exception dispatch itself writes: every registered vectored handler entry and the refcount
// block each one points to, on the process heap. Dispatch updates them while holding the handler-list
// lock, so a fault there would wait on itself forever.
void dispatch_pages(std::vector<uint32_t> &out) {
    if (!g_veh)
        return;
    LIST_ENTRY *head = (LIST_ENTRY *) g_veh;
    LIST_ENTRY *e = head;
    for (int i = 0; i < 64; i++) {
        uint32_t a = (uint32_t) e;
        if (heap_pointer(a)) {
            out.push_back(a & ~(kPage - 1));
            out.push_back((a + 15) & ~(kPage - 1));
            uint32_t refs = ((uint32_t *) e)[2];
            if (heap_pointer(refs))
                out.push_back(refs & ~(kPage - 1));
        }
        e = e->Flink;
        if (!e || e == head)
            break;
    }
}

// Fingerprint of the vectored handler list (entries and their refcount blocks): rebuild_regions
// cuts those pages out, so any change to the list needs a rebuild.
uint32_t veh_list_hash() {
    if (!g_veh)
        return 0;
    LIST_ENTRY *head = (LIST_ENTRY *) g_veh;
    LIST_ENTRY *e = head;
    uint32_t h = 2166136261u;
    for (int i = 0; i < 64; i++) {
        h = (h ^ (uint32_t) e) * 16777619u;
        h = (h ^ ((uint32_t *) e)[2]) * 16777619u;
        e = e->Flink;
        if (!e || e == head)
            break;
    }
    return h;
}

// Active set = persistent regions + this call's windows, sorted and merged.
void rebuild_regions() {
    g_regions_ver++;
    std::vector<Region> all = g_base_regions;
    all.insert(all.end(), g_window_regions.begin(), g_window_regions.end());
    std::sort(all.begin(), all.end(), [](const Region &x, const Region &y) { return x.lo < y.lo; });
    std::vector<Region> merged;
    for (const Region &r: all) {
        if (!merged.empty() && r.lo <= merged.back().hi)
            merged.back().hi = std::max(merged.back().hi, r.hi);
        else
            merged.push_back(r);
    }
    std::vector<uint32_t> holes;
    dispatch_pages(holes);
    std::sort(holes.begin(), holes.end());
    holes.erase(std::unique(holes.begin(), holes.end()), holes.end());
    g_regions.clear();
    for (Region r: merged) {
        for (uint32_t h: holes) {
            if (h < r.lo || h >= r.hi)
                continue;
            if (h > r.lo)
                g_regions.push_back({r.lo, h});
            r.lo = h + kPage;
        }
        if (r.hi > r.lo)
            g_regions.push_back(r);
    }
}

void build_regions() {
    g_regions_built = true;
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR) &shadow_init, &self);
    std::vector<Region> image_regions;
    for (uint8_t *image: {(uint8_t *) GetModuleHandleA(nullptr), (uint8_t *) self}) {
        if (!image)
            continue;
        auto *dos = (IMAGE_DOS_HEADER *) image;
        auto *nt = (IMAGE_NT_HEADERS *) (image + dos->e_lfanew);
        auto *sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD c = sec[i].Characteristics;
            if (!(c & IMAGE_SCN_MEM_WRITE) || (c & IMAGE_SCN_MEM_EXECUTE))
                continue;
            if (strncmp((const char *) sec[i].Name, ".shstate", 8) == 0 || strncmp((const char *) sec[i].Name, ".tls", 4) == 0)
                continue;
            uint32_t lo = (uint32_t) image + sec[i].VirtualAddress;
            uint32_t size = std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            uint32_t hi = (lo + size + kPage - 1) & ~(kPage - 1);
            image_regions.push_back({lo, hi});
            fprintf(g_log, "region image %08x-%08x %.8s\n", lo, hi, (const char *) sec[i].Name);
        }
    }
    if (g_region_mode >= 1)
        g_base_regions = image_regions;
    {
        HANDLE heaps[64];
        DWORD nh = GetProcessHeaps(64, heaps);
        static std::vector<uint32_t> found;
        found.clear();
        uint32_t exe0 = (uint32_t) GetModuleHandleA(nullptr);
        for (const Region &r: image_regions) {
            if (r.lo < exe0 || r.lo >= exe0 + 0x1000000)
                continue;
            for (uint32_t a = r.lo; a + 4 <= r.hi; a += 4)
                for (DWORD h = 0; h < nh && h < 64; h++)
                    if (*(uint32_t *) a == (uint32_t) heaps[h] &&
                        std::find(found.begin(), found.end(), (uint32_t) heaps[h]) == found.end()) {
                        found.push_back((uint32_t) heaps[h]);
                        fprintf(g_log, "game heap %08x (stored at %08x)\n", (uint32_t) heaps[h], a);
                    }
        }
        g_game_heaps = &found;
    }
    // Heap blocks are followed from the EXE's data only: the DLL's data also points into heaps owned
    // by injected overlays and drivers, whose own code cannot take a fault.
    uint32_t exe = (uint32_t) GetModuleHandleA(nullptr);
    for (const Region &r: image_regions)
        if (r.lo >= exe && r.lo < exe + 0x1000000)
            for (uint32_t a = r.lo; a + 4 <= r.hi; a += 4)
                consider_pointer(*(uint32_t *) a, false);
    fflush(g_log);
}

void read_config() {
    FILE *f = fopen(HOOK_MODE_CONFIG_FILE, "r");
    if (!f)
        return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned n;
        if (sscanf(line, " shadow_limit %u", &n) == 1)
            g_limit = n;
        else if (sscanf(line, " shadow_every %u", &n) == 1 && n > 0)
            g_every = n;
        else if (sscanf(line, " shadow_budget_ms %lf", &g_budget_ms) == 1)
            ;
        else if (strncmp(line, "shadow_frames", 13) == 0) {
            int a = -1, b = -1;
            if (sscanf(line + 13, "%d %d", &a, &b) >= 1) {
                g_from_frame = a;
                g_to_frame = b;
            }
        }
        else if (strncmp(line, "shadow_unsafe", 13) == 0)
            g_allow_unsafe = true;
        else if (strncmp(line, "shadow_off", 10) == 0)
            g_enabled = false;
        else if (strncmp(line, "shadow_anytime", 14) == 0)
            g_anytime = true;
        else if (strncmp(line, "shadow_no_heap_segments", 23) == 0)
            g_heap_segments = false;
        else if (strncmp(line, "shadow_heap_lock", 16) == 0)
            g_heap_lock = true;
        else if (strncmp(line, "shadow_no_layout_cache", 22) == 0)
            g_layout_cache = false;
        else if (strncmp(line, "shadow_heap_windows", 19) == 0)
            g_heap_windows = true;
        else if (strncmp(line, "shadow_trace", 12) == 0)
            g_trace = true;
        else if (sscanf(line, " shadow_regions %u", &n) == 1)
            g_region_mode = (int) n;
    }
    fclose(f);
}

void *make_entry(const char *name, uint32_t reimpl, uint32_t retail, hook_ret_kind ret);

}// namespace

extern "C" void shadow_entry(void);
extern "C" void shadow_after(void);
extern "C" void shadow_call(void *fn, const uint32_t *args, const uint32_t *regs, CallOut *out, const uint8_t *fpu_in);
extern "C" CallOut *shadow_dispatch(uint32_t *frame);
extern "C" void shadow_pass_end(uint32_t *frame);

// shadow_entry: reached from a per-function stub `push <ShadowFn*>; jmp shadow_entry`. It saves
// every register (pushad), so a frame is: [0] edi [1] esi [2] ebp [3] esp [4] ebx [5] edx [6] ecx
// [7] eax [8] ShadowFn* [9] return address [10..] arguments. shadow_dispatch returns:
//   a CallOut*  the call was handled; its eax/edx/ST0 go back to the caller.
//   0 or 1      frame[8] now holds where to jump with the caller's registers and stack untouched
//               (retail entries can take hidden register inputs). With 0 the return address was
//               swapped for shadow_after, which re-patches the entry and returns to the caller.
// shadow_call(fn, args, regs, out): calls fn with 16 copied argument dwords and the caller's
// registers from a frame, and records eax/edx, ST0 when the call left one on the x87 stack, and
// how many bytes the callee popped.
asm(R"(
.intel_syntax noprefix
.text
.globl _shadow_entry
_shadow_entry:
    pushad
    mov eax, esp
    push eax
    call _shadow_dispatch
    add esp, 4
    cmp eax, 1
    jbe 1f
    frstor [eax+32]
    mov ecx, [eax]
    mov [esp+28], ecx
    mov ecx, [eax+4]
    mov [esp+20], ecx
    popad
    add esp, 4
    ret
1:
    popad
    ret

.globl _shadow_after
_shadow_after:
    push 0
    pushad
    mov eax, esp
    push eax
    call _shadow_pass_end
    add esp, 4
    popad
    ret

.globl _shadow_call
_shadow_call:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    sub esp, 64
    mov esi, [ebp+12]
    mov edi, esp
    mov ecx, 16
    cld
    rep movsd
    mov eax, [ebp+24]
    frstor [eax]
    mov eax, [ebp+16]
    mov ebx, [eax+16]
    mov ecx, [eax+24]
    mov edx, [eax+20]
    mov esi, [eax+4]
    mov edi, [eax]
    mov eax, [eax+28]
    call dword ptr [ebp+8]
    mov edi, [ebp+20]
    mov [edi], eax
    mov [edi+4], edx
    lea ecx, [ebp-76]
    mov eax, esp
    sub eax, ecx
    mov [edi+28], eax
    fnsave [edi+32]
    lea esp, [ebp-12]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
.att_syntax prefix
)");

namespace {

void *make_entry(const char *name, uint32_t reimpl, uint32_t retail, hook_ret_kind ret) {
    if (ret == HOOK_RET_UNSUPPORTED || g_fn_count >= kMaxFns)
        return nullptr;
    if (!g_stubs) {
        g_stubs = (uint8_t *) VirtualAlloc(nullptr, kMaxFns * kStubSize, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
        if (!g_stubs)
            return nullptr;
    }
    if (hooks.contains((void *) retail))
        return nullptr;// a delta already detours this entry (e.g. lockstep's own hooks)
    // Functions with effects outside memory would run twice: input polling, pause and menus, sound,
    // rendering, file I/O. A name filter, so a broad pattern (`shadow swrRace_*`) is safe.
    static const char *const kUnsafe[] = {"Input", "ause",    "Menu",    "Sound",  "Render",  "Draw",
                                          "Text",  "UI",      "Sprite",  "Hud",    "HUD",     "Profile",
                                          "Cheat", "Load",    "Save",    "Init",   "Camera",  "Music",
                                          "Voice", "Key",     "Wait",    "GameData", "Viewport", "Quad"};
    if (!g_allow_unsafe)
        for (const char *w: kUnsafe)
            if (strstr(name, w)) {
                log_open();
                fprintf(g_log, "shadow: %s skipped (name suggests effects outside memory; shadow_unsafe overrides)\n",
                        name);
                return nullptr;
            }
    const uint8_t *p = (const uint8_t *) retail;
    if (p[0] == 0xE9 || p[0] == 0xEB || (p[0] == 0xFF && p[1] == 0x25))
        return nullptr;// already redirected by something else
    ShadowFn &fn = g_fns[g_fn_count];
    memset(&fn, 0, sizeof(fn));
    memcpy(fn.retail_entry.orig, (void *) retail, kEntryBytes);
    memcpy(fn.ours_entry.orig, (void *) reimpl, kEntryBytes);
    fn.name = name;
    fn.reimpl = reimpl;
    fn.retail = retail;
    fn.ret = ret;
    fn.first_frame = -1;

    uint8_t *stub = g_stubs + g_fn_count * kStubSize;
    stub[0] = 0x68;// push imm32
    uint32_t ctx = (uint32_t) &fn;
    memcpy(stub + 1, &ctx, 4);
    stub[5] = 0xE9;// jmp rel32
    int32_t rel = (int32_t) ((uint32_t) &shadow_entry - (uint32_t) (stub + 10));
    memcpy(stub + 6, &rel, 4);
    g_fn_count++;
    return stub;
}

const char *ret_name(hook_ret_kind k) {
    switch (k) {
    case HOOK_RET_VOID: return "void";
    case HOOK_RET_INT32: return "int32";
    case HOOK_RET_INT8: return "int8";
    case HOOK_RET_INT16: return "int16";
    case HOOK_RET_INT64: return "int64";
    case HOOK_RET_FLOAT: return "float";
    default: return "?";
    }
}

double st0_value(const uint8_t *st0) {
    long double v;
    memcpy(&v, st0, 10);
    return (double) v;
}

// Compares return registers; returns 0 = same, 1 = mismatch, 2 = warning only.
int compare_returns(const ShadowFn &fn, const CallOut &r, const CallOut &o, char *buf, size_t n) {
    buf[0] = 0;
    if (r.popped != o.popped) {
        snprintf(buf, n, "callee popped %d bytes (retail) vs %d (ours)", r.popped, o.popped);
        return 1;
    }
    if (r.has_st0 != o.has_st0) {
        snprintf(buf, n, "x87 stack: retail %s ST0, ours %s", r.has_st0 ? "left" : "left no",
                 o.has_st0 ? "left one" : "left none");
        return 1;
    }
    switch (fn.ret) {
    case HOOK_RET_VOID:
        return 0;
    case HOOK_RET_INT8:
    case HOOK_RET_INT16: {
        uint32_t mask = fn.ret == HOOK_RET_INT8 ? 0xff : 0xffff;
        if ((r.eax & mask) != (o.eax & mask)) {
            snprintf(buf, n, "return %08x (retail) vs %08x (ours)", r.eax, o.eax);
            return 1;
        }
        if (r.eax != o.eax) {
            snprintf(buf, n, "return low bits equal, upper EAX differs: %08x (retail) vs %08x (ours)", r.eax, o.eax);
            return 2;
        }
        return 0;
    }
    case HOOK_RET_INT32:
        if (r.eax != o.eax) {
            snprintf(buf, n, "return %08x (retail) vs %08x (ours)", r.eax, o.eax);
            return 1;
        }
        return 0;
    case HOOK_RET_INT64:
        if (r.eax != o.eax || r.edx != o.edx) {
            snprintf(buf, n, "return %08x%08x (retail) vs %08x%08x (ours)", r.edx, r.eax, o.edx, o.eax);
            return 1;
        }
        return 0;
    case HOOK_RET_FLOAT:
        if (r.has_st0 && memcmp(r.st0, o.st0, 10) != 0) {
            double a = st0_value(r.st0), b = st0_value(o.st0);
            snprintf(buf, n, "return ST0 %.17g (retail) vs %.17g (ours)%s", a, b,
                     (float) a == (float) b ? " [equal as float: excess precision only]" : "");
            return (float) a == (float) b ? 2 : 1;
        }
        return 0;
    default:
        return 0;
    }
}

void dump_bytes(const uint8_t *p, int len) {
    for (int i = 0; i < len; i++)
        fprintf(g_log, "%02x", p[i]);
}

// One differing byte range, with a float/int reading when it is one aligned dword.
void log_run(uint32_t addr, const uint8_t *r, const uint8_t *o, int len) {
    int shown = std::min(len, 16);
    fprintf(g_log, "    %08x +%-3d retail ", addr, len);
    dump_bytes(r, shown);
    fprintf(g_log, " ours ");
    dump_bytes(o, shown);
    uint32_t a = addr & ~3u;
    if (len <= 4 && (addr + len) <= a + 4) {
        const uint8_t *rr = r - (addr - a), *oo = o - (addr - a);
        float fr, fo;
        int32_t ir, io;
        memcpy(&fr, rr, 4);
        memcpy(&fo, oo, 4);
        memcpy(&ir, rr, 4);
        memcpy(&io, oo, 4);
        fprintf(g_log, "   @%08x f %.9g vs %.9g | i %d vs %d", a, fr, fo, ir, io);
        if (g_capture && !g_capture[0])
            snprintf(g_capture, g_capture_len, "%08x: retail %.9g (%d) vs ours %.9g (%d)", a, fr, ir, fo, io);
    }
    if (g_capture && !g_capture[0]) {
        int k = snprintf(g_capture, g_capture_len, "%08x +%d: retail", addr, len);
        for (int i = 0; i < std::min(len, 8) && k < (int) g_capture_len - 4; i++)
            k += snprintf(g_capture + k, g_capture_len - k, " %02x", r[i]);
        k += snprintf(g_capture + k, g_capture_len - k, " vs ours");
        for (int i = 0; i < std::min(len, 8) && k < (int) g_capture_len - 4; i++)
            k += snprintf(g_capture + k, g_capture_len - k, " %02x", o[i]);
    }
    fprintf(g_log, "\n");
}

// Our reimpl's address -> its retail address, for every hooked function: a stored code pointer
// that names our body is the same value as one that names retail's.
SHADOW_STATE std::vector<std::pair<uint32_t, uint32_t>> g_code_map;

bool same_code_pointer(uint32_t retail_val, uint32_t ours_val) {
    auto it = std::lower_bound(g_code_map.begin(), g_code_map.end(), std::make_pair(ours_val, 0u));
    return it != g_code_map.end() && it->first == ours_val && it->second == retail_val;
}

// Diffs two copies of one dword-aligned block; logs merged runs. Returns the number of differing
// dwords.
int diff_block(uint32_t base, const uint8_t *r, const uint8_t *o, uint32_t len, int *runs_left, bool log) {
    const uint32_t *rw = (const uint32_t *) r, *ow = (const uint32_t *) o;
    uint32_t n = len / 4;
    int total = 0;
    uint32_t i = 0;
    auto differs = [&](uint32_t k) { return rw[k] != ow[k] && !same_code_pointer(rw[k], ow[k]); };
    while (i < n) {
        if (!differs(i)) {
            i++;
            continue;
        }
        uint32_t start = i, last = i;
        while (i < n && i - last <= 1) {
            if (differs(i))
                last = i;
            i++;
        }
        total += (int) (last - start + 1);
        if (log && *runs_left > 0) {
            log_run(base + start * 4, r + start * 4, o + start * 4, (int) (last - start + 1) * 4);
            (*runs_left)--;
        }
        i = last + 1;
    }
    return total;
}

// Whether the instruction after the call reads EAX/AL, i.e. retail's caller uses the result. Skips
// stack cleanup first. A function our source declares as returning a value but whose retail callers
// never read EAX leaves garbage there, which is not a mismatch.
bool caller_reads_eax(uint32_t ret) {
    const uint8_t *p = (const uint8_t *) ret;
    for (int guard = 0; guard < 3; guard++) {
        if (p[0] == 0x83 && p[1] == 0xC4)
            p += 3;
        else if (p[0] == 0x81 && p[1] == 0xC4)
            p += 6;
        else if (p[0] == 0x59 || p[0] == 0x5A)
            p += 1;
        else
            break;
    }
    uint8_t op = p[0], modrm = p[1];
    int reg = (modrm >> 3) & 7, rm = modrm & 7, mod = modrm >> 6;
    switch (op) {
    case 0x84: case 0x85:
    case 0x3B: case 0x39: case 0x3A: case 0x38: case 0x2B: case 0x29: case 0x03: case 0x01:
    case 0x23: case 0x21: case 0x0B: case 0x09: case 0x33: case 0x31:
        return reg == 0 || (mod == 3 && rm == 0);
    case 0x88: case 0x89:
        return reg == 0;
    case 0x8B: case 0x8A:
        return mod == 3 && rm == 0;
    case 0x83: case 0x80: case 0x81: case 0xF7: case 0xF6: case 0xD1: case 0xC1: case 0xFF:
        return mod == 3 && rm == 0;
    case 0x3C: case 0x3D: case 0xA8: case 0xA9: case 0x50: case 0xA3: case 0xA2: case 0x40: case 0x48:
    case 0x98: case 0x99:
        return true;
    case 0x0F:
        return (modrm == 0xB6 || modrm == 0xBE || modrm == 0xB7 || modrm == 0xBF) && (p[2] & 0xC7) == 0xC0;
    default:
        return false;
    }
}

int entry_len(const Entry &e) {
    int n = 0;
    for (int i = 0; i < kEntryBytes; i++)
        if (e.orig[i] != e.patched[i])
            n = i + 1;
    return n;
}

void write_entry(uint32_t addr, const uint8_t *bytes, int len) {
    // Other patches restore their page's protection when they finish, so open it every time.
    DWORD old, tmp;
    VirtualProtect((void *) addr, kEntryBytes, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void *) addr, bytes, len);
    VirtualProtect((void *) addr, kEntryBytes, old, &tmp);
}

// x87 state at the shadowed call: both runs start from it, so a value an earlier caller left on the
// stack is neither mistaken for a result nor lost.
SHADOW_STATE uint8_t g_fpu_entry[108];

int fpu_top(const uint8_t *fsave) {
    return (*(const uint16_t *) (fsave + 4) >> 11) & 7;
}

void call_body(uint32_t addr, const Entry &e, const uint32_t *args, const uint32_t *regs, CallOut *out) {
    write_entry(addr, e.orig, e.len);
    shadow_call((void *) addr, args, regs, out, g_fpu_entry);
    write_entry(addr, e.patched, e.len);
    // Pushes move TOP down; one more value than at entry is a returned ST0 (FNSAVE stores ST0 first).
    out->has_st0 = ((fpu_top(g_fpu_entry) - fpu_top(out->fpu)) & 7) == 1;
    memcpy(out->st0, out->fpu + 28, 10);
}

// Pass-through calls, innermost last: which entry to re-patch and where to return.
struct Pass {
    ShadowFn *fn;
    uint32_t ret;
};
SHADOW_STATE Pass g_pass[4096];
SHADOW_STATE int g_pass_depth = 0;

bool open_entry(uint32_t addr, Entry &e) {
    memcpy(e.patched, (void *) addr, kEntryBytes);
    e.len = entry_len(e);
    return e.len >= 5;
}

}// namespace

// Differences that come from retail itself, matched narrowly so anything else still counts.
struct KnownQuirk {
    const char *name;
    bool return_only;// only the return value differs
    int max_mem_words;// otherwise: return and stack match, at most this many memory words differ
    const char *why;
};
const KnownQuirk kKnownQuirks[] = {
    {"swrRace_SpawnDustKickObject", true, 0, "retail returns whatever is left in EAX"},
    {"swrRace_SpawnGroundDustKick", false, 1, "retail stores uninitialized stack (tossFlags), ours stores 0"},
};

const char *known_quirk(const char *name, int ret_cmp, int mem_words, int stack_words) {
    for (const KnownQuirk &q: kKnownQuirks) {
        if (strcmp(name, q.name) != 0)
            continue;
        if (q.return_only ? (ret_cmp == 1 && mem_words == 0 && stack_words == 0)
                          : (ret_cmp != 1 && stack_words == 0 && mem_words > 0 && mem_words <= q.max_mem_words))
            return q.why;
    }
    return nullptr;
}

extern "C" CallOut *shadow_dispatch(uint32_t *frame) {
    ShadowFn *fn = (ShadowFn *) frame[8];
    if (!fn->ready || GetCurrentThreadId() != g_thread) {
        frame[8] = (uint32_t) fn->retail_orig;
        return (CallOut *) 1;
    }
    uint32_t args[kArgDwords];
    memcpy(args, frame + 10, sizeof(args));

    int lsframe = lockstep_shadow_frame();
    if (lsframe < 0)
        lsframe = -(int) g_frame - 2;// outside a lockstep race: own counter, logged as "live N"
    bool compare = g_enabled && g_depth == 0 && !fn->disabled && (lsframe >= 0 || g_anytime);
    if (compare && g_from_frame >= 0 && (lsframe < g_from_frame || (g_to_frame >= 0 && lsframe > g_to_frame)))
        compare = false;
    if (compare) {
        fn->calls++;
        if ((g_limit && fn->compared >= g_limit) || (fn->calls - 1) % g_every != 0)
            compare = false;
    }
    if (compare && g_budget_ticks > 0) {
        // Each function is compared once per round, on a call index that rotates so per-racer
        // functions are not always checked on racer 0. A round ends with a frame in which no called
        // function was still due, so rarely called functions are not starved by frequent ones.
        if (fn->frame_stamp != g_frame) {
            fn->frame_stamp = g_frame;
            fn->frame_calls = 0;
        }
        uint32_t idx = fn->frame_calls++;
        if (fn->round == g_round) {
            compare = false;
        } else {
            g_frame_had_eligible = true;
            uint32_t span = fn->last_frame_calls ? fn->last_frame_calls : 1;
            // Predicted by the running average cost; one comparison per frame always fits.
            int64_t avg = g_total_compared ? g_ticks / (int64_t) g_total_compared : 0;
            if (idx < fn->compared % span || (g_frame_ticks > 0 && g_frame_ticks + avg > g_budget_ticks))
                compare = false;
            else {
                fn->round = g_round;
                g_round_compared = true;
            }
        }
    }
    if (!compare) {
        if (g_pass_depth >= (int) (sizeof(g_pass) / sizeof(g_pass[0]))) {
            frame[8] = (uint32_t) fn->retail_orig;
            return (CallOut *) 1;
        }
        g_pass[g_pass_depth++] = {fn, frame[9]};
        write_entry(fn->retail, fn->retail_entry.orig, fn->retail_entry.len);
        frame[9] = (uint32_t) &shadow_after;
        frame[8] = fn->retail;
        return nullptr;
    }

    g_depth = 1;
    asm volatile("fnsave (%0)\n\tfrstor (%0)" : : "r"(g_fpu_entry) : "memory");
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    g_cur_name = fn->name;
    InterlockedIncrement(&g_heartbeat);
    log_open();
    if (!g_regions_built)
        build_regions();

    // Other handlers registered later (e.g. an injected overlay's) would see our page faults first.
    static uint32_t s_veh_hash = 0;
    static LONG s_regions_gen = -1;
    static size_t s_base_count = 0;
    bool veh_changed = false;
    uint32_t veh_hash = veh_list_hash();
    if (veh_hash != s_veh_hash) {
        if (g_veh && heap_pointer((uint32_t) ((LIST_ENTRY *) g_veh)->Blink)) {
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = AddVectoredExceptionHandler(1, shadow_veh);
            veh_hash = veh_list_hash();
        }
        s_veh_hash = veh_hash;
        veh_changed = true;
    }
    const bool had_windows = !g_window_regions.empty();
    g_window_regions.clear();
    for (uint32_t a: args)
        consider_pointer(a, true);
    const LONG regions_gen = g_layout_gen;
    if (!g_layout_cache || veh_changed || had_windows || !g_window_regions.empty() ||
        regions_gen != s_regions_gen || g_base_regions.size() != s_base_count) {
        rebuild_regions();
        s_regions_gen = regions_gen;
        s_base_count = g_base_regions.size();
    }

    uint8_t *stack_lo = (uint8_t *) (frame + 9);
    uint8_t *stack_hi = (uint8_t *) ((NT_TIB *) NtCurrentTeb())->StackBase;
    size_t stack_len = std::min((size_t) (stack_hi - stack_lo), kMaxStackWindow);
    memcpy(g_stack_pre, stack_lo, stack_len);

    g_overflow = false;
    g_foreign = 0;
    table_clear();

    if (g_trace) {
        MEMORY_BASIC_INFORMATION q = {};
        VirtualQuery((void *) args[0], &q, sizeof(q));
        int k = -9;
        for (const auto &ak: g_alloc_kind)
            if (ak.first == (uint32_t) q.AllocationBase)
                k = ak.second;
        fprintf(g_log, "trace %s frame %d arg0 %08x base %08x run %08x+%lx type %lx prot %lx kind %d protected %d\n",
                fn->name, lsframe, args[0], (uint32_t) q.AllocationBase, (uint32_t) q.BaseAddress, q.RegionSize, q.Type,
                q.Protect, k, (int) in_regions(args[0] & ~(kPage - 1)));
        fflush(g_log);
    }

    CallOut r = {}, o = {};
    g_heap_count = g_heap_lock ? GetProcessHeaps(64, g_heaps) : 0;
    if (g_heap_count > 64)
        g_heap_count = 64;
    for (DWORD h = 0; h < g_heap_count; h++)
        HeapLock(g_heaps[h]);
    protect_all(PAGE_READONLY);
    g_phase = 2;
    g_window = 1;
    call_body(fn->retail, fn->retail_entry, args, frame, &r);
    g_window = 0;
    for (int i = 0; i < g_used_count; i++) {
        PageEntry &e = g_table[g_used[i]];
        if (e.dirty_r)
            memcpy(g_post + (size_t) e.pool * kPage, (void *) e.page, kPage);
    }
    memcpy(g_stack_post, stack_lo, stack_len);

    DWORD old;
    for (int i = 0; i < g_used_count; i++) {
        PageEntry &e = g_table[g_used[i]];
        if (e.dirty_r && !e.foreign) {
            memcpy((void *) e.page, g_pre + (size_t) e.pool * kPage, kPage);
            VirtualProtect((void *) e.page, kPage, PAGE_READONLY, &old);
        }
    }
    memcpy(stack_lo, g_stack_pre, stack_len);
    g_phase = 4;
    g_window = 2;
    call_body(fn->reimpl, fn->ours_entry, args, frame, &o);
    g_window = 0;

    // Stash our result, put retail's back, and only then release the pages: other threads held by
    // the exception handler resume on retail's state.
    DWORD old2;
    for (int i = 0; i < g_used_count; i++) {
        PageEntry &e = g_table[g_used[i]];
        if (e.foreign)
            continue;
        if (e.dirty_o)
            memcpy(g_ours + (size_t) e.pool * kPage, (void *) e.page, kPage);
        else
            VirtualProtect((void *) e.page, kPage, PAGE_READWRITE, &old2);
        memcpy((void *) e.page, e.dirty_r ? g_post + (size_t) e.pool * kPage : g_pre + (size_t) e.pool * kPage, kPage);
    }
    memcpy(g_stack_ours, stack_lo, stack_len);
    memcpy(stack_lo, g_stack_post, stack_len);
    protect_all(PAGE_READWRITE);
    // Heaps stay locked until the rolled-back pages hold retail's result again.
    for (DWORD h = g_heap_count; h-- > 0;)
        HeapUnlock(g_heaps[h]);

    // Compare: retail's bytes vs ours, for every page either run wrote, and the caller's stack.
    char retbuf[256];
    int ret_cmp = compare_returns(*fn, r, o, retbuf, sizeof(retbuf));
    if (ret_cmp != 0 && fn->ret != HOOK_RET_FLOAT && r.popped == o.popped && r.has_st0 == o.has_st0 &&
        !caller_reads_eax(frame[9]))
        ret_cmp = 0;// garbage EAX the caller never reads
    int mem_bytes = 0;
    bool foreign_pages = false;
    for (int i = 0; i < g_used_count; i++) {
        PageEntry &e = g_table[g_used[i]];
        if (e.foreign) {
            foreign_pages = true;
            continue;
        }
        const uint8_t *rp = e.dirty_r ? g_post + (size_t) e.pool * kPage : g_pre + (size_t) e.pool * kPage;
        const uint8_t *op = (e.dirty_o ? g_ours : g_pre) + (size_t) e.pool * kPage;
        int dummy = 0;
        mem_bytes += diff_block(e.page, rp, op, kPage, &dummy, false);
    }
    int stack_bytes;
    {
        int dummy = 0;
        stack_bytes = diff_block((uint32_t) stack_lo, g_stack_post, g_stack_ours, (uint32_t) stack_len, &dummy, false);
    }

    bool mismatch = ret_cmp == 1 || mem_bytes || stack_bytes;
    bool unreliable = g_overflow || foreign_pages || g_foreign;
    fn->compared++;
    g_total_compared++;
    if (unreliable)
        fn->unreliable++;
    if (ret_cmp == 2 && !mismatch)
        fn->warnings++;
    const char *quirk = mismatch ? known_quirk(fn->name, ret_cmp, mem_bytes, stack_bytes) : nullptr;
    if (quirk) {
        mismatch = false;
        fn->quirks++;
        g_quirk_total++;
    }
    ShadowMismatch *rec = nullptr;
    if (mismatch || (quirk && fn->quirks == 1)) {
        if (mismatch) {
            fn->mismatches++;
            g_mismatch_total++;
            if (fn->first_frame < 0)
                fn->first_frame = lsframe;
        }
        if (quirk || fn->mismatches <= kDetailedPerFn) {
            rec = &g_recent[g_recent_count++ % 64];
            rec->function = fn->name;
            rec->live = lsframe < 0;
            rec->frame = lsframe >= 0 ? lsframe : -lsframe - 2;
            rec->unreliable = unreliable;
            rec->known = quirk;
            snprintf(rec->what, sizeof(rec->what), "%s", retbuf);
            if (!retbuf[0]) {
                g_capture = rec->what;
                g_capture_len = sizeof(rec->what);
            }
        }
    }
    if ((mismatch && fn->mismatches <= kDetailedPerFn) || (quirk && fn->quirks == 1) ||
        (ret_cmp == 2 && fn->warnings <= 1)) {
        const char *kind = mismatch ? "MISMATCH" : quirk ? "QUIRK" : "WARN";
        if (lsframe >= 0)
            fprintf(g_log, "%s %s frame %d call %u%s\n", kind, fn->name, lsframe, fn->calls,
                    unreliable ? " (unreliable: page overflow or foreign writes)" : "");
        else
            fprintf(g_log, "%s %s live %d call %u%s\n", kind, fn->name, -lsframe - 2, fn->calls,
                    unreliable ? " (unreliable: page overflow or foreign writes)" : "");
        if (quirk)
            fprintf(g_log, "  known retail quirk: %s (later ones only counted)\n", quirk);
        fprintf(g_log, "  args");
        for (uint32_t a: args)
            fprintf(g_log, " %08x", a);
        fprintf(g_log, "\n");
        if (retbuf[0])
            fprintf(g_log, "  %s\n", retbuf);
        int runs_left = kMaxDiffRuns;
        for (int i = 0; i < g_used_count; i++) {
            PageEntry &e = g_table[g_used[i]];
            if (e.foreign)
                continue;
            const uint8_t *rp = e.dirty_r ? g_post + (size_t) e.pool * kPage : g_pre + (size_t) e.pool * kPage;
            const uint8_t *op = (e.dirty_o ? g_ours : g_pre) + (size_t) e.pool * kPage;
            diff_block(e.page, rp, op, kPage, &runs_left, true);
        }
        if (stack_bytes) {
            fprintf(g_log, "  caller stack:\n");
            diff_block((uint32_t) stack_lo, g_stack_post, g_stack_ours, (uint32_t) stack_len, &runs_left, true);
        }
        fflush(g_log);
    }
    g_capture = nullptr;
    if (r.popped != 0)
        fn->disabled = true;

    memcpy(&g_result, &r, sizeof(r));

    QueryPerformanceCounter(&t1);
    g_ticks += t1.QuadPart - t0.QuadPart;
    g_frame_ticks += t1.QuadPart - t0.QuadPart;
    fn->ticks += t1.QuadPart - t0.QuadPart;
    if (t1.QuadPart - t0.QuadPart > fn->max_ticks)
        fn->max_ticks = t1.QuadPart - t0.QuadPart;
    g_depth = 0;
    g_phase = 0;
    InterlockedIncrement(&g_heartbeat);
    return &g_result;
}

extern "C" void shadow_pass_end(uint32_t *frame) {
    Pass p = g_pass[--g_pass_depth];
    write_entry(p.fn->retail, p.fn->retail_entry.patched, p.fn->retail_entry.len);
    frame[8] = p.ret;
}

// Per race, so the map follows the race's allocations and the build stays off a race frame.
extern "C" void shadow_race_loaded(void) {
    if (g_depth != 0 || !g_enabled)
        return;
    bool any = false;
    for (int i = 0; i < g_fn_count && !any; i++)
        any = g_fns[i].ready;
    if (!any)
        return;
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    log_open();
    g_base_regions.clear();
    g_alloc_kind.clear();
    build_regions();
    QueryPerformanceCounter(&t1);
    fprintf(g_log, "region map built at race load in %.1f ms\n",
            (double) (t1.QuadPart - t0.QuadPart) * 1000.0 / (double) g_qpf.QuadPart);
    fflush(g_log);
}

extern "C" void shadow_frame_tick(void) {
    g_last_frame_ticks = g_frame_ticks;
    if (g_budget_ticks > 0) {
        if (g_frame_ticks > g_max_frame_ticks)
            g_max_frame_ticks = g_frame_ticks;
        if (g_frame_ticks > g_budget_ticks)
            g_over_budget_frames++;
        if (!g_frame_had_eligible) {
            g_round++;
            g_rounds_done += g_round_compared;
            g_round_compared = false;
        }
        for (int i = 0; i < g_fn_count; i++)
            if (g_fns[i].frame_stamp == g_frame)
                g_fns[i].last_frame_calls = g_fns[i].frame_calls;
    }
    g_frame_had_eligible = false;
    g_frame_ticks = 0;
    g_frame++;
}

void shadow_get_status(ShadowStatus *st) {
    double ms = g_qpf.QuadPart ? 1000.0 / (double) g_qpf.QuadPart : 0.0;
    st->installed = 0;
    for (int i = 0; i < g_fn_count; i++)
        st->installed += g_fns[i].ready;
    st->enabled = g_enabled;
    st->anytime = g_anytime;
    st->budget_ms = g_budget_ms;
    st->every = g_every;
    st->compared = g_total_compared;
    st->mismatches = g_mismatch_total;
    st->quirks = g_quirk_total;
    st->total_ms = (double) g_ticks * ms;
    st->last_frame_ms = (double) g_last_frame_ticks * ms;
    st->worst_frame_ms = (double) g_max_frame_ticks * ms;
    st->over_budget_frames = g_over_budget_frames;
    st->rounds = g_rounds_done;
    st->foreign_waits = g_foreign_waits;
}

int shadow_function_count(void) {
    return g_fn_count;
}

bool shadow_get_function(int i, ShadowFunctionStats *out) {
    if (i < 0 || i >= g_fn_count)
        return false;
    const ShadowFn &fn = g_fns[i];
    double ms = g_qpf.QuadPart ? 1000.0 / (double) g_qpf.QuadPart : 0.0;
    out->name = fn.name;
    out->ready = fn.ready;
    out->disabled = fn.disabled;
    out->calls = fn.calls;
    out->compared = fn.compared;
    out->mismatches = fn.mismatches;
    out->warnings = fn.warnings;
    out->unreliable = fn.unreliable;
    out->quirks = fn.quirks;
    out->first_frame = fn.first_frame;
    out->avg_ms = fn.compared ? (double) fn.ticks * ms / fn.compared : 0.0;
    out->max_ms = (double) fn.max_ticks * ms;
    return true;
}

int shadow_recent_mismatches(const ShadowMismatch **out) {
    *out = g_recent;
    return g_recent_count;
}

void shadow_set_enabled(bool on) {
    g_enabled = on;
}

void shadow_set_anytime(bool on) {
    g_anytime = on;
}

void shadow_set_budget_ms(double ms) {
    g_budget_ms = ms > 0 ? ms : 0;
    g_budget_ticks = (int64_t) (g_budget_ms * (double) g_qpf.QuadPart / 1000.0);
}

void shadow_reset_stats(void) {
    for (int i = 0; i < g_fn_count; i++) {
        ShadowFn &fn = g_fns[i];
        fn.calls = fn.compared = fn.mismatches = fn.warnings = fn.unreliable = fn.quirks = 0;
        fn.first_frame = -1;
        fn.ticks = fn.max_ticks = 0;
        fn.round = 0;
    }
    g_total_compared = 0;
    g_mismatch_total = 0;
    g_quirk_total = 0;
    g_ticks = 0;
    g_max_frame_ticks = 0;
    g_over_budget_frames = 0;
    g_round = 1;
    g_rounds_done = 0;
    g_round_compared = false;
    g_recent_count = 0;
}

extern "C" void shadow_init(void) {
    read_config();
    hook_mode_shadow_entry = make_entry;
}

// Watchdog: when the game thread stops in the middle of a comparison, write where it is to
// shadow_watchdog.txt. Raw WriteFile on a stack buffer: the heaps may be locked or read-only.
static DWORD WINAPI shadow_watchdog(void *) {
    HANDLE main = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, g_thread);
    HANDLE f = CreateFileA("shadow_watchdog.txt", GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    LONG last = -1;
    int still = 0;
    for (;;) {
        Sleep(500);
        LONG hb = g_heartbeat;
        if (hb != last || g_phase == 0) {
            last = hb;
            still = 0;
            continue;
        }
        if (++still != 6)
            continue;
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        DWORD eip = 0, esp = 0;
        uint32_t stack[24] = {};
        if (main && SuspendThread(main) != (DWORD) -1) {
            if (GetThreadContext(main, &ctx)) {
                eip = ctx.Eip;
                esp = ctx.Esp;
                SIZE_T got;
                ReadProcessMemory(GetCurrentProcess(), (void *) esp, stack, sizeof(stack), &got);
            }
            ResumeThread(main);
        }
        char buf[1024];
        int n = snprintf(buf, sizeof(buf),
                         "stuck 3s in %s phase %d window %d protected %d eip %08lx esp %08lx foreign tid %lu eip %08lx "
                         "addr %08lx count %d\nstack:",
                         (const char *) g_cur_name, g_phase, g_window, g_protected, eip, esp, g_last_foreign_tid,
                         g_last_foreign_eip, g_last_foreign_addr, g_foreign);
        for (int i = 0; i < 24 && n < (int) sizeof(buf) - 12; i++)
            n += snprintf(buf + n, sizeof(buf) - n, " %08x", stack[i]);
        n += snprintf(buf + n, sizeof(buf) - n, "\n");
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(f, buf, (DWORD) n, &w, nullptr);
            FlushFileBuffers(f);
        }
    }
    return 0;
}

extern "C" void shadow_resolve(void) {
    if (g_fn_count == 0)
        return;
    log_open();
    g_thread = GetCurrentThreadId();
    QueryPerformanceFrequency(&g_qpf);
    g_budget_ticks = (int64_t) (g_budget_ms * (double) g_qpf.QuadPart / 1000.0);
    size_t pool = (size_t) kMaxPages * kPage * 3 + kMaxStackWindow * 3;
    g_pool_lo = (uint8_t *) VirtualAlloc(nullptr, pool, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_pool_lo) {
        fprintf(g_log, "shadow: cannot allocate %zu bytes of snapshot pool, disabled\n", pool);
        g_fn_count = 0;
        return;
    }
    g_pool_hi = g_pool_lo + pool;
    g_pre = g_pool_lo;
    g_post = g_pre + (size_t) kMaxPages * kPage;
    g_ours = g_post + (size_t) kMaxPages * kPage;
    g_stack_pre = g_ours + (size_t) kMaxPages * kPage;
    g_stack_post = g_stack_pre + kMaxStackWindow;
    g_stack_ours = g_stack_post + kMaxStackWindow;
    g_veh = AddVectoredExceptionHandler(1, shadow_veh);
    if (g_layout_cache)
        hook_layout_changes();
    CreateThread(nullptr, 0, shadow_watchdog, nullptr, 0, nullptr);

    for (auto &[key, info]: hooks) {
        uint32_t k = (uint32_t) key, dst = (uint32_t) info.address;
        if (k >= 0x10000000 && dst < 0x10000000)
            g_code_map.push_back({k, dst});// our body redirected to retail
        else if (dst >= 0x10000000 && k < 0x10000000)
            g_code_map.push_back({dst, k});// retail redirected to our body
    }
    for (int i = 0; i < g_fn_count; i++)
        g_code_map.push_back({g_fns[i].reimpl, g_fns[i].retail});
    std::sort(g_code_map.begin(), g_code_map.end());

    int ready = 0;
    for (int i = 0; i < g_fn_count; i++) {
        ShadowFn &fn = g_fns[i];
        auto r = hooks.find((void *) fn.retail);
        auto o = hooks.find((void *) fn.reimpl);
        // Set even when skipped: the retail entry may already lead to this entry, and a function
        // that is not ready passes its calls to the trampoline.
        if (r != hooks.end() && r->second.hook_state != (void *) fn.retail)
            fn.retail_orig = r->second.hook_state;
        if (r == hooks.end() || o == hooks.end() || r->second.hook_state == (void *) fn.retail ||
            o->second.hook_state == (void *) fn.reimpl) {
            fprintf(g_log, "shadow: %s not detoured, skipped\n", fn.name);
            continue;
        }
        fn.retail_orig = r->second.hook_state;
        if (!open_entry(fn.retail, fn.retail_entry) || !open_entry(fn.reimpl, fn.ours_entry)) {
            fprintf(g_log, "shadow: %s entry not patched as expected, skipped\n", fn.name);
            continue;
        }
        fn.ready = true;
        ready++;
    }
    fprintf(g_log, "shadow: %d of %d functions ready (limit %u per function, every %u%s", ready, g_fn_count, g_limit,
            g_every, g_anytime ? ", anytime" : ", lockstep races only");
    if (g_budget_ms > 0)
        fprintf(g_log, ", budget %.2f ms per frame", g_budget_ms);
    if (g_from_frame >= 0)
        fprintf(g_log, ", frames %d..%d", g_from_frame, g_to_frame);
    fprintf(g_log, ")\n");
    fflush(g_log);
}

extern "C" void shadow_report(void) {
    if (!g_log)
        return;
    double secs = g_qpf.QuadPart ? (double) g_ticks / (double) g_qpf.QuadPart : 0.0;
    fprintf(g_log, "\nSUMMARY %llu compared calls, %.1f s in shadow, %d foreign writes held until the end of a comparison\n",
            (unsigned long long) g_total_compared, secs, g_foreign_waits);
    if (g_budget_ticks > 0)
        fprintf(g_log, "budget: %u frames, %u rounds, worst frame %.2f ms, %u frames over budget\n", g_frame, g_rounds_done,
                (double) g_max_frame_ticks * 1000.0 / (double) g_qpf.QuadPart, g_over_budget_frames);
    int bad = 0, clean = 0, unseen = 0;
    for (int i = 0; i < g_fn_count; i++) {
        const ShadowFn &fn = g_fns[i];
        if (fn.compared == 0) {
            unseen++;
            continue;
        }
        if (fn.mismatches)
            bad++;
        else
            clean++;
        fprintf(g_log, "  %-44s %-5s calls %7u compared %7u mismatches %6u%s%s", fn.name, ret_name(fn.ret), fn.calls,
                fn.compared, fn.mismatches, fn.warnings ? " warn" : "", fn.unreliable ? " unreliable" : "");
        if (fn.quirks)
            fprintf(g_log, " known quirks %u", fn.quirks);
        if (fn.first_frame >= 0)
            fprintf(g_log, " first frame %d", fn.first_frame);
        fprintf(g_log, " avg %.2f max %.2f ms", (double) fn.ticks * 1000.0 / (double) g_qpf.QuadPart / fn.compared,
                (double) fn.max_ticks * 1000.0 / (double) g_qpf.QuadPart);
        fprintf(g_log, "\n");
    }
    fprintf(g_log, "TOTAL %d clean, %d mismatched, %d never called, %u known retail quirks\n", clean, bad, unseen,
            g_quirk_total);
    fflush(g_log);
}
