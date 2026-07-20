#include "crash_logger.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <io.h>// _get_osfhandle / _fileno

#include "hook_helper.h"// hook_log

// Render-thread must make progress at least this often; a longer stall is treated as a hang.
// Log-only, so a rare false trip during a legitimately long stall just leaves a spurious file.
static const int HANG_TIMEOUT_MS = 15000;

// ---------------------------------------------------------------------------------------------
// Shared report writers. Everything writes through write_fmt to a caller-supplied Win32 file
// HANDLE (never a CRT FILE): the crash filter runs on the faulting thread and the hang watchdog
// snapshots a possibly-stuck thread, so either may run while the CRT heap or stdio lock is held
// by the very thread we are reporting on. fopen/fprintf would re-acquire that lock and deadlock;
// CreateFileA/WriteFile take neither, and vsnprintf into a stack buffer allocates nothing.
// ---------------------------------------------------------------------------------------------

// Formatted append to a raw file HANDLE -- stack buffer + WriteFile only, no CRT heap/stream lock.
static void write_fmt(HANDLE out, const char *fmt, ...) {
    if (out == INVALID_HANDLE_VALUE || out == nullptr)
        return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int) sizeof(buf) - 1)
        n = sizeof(buf) - 1;// vsnprintf returns the would-be length; clamp to what we buffered
    DWORD written = 0;
    WriteFile(out, buf, (DWORD) n, &written, nullptr);
}

static void log_addr(HANDLE out, void *addr) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR) addr, &mod) &&
        mod) {
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(mod, path, MAX_PATH);
        const char *name = strrchr(path, '\\');
        name = name ? name + 1 : path;
        write_fmt(out, "    %p  %s+0x%lx\n", addr, name,
                  (unsigned long) ((UINT_PTR) addr - (UINT_PTR) mod));
    } else {
        write_fmt(out, "    %p  (no module)\n", addr);
    }
}

static bool addr_is_code(void *addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    const DWORD prot = mbi.Protect & 0xff;
    return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_EXECUTE_WRITECOPY;
}

// Heuristic: any committed-executable value on the stack is a likely return address. May include
// false positives (data that looks like a code address); the genuine frames form the call chain.
static void log_stack_scan(HANDLE out, UINT_PTR esp) {
    write_fmt(out, "  on-stack code addresses:\n");
    UINT_PTR *sp = (UINT_PTR *) esp;
    int logged = 0;
    for (int i = 0; i < 8192 && logged < 64; i++) {
        if (IsBadReadPtr(&sp[i], sizeof(UINT_PTR)))
            break;
        const UINT_PTR val = sp[i];
        if (val > 0x10000 && addr_is_code((void *) val)) {
            log_addr(out, (void *) val);
            logged++;
        }
    }
}

static void write_exception_report(HANDLE out, const EXCEPTION_RECORD *er, UINT_PTR esp) {
    write_fmt(out, "*** unhandled exception: code=0x%08lx addr=%p ***\n", er->ExceptionCode,
              er->ExceptionAddress);
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        write_fmt(out, "    access %s at %p\n", er->ExceptionInformation[0] ? "write" : "read",
                  (void *) er->ExceptionInformation[1]);
    }
    write_fmt(out, "  faulting instruction:\n");
    log_addr(out, er->ExceptionAddress);
    log_stack_scan(out, esp);
    write_fmt(out, "*** end crash report ***\n");
}

// Open crashes\<kind>_YYYYMMDD_HHMMSS_mmm.log. The millisecond field keeps two reports in the
// same second (e.g. a hang then a crash) from colliding. Returns INVALID_HANDLE_VALUE on failure;
// the chosen path is copied into out_path for the pointer line written to hook.log.
static HANDLE open_report_file(const char *kind, char *out_path, size_t out_path_size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    CreateDirectoryA("crashes", nullptr);// ignore ERROR_ALREADY_EXISTS
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "crashes\\%s_%04u%02u%02u_%02u%02u%02u_%03u.log", kind, st.wYear,
             st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (out_path && out_path_size)
        snprintf(out_path, out_path_size, "%s", path);
    return CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

// Best-effort raw HANDLE onto hook.log's underlying file, for the fallback path only. The caller
// must fflush(hook_log) first so buffered CRT output lands before our WriteFile appends to it.
static HANDLE hook_log_handle(void) {
    if (!hook_log)
        return INVALID_HANDLE_VALUE;
    return (HANDLE) (UINT_PTR) _get_osfhandle(_fileno(hook_log));
}

// ---------------------------------------------------------------------------------------------
// Fatal-exception capture. The top-level unhandled filter is the single entry point: anything
// reaching it is by definition unhandled -> fatal (a first-chance vectored handler was tried but
// abandoned; see the note below unhandled_filter).
//
// A one-shot latch means the process writes at most one crash report: the first fatal fault wins.
// This collapses any secondary fault that occurs while the OS is already tearing the process down
// into a single shareable file. Trade-off: a fatal exception the game somehow recovers from would
// latch and suppress a later report -- acceptable, as the game rarely handles access violations
// and a genuinely fatal crash is the process's last act anyway.
// ---------------------------------------------------------------------------------------------

static volatile LONG g_crash_reported = 0;

static void report_crash(EXCEPTION_POINTERS *ep) {
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    const UINT_PTR esp = ep->ContextRecord->Esp;

    // Write the standalone crash file first, via Win32 file I/O only, so a crash that faulted
    // while holding the CRT heap lock -- the most common native crash -- still produces a report
    // where fopen/fprintf would have deadlocked re-entering the allocator.
    char path[MAX_PATH] = {0};
    HANDLE cf = open_report_file("crash", path, sizeof(path));
    if (cf != INVALID_HANDLE_VALUE) {
        write_exception_report(cf, er, esp);
        CloseHandle(cf);
    }

    // hook.log is a shared CRT stream used across the hook; touch it last and best-effort. The
    // crash file above is already safe, so nothing is lost if these stdio calls block on a lock
    // the faulting thread happens to hold. Flush first so buffered pre-crash lines survive.
    if (hook_log) {
        fflush(hook_log);
        if (cf != INVALID_HANDLE_VALUE) {
            fprintf(hook_log, "\n*** crash: code=0x%08lx addr=%p -> %s ***\n", er->ExceptionCode,
                    er->ExceptionAddress, path);
            fflush(hook_log);
        } else {
            // Crash file could not be created -- append the full report to hook.log's OS handle
            // (WriteFile, no heap lock), landing after the just-flushed pre-crash lines.
            write_exception_report(hook_log_handle(), er, esp);
        }
    }
}

static LONG WINAPI unhandled_filter(EXCEPTION_POINTERS *ep) {
    // Anything reaching the top-level filter is by definition unhandled -> fatal, so report it.
    // The latch collapses any secondary fault raised while the process is already tearing down
    // into the single first report.
    if (InterlockedExchange(&g_crash_reported, 1) == 0)
        report_crash(ep);
    return EXCEPTION_CONTINUE_SEARCH;// let WER / the normal crash path proceed
}

// A first-chance vectored handler was tried here but abandoned: routine code (IsBadReadPtr, the
// D3D wrapper's SEH probes, ...) raises access violations it handles itself, and a VEH cannot
// tell those from a real crash at first-chance time -> a flood of bogus reports. The top-level
// filter only sees genuinely unhandled (fatal) exceptions. To stay robust against the game's CRT
// installing its own top-level filter over ours, crash_logger_heartbeat() re-asserts ours each
// frame (see below).

// ---------------------------------------------------------------------------------------------
// Hang watchdog. The render thread bumps g_heartbeat once per frame; a background thread that
// sees it stall past HANG_TIMEOUT_MS snapshots the render thread's context and logs where it is
// frozen. It only logs (never kills the thread), so a false trip is harmless.
// ---------------------------------------------------------------------------------------------

static volatile LONG g_heartbeat = 0;
static HANDLE g_render_thread = nullptr;
static volatile LONG g_render_thread_ready = 0;

static void capture_hang(void) {
    // Suspend only long enough to grab the register context (a kernel call), then resume before
    // writing the report. Report I/O uses raw Win32 file handles (see write_fmt), so it cannot
    // deadlock on a CRT lock the hung render thread may hold; the trailing hook.log write is
    // best-effort. A truly hung thread's stack stays put, so the post-resume scan is stable.
    if (SuspendThread(g_render_thread) == (DWORD) -1)
        return;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    const BOOL got = GetThreadContext(g_render_thread, &ctx);
    ResumeThread(g_render_thread);
    if (!got)
        return;

    char path[MAX_PATH] = {0};
    HANDLE cf = open_report_file("hang", path, sizeof(path));
    if (cf != INVALID_HANDLE_VALUE) {
        write_fmt(cf, "*** hang detected: render thread made no progress for %d s ***\n",
                  HANG_TIMEOUT_MS / 1000);
        write_fmt(cf, "  frozen instruction:\n");
        log_addr(cf, (void *) (UINT_PTR) ctx.Eip);
        log_stack_scan(cf, ctx.Esp);
        write_fmt(cf, "*** end hang report ***\n");
        CloseHandle(cf);
    }
    if (hook_log) {
        fprintf(hook_log, "\n*** hang detected (%d s) -> %s ***\n", HANG_TIMEOUT_MS / 1000, path);
        fflush(hook_log);
    }
}

static DWORD WINAPI watchdog_thread(LPVOID) {
    LONG last = 0;
    int stalled_ms = 0;
    bool reported = false;
    for (;;) {
        Sleep(1000);
        if (!g_render_thread_ready)
            continue;// frames not started yet
        const LONG now = g_heartbeat;
        if (now != last) {
            last = now;
            stalled_ms = 0;
            reported = false;
            continue;
        }
        stalled_ms += 1000;
        if (stalled_ms >= HANG_TIMEOUT_MS && !reported) {
            reported = true;// one report per stall; re-arms when the heartbeat moves again
            capture_hang();
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------

void crash_logger_install(void) {
    // Just the top-level filter -- safe to register from DllMain, and early enough to catch a
    // crash anywhere in startup. The watchdog thread is spawned lazily on the first heartbeat
    // instead, off the render thread and clear of the loader lock.
    SetUnhandledExceptionFilter(unhandled_filter);
}

void crash_logger_heartbeat(void) {
    // Re-assert our filter each frame: if the game's CRT startup installed its own top-level
    // filter over ours, this puts ours back on top so in-game crashes still reach us. Cheap
    // (one syscall) next to a rendered frame, and idempotent once ours is already active.
    SetUnhandledExceptionFilter(unhandled_filter);

    if (!g_render_thread_ready) {
        // First frame: capture a handle to the render thread for the watchdog to snapshot, then
        // start the watchdog now that frames (and thus hang detection) are meaningful. Only arm
        // the watchdog once we actually hold the handle -- otherwise it would spin uselessly, so
        // on a (rare) DuplicateHandle failure we simply retry on the next frame.
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                            &g_render_thread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE,
                            0) &&
            g_render_thread) {
            g_render_thread_ready = 1;
            CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
        }
    }
    InterlockedIncrement(&g_heartbeat);
}
