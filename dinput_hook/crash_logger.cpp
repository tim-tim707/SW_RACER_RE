#include "crash_logger.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <io.h>// _get_osfhandle / _fileno

#include "hook_helper.h"// hook_log

// Render-thread must make progress at least this often once frames start; a longer stall is
// treated as a hang. Log-only, so a rare false trip during a legitimately long stall just leaves
// a spurious file.
static const int HANG_TIMEOUT_MS = 15000;

// Before the first frame renders, the main thread should reach its first present within this
// long even on a slow Wine/Mac cold start. Overshooting it means startup is wedged (device or
// window creation, the Wine graphics layer, ...), so we snapshot the main thread. Generous
// because it is the "mod won't start" path and a false trip is only a spurious file.
static const int STARTUP_TIMEOUT_MS = 45000;

// Most recent boot/init milestone, echoed into every crash/hang report so a silent early failure
// still shows how far startup got. Set via crash_logger_stage() from the main thread and read
// from the crash filter / watchdog; a plain pointer swap is atomic on x86 and the strings are
// static literals, so no lock is needed.
static const char *volatile g_last_stage = "pre-init";

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

// Stamp the runtime environment so a report shared by a Wine/Mac user self-describes. ntdll
// exports wine_get_version only under Wine; absent means native Windows.
static void write_env_line(HANDLE out) {
    typedef const char *(__cdecl * wine_get_version_t)(void);
    typedef void(__cdecl * wine_get_host_version_t)(const char **sysname, const char **release);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    wine_get_version_t get_ver =
        ntdll ? (wine_get_version_t) (void *) GetProcAddress(ntdll, "wine_get_version") : nullptr;
    if (!get_ver) {
        write_fmt(out, "  environment: native Windows\n");
        return;
    }
    const char *ver = get_ver();
    const char *sysname = "?";
    const char *release = "?";
    wine_get_host_version_t get_host =
        (wine_get_host_version_t) (void *) GetProcAddress(ntdll, "wine_get_host_version");
    if (get_host)
        get_host(&sysname, &release);
    write_fmt(out, "  environment: Wine %s on %s %s\n", ver ? ver : "?", sysname, release);
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
    write_env_line(out);
    write_fmt(out, "  last stage: %s\n", g_last_stage);
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
// Hang watchdog. A background thread watches two phases: before the first frame it guards the
// main thread against a startup that never reaches a frame; once frames begin it watches the
// render thread's per-frame heartbeat. Either way it only snapshots where the thread is frozen
// (never kills it), so a false trip is harmless.
// ---------------------------------------------------------------------------------------------

static volatile LONG g_heartbeat = 0;
static HANDLE g_render_thread = nullptr; // captured on the first frame; watched while running
static HANDLE g_startup_thread = nullptr;// captured at init; watched before the first frame
static volatile LONG g_render_thread_ready = 0;

static void capture_hang(HANDLE thread, const char *kind, const char *headline, int seconds) {
    // Suspend only long enough to grab the register context (a kernel call), then resume before
    // writing the report. Report I/O uses raw Win32 file handles (see write_fmt), so it cannot
    // deadlock on a CRT lock the frozen thread may hold; the trailing hook.log write is
    // best-effort. A truly stuck thread's stack stays put, so the post-resume scan is stable.
    if (!thread || SuspendThread(thread) == (DWORD) -1)
        return;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    const BOOL got = GetThreadContext(thread, &ctx);
    ResumeThread(thread);
    if (!got)
        return;

    char path[MAX_PATH] = {0};
    HANDLE cf = open_report_file(kind, path, sizeof(path));
    if (cf != INVALID_HANDLE_VALUE) {
        write_fmt(cf, headline, seconds);
        write_env_line(cf);
        write_fmt(cf, "  last stage: %s\n", g_last_stage);
        write_fmt(cf, "  frozen instruction:\n");
        log_addr(cf, (void *) (UINT_PTR) ctx.Eip);
        log_stack_scan(cf, ctx.Esp);
        write_fmt(cf, "*** end %s report ***\n", kind);
        CloseHandle(cf);
    }
    if (hook_log) {
        fprintf(hook_log, "\n*** %s (%d s) -> %s ***\n", kind, seconds, path);
        fflush(hook_log);
    }
}

static DWORD WINAPI watchdog_thread(LPVOID) {
    int startup_ms = 0;
    bool startup_reported = false;
    LONG last = 0;
    int stalled_ms = 0;
    bool reported = false;
    for (;;) {
        Sleep(1000);
        if (!g_render_thread_ready) {
            // Startup phase: no frame has rendered yet. If the first frame never arrives, the
            // main thread is wedged in init (device/window creation, the Wine graphics layer) --
            // snapshot it so the report shows where startup froze.
            startup_ms += 1000;
            if (startup_ms >= STARTUP_TIMEOUT_MS && !startup_reported && g_startup_thread) {
                startup_reported = true;
                capture_hang(g_startup_thread, "startup",
                             "*** startup hang: no first frame in %d s -- main thread frozen in "
                             "init ***\n",
                             STARTUP_TIMEOUT_MS / 1000);
            }
            continue;
        }
        // Running phase: the render thread must bump the heartbeat each frame.
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
            capture_hang(g_render_thread, "hang",
                         "*** hang detected: render thread made no progress for %d s ***\n",
                         HANG_TIMEOUT_MS / 1000);
        }
    }
    return 0;
}

static volatile LONG g_watchdog_started = 0;

// Spawn the watchdog exactly once, whichever of crash_logger_start() (normal) or the first
// heartbeat (fallback) reaches here first.
static void start_watchdog_once(void) {
    if (InterlockedExchange(&g_watchdog_started, 1) == 0)
        CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
}

// ---------------------------------------------------------------------------------------------

void crash_logger_install(void) {
    // Just the top-level filter -- safe to register from DllMain, and early enough to catch a
    // crash anywhere in startup. The watchdog thread is started later (crash_logger_start),
    // off the loader lock.
    SetUnhandledExceptionFilter(unhandled_filter);
}

void crash_logger_start(void) {
    // Runs once from the game's early init hook (after the loader lock is released, before
    // renderer and device init). Capture the main thread and start the watchdog now -- so a hang
    // BEFORE the first rendered frame is still caught -- and stamp the environment to hook.log so
    // even a report with no crash/hang says whether it is Wine.
    static volatile LONG started = 0;
    if (InterlockedExchange(&started, 1) != 0)
        return;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                    &g_startup_thread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, 0);
    if (hook_log) {
        fflush(hook_log);
        write_env_line(hook_log_handle());
    }
    start_watchdog_once();
}

void crash_logger_stage(const char *name) {
    // Record the latest boot/init milestone (echoed into every crash/hang report) and breadcrumb
    // it to hook.log. `name` must be a static string -- it is stored, not copied.
    g_last_stage = name;
    if (hook_log) {
        fprintf(hook_log, "[stage] %s\n", name);
        fflush(hook_log);
    }
}

void crash_logger_heartbeat(void) {
    // Re-assert our filter each frame: if the game's CRT startup installed its own top-level
    // filter over ours, this puts ours back on top so in-game crashes still reach us. Cheap
    // (one syscall) next to a rendered frame, and idempotent once ours is already active.
    SetUnhandledExceptionFilter(unhandled_filter);

    if (!g_render_thread_ready) {
        // First frame: capture a handle to the render thread for the watchdog to snapshot, and
        // hand off from the startup guard to per-frame hang detection. Only flip ready once we
        // actually hold the handle -- otherwise the watchdog would snapshot a null thread -- so
        // on a (rare) DuplicateHandle failure we retry next frame.
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                            &g_render_thread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE,
                            0) &&
            g_render_thread) {
            g_render_thread_ready = 1;
            crash_logger_stage("running (first frame)");
            start_watchdog_once();// fallback in case crash_logger_start() never ran
        }
    }
    InterlockedIncrement(&g_heartbeat);
}
