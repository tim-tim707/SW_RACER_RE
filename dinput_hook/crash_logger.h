#pragma once

// Diagnostic crash/hang capture for the dinput hook.
//
// On any unhandled (fatal) exception, and on a detected render-thread hang, a uniquely-named,
// timestamped report is written under
// crashes/ (crash_YYYYMMDD_HHMMSS_mmm.log / hang_...). Because each report is its own file it
// survives relaunching, so players can share it with the dev team after the game restarts.
//
// crash_logger_install() must run as early as possible in DllMain, before anything that can
// fault, so even crashes deep in startup are captured. crash_logger_heartbeat() must be called
// once per rendered frame; the hang watchdog uses it to tell a frozen game from a slow one.

#ifdef __cplusplus
extern "C" {
#endif

void crash_logger_install(void);
void crash_logger_heartbeat(void);

#ifdef __cplusplus
}
#endif
