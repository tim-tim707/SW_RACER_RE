#pragma once

// Diagnostic crash/hang capture for the dinput hook.
//
// On any unhandled (fatal) exception, and on a detected hang -- whether the game froze mid-play
// or never reached its first frame -- a uniquely-named, timestamped report is written under
// crashes/ (crash_/hang_/startup_ YYYYMMDD_HHMMSS_mmm.log). Because each report is its own file
// it survives relaunching, so players can share it with the dev team after the game restarts.
// Every report stamps the environment (Wine version + host OS, or native Windows) and the last
// init milestone reached, so a "won't start" report from a Wine/Mac user is self-describing.
//
// Call order:
//   crash_logger_install()   -- first thing in DllMain, before anything can fault, so even a
//                               crash deep in startup is captured.
//   crash_logger_start()     -- once from the game's early init hook (after the loader lock is
//                               released, before renderer/device init); arms the startup hang
//                               watchdog and stamps the environment.
//   crash_logger_stage(name) -- at boot/init milestones; `name` must be a static string. The
//                               most recent one is echoed into every report.
//   crash_logger_heartbeat() -- once per rendered frame; drives per-frame hang detection.

#ifdef __cplusplus
extern "C" {
#endif

void crash_logger_install(void);
void crash_logger_start(void);
void crash_logger_stage(const char *name);
void crash_logger_heartbeat(void);

#ifdef __cplusplus
}
#endif
