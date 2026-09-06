#pragma once

// One-shot async release check against the GitHub Releases API. All network I/O is on a worker
// thread; the UI side only polls a result.

#ifdef __cplusplus
extern "C" {
#endif

// No-op if already started or if the user opted out (ini [settings] check_updates=0).
void update_check_start(void);

// Must be called on shutdown: the teardown path uses ExitProcess(), so the thread is never
// joined for us. WinHTTP timeouts bound the wait.
void update_check_join(void);

#ifdef __cplusplus
}

#include <string>

// True only when a release newer than MOD_VERSION was found, filling *out_latest (tag) and
// *out_url. False while checking, up to date, or offline. Cheap to poll every frame.
bool update_check_get_result(std::string *out_latest, std::string *out_url);
#endif
