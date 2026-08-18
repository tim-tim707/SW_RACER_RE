#pragma once

// One-shot, asynchronous "is there a newer release?" check against the GitHub
// Releases API. All network I/O runs on a background worker thread; the UI side
// only polls a result that the worker fills. See update_check.cpp.

#ifdef __cplusplus
extern "C" {
#endif

// Kick off the background check. Safe to call once at startup; a no-op if it has
// already been started or if the user opted out (ini [settings] check_updates=0).
void update_check_start(void);

// Join the worker thread. Call once on shutdown before the process exits -- the
// teardown path uses ExitProcess(), so the static thread is never joined for us.
// WinHTTP timeouts bound the wait; in practice the one-shot GET is long done.
void update_check_join(void);

#ifdef __cplusplus
}

#include <string>

// If the worker found a release newer than MOD_VERSION, fills *out_latest with
// its tag (e.g. "v0.16") and *out_url with the release page URL, then returns
// true. Returns false while still checking, when up to date, or when offline.
// Cheap to poll every frame from the render thread.
bool update_check_get_result(std::string *out_latest, std::string *out_url);
#endif
