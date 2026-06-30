//
// Lightweight INI-style config for the mod/delta layer (modding API, issue #153).
//
// Replaces the Win32 GetPrivateProfile* / WritePrivateProfile* calls with a portable parser that
// round-trips the file: comments, blank lines, ordering and unrecognised keys all survive a save
// (the Win32 API gave no control over the file's shape and tied the mod layer to Windows). It backs
// the same SW_RACER_RE.ini next to the exe, same `[section]` / `key=value` layout, so existing
// configs load unchanged. ';' and '#' begin a comment; section/key lookups are case-insensitive.
//
#pragma once

#include <string>

namespace config {
    // Absolute path to SW_RACER_RE.ini (next to the exe), resolved once.
    const std::wstring &path();

    // (Re)parse the file from disk. Called lazily on first access; call directly to pick up an
    // external edit. Preserves the on-disk layout for the next save().
    void reload();

    // Typed reads. Return `fallback` when the section/key is absent or unparseable.
    int get_int(const char *section, const char *key, int fallback);
    float get_float(const char *section, const char *key, float fallback);
    std::string get_string(const char *section, const char *key, const char *fallback);

    // In-memory writes (create the section/key if needed). Call save() to flush to disk.
    void set_int(const char *section, const char *key, int value);
    void set_float(const char *section, const char *key, float value);
    void set_bool(const char *section, const char *key, bool value);// writes "1" / "0"
    void set_string(const char *section, const char *key, const std::string &value);

    // Write the in-memory model back to disk, preserving comments + key order.
    void save();
}
