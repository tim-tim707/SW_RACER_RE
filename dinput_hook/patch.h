//
// Reversible memory-patch journal for the mod/delta layer (modding API, issue #153).
//
// Every sanctioned .text/.data mutation routes through here so it can be reverted by owner. Each
// write snapshots the bytes currently at the range before overwriting; UndoOwner() replays an
// owner's snapshots newest-first, so apply + undo is a clean inverse that restores stock and leaves
// the journal empty (even across repeated or overlapping same-owner writes). Two DIFFERENT owners
// may not patch overlapping bytes - the second write is refused and logged. That refusal is the
// corruption guard: "two mods stepping on the same memory" becomes a loud no-op instead of silent
// breakage. (Refcounted layering of intentional overlaps is a later phase; for now: one owner per
// byte.)
//
// `owner` is a short stable string ("ai_full_lod", "boot_window_reroute", ...). It is deliberately
// lightweight - the full mod registry (ModId/ModModule) is a later step, and this is only the key
// UndoOwner() reverts by.
//
#pragma once

#include <cstddef>
#include <cstdint>

typedef const char *PatchOwner;

// Overwrite [addr, addr+len) with `src`, first snapshotting the bytes currently at that range.
// Flips page protection to RWX for the copy and restores it after. Returns false and writes
// NOTHING if the range overlaps a different owner's live patch (the conflict is logged).
bool WriteMemory(PatchOwner owner, void *addr, const void *src, size_t len);

// Owner-tracked single-dword patch (the journaled form of patchMemoryAccess): writes `value` as
// 4 bytes at `addr` (an IAT / vtable / relative-call slot). Same journaling + overlap rules.
bool PatchPointer(PatchOwner owner, void *addr, uint32_t value);

// Revert every journal entry owned by `owner` (newest first), restoring captured originals, then
// drop those entries. No-op if the owner holds nothing journaled.
void UndoOwner(PatchOwner owner);
