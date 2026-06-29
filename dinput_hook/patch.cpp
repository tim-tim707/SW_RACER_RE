//
// Reversible memory-patch journal (modding API, issue #153). See patch.h.
//
#include "patch.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include <windows.h>

extern "C" FILE *hook_log;

namespace {
    struct JournalEntry {
        PatchOwner owner;             // matched by string value, not pointer
        uintptr_t addr;
        std::vector<uint8_t> original;// bytes snapshotted immediately before this write
    };

    std::vector<JournalEntry> g_journal;

    bool same_owner(PatchOwner a, PatchOwner b) {
        if (a == b)
            return true;
        return a && b && std::strcmp(a, b) == 0;
    }

    bool ranges_overlap(uintptr_t a, size_t alen, uintptr_t b, size_t blen) {
        return a < b + blen && b < a + alen;
    }

    void raw_write(void *addr, const void *src, size_t len) {
        DWORD oldProtect;
        VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(addr, src, len);
        VirtualProtect(addr, len, oldProtect, &oldProtect);
    }
}

bool WriteMemory(PatchOwner owner, void *addr, const void *src, size_t len) {
    if (!addr || !src || len == 0)
        return false;

    const uintptr_t a = (uintptr_t) addr;

    // Corruption guard: refuse to clobber a DIFFERENT owner's live patch. Same-owner overlaps are
    // allowed - they just stack, and UndoOwner unwinds them newest-first back to the original.
    for (const JournalEntry &e: g_journal) {
        if (ranges_overlap(a, len, e.addr, e.original.size()) && !same_owner(owner, e.owner)) {
            if (hook_log) {
                fprintf(hook_log,
                        "[patch] CONFLICT: '%s' [%p,+0x%zx) overlaps '%s' at %p - refused\n",
                        owner ? owner : "(null)", addr, len, e.owner ? e.owner : "(null)",
                        (void *) e.addr);
                fflush(hook_log);
            }
            return false;
        }
    }

    // Snapshot the bytes currently at the range, then patch. UndoOwner replays an owner's snapshots
    // newest-first, so apply + undo is a clean inverse - even across repeated/overlapping writes.
    JournalEntry e;
    e.owner = owner;
    e.addr = a;
    e.original.assign((const uint8_t *) addr, (const uint8_t *) addr + len);
    g_journal.push_back(e);
    if (hook_log) {
        fprintf(hook_log, "[patch] '%s' patched [%p,+0x%zx)\n", owner ? owner : "(null)", addr, len);
        fflush(hook_log);
    }

    raw_write(addr, src, len);
    return true;
}

bool PatchPointer(PatchOwner owner, void *addr, uint32_t value) {
    return WriteMemory(owner, addr, &value, sizeof(value));
}

void UndoOwner(PatchOwner owner) {
    // Restore newest-first so stacked/overlapping ranges unwind in reverse order, then drop the
    // entries - apply + undo leaves no trace in the journal.
    for (size_t i = g_journal.size(); i-- > 0;) {
        const JournalEntry &e = g_journal[i];
        if (same_owner(e.owner, owner))
            raw_write((void *) e.addr, e.original.data(), e.original.size());
    }
    g_journal.erase(std::remove_if(g_journal.begin(), g_journal.end(),
                                   [&](const JournalEntry &e) {
                                       return same_owner(e.owner, owner);
                                   }),
                    g_journal.end());
}
