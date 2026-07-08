//
// Extensible roster foundation. See swrRoster_delta.h for the design.
//
#include "swrRoster_delta.h"

extern "C" {
#include <macros.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <globals.h>
}

#include "../patch.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include <windows.h>

extern "C" FILE *hook_log;
extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *new_function);

namespace {
    constexpr const char *kOwner = "extensible_roster";

    // ---- roster sizing -------------------------------------------------------------------------
    constexpr int kStockCount = 23;      // pilots baked into the retail tables (ids 0..22)
    constexpr int kRosterCapacity = 25;  // heap array capacity (headroom is trivial to raise)
    constexpr int kRosterCount = 25;     // pilots offered in the menu (stock 23 + Jinn + Cy)

    // ---- the four relocated tables -------------------------------------------------------------
    // Raw byte arrays sized by the exact retail stride so a reader's `base + id*stride + field`
    // math lands identically in the new array. Only the seeding of ids 23/24 casts to swrRacerData.
    constexpr uintptr_t kPodDataAddr = 0x004c2700;  constexpr int kPodDataStride = 0x34;
    constexpr uintptr_t kHandlingAddr = 0x004c2bb0; constexpr int kHandlingStride = 0x3c;
    constexpr uintptr_t kXformAddr = 0x004c7088;    constexpr int kXformStride = 0x6c;
    constexpr uintptr_t kSelIndexAddr = 0x00e99240; constexpr int kSelIndexStride = 0x08;

    alignas(16) uint8_t g_podData[kRosterCapacity * kPodDataStride];
    alignas(16) uint8_t g_handling[kRosterCapacity * kHandlingStride];
    alignas(16) uint8_t g_xform[kRosterCapacity * kXformStride];
    alignas(16) uint8_t g_selIndex[kRosterCapacity * kSelIndexStride];

    // Private roster-size constant for the two random-racer picks in BuildRosterSinglePlayer (demo
    // attract pick + AI-opponent pick). They scale a [0,1) random by the roster size held in a
    // shared 23.0f constant at 0x4ad0ac -- shared with swrObjHang_LoadScreenAssets, so we don't
    // touch it globally; instead we repoint just these two FMUL operands at our own count so AI
    // opponents (and attract mode) can roll the two appended pilots. (The builder's unlock gate
    // starts uVar8 = 0x0FFFFFFF, i.e. bits 0..27 preset, so 23/24 already pass it.)
    alignas(4) float g_racerCountF = (float) kRosterCount;
    constexpr uintptr_t kSharedCountConst = 0x004ad0ac; // 23.0f
    const uint32_t kRandCountSites[] = {
        0x0045b822, // BuildRosterSinglePlayer demo/attract random pick
        0x0045b855, // BuildRosterSinglePlayer AI-opponent random pick
    };

    // Per-player unlock bitmask (int per player, stride 0x50 bytes). 0x00022e01 is the stock
    // always-available set. The two secret pilots are variants of their host slots, so each unlocks
    // WITH its host rather than always: Jinn Reeso (23) tracks Mars Guo (8), Cy Yunga (24) tracks
    // Bullseye (22). derive_unlock_mask() folds that in.
    constexpr uintptr_t kUnlockMaskAddr = 0x00e35a94;
    constexpr int kUnlockPlayerStride = 0x50;
    constexpr uint32_t kStockAlwaysMask = 0x00022e01u;
    constexpr int kJinnId = 23, kJinnHostId = 8;   // Mars Guo
    constexpr int kCyId = 24, kCyHostId = 22;       // Bullseye

    uint32_t derive_unlock_mask(uint32_t stored) {
        uint32_t m = stored | kStockAlwaysMask;
        if (stored & (1u << kJinnHostId))
            m |= (1u << kJinnId);
        if (stored & (1u << kCyHostId))
            m |= (1u << kCyId);
        return m;
    }

    struct RelocTable {
        uintptr_t oldBase;
        uintptr_t extent;  // bytes of the stock region a reader's operand may fall in
        uint8_t *newBase;
    };
    // 0/1/2 match the `table` column in kPodSites; 3 = SelectIndex; 4 = the roster-size constant.
    RelocTable g_reloc[5];

    void init_reloc_tables() {
        g_reloc[0] = {kPodDataAddr, (uintptr_t) kStockCount * kPodDataStride, g_podData};
        g_reloc[1] = {kHandlingAddr, (uintptr_t) kStockCount * kHandlingStride, g_handling};
        g_reloc[2] = {kXformAddr, (uintptr_t) kStockCount * kXformStride, g_xform};
        g_reloc[3] = {kSelIndexAddr, (uintptr_t) kStockCount * kSelIndexStride, g_selIndex};
        g_reloc[4] = {kSharedCountConst, 4, (uint8_t *) &g_racerCountF};
    }

    // ---- operand-patch site lists (from an exhaustive Ghidra xref scan of the three tables) ------
    // Each entry is (instruction address, relocated-table index). The disp32/imm32 the instruction
    // encodes is the only 4-byte value inside it that lands in the stock table extent; we find it
    // and shift it by (newBase - oldBase). 110 reader instructions across the 3 per-character
    // tables; the 12 SelectIndex readers (table 3) follow.
    struct PodSite {
        uint32_t instr;
        int table;
    };
    const PodSite kPodSites[] = {
#include "swrRoster_sites.inc"
    };

    const uint32_t kSelIndexSites[] = {
#include "swrRoster_selindex_sites.inc"
    };

    // Find the table-address immediate inside `instr`: the lowest offset in [0,8) whose LE dword
    // falls in [lo, hi). x86 encodes the disp32/imm32 as the only in-range value; the opcode/modrm/
    // sib bytes ahead of it never form a 0x004cXXXX value, so the first in-range hit is this
    // instruction's operand. A MISS is expected and benign: the xref scan (Ghidra /xrefs_to) also
    // reports analysis-inferred references from register-relative accesses -- e.g. the pilot-sprite
    // loop's `MOV EAX,[EBP]` (0x457bdb) that Ghidra attributes to PodData[1], where EBP was loaded
    // as a literal one instruction earlier (0x457bd6, patched) and walked by `ADD EBP,0x34`. Those
    // carry no literal to patch; they ride the already-relocated base pointer, so we skip them.
    bool find_operand(uintptr_t instr, uintptr_t lo, uintptr_t hi, uintptr_t *pos, uint32_t *val) {
        for (int off = 0; off < 8; off++) {
            uint32_t v;
            std::memcpy(&v, (const void *) (instr + off), 4);
            if (v >= lo && v < hi) {
                *pos = instr + off;
                *val = v;
                return true;
            }
        }
        return false;
    }

    // ---- secret-pilot seed data (lifted verbatim from swrRace_ReplaceMarsGuoWithJinnReeso @0x44b530
    // and swrRace_ReplaceBullseyeWithCyYunga @0x44b5e0) --------------------------------------------
    // The stock swaps override 6 swrRacerData fields on the host slot and rewrite that host's entry
    // in the engine-xform table; handling is left as the host's. We reproduce exactly that, but into
    // the appended ids 23/24 instead of clobbering slots 8/22, so Mars Guo / Bullseye stay intact.
    struct XformWrite {
        int off;
        uint32_t bits;
    };
    // Host slot 8 (Mars Guo) engine-xform overrides -> Jinn Reeso.
    const XformWrite kJinnXform[] = {
        {0x0c, 0x408dc28f}, {0x24, 0x3fa147ae}, {0x28, 0x3e75c28f}, {0x2c, 0xbeeb851f},
        {0x30, 0x3e851eb8}, {0x34, 0xc068f5c3}, {0x38, 0xbe9eb852}, {0x3c, 0x400e147b},
        {0x40, 0x4031eb85}, {0x44, 0x00000000},
    };
    // Host slot 22 (Bullseye) engine-xform overrides -> Cy Yunga.
    const XformWrite kCyXform[] = {
        {0x30, 0xbda3d70a}, {0x34, 0xbfd47ae1}, {0x38, 0x4009999a},
        {0x3c, 0x3f851eb8}, {0x40, 0x40051eb8}, {0x44, 0xbf8a3d71},
    };

    void seed_secret_pilot(int id, int hostId, MODELID pod, MODELID altPod, MODELID puppet,
                           uintptr_t nameAddr, uintptr_t lastNameAddr, uint32_t unkc0,
                           const XformWrite *xform, int xformCount) {
        // Start each new pilot as a byte-copy of its host slot (matches the stock swap), then
        // override the identity fields and the engine-xform tuning.
        std::memcpy(g_podData + id * kPodDataStride, g_podData + hostId * kPodDataStride, kPodDataStride);
        std::memcpy(g_handling + id * kHandlingStride, g_handling + hostId * kHandlingStride, kHandlingStride);
        std::memcpy(g_xform + id * kXformStride, g_xform + hostId * kXformStride, kXformStride);

        swrRacerData *r = (swrRacerData *) (g_podData + id * kPodDataStride);
        // The `id` field is the pod's SELF-INDEX: the roster builder stores &PodData[racerId] in the
        // score entry, and the in-race engine/cable path (swrRace_PoddAnimateEngines) + engine audio
        // (swrRace_PlayEngineSounds) index the xform (0x4c7088) and handling tables by
        // *(int*)&PodData[racerId] == PodData[racerId].id, NOT by racerId. memcpy from the host slot
        // copied the host's id (8/22), which made the new pilot read the host's xform entry in race
        // (right pod, wrong -- floating -- cables). Point it at this pilot's own relocated entry.
        r->id = id;
        r->pod_modelID = pod;
        r->pod_alt_modelID = altPod;
        r->puppet_modelId = puppet;
        r->name = (char *) nameAddr;
        r->lastname = (char *) lastNameAddr;
        std::memcpy(r->unkc, &unkc0, 4);

        for (int i = 0; i < xformCount; i++)
            std::memcpy(g_xform + id * kXformStride + xform[i].off, &xform[i].bits, 4);
    }

    // Pilot name strings already in the game .rdata (the addresses the stock cheat swaps point at).
    constexpr uintptr_t kStrJinn = 0x004c3b14;  // "Jinn"
    constexpr uintptr_t kStrReeso = 0x004c3b0c; // "Reeso"
    constexpr uintptr_t kStrCy = 0x004c3b24;    // "Cy"
    constexpr uintptr_t kStrYunga = 0x004c3b1c; // "Yunga"
    // swrRacerData.unkc as set by the swaps (opaque per-pod id; copied verbatim from the cheat).
    constexpr uint32_t kJinnUnkc = 0x0000012e;
    constexpr uint32_t kCyUnkc = 0x0000012f;

    void seed_secret_pilots() {
        // id 23 = Jinn Reeso (host slot 8 = Mars Guo); id 24 = Cy Yunga (host slot 22 = Bullseye).
        seed_secret_pilot(kJinnId, kJinnHostId, MODELID_jinn_reeso_pod, MODELID_alt_jinn_reeso_pod,
                          MODELID_char_jinn_reeso_puppet, kStrJinn, kStrReeso, kJinnUnkc,
                          kJinnXform, (int) (sizeof(kJinnXform) / sizeof(kJinnXform[0])));
        seed_secret_pilot(kCyId, kCyHostId, MODELID_cy_yunga_pod, MODELID_alt_cy_yunga_pod,
                          MODELID_char_cy_yunga_puppet, kStrCy, kStrYunga, kCyUnkc,
                          kCyXform, (int) (sizeof(kCyXform) / sizeof(kCyXform[0])));
    }

    bool g_installed = false;
}

// Reimplemented swrRace_BuildPartMenuList (see header). The stock version loops ids 0..0x16 and
// writes the relocated menu list at 0xe99240; here we loop 0..kRosterCount-1 into the relocated
// g_selIndex, gating each id on (unlock mask | always-mask) -- or unconditionally in multiplayer --
// exactly like the stock gate, then zero-fill the tail. Entry layout: {int racerId; u8 0xff; u8 0;}.
extern "C" void swrRace_BuildPartMenuList_delta(swrObjHang *hang) {
    struct SelEntry {
        int32_t racerId;
        uint8_t f0, f1, f2, f3;
    };
    SelEntry *buf = (SelEntry *) g_selIndex;

    const int player = hang->current_player_for_vehicle_selection;
    uint32_t storedMask;
    std::memcpy(&storedMask, (const void *) (kUnlockMaskAddr + (uintptr_t) player * kUnlockPlayerStride), 4);
    const uint32_t unlockMask = derive_unlock_mask(storedMask);

    int count = 0;
    swrRace_MenuMaxSelection = 0;
    for (int id = 0; id < kRosterCount; id++) {
        const bool selectable = (unlockMask & (1u << id)) != 0 || multiplayer_enabled != 0;
        if (selectable) {
            buf[count].racerId = id;
            buf[count].f0 = 0xff;
            buf[count].f1 = 0;
            buf[count].f2 = 0;
            buf[count].f3 = 0;
            swrRace_MenuMaxSelection++;
            count++;
        }
    }
    for (; count < kRosterCapacity; count++) {
        buf[count].racerId = -1;
        buf[count].f0 = 0xff;
        buf[count].f1 = 0;
        buf[count].f2 = 0;
        buf[count].f3 = 0;
    }
}

void swrRoster_InstallExtensibleRoster() {
    if (g_installed)
        return;

    init_reloc_tables();

    // 1. Copy the stock 23 entries so ids 0..22 are byte-identical in the new arrays.
    std::memcpy(g_podData, (const void *) kPodDataAddr, (size_t) kStockCount * kPodDataStride);
    std::memcpy(g_handling, (const void *) kHandlingAddr, (size_t) kStockCount * kHandlingStride);
    std::memcpy(g_xform, (const void *) kXformAddr, (size_t) kStockCount * kXformStride);
    std::memset(g_selIndex, 0, sizeof(g_selIndex)); // rebuilt every open by BuildPartMenuList_delta

    // 2. Append the secret pilots as ids 23/24.
    seed_secret_pilots();

    // 3. Resolve each reader's disp32 position + shifted value. Sites that carry a literal table
    //    address get patched; sites with none are register-relative/analysis-inferred refs that
    //    ride an already-relocated base pointer (see find_operand) and are skipped. Positions are
    //    de-duplicated so a shared disp32 is never shifted twice.
    struct Resolved {
        uintptr_t pos;
        uint32_t newVal;
    };
    std::vector<Resolved> plan;
    std::vector<uintptr_t> seen; // positions already queued (double-shift guard)
    const int nPod = (int) (sizeof(kPodSites) / sizeof(kPodSites[0]));
    const int nSel = (int) (sizeof(kSelIndexSites) / sizeof(kSelIndexSites[0]));
    plan.reserve(nPod + nSel);
    int skipped = 0;

    auto resolve = [&](uintptr_t instr, int t) {
        const RelocTable &rt = g_reloc[t];
        const uintptr_t lo = rt.oldBase;
        const uintptr_t hi = rt.oldBase + rt.extent;
        uintptr_t pos;
        uint32_t val;
        if (!find_operand(instr, lo, hi, &pos, &val)) {
            skipped++;
            if (hook_log)
                fprintf(hook_log,
                        "[extensible_roster] skip computed table-%d ref at instr %p (rides a "
                        "relocated base pointer; nothing to patch).\n",
                        t, (void *) instr);
            return;
        }
        for (uintptr_t p: seen)
            if (p == pos)
                return; // already queued via another site
        seen.push_back(pos);
        const uint32_t newVal = (uint32_t) ((uintptr_t) val - rt.oldBase + (uintptr_t) rt.newBase);
        plan.push_back({pos, newVal});
    };

    for (int i = 0; i < nPod; i++)
        resolve(kPodSites[i].instr, kPodSites[i].table);
    for (int i = 0; i < nSel; i++)
        resolve(kSelIndexSites[i], 3);
    const int nCount = (int) (sizeof(kRandCountSites) / sizeof(kRandCountSites[0]));
    for (int i = 0; i < nCount; i++)
        resolve(kRandCountSites[i], 4);

    // 4. Apply every operand patch through the journaled/owner-tracked writer (revertible).
    int applied = 0;
    for (const Resolved &r: plan)
        if (WriteMemory(kOwner, (void *) r.pos, &r.newVal, 4))
            applied++;

    // 5. Only now that every reader points at the relocated arrays, install the reimplemented
    //    BuildPartMenuList (which fills the relocated SelectIndex buffer). Installing it before the
    //    operand patches would let it write the new buffer while SelectVehicle still read the old
    //    one -- every pick collapses to racer 0 and the menu overruns the stale buffer.
    hook_function("swrRace_BuildPartMenuList", (uint32_t) swrRace_BuildPartMenuList_ADDR,
                  (uint8_t *) swrRace_BuildPartMenuList_delta);

    g_installed = true;
    if (hook_log) {
        fprintf(hook_log,
                "[extensible_roster] relocated 3 tables + SelectIndex: %d operand patches applied, "
                "%d computed refs skipped; PodData->%p Handling->%p Xform->%p SelIndex->%p; "
                "%d pilots (stock %d + Jinn + Cy).\n",
                applied, skipped, (void *) g_podData, (void *) g_handling, (void *) g_xform,
                (void *) g_selIndex, kRosterCount, kStockCount);
        fflush(hook_log);
    }
}
