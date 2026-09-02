// Extensible roster foundation. See swrRoster_delta.h for the design.
#include "swrRoster_delta.h"

extern "C" {
#include <macros.h>
#include <Swr/swrObj.h>
#include <Swr/swrMultiplayer.h>
#include <Swr/swrRace.h>
#include <globals.h>
}

#include "../hook_helper.h"
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

    constexpr int kStockCount = 23;      // pilots baked into the retail tables (ids 0..22)
    constexpr int kRosterCapacity = 25;  // heap array capacity (headroom is trivial to raise)
    constexpr int kRosterCount = 25;     // pilots offered in the menu (stock 23 + Jinn + Cy)

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

    // The two random-racer picks in BuildRosterSinglePlayer scale a [0,1) random by a 23.0f
    // constant at 0x4ad0ac, which is SHARED with swrObjHang_LoadScreenAssets -- so repoint just
    // those two FMUL operands here rather than changing it globally. (The builder's unlock gate
    // presets bits 0..27, so 23/24 already pass it.)
    alignas(4) float g_racerCountF = (float) kRosterCount;
    constexpr uintptr_t kSharedCountConst = 0x004ad0ac; // 23.0f
    const uint32_t kRandCountSites[] = {
        0x0045b822, // BuildRosterSinglePlayer demo/attract random pick
        0x0045b855, // BuildRosterSinglePlayer AI-opponent random pick
    };

    // Per-player unlock bitmask (int per player, stride 0x50). 0x00022e01 is the stock
    // always-available set. Each secret pilot unlocks WITH its host slot: Jinn Reeso (23) tracks
    // Mars Guo (8), Cy Yunga (24) tracks Bullseye (22).
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

    // Operand-patch site lists, from an exhaustive Ghidra xref scan of the three tables. Each entry
    // is (instruction address, relocated-table index); the disp32/imm32 it encodes is the only
    // 4-byte value inside it landing in the stock table extent, and is shifted by (newBase-oldBase).
    // 110 readers across the 3 per-character tables, then the 12 SelectIndex readers (table 3).
    struct PodSite {
        uint32_t instr;
        int table;
    };
    const PodSite kPodSites[] = {
        // {instruction address, relocated-table index}: 0 = swrRacer_PodData (0x4c2700),
        // 1 = swrRacer_PodHandlingData (0x4c2bb0), 2 = pod engine/cockpit xform (0x4c7088).
        // Each comment names the containing function.
        {0x0041acf3, 0}, // swrUI_DrawRaceResultRow
        {0x0041ad4d, 0}, // swrUI_DrawRaceResultRow
        {0x0041ad70, 0}, // swrUI_DrawRaceResultRow
        {0x004208ee, 0}, // swrText_FormatPodName
        {0x004208fe, 0}, // swrText_FormatPodName
        {0x0043386b, 0}, // swrRace_AnimateDisplayPod
        {0x00433ab2, 2}, // swrRace_AnimateDisplayPod
        {0x00433d86, 2}, // swrRace_AnimateDisplayPod
        {0x0043407a, 2}, // swrRace_AnimateDisplayPod
        {0x004340e4, 0}, // swrRace_AnimateDisplayPod
        {0x004343e3, 2}, // swrRace_AnimateDisplayPod
        {0x00434424, 2}, // swrRace_AnimateDisplayPod
        {0x004346a0, 2}, // swrRace_AnimateDisplayPod
        {0x004346eb, 2}, // swrRace_AnimateDisplayPod
        {0x00434954, 2}, // swrRace_AnimateDisplayPod
        {0x00434995, 2}, // swrRace_AnimateDisplayPod
        {0x00434bf4, 2}, // swrRace_AnimateDisplayPod
        {0x00434c3f, 2}, // swrRace_AnimateDisplayPod
        {0x00435976, 0}, // swrRace_SelectVehicle
        {0x00435992, 0}, // swrRace_SelectVehicle
        {0x00435a8b, 0}, // swrRace_SelectVehicle
        {0x00435a91, 0}, // swrRace_SelectVehicle
        {0x00435acf, 0}, // swrRace_SelectVehicle
        {0x00435ad5, 0}, // swrRace_SelectVehicle
        {0x00435eb5, 0}, // swrRace_SelectVehicle
        {0x0043801c, 0}, // swrObjHang_UpdateLookAtVehicle
        {0x00438f3d, 0}, // swrObjHang_UpdateInspectCamera
        {0x00438f58, 0}, // swrObjHang_UpdateInspectCamera
        {0x00439252, 0}, // swrObjHang_UpdateInspectCamera
        {0x00439274, 0}, // swrObjHang_UpdateInspectCamera
        {0x00439318, 0}, // swrObjHang_UpdateInspectCamera
        {0x0043933a, 0}, // swrObjHang_UpdateInspectCamera
        {0x0043a797, 0}, // swrRace_ResultsMenu
        {0x0043a7b5, 0}, // swrRace_ResultsMenu
        {0x0043a87e, 0}, // swrRace_ResultsMenu
        {0x0043a89c, 0}, // swrRace_ResultsMenu
        {0x0043c066, 0}, // swrRace_CourseInfoMenu
        {0x0043c072, 0}, // swrRace_CourseInfoMenu
        {0x0043c127, 0}, // swrRace_CourseInfoMenu
        {0x0043c137, 0}, // swrRace_CourseInfoMenu
        {0x0043c1fa, 0}, // swrRace_CourseInfoMenu
        {0x0043c20a, 0}, // swrRace_CourseInfoMenu
        {0x0043caa0, 0}, // swrObjHang_UpdateTauntScene
        {0x0043cab9, 0}, // swrObjHang_UpdateTauntScene
        {0x0043cb0c, 0}, // swrObjHang_UpdateTauntScene
        {0x0043cb45, 0}, // swrObjHang_UpdateTauntScene
        {0x0043cef2, 0}, // swrObjHang_UpdatePlanetSelectIntro
        {0x0043f9da, 0}, // swrObjHang_AimHoloCamera
        {0x0043fc00, 0}, // swrObjHang_UpdateHoloCameraTarget
        {0x00451f6e, 2}, // swrObjcMan_UpdatePreRaceSweep
        {0x00451f7e, 2}, // swrObjcMan_UpdatePreRaceSweep
        {0x00451f97, 2}, // swrObjcMan_UpdatePreRaceSweep
        {0x00451fab, 2}, // swrObjcMan_UpdatePreRaceSweep
        {0x00451fce, 2}, // swrObjcMan_UpdatePreRaceSweep
        {0x00452b4d, 2}, // swrObjcMan_UpdateChaseCamera
        {0x00452b5f, 2}, // swrObjcMan_UpdateChaseCamera
        {0x00452b70, 2}, // swrObjcMan_UpdateChaseCamera
        {0x00452b8e, 2}, // swrObjcMan_UpdateChaseCamera
        {0x00457bd6, 0}, // swrObjHang_LoadAllPilotSprites
        {0x00457bdb, 0}, // swrObjHang_LoadAllPilotSprites
        {0x004589b0, 0}, // swrObjHang_LoadScreenAssets
        {0x004589b6, 0}, // swrObjHang_LoadScreenAssets
        {0x00458a1b, 0}, // swrObjHang_LoadScreenAssets
        {0x00458a21, 0}, // swrObjHang_LoadScreenAssets
        {0x00458b3e, 0}, // swrObjHang_LoadScreenAssets
        {0x00458b45, 0}, // swrObjHang_LoadScreenAssets
        {0x00458bb2, 0}, // swrObjHang_LoadScreenAssets
        {0x00458bb8, 0}, // swrObjHang_LoadScreenAssets
        {0x00458cbc, 0}, // swrObjHang_LoadScreenAssets
        {0x00458cc3, 0}, // swrObjHang_LoadScreenAssets
        {0x00458db7, 0}, // swrObjHang_LoadScreenAssets
        {0x00458dbe, 0}, // swrObjHang_LoadScreenAssets
        {0x00458f5e, 0}, // swrObjHang_LoadScreenAssets
        {0x00458f64, 0}, // swrObjHang_LoadScreenAssets
        {0x00458f74, 0}, // swrObjHang_LoadScreenAssets
        {0x00458f7a, 0}, // swrObjHang_LoadScreenAssets
        {0x00458fd2, 0}, // swrObjHang_LoadScreenAssets
        {0x00458fd9, 0}, // swrObjHang_LoadScreenAssets
        {0x0045908c, 0}, // swrObjHang_LoadScreenAssets
        {0x00459092, 0}, // swrObjHang_LoadScreenAssets
        {0x0045b73a, 0}, // swrObjHang_BuildRosterMultiplayer
        {0x0045b75e, 1}, // swrObjHang_BuildRosterMultiplayer
        {0x0045b76a, 1}, // swrObjHang_BuildRosterMultiplayer
        {0x0045b947, 0}, // swrObjHang_BuildRosterSinglePlayer
        {0x0045b975, 1}, // swrObjHang_BuildRosterSinglePlayer
        {0x0045b98a, 1}, // swrObjHang_BuildRosterSinglePlayer
        {0x0045b99f, 1}, // swrObjHang_BuildRosterSinglePlayer
        {0x0045ba02, 1}, // swrObjHang_BuildRosterSinglePlayer
        {0x0045cf85, 0}, // swrObjHang_ComputeUpgradedStats
        {0x0045cf97, 1}, // swrObjHang_ComputeUpgradedStats
        {0x0045cfa2, 1}, // swrObjHang_ComputeUpgradedStats
        {0x0046d7c9, 1}, // swrRace_PlayEngineSounds
        {0x0046e683, 2}, // swrRace_AnimateEngineWobble
        {0x0046f129, 2}, // swrRace_BuildStretchedQuad
        {0x0046f136, 2}, // swrRace_BuildStretchedQuad
        {0x0046f13c, 2}, // swrRace_BuildStretchedQuad
        {0x0046f146, 2}, // swrRace_BuildStretchedQuad
        {0x0046f158, 2}, // swrRace_BuildStretchedQuad
        {0x0046f16e, 2}, // swrRace_BuildStretchedQuad
        {0x00471173, 2}, // swrRace_PoddAnimateEngines
        {0x004714a1, 2}, // swrRace_PoddAnimateEngines
        {0x00471817, 2}, // swrRace_PoddAnimateVariousThings
        {0x00471893, 2}, // swrRace_PoddAnimateVariousThings
        {0x0047192e, 2}, // swrRace_PoddAnimateVariousThings
        {0x004719a2, 2}, // swrRace_PoddAnimateVariousThings
        {0x00471aeb, 2}, // swrRace_PoddAnimateVariousThings
        {0x00471c06, 2}, // swrRace_PoddAnimateVariousThings
        {0x00471d33, 2}, // swrRace_PoddAnimateVariousThings
        {0x00476782, 2}, // swrRace_UpdateHoverPads
        {0x004767aa, 2}, // swrRace_UpdateHoverPads
    };

    const uint32_t kSelIndexSites[] = {
        // SelectIndex (0xe99240) readers -- relocated table 3. swrRace_BuildPartMenuList writes the
        // buffer and is reimplemented, so its own accesses are not patched.
        0x004192d8, // swrUI_Menu_MpSelectVehicle
        0x0043579b, // swrRace_SelectVehicle
        0x004357a0, // swrRace_SelectVehicle
        0x004357b6, // swrRace_SelectVehicle
        0x00435804, // swrRace_SelectVehicle
        0x00435826, // swrRace_SelectVehicle
        0x00435a36, // swrRace_SelectVehicle
        0x00435df9, // swrRace_SelectVehicle
        0x00435ea8, // swrRace_SelectVehicle
        0x00435eeb, // swrRace_SelectVehicle
        0x00435f01, // swrRace_SelectVehicle
        0x00435f3d, // swrRace_SelectVehicle
    };

    // The table-address immediate is the lowest offset in [0,8) whose LE dword falls in [lo,hi):
    // the opcode/modrm/sib bytes ahead of the disp32 never form a 0x004cXXXX value, so the first
    // in-range hit is the operand. A MISS is expected and benign -- the xref scan also reports
    // analysis-inferred register-relative accesses (e.g. the pilot-sprite loop's MOV EAX,[EBP] at
    // 0x457bdb, where EBP was loaded as a literal at 0x457bd6 and walked by ADD EBP,0x34). Those
    // carry no literal and ride the already-relocated base pointer.
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

    // Secret-pilot seed data, verbatim from swrRace_ReplaceMarsGuoWithJinnReeso @0x44b530 and
    // swrRace_ReplaceBullseyeWithCyYunga @0x44b5e0: the stock swaps override 6 swrRacerData fields
    // on the host slot and rewrite that host's engine-xform entry, leaving handling as the host's.
    // Same thing here, but into the appended ids 23/24 rather than clobbering slots 8/22.
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
        std::memcpy(g_podData + id * kPodDataStride, g_podData + hostId * kPodDataStride, kPodDataStride);
        std::memcpy(g_handling + id * kHandlingStride, g_handling + hostId * kHandlingStride, kHandlingStride);
        std::memcpy(g_xform + id * kXformStride, g_xform + hostId * kXformStride, kXformStride);

        swrRacerData *r = (swrRacerData *) (g_podData + id * kPodDataStride);
        // `id` is the pod's SELF-INDEX: swrRace_PoddAnimateEngines and swrRace_PlayEngineSounds
        // index the xform (0x4c7088) and handling tables by PodData[racerId].id, NOT by racerId.
        // The memcpy above brought the host's id (8/22) along, which made the new pilot read the
        // host's xform entry (right pod, floating cables).
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

    // Pilot name strings already in .rdata (the addresses the stock cheat swaps point at).
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

// Reimplemented swrRace_BuildPartMenuList (see header): the stock 0..0x16 loop becomes
// 0..kRosterCount-1 into the relocated g_selIndex, with the same (unlock mask | always-mask) gate
// (unconditional in multiplayer), then a zero-filled tail. Entry: {int racerId; u8 0xff; u8 0;}.
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

    // Only the retail roster in multiplayer: the racer id travels the wire verbatim and a peer on
    // stock SWE1R still has 23-entry tables, so an appended id reads past their end.
    const int visibleCount = multiplayer_enabled != 0 ? kStockCount : kRosterCount;

    int count = 0;
    swrRace_MenuMaxSelection = 0;
    for (int id = 0; id < visibleCount; id++) {
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

// Multiplayer wire guards. The racer id is exchanged raw: swrMultiplayer_RacerPick puts the local
// pick in message 0x33 and swrMultiplayer_ApplyRacerPick stores the received id into
// multiplayer_racer1_id[] with NO range check, after which swrObjHang_BuildRosterMultiplayer indexes
// the per-character tables with it. Outbound: never publish an appended id. Inbound: clamp to the
// roster we actually have.

typedef void(swrMultiplayer_RacerPick_t)(int a);
typedef int(swrMultiplayer_ApplyRacerPick_t)(void *message);

// Fallback pilot: id 0 exists in every build, stock or modded.
constexpr int kFallbackRacerId = 0;

extern "C" void swrMultiplayer_RacerPick_delta(int a) {
    if (multiplayer_enabled != 0 && (a < 0 || a >= kStockCount)) {
        fprintf(hook_log, "[%s] clamping out-of-roster racer pick %d -> %d before sending\n", kOwner,
                a, kFallbackRacerId);
        fflush(hook_log);
        a = kFallbackRacerId;
    }
    hook_call_original((swrMultiplayer_RacerPick_t *) swrMultiplayer_RacerPick_ADDR, a);
}

extern "C" int swrMultiplayer_ApplyRacerPick_delta(void *message) {
    if (message != nullptr) {
        // Message body: {int playerIndex; int racerId;} at +0x28.
        int32_t *racerId = (int32_t *) ((uint8_t *) message + 0x2c);
        if (*racerId < 0 || *racerId >= kRosterCount) {
            fprintf(hook_log, "[%s] rejecting out-of-roster racer pick %d from the wire -> %d\n",
                    kOwner, *racerId, kFallbackRacerId);
            fflush(hook_log);
            *racerId = kFallbackRacerId;
        }
    }
    return hook_call_original((swrMultiplayer_ApplyRacerPick_t *) swrMultiplayer_ApplyRacerPick_ADDR,
                              message);
}

void swrRoster_InstallExtensibleRoster() {
    if (g_installed)
        return;

    init_reloc_tables();

    std::memcpy(g_podData, (const void *) kPodDataAddr, (size_t) kStockCount * kPodDataStride);
    std::memcpy(g_handling, (const void *) kHandlingAddr, (size_t) kStockCount * kHandlingStride);
    std::memcpy(g_xform, (const void *) kXformAddr, (size_t) kStockCount * kXformStride);
    std::memset(g_selIndex, 0, sizeof(g_selIndex)); // rebuilt every open by BuildPartMenuList_delta

    seed_secret_pilots();

    // Sites carrying no literal are register-relative refs riding an already-relocated base
    // pointer (see find_operand) and are skipped. Positions are de-duplicated so a shared disp32
    // is never shifted twice.
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

    int applied = 0;
    for (const Resolved &r: plan)
        if (WriteMemory(kOwner, (void *) r.pos, &r.newVal, 4))
            applied++;

    // Only AFTER every reader points at the relocated arrays: installing this first would let it
    // fill the new SelectIndex buffer while SelectVehicle still read the old one -- every pick
    // collapses to racer 0 and the menu overruns the stale buffer.
    hook_function("swrRace_BuildPartMenuList", (uint32_t) swrRace_BuildPartMenuList_ADDR,
                  (uint8_t *) swrRace_BuildPartMenuList_delta);

    // Multiplayer wire guards (see the block above).
    hook_function("swrMultiplayer_RacerPick", (uint32_t) swrMultiplayer_RacerPick_ADDR,
                  (uint8_t *) swrMultiplayer_RacerPick_delta);
    hook_function("swrMultiplayer_ApplyRacerPick", (uint32_t) swrMultiplayer_ApplyRacerPick_ADDR,
                  (uint8_t *) swrMultiplayer_ApplyRacerPick_delta);

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
