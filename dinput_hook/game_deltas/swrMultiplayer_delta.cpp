#include "swrMultiplayer_delta.h"

#include <windows.h>
#include <filesystem>

extern "C" {
#include <macros.h>
#include <Dss/sithMulti.h>
#include <Win95/stdComm.h>
#include <globals.h>

extern FILE *hook_log;
}

#include "../hook_helper.h"

// DirectPlay send flags (the project's custom DirectX types omit them).
#ifndef DPSEND_ASYNC
#define DPSEND_ASYNC 0x00000200
#endif
#ifndef DPSEND_NOCOMPLETE
#define DPSEND_NOCOMPLETE 0x00000400
#endif

// ===========================================================================================
// Multiplayer netcode stability.
//
// (1) Async send (mp_async_send): the synchronous IDirectPlay4::Send (stdComm_Send -> vtable+0x68)
//     blocks the GAME THREAD for tens of ms per call under packet loss (it waits on DirectPlay's
//     retransmit/ACK cycle). At the ~31 Hz state-broadcast rate that stall blows the frame budget,
//     so the whole lobby stutters whenever any peer's link is lossy. We reissue the send via SendEx
//     (vtable+0xC4) with DPSEND_ASYNC, so DirectPlay's own worker thread absorbs the wait and the
//     game thread returns immediately. The caller's reliability flag is preserved (guaranteed stays
//     guaranteed); DPSEND_NOCOMPLETE skips the send-completion message we would otherwise drain.
//
// (2) PumpPackets per-frame cap (mp_packet_cap): swrMultiplayer_PumpPackets drains the ENTIRE
//     DirectPlay receive queue each frame (loops sithMulti_HandleIncomingPacket until empty). A
//     bursty/laggy peer can make the receiver process the whole backlog in one frame and hitch
//     everyone; we bound packets processed per pump (overflow stays queued in DirectPlay -- deferred,
//     not dropped).
//
// Tunable via SW_RACER_RE.ini [settings]:
//   mp_async_send  (default 1, 0 = original blocking Send)
//   mp_packet_cap  (default 32, 0 = unlimited / original behaviour)
// ===========================================================================================

static int g_mp_async_send = 1;
static int g_mp_packet_cap = 32;

// Packets processed in the current pump (one PumpPackets drain; ends when the queue reports empty).
static int g_mp_pump_count = 0;

static void load_mp_settings_once() {
    static bool loaded = false;
    if (loaded)
        return;
    loaded = true;

    wchar_t module_path[1024];
    GetModuleFileNameW(nullptr, module_path, (DWORD) std::size(module_path));
    const std::wstring ini =
        (std::filesystem::path(module_path).parent_path() / "SW_RACER_RE.ini").wstring();
    g_mp_async_send = (int) GetPrivateProfileIntW(L"settings", L"mp_async_send", 1, ini.c_str());
    g_mp_packet_cap = (int) GetPrivateProfileIntW(L"settings", L"mp_packet_cap", 32, ini.c_str());

    fprintf(hook_log, "[swrMultiplayer_delta] mp_async_send=%d mp_packet_cap=%d\n", g_mp_async_send,
            g_mp_packet_cap);
    fflush(hook_log);
}

int sithMulti_HandleIncomingPacket_delta(DPID dpid) {
    load_mp_settings_once();

    if (g_mp_packet_cap > 0 && g_mp_pump_count >= g_mp_packet_cap) {
        // Per-pump cap reached: defer the rest of the queue to the next pump. Returning != 1 ends
        // the pump loop (same as an empty queue); the counter resets so the next pump starts fresh.
        g_mp_pump_count = 0;
        return 0;
    }

    const int result = hook_call_original(sithMulti_HandleIncomingPacket, dpid);

    if (result == 1)
        g_mp_pump_count++;
    else
        g_mp_pump_count = 0;  // queue drained / session ended

    return result;
}

int stdComm_Send_delta(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags) {
    load_mp_settings_once();

    if (g_mp_async_send) {
        // stdComm_pDirectPlay is the IDirectPlay4* (globals.h). Cast to void* and index the vtable
        // manually so this C++ TU does not depend on the C-style lpVtbl member.
        void *const dp = (void *) stdComm_pDirectPlay;
        if (dp != nullptr) {
            // Reissue asynchronously: DirectPlay's worker thread (not the game thread) absorbs the
            // retransmit/ACK wait that otherwise blocks Send for tens of ms per call under loss.
            // IDirectPlay4::SendEx is vtable offset 0xC4 (index 49) -- verified against
            // IDirectPlay4Vtbl (Send=0x68, GetGroupOwner=0xbc, SetGroupOwner=0xc0, SendEx=0xc4).
            typedef HRESULT(__stdcall * SendEx_t)(void *, DPID, DPID, DWORD, LPVOID, DWORD, DWORD,
                                                  DWORD, LPVOID, DWORD *);
            void **const vtbl = *(void ***) dp;
            const SendEx_t pSendEx = (SendEx_t) vtbl[0xC4 / 4];
            const DWORD ex_flags = dwFlags | DPSEND_ASYNC | DPSEND_NOCOMPLETE;
            pSendEx(dp, idFrom, idTo, ex_flags, lpData, dwDataSize, 0, 0, nullptr, nullptr);
            // The message is queued; report success (callers treat a non-zero HRESULT as failure).
            return 0;
        }
    }

    return hook_call_original(stdComm_Send, idFrom, idTo, lpData, dwDataSize, dwFlags);
}
