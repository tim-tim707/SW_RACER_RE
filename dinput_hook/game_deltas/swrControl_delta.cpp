#include <windows.h>
#include <xinput.h>
#include <cstdint>

extern "C" {
#include <globals.h>
}

#include "swrControl_delta.h"

#include <cstdio>
extern "C" FILE *hook_log;

// P2's boost button (XInput A), sampled each frame in feedPlayer2FromGamepad. The pump-boost FIRE
// reads swrRace_BoostInput (the dedicated boost action), a main-device global; swrRace_UpdatePlayerControl_delta
// swaps this value in for the 2nd local player. 1.0 = pressed, 0.0 = released/no pad.
float swrControl_player2BoostInput = 0.0f;

// In-race raw input slots: 4 x 0x18 bytes starting at 0x00e98ee0. swrControl_ProcessInputs fills
// slot 0 from the active device; updateInRaceInputBitsets (0x00440df0) translates all four into
// inRaceLocalPlayerInputBitset*[player] plus the per-player steer/pitch float arrays. Per-slot byte
// layout (offsets within a slot), derived from updateInRaceInputBitsets + swrRace_UpdatePlayerControl:
//   +0x00 int16 steer  -> FLOAT_ARRAY_00e98ea0[player]   (* 0.01, so ~+-100 = full deflection)
//   +0x02 int16 pitch  -> FLOAT_ARRAY_00e98e80[player]   (nose up/down -- there is NO analog throttle)
//   +0x04 lean-right   +0x05 lean-left   +0x06 look-back
//   +0x11 accelerate   +0x12 brake       (button bytes are 0 / non-zero -> bitset3 bits 0x100 / 0x2)
// Forward thrust is the accelerate bit (+0x11); the main.cpp .text patch redirects the indexed
// control path's local_48 to read it per-player (it otherwise reads the shared main-device global).
static constexpr uintptr_t kRawInputSlot0 = 0x00e98ee0;
static constexpr uintptr_t kRawInputSlotStride = 0x18;

typedef DWORD(WINAPI *XInputGetState_t)(DWORD, XINPUT_STATE *);

// XInput is loaded lazily so we don't add a link-time dependency.
static XInputGetState_t getXInputGetState() {
    static XInputGetState_t fn = []() -> XInputGetState_t {
        const wchar_t *names[] = {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"};
        for (const wchar_t *name: names) {
            if (HMODULE m = LoadLibraryW(name))
                if (auto f = (XInputGetState_t) GetProcAddress(m, "XInputGetState"))
                    return f;
        }
        return nullptr;
    }();
    return fn;
}

// Map a thumbstick axis (-32768..32767) to the slot's +-100 range with a deadzone. The downstream
// translation (updateInRaceInputBitsets) multiplies the slot int16 by 0.01, so full deflection is
// ~+-100 -> +-1.0 in the per-player steer/pitch floats, matching the stock main-device range.
static int16_t axisToSlot(SHORT v) {
    if (v > -XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE && v < XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE)
        return 0;
    int scaled = (int) v * 100 / 32767;
    if (scaled > 100)
        scaled = 100;
    if (scaled < -100)
        scaled = -100;
    return (int16_t) scaled;
}

static void feedPlayer2FromGamepad() {
    volatile uint8_t *slot = (volatile uint8_t *) (kRawInputSlot0 + kRawInputSlotStride);// slot 1
    // Clear first so a disconnected/idle pad reads as no input.
    for (uintptr_t i = 0; i < kRawInputSlotStride; i++)
        slot[i] = 0;
    swrControl_player2BoostInput = 0.0f;// default off (overridden below on a live pad)

    XInputGetState_t XInputGetState_ = getXInputGetState();
    XINPUT_STATE st = {};
    // Player 2 = the 2nd XInput controller (user index 1).
    if (!XInputGetState_ || XInputGetState_(1, &st) != ERROR_SUCCESS)
        return;
    const XINPUT_GAMEPAD &gp = st.Gamepad;

    // Analog axes (left stick): X steers, Y pitches the nose. The triggers are NOT analog throttle --
    // the indexed control path has no analog throttle; forward thrust is the accelerate button bit.
    //   slot+0x00 -> steer   (+ = right)
    //   slot+0x02 -> pitch   (+ = nose down, per the engine; stick up = nose down)
    *(volatile int16_t *) (slot + 0x00) = axisToSlot(gp.sThumbLX);// steer
    *(volatile int16_t *) (slot + 0x02) = axisToSlot(gp.sThumbLY);// pitch

    // Button bytes (0 / non-zero); updateInRaceInputBitsets folds them into bitset3.
    slot[0x11] = (gp.bRightTrigger > 60) ? 1 : 0;                       // accelerate  (bit 0x100)
    slot[0x12] = (gp.bLeftTrigger > 60) ? 1 : 0;                        // brake       (bit 0x2)
    slot[0x05] = (gp.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER) ? 1 : 0;  // lean left   (bit 0x10)
    slot[0x04] = (gp.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) ? 1 : 0; // lean right  (bit 0x20)
    slot[0x06] = (gp.wButtons & XINPUT_GAMEPAD_BACK) ? 1 : 0;           // look back   (bit 0x8)

    // Boost (A): the pump-boost FIRE button. Not a raw-slot action -- the indexed control path has no
    // boost bit; swrRace_UpdatePlayerControl_delta swaps this into swrRace_BoostInput for P2.
    swrControl_player2BoostInput = (gp.wButtons & XINPUT_GAMEPAD_A) ? 1.0f : 0.0f;
}

// DIAGNOSTIC: pinpoint why P2 isn't responding -- which XInput pad is connected, whether slot 1 is
// being written, and what control index/type each local player's pod reads (raw pointers to avoid a
// struct dependency: swrScore +0x10 low byte = control index, *(ptr@+0xc)+0x23 = control type).
static void diagLog() {
    static int frame = 0;
    if ((frame++ % 90) != 0)
        return;
    volatile uint8_t *s1 = (volatile uint8_t *) (kRawInputSlot0 + kRawInputSlotStride);// slot 1
    const char *p2 = *(const char **) 0x00E27820;        // secondLocalPlayer (swrScore*)
    const char *pod = p2 ? *(const char **) (p2 + 0x84) : nullptr;// obj_test_ptr (swrRace*)
    fprintf(hook_log,
            "[p2input] nLP=%d slot1[steer=%d pitch=%d accelbit=%d brakebit=%d] "
            "P2pod[thrust=%.2f grav=%.2f speed=%.2f pitch=%.2f]\n",
            numLocalPlayers, *(int16_t *) (s1 + 0), *(int16_t *) (s1 + 2), s1[0x11], s1[0x12],
            pod ? *(float *) (pod + 0x188) : -1.0f, pod ? *(float *) (pod + 0x18c) : -1.0f,
            pod ? *(float *) (pod + 0x1a0) : -1.0f, pod ? *(float *) (pod + 0x2fc) : -1.0f);
    fflush(hook_log);
}

void swrControl_FeedPlayer2Input(void) {
    if (numLocalPlayers >= 2)
        feedPlayer2FromGamepad();
    diagLog();
}
