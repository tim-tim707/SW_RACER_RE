#include "lockstep.h"

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <windows.h>

extern "C" {
#include <Swr/swrRace.h> // swrRace_IncrementFrameTimer_ADDR
#include <Swr/swrObj.h>  // swrObjHang_StartRace_ADDR
#include <Swr/swrEvent.h>// swrEvent_GetItem_ADDR
#include <engine_config.h>
#include <globals.h>
#include <types.h>

extern FILE *hook_log;
}

#include "hook_helper.h"
#include "game_deltas/swrMain_delta.h"   // swr_fixedTimestep
#include "game_deltas/swrControl_delta.h"// g_cutscene_skip_edge

namespace {

typedef void(__cdecl *void_fn_t)(void);
typedef void *(__cdecl *GetItem_t)(int, int);

constexpr int kJdgeEvent = 0x4a646765;// 'Jdge'
constexpr int kJdgeStateMask = 0xf;
constexpr int kJdgeStateCountdown = 0;
constexpr int kJdgeStateRacing = 1;
constexpr int kMaxRacers = 20;// swrScores[20]
constexpr int kMaxAnimations = 300;// swrScene_animations[300]
constexpr uint32_t kFileMagic = 0x31534b4c;// "LKS1"
constexpr uint32_t kFileVersion = 2;

enum Mode { MODE_OFF, MODE_RECORD, MODE_REPLAY };

// Every input global swrControl_ProcessInputs (and its delta) writes. Pinned right after it, before
// the UI and the frame consume them; the in-race bitsets are then derived from these
// deterministically by swrRace_UpdateInRaceInputBitsets.
struct InputRegion {
    void *addr;
    size_t size;
};
const InputRegion kInputRegions[] = {
    {&swrControl_joystickAxes, sizeof(swrControl_joystickAxes)},
    {&swrControl_mouseAxes, sizeof(swrControl_mouseAxes)},
    {&swrControl_keyboardAxes, sizeof(swrControl_keyboardAxes)},
    // swrRace_ThrottleInput..PitchInput, then the 15 action floats (viewButton..)
    {&swrRace_ThrottleInput, (SWR_CONTROL_NUM_ANALOG_ACTIONS + SWR_CONTROL_NUM_ACTIONS) * sizeof(float)},
    {&swrControl_viewHoldTime, SWR_CONTROL_NUM_ACTIONS * sizeof(float)},
    {&inRaceLocalPlayerInputRecord, sizeof(inRaceLocalPlayerInputRecord)},
    // UI edges: the judge's flyover / results skips also accept these
    {&swrControl_acceptPressedEdge, sizeof(int)},
    {&swrControl_cancelPressedEdge, sizeof(int)},
    {&swrControl_acceptReleasedEdge, sizeof(int)},
    {&swrControl_cancelReleasedEdge, sizeof(int)},
    {&swrControl_menuAcceptPressedEdge, sizeof(int)},
    // delta layer: the shared cutscene/flyover advance, turned into cancelPressedEdge later
    {&g_cutscene_skip_edge, sizeof(int)},
};

size_t input_block_size() {
    size_t n = 0;
    for (const InputRegion &r: kInputRegions)
        n += r.size;
    return n;
}

// The animation clocks carry over from the intro cutscene (how long it ran before the skip), so
// replay restores them at T0. Only the scalar run loop_transition_speed..key_frame_index; the
// pointers that follow are per-process.
constexpr size_t kAnimScalarsBegin = offsetof(swrModel_Animation, loop_transition_speed);
constexpr size_t kAnimScalarsEnd = offsetof(swrModel_Animation, key_frame_times);
constexpr size_t kAnimScalarsSize = kAnimScalarsEnd - kAnimScalarsBegin;

// The hangar's race setup at swrObjHang_StartRace, so a replay can start the same race itself.
struct RaceSetup {
    int32_t demoMode;
    int8_t trackIndex;
    int8_t circuitIdx;
    int8_t isTournamentMode;
    int8_t timeAttackMode;
    int8_t mirror;
    int8_t localPlayers;
    int8_t numPlayers;
    int8_t vehiclePlayer;
    int8_t numLaps;
    int8_t aiSpeed;
    int8_t pad[2];
};

struct FileHeader {
    uint32_t magic;
    uint32_t version;
    float hz;
    uint32_t inputBlockSize;
    int32_t randState;
    int32_t animCount;
    int32_t racerCount;
    int32_t startRaceRandState;// at swrObjHang_StartRace entry: seeds the AI roster
    RaceSetup setup;
};

struct FrameHashes {
    uint32_t rng;
    uint32_t anim;
    uint32_t jdge;
    uint32_t racerCount;
    uint32_t racer[kMaxRacers];
};

struct State {
    Mode mode = MODE_OFF;
    bool configRead = false;
    bool active = false;// inside a captured race
    bool finished = false;
    float hz = 60.0f;
    int dumpAt = -1;
    int dumpTo = -1;// dump_at <first> [last]: every frame in the range
    char path[MAX_PATH] = "lockstep_run.bin";
    FILE *file = nullptr;
    FILE *log = nullptr;
    uint32_t frame = 0;
    uint32_t mismatches = 0;
    int firstMismatch = -1;
    int savedFastMode = 0;
    double savedFixedDt = 0.0;
    bool pinDt = false;// fixed dt from StartRace on: the pods tick while the race scene loads, before T0
    bool sawRace = false;// reached countdown/racing; leaving them after that ends the capture
    int startRaceRand = 0;
    bool haveStartRaceRand = false;
    bool headerRead = false;
    FileHeader hdr = {};
    RaceSetup setup = {};// record: captured at StartRace
    bool autostart = false;// replay: start the recorded race from the main menu, no menu input
    bool exitWhenDone = false;
    bool autostarted = false;
    bool fastForward = false;
    char lastSignature[512] = "";
    bool haveInputs = false;// replay: the next frame's input block is loaded; ProcessInputs pins it
    std::vector<uint8_t> inputs;
} s;

GetItem_t get_item() { return (GetItem_t) swrEvent_GetItem_ADDR; }

swrObjJdge *judge() {
    swrObjJdge *j = (swrObjJdge *) get_item()(kJdgeEvent, 0);
    if (j == nullptr || (j->obj.flags & swrObj_FLAG_FREED) != 0)
        return nullptr;
    return j;
}

// Racers by score slot: the 'Test' event list order follows allocation and changes between
// launches, the swrScores slots don't.
int racer_count() {
    swrObjJdge *j = judge();
    if (j == nullptr || swrScoresPtr == nullptr)
        return 0;
    return j->num_players > kMaxRacers ? kMaxRacers : j->num_players;
}

const swrRace *racer_at(int i) { return swrScoresPtr[i].obj_test_ptr; }

bool race_running(swrObjJdge *j) {
    if (j == nullptr)
        return false;
    const int state = j->flag & kJdgeStateMask;
    return state == kJdgeStateCountdown || state == kJdgeStateRacing;
}

// T0 is the first frame the race scene is up (racers spawned, track animations registered). That is
// in the intro flyover (judge state 4), so the flyover runs on the fixed dt too and its skip is a
// replayed input.
bool race_scene_ready(swrObjJdge *j) {
    return j != nullptr && racer_count() > 0 && swrScene_animations_count > 0;
}

void log_line(const char *fmt, ...) {
    if (s.log == nullptr)
        s.log = fopen("lockstep.log", "w");
    if (s.log == nullptr)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(s.log, fmt, ap);
    va_end(ap);
    fputc('\n', s.log);
    fflush(s.log);
}

void read_config() {
    s.configRead = true;
    FILE *f = fopen("lockstep.txt", "r");
    if (f == nullptr)
        return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char key[64] = {0};
        char val[MAX_PATH] = {0};
        char val2[64] = {0};
        if (line[0] == '#' || sscanf(line, "%63s %259s %63s", key, val, val2) < 1)
            continue;
        if (strcmp(key, "record") == 0 || strcmp(key, "replay") == 0) {
            s.mode = strcmp(key, "record") == 0 ? MODE_RECORD : MODE_REPLAY;
            if (val[0])
                snprintf(s.path, sizeof(s.path), "%s", val);
        } else if (strcmp(key, "hz") == 0) {
            s.hz = (float) atof(val);
        } else if (strcmp(key, "autostart") == 0) {
            s.autostart = true;
        } else if (strcmp(key, "exit_when_done") == 0) {
            s.exitWhenDone = true;
        } else if (strcmp(key, "dump_at") == 0) {
            s.dumpAt = atoi(val);
            s.dumpTo = val2[0] ? atoi(val2) : s.dumpAt;
        }
    }
    fclose(f);
    if (s.hz < 1.0f)
        s.hz = 60.0f;
    if (s.mode != MODE_OFF)
        log_line("lockstep: %s %s at %.3f Hz, dump_at %d", s.mode == MODE_RECORD ? "record" : "replay",
                 s.path, s.hz, s.dumpAt);
}

// FNV-1a over 32-bit words. Pointer-like words are folded in as a fixed marker: heap and model
// addresses differ between processes. The test is on the value alone, so both runs classify a word
// the same way (asking the OS whether it is mapped does not: the address spaces differ).
struct Hasher {
    uint32_t h = 2166136261u;
    void word(uint32_t w) {
        for (int i = 0; i < 4; i++) {
            h ^= (w >> (i * 8)) & 0xff;
            h *= 16777619u;
        }
    }
};

bool is_pointer(uint32_t w) {
    // Sim floats sit above 0x30000000 (|x| > ~6e-10) or have the sign bit set, and counters are
    // small; only the band between, 4-aligned, is treated as an address.
    return w >= 0x10000 && w < 0x30000000 && (w & 3) == 0;
}

constexpr uint32_t kPointerMarker = 0x50545221;// "!RTP"

// swrRace +0xa50 (inside the unmapped unk5d0 block) holds an rdMatrix44 whose 3x3 part is a scaled
// Y rotation that pulses down to zero scale. Its angle differs between two replays of the same input
// while RNG, judge and every other field match (presumably a render path on its own clock), and the
// signs of its zeros differ record vs replay. The rotation rows are left out of the hash; the
// translation row (+0xa80) stays in.
constexpr size_t kRacerVolatileBegin = 0xa50;
constexpr size_t kRacerVolatileEnd = 0xa80;

bool racer_volatile(size_t offset) { return offset >= kRacerVolatileBegin && offset < kRacerVolatileEnd; }

uint32_t hash_struct(const void *p, size_t size, uint8_t *pointerMask, bool isRacer = false) {
    Hasher h;
    const uint32_t *w = (const uint32_t *) p;
    for (size_t i = 0; i < size / 4; i++) {
        // the swrObj header (event, id, flags) is data, and id/flags can look like a heap address
        const bool ptr = i * 4 >= sizeof(swrObj) && is_pointer(w[i]);
        if (pointerMask != nullptr)
            pointerMask[i] = ptr;
        if (isRacer && racer_volatile(i * 4))
            continue;
        h.word(ptr ? kPointerMarker : w[i]);
    }
    return h.h;
}

FrameHashes hash_state() {
    FrameHashes fh = {};
    fh.rng = (uint32_t) swrUtils_randState;
    Hasher a;
    const int animCount = swrScene_animations_count;
    for (int i = 0; i < animCount && i < kMaxAnimations; i++) {
        const swrModel_Animation *anim = swrScene_animations[i];
        if (anim == nullptr) {
            a.word(0);
            continue;
        }
        const uint32_t *w = (const uint32_t *) ((const uint8_t *) anim + kAnimScalarsBegin);
        for (size_t k = 0; k < kAnimScalarsSize / 4; k++)
            a.word(w[k]);
    }
    fh.anim = a.h;
    swrObjJdge *j = judge();
    fh.jdge = j ? hash_struct(j, sizeof(swrObjJdge), nullptr) : 0;
    fh.racerCount = racer_count();
    for (uint32_t i = 0; i < fh.racerCount; i++) {
        const void *r = racer_at(i);
        fh.racer[i] = r ? hash_struct(r, sizeof(swrRace), nullptr, true) : 0;
    }
    return fh;
}

// Raw racer + judge structs with their pointer masks, for diffing two runs at one frame
// (scripts/lockstep_diff.py).
void dump_state(uint32_t frame) {
    char name[MAX_PATH];
    snprintf(name, sizeof(name), "lockstep_dump_%s_%u.bin", s.mode == MODE_RECORD ? "rec" : "rep", frame);
    FILE *f = fopen(name, "wb");
    if (f == nullptr)
        return;
    std::vector<uint8_t> mask(sizeof(swrRace) / 4);
    const uint32_t racers = racer_count();
    fwrite(&racers, 4, 1, f);
    for (uint32_t i = 0; i < racers; i++) {
        const void *r = racer_at(i);
        static const uint8_t zero[sizeof(swrRace)] = {};
        const void *src = r ? r : zero;
        hash_struct(src, sizeof(swrRace), mask.data());
        fwrite(src, sizeof(swrRace), 1, f);
        fwrite(mask.data(), mask.size(), 1, f);
    }
    swrObjJdge *j = judge();
    std::vector<uint8_t> jmask(sizeof(swrObjJdge) / 4);
    static const uint8_t jzero[sizeof(swrObjJdge)] = {};
    const void *jsrc = j ? (const void *) j : jzero;
    hash_struct(jsrc, sizeof(swrObjJdge), jmask.data());
    fwrite(jsrc, sizeof(swrObjJdge), 1, f);
    fwrite(jmask.data(), jmask.size(), 1, f);
    fclose(f);
    log_line("frame %u: dumped %s", frame, name);
}

void capture_inputs(uint8_t *dst) {
    for (const InputRegion &r: kInputRegions) {
        memcpy(dst, r.addr, r.size);
        dst += r.size;
    }
}

void apply_inputs(const uint8_t *src) {
    for (const InputRegion &r: kInputRegions) {
        memcpy(r.addr, src, r.size);
        src += r.size;
    }
}

void write_anim_scalars(FILE *f) {
    std::vector<uint8_t> buf(kAnimScalarsSize);
    for (int i = 0; i < swrScene_animations_count && i < kMaxAnimations; i++) {
        const swrModel_Animation *anim = swrScene_animations[i];
        if (anim)
            memcpy(buf.data(), (const uint8_t *) anim + kAnimScalarsBegin, kAnimScalarsSize);
        else
            memset(buf.data(), 0, kAnimScalarsSize);
        fwrite(buf.data(), kAnimScalarsSize, 1, f);
    }
}

bool restore_anim_scalars(FILE *f, int count) {
    std::vector<uint8_t> buf(kAnimScalarsSize);
    for (int i = 0; i < count; i++) {
        if (fread(buf.data(), kAnimScalarsSize, 1, f) != 1)
            return false;
        swrModel_Animation *anim = swrScene_animations[i];
        if (anim)
            memcpy((uint8_t *) anim + kAnimScalarsBegin, buf.data(), kAnimScalarsSize);
    }
    return true;
}

void stop(const char *why) {
    if (s.file) {
        fclose(s.file);
        s.file = nullptr;
    }
    swr_FastMode = s.savedFastMode;
    swr_fixedDeltaTimeSecs = s.savedFixedDt;
    s.pinDt = false;
    s.active = false;
    s.finished = true;
    if (s.mode == MODE_REPLAY) {
        if (s.mismatches == 0)
            log_line("lockstep: %s after %u frames - ALL MATCH", why, s.frame);
        else
            log_line("lockstep: %s after %u frames - %u mismatched, first at frame %d", why, s.frame,
                     s.mismatches, s.firstMismatch);
    } else {
        log_line("lockstep: %s, recorded %u frames", why, s.frame);
    }
    if (hook_log) {
        fprintf(hook_log, "[lockstep] %s: %u frames, %u mismatched\n", why, s.frame, s.mismatches);
        fflush(hook_log);
    }
    if (s.exitWhenDone) {
        if (s.log)
            fclose(s.log);
        ExitProcess(s.mismatches == 0 ? 0 : 1);
    }
}

bool open_replay() {
    s.file = fopen(s.path, "rb");
    if (s.file == nullptr) {
        log_line("lockstep: cannot read %s", s.path);
        return false;
    }
    if (fread(&s.hdr, sizeof(s.hdr), 1, s.file) != 1 || s.hdr.magic != kFileMagic || s.hdr.version != kFileVersion ||
        s.hdr.inputBlockSize != input_block_size()) {
        log_line("lockstep: %s is not a v%u recording from this build", s.path, kFileVersion);
        fclose(s.file);
        s.file = nullptr;
        return false;
    }
    s.headerRead = true;
    return true;
}

bool start() {
    const int animCount = swrScene_animations_count;
    if (animCount < 0 || animCount > kMaxAnimations) {
        log_line("lockstep: bad animation count %d", animCount);
        return false;
    }
    if (s.inputs.size() != input_block_size())
        s.inputs.assign(input_block_size(), 0);
    if (s.mode == MODE_RECORD) {
        s.file = fopen(s.path, "wb");
        if (s.file == nullptr) {
            log_line("lockstep: cannot write %s", s.path);
            return false;
        }
        FileHeader hdr = {kFileMagic,   kFileVersion,  s.hz,
                          (uint32_t) s.inputs.size(), swrUtils_randState, animCount,
                          racer_count(), s.haveStartRaceRand ? s.startRaceRand : swrUtils_randState, s.setup};
        if (!s.haveStartRaceRand)
            log_line("lockstep: StartRace not seen, the AI roster won't be pinned");
        fwrite(&hdr, sizeof(hdr), 1, s.file);
        write_anim_scalars(s.file);
    } else {
        if (!s.headerRead && !open_replay())
            return false;
        const FileHeader &hdr = s.hdr;
        if (hdr.animCount != animCount || hdr.racerCount != racer_count()) {
            log_line("lockstep: scene mismatch (anims %d vs %d, racers %d vs %d) - same track/pod/racer count?",
                     hdr.animCount, animCount, hdr.racerCount, racer_count());
            return false;
        }
        s.hz = hdr.hz;
        swrUtils_randState = hdr.randState;
        if (!restore_anim_scalars(s.file, animCount)) {
            log_line("lockstep: truncated header");
            return false;
        }
    }
    s.frame = 0;
    s.mismatches = 0;
    s.firstMismatch = -1;
    s.active = true;
    log_line("lockstep: race start, %d racers, %d animations, rng %08x", racer_count(), animCount,
             (uint32_t) swrUtils_randState);
    return true;
}

void compare(const FrameHashes &want, const FrameHashes &got) {
    if (memcmp(&want, &got, sizeof(want)) == 0) {
        if (s.lastSignature[0] != '\0')
            log_line("frame %u: matching again", s.frame);
        s.lastSignature[0] = '\0';
        return;
    }
    s.mismatches++;
    if (s.firstMismatch < 0)
        s.firstMismatch = (int) s.frame;
    char buf[512];
    int n = 0;
    buf[0] = '\0';
    if (want.rng != got.rng)
        n += snprintf(buf + n, sizeof(buf) - n, " rng %08x/%08x", want.rng, got.rng);
    if (want.anim != got.anim)
        n += snprintf(buf + n, sizeof(buf) - n, " anim");
    if (want.jdge != got.jdge)
        n += snprintf(buf + n, sizeof(buf) - n, " jdge");
    if (want.racerCount != got.racerCount)
        n += snprintf(buf + n, sizeof(buf) - n, " racers %u/%u", want.racerCount, got.racerCount);
    for (uint32_t i = 0; i < want.racerCount && i < kMaxRacers && n < (int) sizeof(buf) - 16; i++)
        if (want.racer[i] != got.racer[i])
            n += snprintf(buf + n, sizeof(buf) - n, " racer%u", i);
    // rng values change every frame; log only when the set of diverged components changes
    char sig[sizeof(buf)];
    const char *p = buf;
    if (strncmp(p, " rng ", 5) == 0)
        p = strchr(p + 5, ' ') ? strchr(p + 5, ' ') : "";
    snprintf(sig, sizeof(sig), "%s%s", want.rng != got.rng ? "rng" : "", p);
    if (strcmp(sig, s.lastSignature) == 0)
        return;
    snprintf(s.lastSignature, sizeof(s.lastSignature), "%s", sig);
    log_line("frame %u MISMATCH:%s", s.frame, buf);
}

void frame_step() {
    // State hashed here is the end of the previous frame's sim (= the start of this one).
    if (s.file == nullptr) {
        stop("no recording file");
        return;
    }
    if (s.mode == MODE_RECORD) {
        const FrameHashes fh = hash_state();
        fwrite(s.inputs.data(), s.inputs.size(), 1, s.file);
        fwrite(&fh, sizeof(fh), 1, s.file);
    } else {
        // Frame 0's inputs were live by the time T0 was detected. ProcessInputs does not run every
        // frame, so the next block is loaded here and pinned by however many calls the frame makes;
        // the recording holds a frame without a call at the previous values, same as the game.
        FrameHashes want;
        if ((!s.haveInputs && fread(s.inputs.data(), s.inputs.size(), 1, s.file) != 1) ||
            fread(&want, sizeof(want), 1, s.file) != 1) {
            stop("recording ended");
            return;
        }
        compare(want, hash_state());
        s.haveInputs = fread(s.inputs.data(), s.inputs.size(), 1, s.file) == 1;
    }
    if ((int) s.frame >= s.dumpAt && (int) s.frame <= s.dumpTo)
        dump_state(s.frame);
    s.frame++;
}

}// namespace

extern "C" void lockstep_pin_inputs(void) {
    if (s.mode == MODE_RECORD) {
        if (s.inputs.empty())
            s.inputs.resize(input_block_size());
        capture_inputs(s.inputs.data());
    } else if (s.mode == MODE_REPLAY && s.active && s.haveInputs) {
        apply_inputs(s.inputs.data());
    }
}

extern "C" void __cdecl swrRace_IncrementFrameTimer_lockstep(void) {
    if (!s.configRead)
        read_config();
    if (s.mode != MODE_OFF && !s.finished) {
        swrObjJdge *j = judge();
        const bool running = race_running(j);
        if (!s.active && race_scene_ready(j)) {
            if (swr_fixedTimestep) {
                log_line("lockstep: fixed-timestep is on; it changes the sim, turn it off");
                s.finished = true;
            } else if (!start()) {
                s.finished = true;
                if (s.file) {
                    fclose(s.file);
                    s.file = nullptr;
                }
            }
        } else if (s.active) {
            if (running)
                s.sawRace = true;
            if (j == nullptr || racer_count() == 0)
                stop("race left");
            else if (s.sawRace && !running)
                stop("race over");
        }
        if (s.active)
            frame_step();
    }
    if (s.pinDt && !s.finished) {
        swr_FastMode = 1;
        swr_fixedDeltaTimeSecs = 1.0 / (double) s.hz;
    }
    hook_call_original((void_fn_t) swrRace_IncrementFrameTimer_ADDR);
    // swr_FastMode leaves the unclamped delta alone, and the race clock (swrObjJdge_F2) sums it.
    if (s.pinDt && !s.finished)
        swrRace_dt_raw_d = swr_fixedDeltaTimeSecs;
}

typedef void(__cdecl *StartRace_t)(swrObjHang *, int *, int);

// The single-player roster (AI pilots, grid) is rolled from swrUtils_Rand here, from whatever state
// the menus left it in; pin it so record and replay race the same field.
extern "C" void __cdecl swrObjHang_StartRace_lockstep(swrObjHang *hang, int *rosterArg, int noBroadcast) {
    if (!s.configRead)
        read_config();
    if (s.mode != MODE_OFF && !s.finished && !s.active) {
        if (s.mode == MODE_RECORD) {
            s.startRaceRand = swrUtils_randState;
            s.haveStartRaceRand = true;
            s.setup = {hang->demo_mode,      hang->track_index,       hang->circuitIdx, hang->isTournamentMode,
                       hang->timeAttackMode, hang->bMirror,           hang->num_local_players,
                       hang->num_players,    hang->vehiclePlayer,     hang->numLaps,    hang->AISpeed,
                       {0, 0}};
        } else if (s.headerRead || open_replay()) {
            s.hz = s.hdr.hz;
            swrUtils_randState = s.hdr.startRaceRandState;
            log_line("lockstep: StartRace, rng pinned to %08x", (uint32_t) s.hdr.startRaceRandState);
        }
        if (!s.pinDt) {
            s.savedFastMode = swr_FastMode;
            s.savedFixedDt = swr_fixedDeltaTimeSecs;
            s.pinDt = true;
        }
    }
    hook_call_original((StartRace_t) swrObjHang_StartRace_ADDR, hang, rosterArg, noBroadcast);
}

typedef void(__cdecl *LoadScreen_t)(swrObjHang *, int, int);

// Frames the main menu must have been up before autostart, so the profile and hangar are settled.
constexpr int kAutostartMenuFrames = 30;

extern "C" void lockstep_frame_service(void) {
    if (!s.configRead)
        read_config();
    s.fastForward = s.mode == MODE_REPLAY && s.pinDt && !s.finished;
}

// Called after the hangar's own F0, the slot where retail's menus call LoadScreen, so the rest of
// that frame (the new racers' first tick) runs exactly as it does after a menu-driven start.
extern "C" void lockstep_hang_f0(swrObjHang *hang) {
    static bool inService = false;
    if (inService)
        return;
    if (!s.configRead)
        read_config();
    if (s.mode != MODE_REPLAY || !s.autostart || s.autostarted || s.finished)
        return;
    static int menuFrames = 0;
    if (hang == nullptr ||
        (hang->menuScreen != swrObjHang_STATE_SPLASH && hang->menuScreen != swrObjHang_STATE_MAIN_MENU)) {
        menuFrames = 0;
        return;
    }
    if (++menuFrames < kAutostartMenuFrames)
        return;
    if (!s.headerRead && !open_replay()) {
        s.finished = true;
        return;
    }
    const RaceSetup &r = s.hdr.setup;
    hang->demo_mode = r.demoMode;
    hang->track_index = r.trackIndex;
    hang->circuitIdx = r.circuitIdx;
    hang->isTournamentMode = r.isTournamentMode;
    hang->timeAttackMode = r.timeAttackMode;
    hang->bMirror = r.mirror;
    hang->num_local_players = r.localPlayers;
    hang->num_players = r.numPlayers;
    hang->vehiclePlayer = r.vehiclePlayer;
    hang->numLaps = r.numLaps;
    hang->AISpeed = r.aiSpeed;
    s.autostarted = true;
    log_line("lockstep: autostart track %d, %d racers, %d laps, pod %d", r.trackIndex, r.numPlayers, r.numLaps,
             r.vehiclePlayer);
    inService = true;
    ((LoadScreen_t) swrObjHang_LoadScreen_ADDR)(hang, 1, 0);
    inService = false;
}

extern "C" bool lockstep_fast_forward(void) { return s.fastForward; }
