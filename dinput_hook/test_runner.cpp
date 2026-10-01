#include "test_runner.h"
#include "hook_helper.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <Main/swrMain.h>
#include <Swr/swrEvent.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <globals.h>
#include <types_enums.h>
#include "game_deltas/tracks_delta.h"
#include "game_deltas/Window_delta.h"
}

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

#if SWR_COVERAGE
extern "C" int __llvm_profile_write_file(void);
extern "C" void __llvm_profile_set_filename(const char *name);
#endif

#define TEST_PLAN_FILE "swr_test_plan.ini"
#define TEST_PLAN_RUNNING_FILE "swr_test_plan.running"
#define TEST_RESULTS_FILE "swr_test_results.jsonl"
#define TEST_STOCK_TRACK_COUNT (25)
#define TEST_FINISHED_SCORE_FLAG (2)// swrScore.flag: racer crossed the line on the last lap
#define TEST_FINISH_ARM_S (10)// the previous race's score can still read finished this long
#define TEST_HANGAR_TIMEOUT_S (180)
#define TEST_ENDING_TIMEOUT_S (60)
#define TEST_STUCK_S (30)// no lap progress this long while racing -> give up on the race
#define TEST_STUCK_MIN_GAIN (0.01f)// laps
#define TEST_MAX_UPGRADE_LEVEL (5)
#define TEST_PART_HEALTH_NEW ((char) 0xFF)
#define TEST_UPGRADE_CATEGORIES (7)
#define TEST_POD_COUNT (23)// swrRacer_PodHandlingData entries
#define TEST_SCORE_COUNT (20)// swrScores capacity
#define TEST_AI_PACE_CEILING (1.6f)// swrRace_AI clamps its speed multiplier to [0.5, 1.6]

typedef void(__cdecl *swrObjHang_LoadScreenFn)(swrObjHang *hang, int a, int b);
typedef int(__cdecl *swrObjHang_F4Fn)(swrObjHang *hang, int *subEvents, int *p3);
typedef void(__cdecl *swrRace_CalcTargetTurnRateFn)(swrRace *player);
typedef void *(__cdecl *swrObjHang_BuildRosterSinglePlayerFn)(swrObjHang *hang, int *out);

struct TestPlan {
    std::vector<int> tracks;
    int laps = 1;
    int racers = 6;
    std::vector<int> finish_tracks;// raced to the line; every other track is driven for sample_s
    int sample_s = 45;
    float pace = TEST_AI_PACE_CEILING;// floor for the autopilot pod's speedMultiplier; 0 = game's own
    int race_timeout_s = 300;
    int finish_grace_s = 3;
    bool autopilot = true;
    bool max_upgrades = true;
};

enum TestPhase {
    TEST_IDLE,
    TEST_WAIT_HANGAR,
    TEST_RACING,
    TEST_ENDING,// swrObjJdge_Clear issued; waiting for 'Fini' / 'Abrt' to reach the hangar
    TEST_DONE,
};

static TestPlan g_plan;
static TestPhase g_phase = TEST_IDLE;
static FILE *g_results;
static size_t g_next;// index into g_plan.tracks of the race being run
static int g_passed;
static int g_failed;
static DWORD g_phase_ms;
static DWORD g_finished_ms;
static DWORD g_race_start_ms;
static DWORD g_racing_ms;// first frame the local pod was racing (load + countdown before it)
static DWORD g_progress_ms;// last time lap progress grew
static float g_progress;
static int g_race_frames;
static const char *g_outcome;

static void log_result(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(g_results, fmt, args);
    va_end(args);
    fputc('\n', g_results);
    fflush(g_results);
}

static std::vector<int> parse_tracks(const char *value) {
    std::vector<int> tracks;
    if (strcmp(value, "all") == 0) {
        for (int t = 0; t < TEST_STOCK_TRACK_COUNT; t++)
            tracks.push_back(t);
        return tracks;
    }
    for (const char *p = value; *p != '\0';) {
        char *end;
        const long t = strtol(p, &end, 10);
        if (end == p)
            break;
        if (t >= 0 && t < TEST_STOCK_TRACK_COUNT)
            tracks.push_back((int) t);
        p = (*end == ',') ? end + 1 : end;
    }
    return tracks;
}

static bool read_plan(FILE *f) {
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n#")] = '\0';
        char *eq = strchr(line, '=');
        if (eq == nullptr)
            continue;
        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;
        if (strcmp(key, "tracks") == 0)
            g_plan.tracks = parse_tracks(value);
        else if (strcmp(key, "laps") == 0)
            g_plan.laps = atoi(value);
        else if (strcmp(key, "racers") == 0)
            g_plan.racers = atoi(value);
        else if (strcmp(key, "race_timeout_s") == 0)
            g_plan.race_timeout_s = atoi(value);
        else if (strcmp(key, "finish_grace_s") == 0)
            g_plan.finish_grace_s = atoi(value);
        else if (strcmp(key, "autopilot") == 0)
            g_plan.autopilot = atoi(value) != 0;
        else if (strcmp(key, "finish_tracks") == 0)
            g_plan.finish_tracks = strcmp(value, "none") == 0 ? std::vector<int>() : parse_tracks(value);
        else if (strcmp(key, "sample_s") == 0)
            g_plan.sample_s = atoi(value);
        else if (strcmp(key, "pace") == 0)
            g_plan.pace = (float) atof(value);
        else if (strcmp(key, "max_upgrades") == 0)
            g_plan.max_upgrades = atoi(value) != 0;
    }
    return !g_plan.tracks.empty() && g_plan.laps > 0 && g_plan.racers > 0;
}

// Without the leading "~x" text-formatting codes.
static const char *track_name(int track) {
    const char *name = swrUI_GetTrackNameFromId_delta(track);
    while (name[0] == '~' && name[1] != '\0')
        name += 2;
    return name;
}

static bool finishes(int track) {
    for (int t: g_plan.finish_tracks)
        if (t == track)
            return true;
    return false;
}

static void set_phase(TestPhase phase) {
    g_phase = phase;
    g_phase_ms = GetTickCount();
}

// Same entry the retail demo loop and the pause-menu restart use. Never from inside the ImGui
// frame: LoadScreen renders its progress bar through a nested display update.
static void start_race(swrObjHang *hang) {
    const int track = g_plan.tracks[g_next];
    hang->demo_mode = 0;
    hang->isTournamentMode = 0;
    hang->timeAttackMode = 0;
    hang->num_players = (char) g_plan.racers;
    hang->numLaps = (char) g_plan.laps;
    hang->track_index = (char) track;
    g_race_frames = 0;
    g_finished_ms = 0;
    g_race_start_ms = GetTickCount();
    g_racing_ms = 0;
    g_progress = 0.0f;
    g_outcome = nullptr;
    fprintf(hook_log, "[test_runner] race %u/%u: track %d (%s)\n", (unsigned) g_next + 1,
            (unsigned) g_plan.tracks.size(), track, track_name(track));
    fflush(hook_log);
    set_phase(TEST_RACING);
    ((swrObjHang_LoadScreenFn) swrObjHang_LoadScreen_ADDR)(hang, 1, 0);
}

static void end_race(const char *outcome, int event) {
    swrObjJdge *jdge = (swrObjJdge *) swrEvent_GetItem('Jdge', 0);
    g_outcome = outcome;
    if (jdge != nullptr)
        swrObjJdge_Clear(jdge, event);
    set_phase(TEST_ENDING);
}

static void record_race(void) {
    const int track = g_plan.tracks[g_next];
    const DWORD now = GetTickCount();
    const DWORD racing = g_racing_ms != 0 ? g_racing_ms : now;
    log_result("{\"race\":%u,\"track\":%d,\"name\":\"%s\",\"outcome\":\"%s\",\"frames\":%d,"
               "\"seconds\":%lu,\"load_s\":%lu,\"race_s\":%lu,\"laps_done\":%.2f}",
               (unsigned) g_next + 1, track, track_name(track),
               g_outcome != nullptr ? g_outcome : "ended_by_game", g_race_frames,
               (now - g_race_start_ms) / 1000, (racing - g_race_start_ms) / 1000, (now - racing) / 1000,
               g_progress);
    if (g_outcome != nullptr && (strcmp(g_outcome, "finished") == 0 || strcmp(g_outcome, "sampled") == 0))
        g_passed++;
    else
        g_failed++;
}

// Race end reaches the hangar here; chain straight into the next race like the retail demo loop,
// skipping the holotable results screen. swrObjHang_F4 is a HANG stub, so hook the raw address.
static int __cdecl swrObjHang_F4_testrunner(swrObjHang *hang, int *subEvents, int *p3) {
    const int event = *subEvents;
    const int r = hook_call_original((swrObjHang_F4Fn) swrObjHang_F4_ADDR, hang, subEvents, p3);
    if ((g_phase == TEST_RACING || g_phase == TEST_ENDING) && (event == 'Fini' || event == 'Abrt')) {
        record_race();
        if (++g_next < g_plan.tracks.size())
            start_race(hang);
        else
            set_phase(TEST_DONE);
    }
    return r;
}

// The local pod takes swrRace_UpdatePlayerControl while LOCAL is set; lend the AI bit for this one
// call so swrRace_UpdateAutopilotControl drives it, and everything else still sees a local racer.
static void __cdecl swrRace_CalcTargetTurnRate_testrunner(swrRace *pod) {
    const uint32_t lendMask = swrObjTest_FLAG0_LOCAL | swrObjTest_FLAG0_AI;
    const bool lend = g_phase == TEST_RACING && g_plan.autopilot && (pod->flags0 & swrObjTest_FLAG0_LOCAL);
    const uint32_t saved = pod->flags0 & lendMask;
    if (lend)
        pod->flags0 = (swrObjTest_FLAG0) ((pod->flags0 & ~lendMask) | swrObjTest_FLAG0_AI);
    hook_call_original((swrRace_CalcTargetTurnRateFn) swrRace_CalcTargetTurnRate_ADDR, pod);
    if (lend) {
        pod->flags0 = (swrObjTest_FLAG0) ((pod->flags0 & ~lendMask) | saved);
        if (pod->speedMultiplier < g_plan.pace)
            pod->speedMultiplier = g_plan.pace;
    }
}

// Max upgrades on the local pod, layered on its base stats (the profile's own upgrades are already
// in podStats, so starting from podStats would stack them). Same call the roster builder makes.
static void *__cdecl swrObjHang_BuildRosterSinglePlayer_testrunner(swrObjHang *hang, int *out) {
    void *r = hook_call_original((swrObjHang_BuildRosterSinglePlayerFn) swrObjHang_BuildRosterSinglePlayer_ADDR,
                                 hang, out);
    if (g_phase != TEST_RACING || !g_plan.max_upgrades || out == nullptr)
        return r;
    char levels[TEST_UPGRADE_CATEGORIES];
    char healths[TEST_UPGRADE_CATEGORIES];
    memset(levels, TEST_MAX_UPGRADE_LEVEL, sizeof(levels));
    memset(healths, TEST_PART_HEALTH_NEW, sizeof(healths));
    for (int i = 0; i < TEST_SCORE_COUNT; i++) {
        swrScore *score = &swrScores[i];
        if (score->identifier != 'Locl' || score->pilotId == nullptr)
            continue;
        const int pod = *score->pilotId;
        if (pod >= 0 && pod < TEST_POD_COUNT)
            swrRace_ApplyUpgradesToStats(&score->podStats, &swrRacer_PodHandlingData[pod], levels, healths);
    }
    return r;
}

static void finish_run(const char *error) {
    if (error != nullptr)
        log_result("{\"event\":\"error\",\"race\":%u,\"message\":\"%s\"}", (unsigned) g_next + 1, error);
    log_result("{\"event\":\"done\",\"races\":%u,\"passed\":%d,\"failed\":%d}",
               (unsigned) g_plan.tracks.size(), g_passed, g_failed);
    fclose(g_results);
    fprintf(hook_log, "[test_runner] done: %d passed, %d failed\n", g_passed, g_failed);
    fflush(hook_log);
#if SWR_COVERAGE
    __llvm_profile_write_file();// ExitProcess below skips the runtime's atexit dump
#endif
    remove(TEST_PLAN_RUNNING_FILE);
    Main_Shutdown();
    ExitProcess(error == nullptr && g_failed == 0 ? 0 : 1);
}

extern "C" void test_runner_Init(void) {
    FILE *f = fopen(TEST_PLAN_FILE, "r");
    if (f == nullptr)
        return;
    const bool ok = read_plan(f);
    fclose(f);
    remove(TEST_PLAN_RUNNING_FILE);
    rename(TEST_PLAN_FILE, TEST_PLAN_RUNNING_FILE);
    if (!ok) {
        fprintf(hook_log, "[test_runner] " TEST_PLAN_FILE " has no valid tracks; not arming\n");
        return;
    }
    g_results = fopen(TEST_RESULTS_FILE, "w");
    if (g_results == nullptr)
        return;
#if SWR_COVERAGE
    CreateDirectoryA("coverage", nullptr);// ignore ERROR_ALREADY_EXISTS
    __llvm_profile_set_filename("coverage\\dinput-%p.profraw");
#endif
    log_result("{\"event\":\"start\",\"races\":%u,\"laps\":%d,\"racers\":%d,\"autopilot\":%d,"
               "\"max_upgrades\":%d,\"pace\":%.2f,\"sample_s\":%d,\"finish_tracks\":%u}",
               (unsigned) g_plan.tracks.size(), g_plan.laps, g_plan.racers, g_plan.autopilot,
               g_plan.max_upgrades, g_plan.pace, g_plan.sample_s, (unsigned) g_plan.finish_tracks.size());
    fprintf(hook_log, "[test_runner] armed: %u race(s)\n", (unsigned) g_plan.tracks.size());
    fflush(hook_log);
    set_phase(TEST_WAIT_HANGAR);
}

extern "C" void test_runner_RegisterHooks(void) {
    if (g_phase == TEST_IDLE)
        return;
    hook_function("swrObjHang_F4", (uint32_t) swrObjHang_F4_ADDR, (uint8_t *) swrObjHang_F4_testrunner);
    hook_function("swrRace_CalcTargetTurnRate", (uint32_t) swrRace_CalcTargetTurnRate_ADDR,
                  (uint8_t *) swrRace_CalcTargetTurnRate_testrunner);
    hook_function("swrObjHang_BuildRosterSinglePlayer", (uint32_t) swrObjHang_BuildRosterSinglePlayer_ADDR,
                  (uint8_t *) swrObjHang_BuildRosterSinglePlayer_testrunner);
}

extern "C" int test_runner_Active(void) {
    return g_phase != TEST_IDLE;
}

extern "C" void test_runner_Service(void) {
    if (g_phase == TEST_IDLE)
        return;
    // Only once the hangar exists: earlier, input and the display aren't up yet.
    if (Window_Active == 0 && swrEvent_GetItem('Hang', 0) != nullptr)
        Window_ForceActive_delta();

    const DWORD now = GetTickCount();
    switch (g_phase) {
        case TEST_WAIT_HANGAR: {
            swrObjHang *hang = (swrObjHang *) swrEvent_GetItem('Hang', 0);
            static int lastScreen = -2;
            const int screen = hang != nullptr ? (int) hang->menuScreen : -1;
            if (screen != lastScreen) {
                fprintf(hook_log, "[test_runner] waiting: hangar screen %d\n", screen);
                fflush(hook_log);
                lastScreen = screen;
            }
            if (hang != nullptr && (hang->menuScreen == swrObjHang_STATE_SPLASH ||
                                    hang->menuScreen == swrObjHang_STATE_ENTER_NAME ||
                                    hang->menuScreen == swrObjHang_STATE_MAIN_MENU))
                start_race(hang);
            else if (now - g_phase_ms >= (DWORD) TEST_HANGAR_TIMEOUT_S * 1000)
                finish_run("never reached the hangar");
            break;
        }
        case TEST_RACING: {
            g_race_frames++;
            const swrRace *pod = firstLocalPlayer != nullptr ? firstLocalPlayer->obj_test_ptr : nullptr;
            const bool racing = pod != nullptr &&
                                (pod->flags0 & swrObjTest_FLAG0_STATE_MASK) == swrObjTest_FLAG0_RACING;
            if (racing && g_racing_ms == 0) {
                g_racing_ms = now;
                g_progress_ms = now;
            }
            if (racing) {
                const float progress = swrObjJdge_GetRacerProgress(firstLocalPlayer);
                if (progress > g_progress + TEST_STUCK_MIN_GAIN) {
                    g_progress = progress;
                    g_progress_ms = now;
                }
            }
            if (now - g_race_start_ms >= (DWORD) TEST_FINISH_ARM_S * 1000 &&
                firstLocalPlayer != nullptr && (firstLocalPlayer->flag & TEST_FINISHED_SCORE_FLAG)) {
                if (g_finished_ms == 0)
                    g_finished_ms = now;
                if (now - g_finished_ms >= (DWORD) g_plan.finish_grace_s * 1000)
                    end_race("finished", 'Fini');
            } else if (racing && !finishes(g_plan.tracks[g_next]) &&
                       now - g_racing_ms >= (DWORD) g_plan.sample_s * 1000) {
                end_race("sampled", 'Abrt');
            } else if (racing && now - g_progress_ms >= (DWORD) TEST_STUCK_S * 1000) {
                end_race("stuck", 'Abrt');
            } else if (now - g_race_start_ms >= (DWORD) g_plan.race_timeout_s * 1000) {
                end_race("timeout", 'Abrt');
            }
            break;
        }
        case TEST_ENDING:
            if (now - g_phase_ms >= (DWORD) TEST_ENDING_TIMEOUT_S * 1000)
                finish_run("race end never reached the hangar");
            break;
        case TEST_DONE:
            finish_run(nullptr);
            break;
        default:
            break;
    }
}
