#include "test_runner.h"
#include "hook_helper.h"
#include "imgui_utils.h"

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
#define TEST_MENU_BIT_UP (0x4000)// swrUI_localPlayersInputPressedBitset, as the menus read it
#define TEST_MENU_BIT_DOWN (0x8000)
#define TEST_MENU_BIT_LEFT (0x10000)
#define TEST_MENU_BIT_RIGHT (0x20000)
#define TEST_MENU_STEP_MS (600)   // between synthetic presses
#define TEST_MENU_SETTLE_MS (1500)// after a screen change, before the first press
#define TEST_MENU_DWELL_MS (2500) // TEST_KEY_WAIT
#define TEST_MENU_IDLE_SKIP_MS (8000)// a screen with no script this long gets an accept
#define TEST_MENU_TIMEOUT_S (240)

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
    bool menus = false;// tour the front-end menus with synthetic input before the planned races
    int hd = -1;       // HD model replacement: 1 on, 0 off, -1 the user's setting
};

enum TestPhase {
    TEST_IDLE,
    TEST_WAIT_HANGAR,
    TEST_MENU_TOUR,
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
static int g_track;     // track of the race being run
static bool g_tour_race;// the current race was started from the menus, not the plan
static int g_user_hd = -1;// imgui_state.HD_replacement before the plan overrode it

enum TestKey {
    TEST_KEY_NONE,
    TEST_KEY_UP,
    TEST_KEY_DOWN,
    TEST_KEY_LEFT,
    TEST_KEY_RIGHT,
    TEST_KEY_ACCEPT,
    TEST_KEY_CANCEL,
    TEST_KEY_WAIT,
    TEST_KEY_START_RACE,// accept on the main menu's Start Race row; the race that follows is tracked
};

static TestKey g_key;// queued for the next input build
static std::vector<TestKey> g_script;// keys left for the current screen visit
static int g_screen = -2;
static DWORD g_screen_ms;
static DWORD g_key_ms;
static int g_main_menu_visits;
static bool g_browsed_vehicles;
static bool g_browsed_tracks;

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
        else if (strcmp(key, "menus") == 0)
            g_plan.menus = atoi(value) != 0;
        else if (strcmp(key, "hd") == 0)
            g_plan.hd = atoi(value);
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
static void reset_race_watch(int track) {
    g_track = track;
    g_race_frames = 0;
    g_finished_ms = 0;
    g_race_start_ms = GetTickCount();
    g_racing_ms = 0;
    g_progress = 0.0f;
    g_outcome = nullptr;
    set_phase(TEST_RACING);
}

static void start_race(swrObjHang *hang) {
    const int track = g_plan.tracks[g_next];
    hang->demo_mode = 0;
    hang->isTournamentMode = 0;
    hang->timeAttackMode = 0;
    hang->num_players = (char) g_plan.racers;
    hang->numLaps = (char) g_plan.laps;
    hang->track_index = (char) track;
    fprintf(hook_log, "[test_runner] race %u/%u: track %d (%s)\n", (unsigned) g_next + 1,
            (unsigned) g_plan.tracks.size(), track, track_name(track));
    fflush(hook_log);
    reset_race_watch(track);
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
    const DWORD now = GetTickCount();
    const DWORD racing = g_racing_ms != 0 ? g_racing_ms : now;
    log_result("{\"race\":%u,\"track\":%d,\"name\":\"%s%s\",\"outcome\":\"%s\",\"frames\":%d,"
               "\"seconds\":%lu,\"load_s\":%lu,\"race_s\":%lu,\"laps_done\":%.2f}",
               g_tour_race ? 0u : (unsigned) g_next + 1, g_track, g_tour_race ? "menu tour: " : "",
               track_name(g_track),
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
        if (g_tour_race)
            g_tour_race = false;// the planned races follow
        else
            g_next++;
        if (g_next < g_plan.tracks.size())
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

extern "C" int test_runner_TakeMenuBits(int player) {
    if (player != 0)
        return 0;
    int bits = 0;
    switch (g_key) {
        case TEST_KEY_UP:
            bits = TEST_MENU_BIT_UP;
            break;
        case TEST_KEY_DOWN:
            bits = TEST_MENU_BIT_DOWN;
            break;
        case TEST_KEY_LEFT:
            bits = TEST_MENU_BIT_LEFT;
            break;
        case TEST_KEY_RIGHT:
            bits = TEST_MENU_BIT_RIGHT;
            break;
        default:
            return 0;
    }
    g_key = TEST_KEY_NONE;
    return bits;
}

extern "C" void test_runner_InjectEdges(void) {
    if (g_key == TEST_KEY_ACCEPT) {
        swrControl_acceptPressedEdge = 1;
        swrControl_menuAcceptPressedEdge = 1;
        g_key = TEST_KEY_NONE;
    } else if (g_key == TEST_KEY_CANCEL) {
        swrControl_cancelPressedEdge = 1;
        g_key = TEST_KEY_NONE;
    }
}

static void push_keys(TestKey key, int count) {
    for (int i = 0; i < count; i++)
        g_script.push_back(key);
}

// What to do on each visit to a front-end screen. Browses each list once, opens Inspect Vehicle,
// backs out of the main menu once (back path), then starts a race from the main menu.
static void plan_screen(const swrObjHang *hang, int screen) {
    g_script.clear();
    switch (screen) {
        case swrObjHang_STATE_SPLASH:
        case swrObjHang_STATE_ENTER_NAME:
            g_script = {TEST_KEY_ACCEPT};
            break;
        case swrObjHang_STATE_SELECT_VEHICLE:
            if (!g_browsed_vehicles) {
                push_keys(TEST_KEY_RIGHT, 3);
                push_keys(TEST_KEY_LEFT, 2);
                g_browsed_vehicles = true;
            }
            g_script.push_back(TEST_KEY_ACCEPT);
            break;
        case swrObjHang_STATE_SELECT_PLANET:
        case swrObjHang_STATE_SELECT_TRACK:
            if (!g_browsed_tracks) {
                push_keys(TEST_KEY_RIGHT, 2);
                push_keys(TEST_KEY_LEFT, 1);
                g_browsed_tracks = true;
            }
            g_script.push_back(TEST_KEY_ACCEPT);
            break;
        case swrObjHang_STATE_MAIN_MENU:
            g_main_menu_visits++;
            push_keys(TEST_KEY_UP, hang->mainMenuSelection);// row 0 = Start Race
            if (g_main_menu_visits == 1) {
                push_keys(TEST_KEY_DOWN, 2);
                push_keys(TEST_KEY_UP, 2);
                g_script.push_back(TEST_KEY_DOWN);// row 1 = Inspect Vehicle (single local player)
                g_script.push_back(TEST_KEY_ACCEPT);
            } else if (g_main_menu_visits == 2) {
                g_script.push_back(TEST_KEY_CANCEL);
            } else {
                g_script.push_back(TEST_KEY_START_RACE);
            }
            break;
        case swrObjHang_STATE_LOOK_AT_VEHICLE:
            g_script = {TEST_KEY_WAIT, TEST_KEY_CANCEL};
            break;
        case swrObjHang_STATE_LEGAL:
        case swrObjHang_STATE_LOAD_SCREEN:
        case swrObjHang_STATE_TAUNT_SCENE:
        case swrObjHang_STATE_PLANET_SELECT_INTRO:
        case swrObjHang_STATE_RESULTS_INTRO:
        case swrObjHang_STATE_VEHICLE_SELECT_INTRO:
            break;// transitions: wait (an idle accept fires if one stalls)
        default:
            g_script = {TEST_KEY_CANCEL};
            break;
    }
}

static void service_menu_tour(DWORD now) {
    swrObjHang *hang = (swrObjHang *) swrEvent_GetItem('Hang', 0);
    if (hang == nullptr)
        return;
    const int screen = (int) hang->menuScreen;
    if (screen != g_screen) {
        fprintf(hook_log, "[test_runner] menu tour: screen %d -> %d\n", g_screen, screen);
        fflush(hook_log);
        g_screen = screen;
        g_screen_ms = now;
        g_key_ms = now;
        plan_screen(hang, screen);
    }
    if (g_key != TEST_KEY_NONE || now - g_screen_ms < TEST_MENU_SETTLE_MS)
        return;
    if (g_script.empty()) {
        if (now - g_key_ms >= TEST_MENU_IDLE_SKIP_MS) {
            g_key = TEST_KEY_ACCEPT;
            g_key_ms = now;
        }
        return;
    }
    const TestKey next = g_script.front();
    if (now - g_key_ms < (next == TEST_KEY_WAIT ? TEST_MENU_DWELL_MS : TEST_MENU_STEP_MS))
        return;
    g_script.erase(g_script.begin());
    g_key_ms = now;
    if (next == TEST_KEY_WAIT)
        return;
    if (next == TEST_KEY_START_RACE) {
        g_key = TEST_KEY_ACCEPT;
        g_tour_race = true;
        fprintf(hook_log, "[test_runner] menu tour: starting track %d from the main menu\n",
                (int) hang->track_index);
        fflush(hook_log);
        reset_race_watch(hang->track_index);
        return;
    }
    g_key = next;
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
    if (g_user_hd >= 0)
        imgui_state.HD_replacement = g_user_hd != 0;// Main_Shutdown may persist settings
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
               "\"max_upgrades\":%d,\"pace\":%.2f,\"sample_s\":%d,\"finish_tracks\":%u,\"menus\":%d,"
               "\"hd\":%d}",
               (unsigned) g_plan.tracks.size(), g_plan.laps, g_plan.racers, g_plan.autopilot,
               g_plan.max_upgrades, g_plan.pace, g_plan.sample_s, (unsigned) g_plan.finish_tracks.size(),
               g_plan.menus, g_plan.hd);
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

    // Every frame: the settings ini is read after test_runner_Init and would overwrite it.
    if (g_plan.hd >= 0) {
        if (g_user_hd < 0)
            g_user_hd = imgui_state.HD_replacement ? 1 : 0;
        imgui_state.HD_replacement = g_plan.hd != 0;
    }

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
                                    hang->menuScreen == swrObjHang_STATE_MAIN_MENU)) {
                if (g_plan.menus)
                    set_phase(TEST_MENU_TOUR);
                else
                    start_race(hang);
            }
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
            } else if (racing && !finishes(g_track) &&
                       now - g_racing_ms >= (DWORD) g_plan.sample_s * 1000) {
                end_race("sampled", 'Abrt');
            } else if (racing && now - g_progress_ms >= (DWORD) TEST_STUCK_S * 1000) {
                end_race("stuck", 'Abrt');
            } else if (now - g_race_start_ms >= (DWORD) g_plan.race_timeout_s * 1000) {
                end_race("timeout", 'Abrt');
            }
            break;
        }
        case TEST_MENU_TOUR:
            service_menu_tour(now);
            if (g_phase == TEST_MENU_TOUR && now - g_phase_ms >= (DWORD) TEST_MENU_TIMEOUT_S * 1000)
                finish_run("menu tour never started a race");
            break;
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
