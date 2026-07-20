#include <macros.h>
#include <cstring>
#include <cstdio>
#include "swrObjJdge_delta.h"
#include "swrRace_delta.h"

extern "C" {
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrText.h>
#include <Swr/swrSprite.h>
#include <Swr/swrEvent.h>
#include <Swr/swrMultiplayer.h>
#include <Swr/swrSound.h>
#include <Swr/swrModel.h>       // ClearSceneAnimations / Reset*Sprites addresses
#include <Swr/swrWeather.h>     // swrWeather_ResetParticles address
#include <Platform/stdControl.h>// stdControl_ReadControls_ADDR (boost-start Enter suppression)
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"
#include "../patch.h"
#include "../ui_transform.h"
#include "../imgui_utils.h"// imgui_state.fast_restart (the debug-menu toggle)

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

// Snapshot the freshly-loaded scene-animation state so a fast restart can restore it (defined in
// the fast-restart section; called from InitTrack_delta after each real track load).
static void capture_scene_animation_state();

// The race's intro-countdown duration, latched fresh by the 'Begn' handler before InitTrack and then
// counted down during the run. A fast restart must restore it (not the drained value) so the
// pre-race countdown -- and the boost-start window it provides -- is the same as a fresh race.
static float g_countdown_ms = 0.0f;
static bool g_countdown_valid = false;

int fixup_invalid_node_ptrs(swrModel_Node *&node) {
    if (!node)
        return 0;

    switch (node->type) {
        case NODE_MESH_GROUP:
            break;
        case NODE_BASIC:
            break;
        case NODE_SELECTOR:
            break;
        case NODE_LOD_SELECTOR:
            break;
        case NODE_TRANSFORMED:
            break;
        case NODE_TRANSFORMED_WITH_PIVOT:
            break;
        case NODE_TRANSFORMED_COMPUTED:
            break;
        default:
            // this model type is invalid, set it to null.
            node = nullptr;
            return 1;
    }

    int num_removed_nodes = 0;
    if (node->type & NODE_HAS_CHILDREN) {
        for (int i = 0; i < node->num_children; i++)
            num_removed_nodes += fixup_invalid_node_ptrs(node->children.nodes[i]);
    }
    return num_removed_nodes;
}

// TODO hack: this is a workaround for a crash when loading custom tracks. sometimes the scene graph
//  contains nodes with invalid child pointers, this happens after playing a vanilla track and
//  afterwards a custom track. can be reproduced playing "Spice Mine Run" and then "Bowsers Castle 1".
static void reset_lap_tracking(swrScore *scores); // 100-lap support, defined below

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore *scores) {
    // Drop cable nodes from the previous track so freed pointers aren't matched against new meshes.
    swrRace_ClearCableBends();
    const unsigned int x = hook_call_original(swrObjJdge_InitTrack, judge, scores);
    reset_lap_tracking(scores);
    capture_scene_animation_state();// record fresh animation state for a later fast restart
    g_countdown_ms = judge->countdownTimer_ms;// fresh countdown duration ('Begn' latched it above)
    g_countdown_valid = true;
    const int num_removed_nodes = fixup_invalid_node_ptrs(swrViewport_array[0].model_root_node);
    if (num_removed_nodes != 0)
    {
        fprintf(hook_log, "[swrObjJdge_InitTrack_delta] HACK: removed %d nodes with an invalid node type.\n", num_removed_nodes);
        fflush(hook_log);
    }
    return x;
}

// --- fast restart (speedrunner hotkey) -------------------------------------------------------
// A hotkey (Enter) that restarts the current race INSTANTLY with no loading screen, landing in the
// pre-race countdown exactly like a freshly started race. The pause-menu "Restart Race" and the
// debug "Restart race (apply settings)" button are deliberately left on the full-reload path (they
// re-read the track from disk) so modders keep asset hot-reload -- only this hotkey is fast.
//
// The vanilla restart tears the whole race down (freeing every pod) and rebuilds it via
// swrObjHang_LoadScreen -> StartRace -> swrObjJdge_InitTrack, which resets the asset buffer and
// re-reads/re-parses the track AND respawns every pod. Profiling showed the pod respawn
// (swrObjJdge_SpawnRacers, ~187 ms for a full grid) plus the teardown resets (~140 ms) dominate --
// i.e. tearing down and rebuilding the same field every time. So instead we DON'T tear down: we
// keep every pod (and all loaded assets) resident and reset each pod in place.
//
// swrRace_Init (0x00475ad0, called by swrObjJdge_SpawnRacer) is a pure state initializer -- given a
// pod, its model, and a spawn transform it resets the pod to race-start (position, velocity, laps,
// heat, flags, ...) with no allocation. We capture the exact 10 arguments of each pod's swrRace_Init
// at spawn time (swrRace_Init_capture below), then on restart replay them verbatim on the SAME pod.
// Because nothing is freed or moved, every captured pointer (pod model, spline, node arrays) stays
// valid, so the replay reproduces a fresh spawn byte-for-byte. Around that we reset the score, the
// judge (into the countdown), the AI, particles/weather, sound and cameras -- the same things a
// fresh race sets up outside the pods.

typedef void(__cdecl *swrObjHang_AssignRacerCameras_t)(void *hang);
typedef void(__cdecl *swrRace_Init_t)(swrRace *, float, int, void *, int, float *, int, int, int,
                                      int);

static bool g_fast_restart_requested = false;// set by the hotkey, consumed next frame

// Boost-start fix. The build sets ENABLE_GLFW_INPUT_HANDLING=0, so the game reads the keyboard from
// real DirectInput -- consuming Enter in the GLFW callback does NOT hide it from the game. A restart
// key (Enter) still physically held into the fresh countdown reads as accelerate/accept and cancels
// the boost-start charge (confirmed: the game sees Enter held right as the countdown begins). So
// after a fast restart we zero Enter's key state each frame -- right after the game's input read --
// until it is physically released, so the held restart-Enter can't reach the boost logic.
static bool g_suppress_enter = false;
#define DIK_RETURN_KEY 0x1c

// Pre-race pod-orbit skip. After a fast restart the intro plays out as judge states: nibble 4 =
// track fly-by sweep (dormant by default -> advances immediately), nibble 5 = pod orbit / binder
// ignition (~9s), then the 3-2-1 countdown. Ending the camera sweep alone left the ~9s state-5
// duration, so instead we advance the judge state machine itself (same mechanism as the cutscene
// skip feature, PR #222): in state 4 clear camSweepState so it advances to the orbit, in state 5
// raise the accept edge so the game advances the orbit straight to the countdown. Armed for a short
// frame window after a restart (bounded so it can never catch the post-race sweep). Done in
// swrObjJdge_F0_delta -- the edge must be set the same frame F0 reads it.
static int g_skip_orbit_frames = 0;

typedef void(__cdecl *swrObjJdge_F0_t)(swrObjJdge *);
void swrObjJdge_F0_delta(swrObjJdge *jdge) {
    if (g_skip_orbit_frames > 0) {
        g_skip_orbit_frames--;
        switch (jdge->flag & 0xf) {
            case 4:
                jdge->camSweepState = NULL;// end the (dormant) track sweep -> advance to the orbit
                break;
            case 5:
                swrControl_acceptPressedEdge = 1;// orbit -> countdown via the game's own advance
                break;
            default:
                g_skip_orbit_frames = 0;// reached the countdown / racing -> stop
                break;
        }
    }
    hook_call_original((swrObjJdge_F0_t) swrObjJdge_F0_ADDR, jdge);
}

typedef void(__cdecl *stdControl_ReadControls_t)(void);
void stdControl_ReadControls_boostfix_delta(void) {
    hook_call_original((stdControl_ReadControls_t) stdControl_ReadControls_ADDR);
    if (g_suppress_enter) {
        if (stdControl_aKeyInfos[DIK_RETURN_KEY] != 0)
            stdControl_aKeyInfos[DIK_RETURN_KEY] = 0;// still held from the restart -> hide it
        else
            g_suppress_enter = false;// released -> resume normal Enter input
    }
}

// Fresh scene-animation state captured after each real track load (InitTrack_delta), so a fast
// restart can rewind every scene animation to frame 0 and restore its loaded enabled/disabled
// state: ambient loops (enabled) restart from 0, while destructible/explosion FX (disabled until
// triggered) reset to their un-triggered, whole state. Keyed by index into swrScene_animations,
// which the surgical restart never clears/reloads, so the indices/pointers stay valid.
static swrModel_Animation *g_anim_ptr[300];
static bool g_anim_enabled[300];
static float g_anim_speed[300];
static int g_anim_count = 0;

static unsigned int g_fx_enabled_mask;// fwd: cleared here, set by the EnableFXAnimation hook

static void capture_scene_animation_state() {
    // A fresh track load repopulates only this planet's FX indices, freeing the previous planet's.
    // Drop the recorded FX-enabled indices so a restart never resets a now-freed list (see below).
    g_fx_enabled_mask = 0;
    g_anim_count = swrScene_animations_count;
    if (g_anim_count > 300)
        g_anim_count = 300;
    for (int i = 0; i < g_anim_count; i++) {
        swrModel_Animation *a = swrScene_animations[i];
        g_anim_ptr[i] = a;
        g_anim_enabled[i] = a != NULL && (a->flags & ANIMATION_ENABLED) != 0;
        g_anim_speed[i] = a != NULL ? a->animation_speed : 0.0f;
    }
}

static void restore_scene_animation_state() {
    typedef void(__cdecl * anim_time_t)(swrModel_Animation *, float);
    typedef void(__cdecl * anim_flag_t)(swrModel_Animation *, swrModel_AnimationFlags);
    anim_time_t setTime = (anim_time_t) swrModel_AnimationSetTime_ADDR;
    anim_time_t setSpeed = (anim_time_t) swrModel_AnimationSetSpeed_ADDR;
    anim_flag_t setFlags = (anim_flag_t) swrModel_AnimationSetFlags_ADDR;
    anim_flag_t clearFlags = (anim_flag_t) swrModel_AnimationClearFlags_ADDR;
    for (int i = 0; i < g_anim_count; i++) {
        swrModel_Animation *a = swrScene_animations[i];
        if (a == NULL || a != g_anim_ptr[i])// list changed (a full reload happened) -> skip
            continue;
        setTime(a, 0.0f);
        setSpeed(a, g_anim_speed[i]);// triggers (e.g. doors) flip anim speed to +/-20; reset it
        if (g_anim_enabled[i])
            setFlags(a, ANIMATION_ENABLED);
        else
            clearFlags(a, ANIMATION_ENABLED);
    }
}

// --- destructible / FX trigger restore --------------------------------------------------------
// Every trigger the pod interacts with -- destructibles, breakables, doors / animated props,
// hazards, camera-shake and sound zones, ... -- fires through one dispatcher: swrRace_TriggerHandler.
// Detection (swrRace_ActivateTriggersInRange) processes a swrModel_TriggerDescription only while its
// flags bit 0x1 is CLEAR (armed); firing a one-shot sets 0x1 (disarm) and the handler often hides or
// animates a scene node, then frees the on-demand swrObjTrig entity. So for a deterministic restart
// we hook the dispatcher and, the first time each trigger fires this run, snapshot (a) its
// description's flags (the armed state -- the low bits are per-lap/speed/AI config we must preserve)
// and (b) any node it acts on: the destructible intact node (swrObjTrig.unk3c_node, set lazily) and
// the description's affected_node, with their visibility. On restart we restore those description
// flags (re-arming every trigger) and node flags (re-showing anything hidden). Node *animations*
// (doors, etc.) are reset separately by the scene-animation rewind, and the entity needs nothing --
// detection recreates it once the description is armed. No pool/allocation/reload is touched.
struct FiredDesc {
    swrModel_TriggerDescription *desc;
    uint16_t flags;
};
struct HiddenNode {
    swrModel_Node *node;
    uint32_t flags_1;
    uint32_t flags_2;
};
static FiredDesc g_fired_desc[128];
static int g_fired_desc_count = 0;
static HiddenNode g_hidden_node[128];
static int g_hidden_node_count = 0;

// Knock-over flags (trigger type 0x6c / HandleTrigger108). The flag is a single per-trigger node
// (swrObjTrig_FindNode(desc) -> swrObjTrig_NodePerTriggerArray[i]); knocking it swaps that node's
// children pointer from the standing model to the fallen one (ModelArray1+4) and toggles its
// visibility -- unk3c_node / affected_node are null for these. So we snapshot the node's standing
// children + visibility the first time it's knocked (via FindNode at the dispatcher, before the
// handler swaps it) and restore both on restart, returning the flag to upright.
#define TRIGGER_TYPE_KNOCKOVER_FLAG 0x6c
typedef swrModel_NodeTransformedWithPivot *(__cdecl *swrObjTrig_FindNode_t)(
    swrModel_TriggerDescription *);
struct FlagNode {
    swrModel_Node *node;
    swrModel_Node **standing_children;
    uint32_t standing_flags_1;
};
static FlagNode g_flag_node[64];
static int g_flag_node_count = 0;

static void record_flag_standing(swrModel_TriggerDescription *desc) {
    if (desc == NULL || g_flag_node_count >= 64)
        return;
    swrModel_NodeTransformedWithPivot *n = ((swrObjTrig_FindNode_t) swrObjTrig_FindNode_ADDR)(desc);
    if (n == NULL)
        return;
    swrModel_Node *node = &n->node;
    for (int i = 0; i < g_flag_node_count; i++)
        if (g_flag_node[i].node == node)
            return;// keep the first (pre-knock, standing) snapshot
    g_flag_node[g_flag_node_count].node = node;
    g_flag_node[g_flag_node_count].standing_children = node->children.nodes;
    g_flag_node[g_flag_node_count].standing_flags_1 = node->flags_1;
    g_flag_node_count++;
}

// g_fx_enabled_mask (defined above capture_scene_animation_state): trigger FX animations (flag
// falls, debris, ...) live in swrObjTrig_AnimationArray[6], populated PER PLANET by
// swrObjTrig_LoadAndInitializeTriggerModels -- and it only writes the indices the current planet
// uses, never clearing the rest, so unused indices keep stale/freed list pointers from a
// previously-loaded planet. Blind-iterating all 6 (as an early version did) walks a freed list and
// crashes. Instead we hook swrObjTrig_EnableFXAnimation to record which indices actually play this
// run -- always the current track's valid, just-loaded lists -- and reset only those.
typedef void(__cdecl *swrObjTrig_FX_t)(int);
void swrObjTrig_EnableFXAnimation_delta(int index) {
    if (index >= 0 && index < 6)
        g_fx_enabled_mask |= (1u << index);
    hook_call_original((swrObjTrig_FX_t) swrObjTrig_EnableFXAnimation_ADDR, index);
}

static void record_fired_desc(swrModel_TriggerDescription *desc) {
    if (desc == NULL || g_fired_desc_count >= 128)
        return;
    for (int i = 0; i < g_fired_desc_count; i++)
        if (g_fired_desc[i].desc == desc)
            return;// keep the first (armed) snapshot from before this run's firings disarmed it
    g_fired_desc[g_fired_desc_count].desc = desc;
    g_fired_desc[g_fired_desc_count].flags = desc->flags;
    g_fired_desc_count++;
}

static void record_hidden_node(swrModel_Node *n) {
    if (n == NULL || g_hidden_node_count >= 128)
        return;
    for (int i = 0; i < g_hidden_node_count; i++)
        if (g_hidden_node[i].node == n)
            return;// keep the first (visible) snapshot from before the trigger hid it
    g_hidden_node[g_hidden_node_count].node = n;
    g_hidden_node[g_hidden_node_count].flags_1 = n->flags_1;
    g_hidden_node[g_hidden_node_count].flags_2 = n->flags_2;
    g_hidden_node_count++;
}

// Hook on the single trigger dispatcher: snapshot the firing trigger's armed description + the nodes
// it may hide, before the original runs and disarms/hides them.
typedef void(__cdecl *swrRace_TriggerHandler_t)(int player, int a, char b);
void swrRace_TriggerHandler_delta(int player, int a, char b) {
    swrObjTrig *trig = (swrObjTrig *) player;
    record_fired_desc(trig->trigger_description);
    record_hidden_node(trig->unk3c_node);
    if (trig->trigger_description != NULL)
        record_hidden_node(trig->trigger_description->affected_node);
    // Knock-over flag: snapshot the flag node's standing children + visibility before the handler
    // swaps it to the fallen model (the node is FindNode(desc), the same one the handler uses).
    if (trig->trigger_type == TRIGGER_TYPE_KNOCKOVER_FLAG)
        record_flag_standing(trig->trigger_description);
    hook_call_original((swrRace_TriggerHandler_t) swrRace_TriggerHandler_ADDR, player, a, b);
}

static void restore_trigger_state() {
    // Re-show every node a trigger hid this run, re-arm every fired description (restore its flags),
    // then clear the lists -- after the restart nothing has fired.
    for (int i = 0; i < g_hidden_node_count; i++) {
        g_hidden_node[i].node->flags_1 = g_hidden_node[i].flags_1;
        g_hidden_node[i].node->flags_2 = g_hidden_node[i].flags_2;
    }
    for (int i = 0; i < g_fired_desc_count; i++)
        g_fired_desc[i].desc->flags = g_fired_desc[i].flags;
    // Return each knocked-over flag to upright: restore the node's standing children pointer + its
    // visibility (the knock swapped the children to the fallen model and toggled the flags).
    for (int i = 0; i < g_flag_node_count; i++) {
        g_flag_node[i].node->children.nodes = g_flag_node[i].standing_children;
        g_flag_node[i].node->flags_1 = g_flag_node[i].standing_flags_1;
    }
    g_hidden_node_count = 0;
    g_fired_desc_count = 0;
    g_flag_node_count = 0;

    // Reset each live trigger entity to its freshly-allocated runtime state (flag + timers). Some
    // triggers gate their animation on swrObjTrig.unk10_ms -- e.g. a door that stays shut on the
    // first pass and only animates on the 2nd+ pass, once that timer has built past a threshold. But
    // swrObjTrig_F0 only advances unk10_ms once the entity's `flag & 1` is set (i.e. after it has
    // fired once). A fresh race frees these entities at teardown and recreates them (via
    // swrEvent_AllocObj) with flag=0, so the timer doesn't start until the first pass and stays below
    // threshold on lap 1. A surgical restart keeps them resident with `flag & 1` still set, so the
    // timer resumes from race start and is already over threshold by the first pass -- firing the
    // animation on the restarted lap 1. Clearing flag (and the timers) restores fresh-race behaviour.
    const int trig_count = swrEvent_GetEventCount('Trig');
    for (int i = 0; i < trig_count; i++) {
        swrObjTrig *t = (swrObjTrig *) swrEvent_GetItem('Trig', i);
        if (t != NULL) {
            t->flag = 0;
            t->unk10_ms = 0.0f;
            t->unk14_ms = 0.0f;
        }
    }

    // Reset the trigger FX animations (flag falls, debris, ...). These live in
    // swrObjTrig_AnimationArray, separate from swrScene_animations, so the scene-animation rewind
    // misses them -- a knocked-over flag whose fall FX played stays down otherwise.
    // swrObjTrig_StopFXAnimation clears ENABLED + rewinds each to time 0. Reset ONLY the indices
    // that actually played this run (g_fx_enabled_mask, from the EnableFXAnimation hook); other
    // indices hold stale/freed lists from a previous planet (see the mask's declaration) and walking
    // them crashes. The mask is cleared per track load, so every recorded index is a valid list.
    typedef void(__cdecl * stop_fx_t)(int);
    stop_fx_t stopFx = (stop_fx_t) swrObjTrig_StopFXAnimation_ADDR;
    for (int i = 0; i < 6; i++)// swrObjTrig_AnimationArray is [6]
        if (g_fx_enabled_mask & (1u << i))
            stopFx(i);
}

// The 10 swrRace_Init arguments captured per racer at spawn time, so a restart can replay them on
// the resident pod. Indexed by the racer's slot in swrScoresPtr (swrScore[20]).
struct PodSpawnArgs {
    bool valid;
    float spline;       // arg2: spline pointer passed through the float slot (kept as raw bits)
    int podModel;       // arg3
    void *trackModel;   // arg4
    int lightIndex;     // arg5
    float transform[16];// arg6: starting-grid transform (copied; the original is a stack matrix)
    int gridPos;        // arg7
    int numRacers;      // arg8
    int numLocal;       // arg9 (member NOT named numLocalPlayers -- that's a globals.h macro)
    int dupModelsFlag;  // arg10
};
static PodSpawnArgs g_pod_spawn_args[20];

// Wraps swrRace_Init to record each pod's spawn arguments (keyed by its swrScoresPtr slot) so a
// fast restart can replay them exactly. Hooked by address in renderer_hook.cpp.
void swrRace_Init_capture(swrRace *player, float a2_spline, int a3_podModel, void *a4_trackModel,
                          int a5_light, float *a6_transform, int a7_grid, int a8_numPlayers,
                          int a9_numLocal, int a10_dup) {
    hook_call_original((swrRace_Init_t) swrRace_Init_ADDR, player, a2_spline, a3_podModel,
                       a4_trackModel, a5_light, a6_transform, a7_grid, a8_numPlayers, a9_numLocal,
                       a10_dup);
    if (player == NULL || player->score_ptr == NULL || swrScoresPtr == NULL)
        return;
    const int idx = (int) (player->score_ptr - swrScoresPtr);
    if (idx < 0 || idx >= 20)
        return;
    PodSpawnArgs &s = g_pod_spawn_args[idx];
    s.valid = true;
    s.spline = a2_spline;
    s.podModel = a3_podModel;
    s.trackModel = a4_trackModel;
    s.lightIndex = a5_light;
    std::memcpy(s.transform, a6_transform, sizeof(s.transform));
    s.gridPos = a7_grid;
    s.numRacers = a8_numPlayers;
    s.numLocal = a9_numLocal;
    s.dupModelsFlag = a10_dup;
}

// Reset a score's per-race result fields to their fresh-spawn values (mirrors the block at the top
// of swrObjJdge_SpawnRacer). Lap counters, finishing position, total time and per-lap splits.
static void reset_score_for_restart(swrScore *score) {
    score->unk58 = 0;
    score->unk5a = 0;
    score->results_P1_Lap = 0.0f;
    *(short *) &score->results_P1_Position = -1;
    score->results_P1_total_time = 0.0f;
    score->results_P1_Lap1 = 0.0f;// SpawnRacer sets Lap1 to -1 then 0 -> 0
    score->results_P1_Lap2 = -1.0f;
    score->results_P1_Lap3 = -1.0f;
    score->results_P1_Lap4 = -1.0f;
    score->results_P1_Lap5 = -1.0f;
    score->unk7c = 0;
    score->flag &= 0xfffffffc;
}

// Re-arm the judge into the fresh pre-race countdown, mirroring the tail of the 'Begn' handler
// (swrObjJdge_F4 @0x00463a50) that runs after a fresh InitTrack. The per-race config (num_players,
// planetId, splines, laps, ...) still lives in jdge from the original 'Begn', so only the run-state
// is reset here.
static void rearm_fresh_countdown(swrObjJdge *jdge) {
    swr_FastMode = 0;
    swrRace_DebugFlag = 0;
    swrControl_uiInputActive = 0;
    swrJdge_Cleared = 0;
    if (g_countdown_valid)
        jdge->countdownTimer_ms = g_countdown_ms;// restore the fresh countdown (it was consumed)
    jdge->flag &= ~0x80;
    if (jdge->countdownTimer_ms <= 0.0f)
        jdge->flag &= ~0x20;// no intro countdown
    else
        jdge->flag |= 0x20;
    if (firstLocalPlayer == NULL)
        jdge->flag |= 0x40;
    else
        jdge->flag &= ~0x40;
    jdge->flag = (jdge->flag & 0xfffffff4) | 4;// state 4 == fresh pre-race countdown/intro
    jdge->raceTimer_ms = 0.5f;
    swrSprite_SetColor(-0x67, 0, 0, 0,
                       0xff);// full-screen black overlay, faded in as the race starts
    swrObjJdge_postRaceHudState = 0;
    swrSound_SelectPlanetIntroMusic(jdge->planetId);
    swrObjJdge_UpdateViewportLayout(jdge, 2);
    if (jdge->planetId == 3 && jdge->planet_track_number == 1)
        swrPlayerHUD_lightStreakParam = 10000.0f;
}

// The surgical in-place restart: reset every pod and the race state without tearing down or
// reloading anything. Runs on the game thread (from service_fast_restart).
static void fast_restart_inplace(swrObjJdge *jdge) {
    // Clear active weather particles so precipitation restarts clean (they regenerate per frame; no
    // asset reload). Called by address -- not reimplemented, so no linkable symbol.
    //
    // NOTE: we deliberately do NOT call swrModel_ClearSceneAnimations, ResetLightStreakSprites,
    // ResetSunAndLensFlareSprites or ResetPlayerSpriteValues here. In a fresh load each of those is
    // paired with a re-setup (LoadTrackModels / the lens-flare + light-streak setup) that we skip;
    // calling the reset alone leaves those subsystems un-configured (froze scene animations; broke
    // the sun/lens-flare sprites). Those sprites/animations regenerate per frame from the unchanged
    // scene, so leaving them as they were is correct for a same-track restart.
    typedef void(__cdecl * void_fn_t)(void);
    ((void_fn_t) swrWeather_ResetParticles_ADDR)();

    // Rewind every scene animation to frame 0 and restore its loaded enabled state: the track's
    // ambient loops restart from the top and destructibles/explosion FX reset to whole, so a
    // restart is visually deterministic (same as a fresh race) without reloading the models.
    restore_scene_animation_state();
    // Rearm every destructible/FX trigger and re-show any smashed object's intact node.
    restore_trigger_state();

    // Re-init each resident pod in place by replaying its captured swrRace_Init arguments.
    swrRace_Init_t init = (swrRace_Init_t) swrRace_Init_ADDR;
    for (int i = 0; i < jdge->num_players && i < 20; i++) {
        swrScore *score = &swrScoresPtr[i];
        swrRace *pod = score->obj_test_ptr;
        const PodSpawnArgs &s = g_pod_spawn_args[i];
        if (pod == NULL || !s.valid)
            continue;
        reset_score_for_restart(score);
        float transform[16];
        std::memcpy(transform, s.transform, sizeof(transform));
        init(pod, s.spline, s.podModel, s.trackModel, s.lightIndex, transform, s.gridPos,
             s.numRacers, s.numLocal, s.dupModelsFlag);
    }

    // Reset music + in-race SFX flags (mirrors the tail of InitTrack).
    swrSound_ResetMusic();
    for (int i = 0; i < 0x14; i++)
        swrSound_ClearSfxFlag(i, 0xff0000);

    InitAISettingsForTrack(jdge);
    rearm_fresh_countdown(jdge);

    // Re-establish camera<->pod association: reset the camera manager, then re-associate each local
    // racer's camera ('NAsn' per racer via AssignRacerCameras) with the reset pods.
    int rset[16];
    rset[0] = 'RSet';
    swrEvent_CallF4('cMan', rset);
    void *hang = swrEvent_GetItem('Hang', 0);
    if (hang != NULL)
        ((swrObjHang_AssignRacerCameras_t) swrObjHang_AssignRacerCameras_ADDR)(hang);

    // Suppress the restart key (Enter) until it's physically released, so holding it into the fresh
    // countdown doesn't register as accelerate input and cancel the boost start. See the wrapper.
    g_suppress_enter = true;

    // Arm the pre-race orbit skip: watch for the camera sweep (mode 7) over the next ~2s and end it.
    g_skip_orbit_frames = 120;
}

// True when a fast restart may be triggered: a single-player race is live (judge awake), not
// already tearing down, and not paused. The judge is slept ('Slep' sets obj.flags bit 0x1000) in
// the hangar/menus, where its pods are freed. The swrJdge_Cleared guard skips the teardown window
// after any Clear. The pauseState guard keeps the restart from firing while the pause menu is open,
// so Enter still confirms menu selections there. Multiplayer and demo playback are excluded.
static bool fast_restart_available() {
    if (swrMultiplayer_IsMultiplayerEnabled() != 0 || swrRace_demoMode != 0)
        return false;
    if (pauseState != 0)
        return false;// paused: let Enter drive the pause menu instead
    swrObjJdge *jdge = (swrObjJdge *) swrEvent_GetItem('Jdge', 0);
    if (jdge == NULL)
        return false;
    const bool asleep = (((uint8_t *) &jdge->obj.flags)[1] & 0x10) != 0;
    return !asleep && swrJdge_Cleared == 0;
}

// Hotkey entry point, called from the game's GLFW key callback (Window_delta.c key_callback) when
// the fast-restart key is pressed. Returns true if the press was consumed (feature enabled and a
// live single-player race), so the caller can swallow the key; false lets it keep its normal
// function. The restart itself is deferred to service_fast_restart on the next frame.
extern "C" bool fast_restart_try_request() {
    if (!imgui_state.fast_restart || !fast_restart_available())
        return false;
    g_fast_restart_requested = true;
    return true;
}

// Per-frame, on the game thread (called from imgui_Update). If a fast restart was requested and a
// single-player race is still live, perform the in-place reset.
void service_fast_restart() {
    if (!g_fast_restart_requested)
        return;
    g_fast_restart_requested = false;

    if (!fast_restart_available())
        return;

    fast_restart_inplace((swrObjJdge *) swrEvent_GetItem('Jdge', 0));
}

// --- 100-lap support -------------------------------------------------------------------------
// swrObjJdge_F2 (0x0045ea30) accumulates each frame's elapsed time into a fixed 5-element array
// swrScore::results_P1_Lap1..Lap5 (offsets 0x60..0x70), indexed *directly* by the current lap
// counter swrScore::results_P1_Lap (offset 0x78, read as an int). The vanilla menu caps laps at
// 5, so the index never exceeds 4. With more than 5 laps the index walks off the end of the
// array and corrupts the score struct -- total_time (0x74) at lap index 5, the lap counter
// itself (0x78) at lap index 6, then obj_test_ptr (0x84) at lap index 9 -> crash -- within a
// handful of laps. This is the real "hardcoded 5-lap" limit (the menu wrap is only cosmetic).
//
// Fix: de-index every access to that array inside F2 so it always uses the first slot
// (Lap1, [esi+0x60]). The lap counter (0x78) and total race time (0x74) are left untouched, so
// lap counting, the finish check (lap+1 == num_laps at judge+0x1c8) and the "n / N" HUD all work
// natively for any lap count. Per-lap split data is no longer kept in the score; instead
// swrObjJdge_F2_delta (below) reconstructs each lap's time from the running total at every lap
// boundary, the in-race "LAP TIME" reads are pointed at the live current/last-lap slots (the two
// swrRace_InRaceTimer sites in the table), and the on-track results screen is replaced with a
// best/worst/average summary (swrRace_InRaceEndStatistics_delta). Total time + lap counting are
// unaffected.
//
// Most sites are a 4-byte SIB-indexed memory operand ([esi + reg*4 + 0x60], plus one
// +num_laps*4+0x5c at the finish check). The de-indexed form is 3 bytes, padded with a NOP, so
// instruction boundaries are preserved and no trampoline is needed. We verify the original bytes
// before patching so a mismatched / already-patched / future binary is skipped, never corrupted.
void swrObjJdge_PatchLapTimeOverflow() {
    struct LapTimeSite {
        uint32_t address;
        uint8_t original[4];
        uint8_t patched[4];
    };

    static const LapTimeSite sites[] = {
        {0x0045ebc6, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045ebe4, {0xd9, 0x44, 0x86, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045ebee, {0x8d, 0x4c, 0x86, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]
        {0x0045ec49, {0xd9, 0x44, 0x96, 0x5c}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60] (was +num_laps*4+0x5c)
        {0x0045ed5f, {0x89, 0x5c, 0x86, 0x60}, {0x89, 0x5e, 0x60, 0x90}}, // mov [esi+0x60],ebx
        {0x0045eda8, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045edb3, {0xd9, 0x44, 0x96, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045edbd, {0x8d, 0x4c, 0x96, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]

        // swrRace_InRaceTimer (0x00460950) in-race "LAP TIME" reads, indexed by current lap:
        // point the current-lap read at Lap1 (slot 0, where F2 now writes the live accumulator) and
        // the just-completed-lap read at Lap2 (slot 1, which swrObjJdge_F2_delta fills with the last
        // lap's time) so the readout ticks and the lap-complete flash shows the real last-lap time
        // instead of 00.000 / out-of-bounds garbage.
        {0x00460aec, {0xd9, 0x44, 0x85, 0x60}, {0xd9, 0x45, 0x60, 0x90}}, // fld [ebp+0x60] (current lap)
        {0x00460af6, {0xd9, 0x44, 0x85, 0x5c}, {0xd9, 0x45, 0x64, 0x90}}, // fld [ebp+0x64] (last lap)
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const LapTimeSite &site: sites) {
        uint8_t *code = (uint8_t *) site.address;
        if (std::memcmp(code, site.original, 4) != 0) {
            if (std::memcmp(code, site.patched, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchLapTimeOverflow] unexpected bytes at %p; aborting patch. "
                    ">5 laps will corrupt memory / crash.\n",
                    (void *) code);
            fflush(hook_log);
            return;
        }

        // Route the write through the owner-tagged journal (revertible, overlap-checked) instead
        // of a raw VirtualProtect+memcpy. The verify above guarantees WriteMemory snapshots the
        // stock bytes, so UndoOwner("lap_time_overflow") restores the original binary exactly.
        if (WriteMemory("lap_time_overflow", code, site.patched, 4))
            patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchLapTimeOverflow] de-indexed %d/%d lap-time sites; >5 laps now safe.\n",
            patched, total);
    fflush(hook_log);
}

// --- 1hr+ race-time support ------------------------------------------------------------------
// swrObjJdge_F2 caps the running race time (and each lap slot) at 3000.0s == 50:00 every frame:
//   if (total >= 3000.0f) total = 3000.0f;   // at 0x0045ed94 (total) and 0x0045edc8 (lap slot)
// using a shared threshold constant 3000.0f at 0x004ad264 (referenced only by these two compares).
// So the in-game timer pins at 50:00.000 and a longer race shows ~50:00.0xx. Raise the threshold
// and both clamp values to 24h so the time keeps accumulating; the time formatter
// (swrText_CreateTimeEntryPrecise) already prints minutes unbounded (MM:SS.mmm, e.g. 72:34.567),
// so every total-time readout (in-race timer, results summary, hangar results) follows.
void swrObjJdge_PatchRaceTimeCap() {
    const float kCap = 86400.0f; // 24h; effectively no cap for any real race, keeps ms precision
    uint8_t cap_bytes[4];
    std::memcpy(cap_bytes, &kCap, 4);

    static const uint8_t old_3000[4] = {0x00, 0x80, 0x3b, 0x45}; // 3000.0f

    struct CapSite {
        uint32_t address;
        bool executable; // .text immediate vs .rdata constant
    };
    static const CapSite sites[] = {
        {0x004ad264, false}, // shared threshold constant (.rdata), used by both fcom compares
        {0x0045ed97, true},  // total_time clamp immediate: mov [esi+0x74], 3000.0f
        {0x0045edca, true},  // lap-slot clamp immediate:  mov [ecx], 3000.0f
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const CapSite &site: sites) {
        uint8_t *p = (uint8_t *) site.address;
        if (std::memcmp(p, old_3000, 4) != 0) {
            if (std::memcmp(p, cap_bytes, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchRaceTimeCap] unexpected bytes at %p; skipping (timer stays "
                    "capped at 50:00).\n",
                    (void *) p);
            fflush(hook_log);
            return;
        }

        // Journaled write (see PatchLapTimeOverflow): the verify above pins the snapshot to the
        // stock 3000.0f, so UndoOwner("race_time_cap") restores the original cap.
        if (WriteMemory("race_time_cap", p, cap_bytes, 4))
            patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchRaceTimeCap] raised race-time cap %d/%d sites (50:00 -> 24h).\n",
            patched, total);
    fflush(hook_log);
}

// --- hours in time displays ------------------------------------------------------------------
// The stock time formatters (swrText_CreateTimeEntry @0x00450670 -> centiseconds, and
// swrText_CreateTimeEntryPrecise @0x00450760 -> milliseconds) split the time only into
// minutes:seconds.fraction, with the minutes field unbounded -- so a 1h12m race renders as
// "72:34.567". Reimplement both to break out an hours field once the time reaches an hour
// ("1:12:34.567"). Under one hour the output is byte-for-byte the vanilla layout, so lap times,
// records and short totals are unchanged. The time arrives as the 3rd argument, a float passed as
// its raw bits (callers pass *(int*)&seconds); screenText is the leading ~format-code prefix.
// Formats a time (seconds) into out as H:MM:SS.frac (>=1h), M:SS.frac (>=1m) or SS.frac, with
// frac_digits of a frac_scale-th fraction (100 = centiseconds, 1000 = milliseconds). The hours
// field only appears past an hour; under an hour the layout matches stock exactly.
static void format_time_str(float t, int frac_scale, int frac_digits, char *out, int out_size) {
    if (t < 0.0f)
        t = 0.0f;
    int total_sec = (int) t;
    int frac = (int) ((t - (float) total_sec) * (float) frac_scale);
    if (frac >= frac_scale) { // guard against float edge cases, matching the stock carry
        frac -= frac_scale;
        total_sec++;
    }
    const int h = total_sec / 3600;
    const int m = (total_sec / 60) % 60;
    const int s = total_sec % 60;
    if (h > 0)
        snprintf(out, out_size, "%d:%02d:%02d.%0*d", h, m, s, frac_digits, frac);
    else if (m > 0)
        snprintf(out, out_size, "%d:%02d.%0*d", m, s, frac_digits, frac);
    else
        snprintf(out, out_size, "%02d.%0*d", s, frac_digits, frac);
}

static void format_time_with_hours(int x, int y, int time_bits, int r, int g, int b, int a,
                                   char *screenText, int frac_scale, int frac_digits) {
    float t;
    std::memcpy(&t, &time_bits, sizeof(t));
    char tstr[32];
    format_time_str(t, frac_scale, frac_digits, tstr, sizeof(tstr));
    char body[96];
    snprintf(body, sizeof(body), "%s%s", screenText ? screenText : "", tstr);
    swrText_CreateTextEntry1(x, y, r, g, b, a, body);
}

void swrText_CreateTimeEntry_delta(int x, int y, int unused, int r, int g, int b, int a,
                                   char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 100, 2); // centiseconds
}

void swrText_CreateTimeEntryPrecise_delta(int x, int y, int unused, int r, int g, int b, int a,
                                          char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 1000, 3); // milliseconds
}

// --- 100-lap lap-time tracking + summary -----------------------------------------------------
// Because the de-index collapses the score's 5-slot per-lap array, we reconstruct each lap's time
// from the racer's running total_time (swrScore+0x74) at every lap boundary. This needs no per-lap
// storage in the score -- only a running best / worst (+ their lap numbers) per racer, plus the
// last completed lap time (mirrored into the score's Lap2 slot so the patched in-race readout can
// show it). swrScore field offsets:
#define SCORE_STRIDE     0x88
#define SCORE_POSITION   0x5c // short
#define SCORE_LAP1       0x60 // float, slot 0 (F2's live current-lap accumulator after de-index)
#define SCORE_LAP2       0x64 // float, slot 1 (we mirror the last completed lap time here)
#define SCORE_TOTAL_TIME 0x74 // float
#define SCORE_CUR_LAP    0x78 // int, completed-lap count for this racer
#define JDGE_NUM_RACERS  0x1bc // swrObjJdge::num_players (total racers, local + AI); 0x1ac is planetId
#define JDGE_NUM_LAPS    0x1c8

#define LAP_RACER_MAX 24
// The vanilla on-track results screen has exactly 5 per-lap rows (the score's 5-slot per-lap
// array). g_lapTimes only feeds that screen, and only on the <=5-lap path, so it needs no more
// than these 5 slots -- a >5-lap race uses the best/worst/avg summary instead and never reads it.
#define VANILLA_RESULTS_LAPS 5

static const char *g_lapScores = nullptr; // == DAT_00e28960 (scores base), captured at InitTrack
static float g_bestLap[LAP_RACER_MAX];
static int g_bestLapNum[LAP_RACER_MAX];
static float g_worstLap[LAP_RACER_MAX];
static int g_worstLapNum[LAP_RACER_MAX];
static float g_lastLap[LAP_RACER_MAX];
static float g_prevTotal[LAP_RACER_MAX];
static int g_prevLap[LAP_RACER_MAX];
static bool g_lapFinished[LAP_RACER_MAX];
// Per-lap times for the first VANILLA_RESULTS_LAPS laps, kept so the <=5-lap vanilla results screen
// (which reads the 5-slot per-lap array the de-index collapsed) can be refilled with real times.
static float g_lapTimes[LAP_RACER_MAX][VANILLA_RESULTS_LAPS];

static void reset_lap_tracking(swrScore *scores) {
    g_lapScores = (const char *) scores;
    for (int i = 0; i < LAP_RACER_MAX; i++) {
        g_bestLap[i] = 1.0e9f;
        g_bestLapNum[i] = 0;
        g_worstLap[i] = 0.0f;
        g_worstLapNum[i] = 0;
        g_lastLap[i] = 0.0f;
        g_prevTotal[i] = 0.0f;
        g_prevLap[i] = 0;
        g_lapFinished[i] = false;
        for (int j = 0; j < VANILLA_RESULTS_LAPS; j++)
            g_lapTimes[i][j] = 0.0f;
    }
}

// Wraps swrObjJdge_F2: runs the (de-indexed, crash-safe) original, then reconstructs per-lap times
// from each racer's total_time so we can report best / worst / average for any lap count.
void swrObjJdge_F2_delta(swrObjJdge *jdge) {
    hook_call_original(swrObjJdge_F2, jdge);

    if (!g_lapScores)
        return;

    int numRacers = *(int *) ((char *) jdge + JDGE_NUM_RACERS);
    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    if (numRacers > LAP_RACER_MAX)
        numRacers = LAP_RACER_MAX;

    for (int r = 0; r < numRacers; r++) {
        char *sc = (char *) g_lapScores + r * SCORE_STRIDE;
        const int lap = *(int *) (sc + SCORE_CUR_LAP);
        const float total = *(float *) (sc + SCORE_TOTAL_TIME);

        if (lap > g_prevLap[r]) {
            const float lapTime = total - g_prevTotal[r];
            const int completedIdx = g_prevLap[r]; // 0-based index of the lap that just finished
            const int lapNum = completedIdx + 1;   // 1-based number for display
            if (lapTime > 0.0f) {
                if (completedIdx < VANILLA_RESULTS_LAPS)
                    g_lapTimes[r][completedIdx] = lapTime; // for the <=5 vanilla results refill
                g_lastLap[r] = lapTime;
                if (lapTime < g_bestLap[r]) {
                    g_bestLap[r] = lapTime;
                    g_bestLapNum[r] = lapNum;
                }
                if (lapTime > g_worstLap[r]) {
                    g_worstLap[r] = lapTime;
                    g_worstLapNum[r] = lapNum;
                }
            }
            g_prevTotal[r] = total;
            g_prevLap[r] = lap;
        }

        if (!g_lapFinished[r] && lap < numLaps) {
            // Mirror the last completed lap time into slot 1 so the patched in-race "LAP TIME"
            // flash (which now reads slot 1) shows it instead of garbage.
            *(float *) (sc + SCORE_LAP2) = g_lastLap[r];
        } else if (!g_lapFinished[r] && numLaps > 0 && lap >= numLaps) {
            // On finish, overwrite the de-indexed lap slots so the records save in
            // swrRace_ResultsMenu (min over Lap1..Lap_n) records the real best lap rather than the
            // de-indexed 0.0; the sentinel in Lap2 makes its min loop stop after Lap1.
            g_lapFinished[r] = true;
            if (g_bestLapNum[r] > 0) {
                *(float *) (sc + SCORE_LAP1) = g_bestLap[r];
                *(float *) (sc + SCORE_LAP2) = -1.0f;
            }
        }
    }
}

// On-track end-of-race results. For <=5 laps the score's 5 per-lap slots fit, so refill them from
// the reconstructed lap times (the de-index dropped per-lap storage) and defer to the original
// screen -- it looks exactly like vanilla. For >5 laps a per-lap list can't fit (the vanilla layout
// stacks one row per lap off the top of the screen), so show a compact best/worst/average/total
// summary in the same left-label / time-column style.
void swrRace_InRaceEndStatistics_delta(void *jdge, void *score) {
    if (!g_lapScores) {
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    const int r = (int) (((char *) score - g_lapScores) / SCORE_STRIDE);

    if (numLaps <= 5) {
        if (r >= 0 && r < LAP_RACER_MAX) {
            for (int i = 0; i < numLaps && i < VANILLA_RESULTS_LAPS; i++)
                *(float *) ((char *) score + SCORE_LAP1 + i * 4) = g_lapTimes[r][i];
        }
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    // >5 laps: hide the results-screen sprites the vanilla screen would lay out, then draw the
    // summary. These are UI sprites, not racers: the original swrRace_InRaceEndStatistics
    // (0x00462320) single-player branch hides sprite IDs 0..0x12 (loop `while (i < 0x13)`) -- the
    // per-lap row sprites it would otherwise show. We mirror that exact range so none show through
    // our summary. (The vanilla 2-player splitscreen branches instead clear 0xf..0x12 / 0x13..0x16;
    // the >5-lap summary path only runs single-player.) Times are formatted here (hour-aware) and
    // drawn left-aligned so they sit in a clean column instead of right-aligning over the labels.
    const short kResultsScreenSprites = 0x13; // == original single-player sprite-hide loop bound
    for (short i = 0; i < kResultsScreenSprites; i++)
        swrSprite_SetVisible(i, 0);

    const float total = *(float *) ((char *) score + SCORE_TOTAL_TIME);
    const int pos = *(short *) ((char *) score + SCORE_POSITION);
    char buf[96];
    char tstr[32];

    swrText_CreateTextEntry1(0xa0, 0x14, -1, -1, -1, -1, swrText_Translate((char *) "~cResults"));

    const int label_x = 0x2d; // 45
    const int time_x = 0x82;  // 130
    const int lapn_x = 0xd2;  // 210
    int y = 0x48;             // 72

    if (r >= 0 && r < LAP_RACER_MAX && g_bestLapNum[r] > 0) {
        const float avg = (numLaps > 0) ? total / (float) numLaps : 0.0f;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sBest");
        format_time_str(g_bestLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_bestLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sWorst");
        format_time_str(g_worstLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_worstLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sAverage");
        format_time_str(avg, 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        y += 0xe;
    }

    swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sTotal");
    format_time_str(total, 1000, 3, tstr, sizeof(tstr));
    snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
    swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
    y += 0x16;

    snprintf(buf, sizeof(buf), "~cFinished %d laps - position %d", numLaps, pos);
    swrText_CreateTextEntry1(0xa0, y, -1, -1, -1, -1, buf);
}

// #97 follow-up: keep finished racers placed above still-racing ones at any race length.
// swrObjJdge_UpdateStandings ranks a finished racer by (10000 - total_time) and a still-racing one
// by progress (lap + fraction, below ~num_laps). Vanilla pinned total_time at the 50:00 (3000s)
// clamp, so the finished key stayed >= 7000 and always beat the progress keys. PatchRaceTimeCap
// raised that clamp to 24h, so a race past ~2h46m (total_time > 10000s, reachable in a long
// 125-lap race) drives a finished racer's key negative and sorts it BELOW a still-racing pod.
// Widening the key would cost finish-time precision (the unfinished band must stay at progress for
// the original's gap math), so instead: let the original compute the gap / rival-arrow displays,
// then re-assign the finishing positions finished-first -- finished racers (ordered by total_time)
// always above still-racing ones (ordered by progress), comparing total_time directly so the order
// keeps full precision. A no-op for any race the original already ordered correctly.
typedef void swrObjJdge_UpdateStandings_t(swrObjJdge *jdge);
typedef float swrObjJdge_GetRacerProgress_t(swrScore *score);

void swrObjJdge_UpdateStandings_delta(swrObjJdge *jdge) {
    hook_call_original((swrObjJdge_UpdateStandings_t *) swrObjJdge_UpdateStandings_ADDR, jdge);

    int numRacers = jdge->num_players;
    if (numRacers > 20)
        numRacers = 20;// swrScoresPtr is swrScore[20]

    swrObjJdge_GetRacerProgress_t *getRacerProgress =
        (swrObjJdge_GetRacerProgress_t *) swrObjJdge_GetRacerProgress_ADDR;
    float progress[20];
    for (int i = 0; i < numRacers; i++)
        progress[i] = getRacerProgress(&swrScoresPtr[i]);

    for (int i = 0; i < numRacers; i++) {
        swrScore *a = &swrScoresPtr[i];
        bool finishedA = (a->flag & 2) != 0;
        int place = 1;
        for (int j = 0; j < numRacers; j++) {
            if (j == i)
                continue;
            swrScore *b = &swrScoresPtr[j];
            bool finishedB = (b->flag & 2) != 0;
            bool bAhead;
            if (finishedA != finishedB)
                bAhead = finishedB;// a finished racer always outranks a still-racing one
            else if (finishedA)
                bAhead = b->results_P1_total_time <
                         a->results_P1_total_time;// both finished: faster first
            else
                bAhead = progress[j] > progress[i];// both racing: more progress first
            if (bAhead)
                place++;
        }
        *(short *) &a->results_P1_Position = (short) place;
    }
}

// Manual in-race HUD-mode cycle. Vanilla advances jdge->hud_mode on Caps Lock (swrObjJdge_CycleHudMode,
// which changes the minimap/speedometer layout), but Caps Lock does not emulate over remote desktop,
// so expose the same cycle to a debug-overlay button. The button sets g_request_hud_mode_cycle; here --
// called every frame from swrObjJdge_F0 with the live jdge -- we consume it and advance hud_mode with
// the vanilla wrap (0..4 single-player, 4..7 splitscreen). The original runs first so Caps Lock still
// works for local players. g_current_hud_mode is published for the overlay to display.
bool g_request_hud_mode_cycle = false;
int g_current_hud_mode = -1;

typedef void swrObjJdge_CycleHudMode_t(swrObjJdge *jdge);

// 0x0045f230 -- swrObjJdge_DrawRaceHUD draws the per-racer POSITION MARKERS (sprites 0x2b-0x34 + their
// number text), which live in a different layout each hud_mode. Publish the mode into ui_hud_marker_mode
// for the duration of the draw so the sprite + text sinks can remap the markers by mode (right strip in
// mode 0, full-width ring in mode 1) instead of the plain centering. Cleared to -1 afterward so no other
// HUD text/sprite is affected.
typedef void swrObjJdge_DrawRaceHUD_t(swrObjJdge *jdge);

void swrObjJdge_DrawRaceHUD_delta(swrObjJdge *jdge) {
    ui_hud_marker_mode = jdge->hud_mode;
    hook_call_original((swrObjJdge_DrawRaceHUD_t *) swrObjJdge_DrawRaceHUD_ADDR, jdge);
    ui_hud_marker_mode = -1;
}

// 0x00462b20 -- swrObjJdge_UpdatePlayerHUD draws the per-player HUD (header bar, speedometer, engine
// readout + their text). Scope it so the id-based HUD edge-anchoring only fires here: those sprite ids
// and text columns are reused by other screens (the race-settings pilot portrait / track favorite),
// which would otherwise get stretched/offset. Cleared afterward. Reentrant-safe as a counter (two local
// players call it in turn, never nested, but a counter is harmless if that ever changes).
typedef void swrObjJdge_UpdatePlayerHUD_t(swrObjJdge *jdge, swrScore *score);

void swrObjJdge_UpdatePlayerHUD_delta(swrObjJdge *jdge, swrScore *score) {
    ui_in_race_hud++;
    hook_call_original((swrObjJdge_UpdatePlayerHUD_t *) swrObjJdge_UpdatePlayerHUD_ADDR, jdge, score);
    ui_in_race_hud--;
}

void swrObjJdge_CycleHudMode_delta(swrObjJdge *jdge) {
    hook_call_original((swrObjJdge_CycleHudMode_t *) swrObjJdge_CycleHudMode_ADDR, jdge);
    if (g_request_hud_mode_cycle) {
        g_request_hud_mode_cycle = false;
        jdge->hud_mode++;
        if (numLocalPlayers < 2) {
            if (jdge->hud_mode > 4)
                jdge->hud_mode = 0;
        } else if (jdge->hud_mode > 7) {
            jdge->hud_mode = 4;
        }
    }
    g_current_hud_mode = jdge->hud_mode;
}
