#ifndef SWRRACE_H
#define SWRRACE_H

#include "types.h"

#define swrRace_SelectProfileMenu_ADDR (0x00401340)

#define swrRace_ReservedSettingsMenu_ADDR (0x0040fb50)

#define swrRace_LoadSaveConfigMenu_ADDR (0x0040ffe0)

#define swrRace_SettingsMenu_ADDR (0x00411950)

#define swrRace_GetSelectedTrack_ADDR (0x0041c4e0)

#define swrRace_DebugSetVehicleStat_ADDR (0x0042a110)

#define swrRace_InRace_EscMenu_ADDR (0x0042a840)

#define swrRace_DebugSetGameValue_ADDR (0x0042a9f0)

#define swrRace_SelectVehicle_ADDR (0x00435700)

#define swrRace_MainMenu_ADDR (0x004368a0)

#define swrRace_AudioVideoSettings_ADDR (0x00436fa0)

#define swrRace_HangarMenu_ADDR (0x004396d0)

#define swrRace_ResultsMenu_ADDR (0x00439ce0)

#define swrRace_CourseSelectionMenu_ADDR (0x0043b240)

#define swrRace_CourseInfoMenu_ADDR (0x0043b880)

#define swrRace_UpdatePartsHealth_ADDR (0x0043d720)

#define swrRace_GenerateDefaultDataSAV_ADDR (0x0043ea00)

#define swrRace_BuyPitdroidsMenu_ADDR (0x0043f380)

#define swrRace_InitUnk_ADDR (0x00444d10)

#define swrRace_ApplyStatsMultipliers_ADDR (0x00449330)

#define swrRace_ApplyUpgradesToStats_ADDR (0x00449d00)

#define swrRace_CalculateUpgradedStat_ADDR (0x004493f0)

#define swrRace_UpdateTurn_ADDR (0x0044ae40)

#define swrRace_SetAngleFromTurnRate_ADDR (0x0044af50)

#define swrRace_ReplaceMarsGuoWithJinnReeso_ADDR (0x0044B530)
#define swrRace_ReplaceBullseyeWithCyYunga_ADDR (0x0044B5E0)

#define swrRace_VehicleStatisticsSubMenu_ADDR (0x004550d0)

#define swrRace_InRaceTimer_ADDR (0x00460950)

#define swrRace_InRaceEngineUI_ADDR (0x004611f0)

#define swrRace_InRaceEndStatistics_ADDR (0x00462320)

#define swrRace_Repair_ADDR (0x0046ab10)

#define swrRace_Tilt_ADDR (0x0046b5a0)

#define swrRace_AI_ADDR (0x0046b670)

#define swrRace_BoostCharge_ADDR (0x0046bd20)

#define swrRace_CalculateTiltFromTurn_ADDR (0x00477ad0)

#define swrRace_TakeDamage_ADDR (0x00474cd0)

#define swrRace_ActivateTriggersInRange_ADDR (0x00476AC0)
#define swrRace_UpdateSurfaceTag_ADDR (0x00476ea0)

#define swrRace_ApplyGravity_ADDR (0x004774f0)

#define swrRace_UpdateTurn2_ADDR (0x00477c27)

#define swrRace_UpdateSpeed_ADDR (0x004783e0)
#define swrRace_ApplyBoost_ADDR (0x004787f0)
#define swrRace_UpdateHeat_ADDR (0x004788c0)
#define swrRace_ApplyTraction_ADDR (0x00478a70)
#define swrRace_MainSpeed_ADDR (0x00478d80)

#define swrRace_DeathSpeed_ADDR (0x0047b000)

#define swrRace_CalcTargetTurnRate_ADDR (0x0046cf00)
#define swrRace_UpdateSpinoutNodes_ADDR (0x0046e150)
#define swrRace_UpdateGroundContact_ADDR (0x00479e10)

// swrObjTest_F3 per-frame model/effects pipeline
#define swrRace_ResetModelNodeFlags_ADDR (0x0046d4c0)
#define swrRace_ExtrapolateTransform_ADDR (0x004705d0)
#define swrRace_UpdateEngineExhaust_ADDR (0x0046f2c0)
#define swrRace_PoddAnimateEngines_ADDR (0x00470ae0)
#define swrRace_UpdateScrapeSparks_ADDR (0x0046ee20)
#define swrRace_UpdateThrustNode_ADDR (0x004709a0)
#define swrRace_UpdateEngineSound_ADDR (0x00470a40)
#define swrRace_UpdateEngineDamageFX_ADDR (0x0046f9a0)

// pod state + engine secondary-motion helpers
#define swrRace_HandleDeathSnap_ADDR (0x0046d040)
#define swrRace_HandleRespawnFlag_ADDR (0x0046d100)
#define swrRace_PlayEngineSounds_ADDR (0x0046d7a0)
#define swrRace_TiltEngines_ADDR (0x0046dcd0)
#define swrRace_AnimateSpinoutEngines_ADDR (0x0046dea0)
#define swrRace_AnimateEngineWobble_ADDR (0x0046e2c0)
#define swrRace_CollectMeshNodes_ADDR (0x0046e750)
#define swrRace_AssignRandomMeshNodes_ADDR (0x0046e850)
#define swrRace_RandomizeMeshNodes_ADDR (0x0046e910)

// player/AI/autopilot control + engine-damage helpers
#define swrRace_CheckResetInput_ADDR (0x0046a990)
#define swrRace_GetDamagedEngineSides_ADDR (0x0046a9c0)
#define swrRace_GetEngineDamagePenalty_ADDR (0x0046a9f0)
#define swrRace_ApplyEngineDamage_ADDR (0x0046aa30)
#define swrRace_AutopilotSteer_ADDR (0x0046af20)
#define swrRace_ApplyPodProximityForce_ADDR (0x0046b430)
#define swrRace_UpdateAutopilotControl_ADDR (0x0046bb70)
#define swrRace_UpdatePlayerControl_ADDR (0x0046bec0)
#define swrRace_UpdateCatchup_ADDR (0x0046ce30)

#define swrRace_TriggerHandler_ADDR (0x0047ce60)

#define swrRace_LapProgress_ADDR (0x0047f810)

#define swrRace_LapCompletion_ADDR (0x0047fdd0)

#define swrRace_IncrementFrameTimer_ADDR (0x00480540)

int swrRace_SelectProfileMenu(void* param_1, unsigned int param_2, unsigned int param_3, int param_4);

void swrRace_ReservedSettingsMenu(swrUI_unk* param_1);

void swrRace_LoadSaveConfigMenu(swrUI_unk* param_1);

int swrRace_SettingsMenu(void);

swrRace_TRACK swrRace_GetSelectedTrack(void);

void swrRace_DebugSetVehicleStat(unsigned int id, float value);

int swrRace_InRace_EscMenu(int textIndex, char* textBuffer, char* unk, int* c, float* d);

void swrRace_DebugSetGameValue(int id, float value);

void swrRace_SelectVehicle(swrObjHang* hang);

void swrRace_MainMenu(swrObjHang* hang);

void swrRace_AudioVideoSettings(swrObjHang* hang);

void swrRace_HangarMenu(swrObjHang* hang);

void swrRace_ResultsMenu(swrObjHang* hang);

void swrRace_CourseSelectionMenu(void);

void swrRace_CourseInfoMenu(swrObjHang* hang);

void swrRace_UpdatePartsHealth(void);

void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot);

void swrRace_BuyPitdroidsMenu(swrObjHang* hang);

float swrRace_InitUnk(int a, float b, float c, int* d);

void swrRace_ApplyStatsMultipliers(PodHandlingData* out_stats, PodHandlingData* stats);

void swrRace_ApplyUpgradesToStats(PodHandlingData* pActiveStats, PodHandlingData* pBaseStats, char* pUpgradeLevels, char* pUpgradeHealths);

void swrRace_CalculateUpgradedStat(PodHandlingData* podHandlingData, int upgradeCategory, int upgradeLevel, float upgradeHealth);

void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6);

void swrRace_SetAngleFromTurnRate(float* out_tilt, float cur_turnrate, void* unused, float max_turnrate, float max_angle);

void swrRace_ReplaceMarsGuoWithJinnReeso(void);
void swrRace_ReplaceBullseyeWithCyYunga(void);

void swrRace_VehicleStatisticsSubMenu(void* param_1, float param_2, float param_3);

void swrRace_InRaceTimer(void* param_1, void* param_2);

void swrRace_InRaceEngineUI(void* param_1, int param_2);

void swrRace_InRaceEndStatistics(void* param_1, void* param_2);

void swrRace_Repair(swrRace* player);

void swrRace_Tilt(swrRace* player, float b);

void swrRace_AI(int player);

void swrRace_TakeDamage(int player, int a, float b);

void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2);
void swrRace_UpdateSurfaceTag(swrRace* test);

void swrRace_ApplyGravity(swrRace* player, float* a, float b);

int swrRace_BoostCharge(int player);

void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot);

void swrRace_UpdateTurn2(int player, int a, int b, int c);

float swrRace_UpdateSpeed(swrRace* player);
float swrRace_ApplyBoost(swrRace* player);
void swrRace_UpdateHeat(swrRace* player);
void swrRace_ApplyTraction(swrRace* player, float b, rdVector3* c, rdVector3* d);
void swrRace_MainSpeed(swrRace* player, rdVector3* b, rdVector3* c, int d);

void swrRace_DeathSpeed(swrRace* player, float a, float b);

// Computes the projected/target turn rate (projTurnRate) and gravity multiplier
// for the frame, clamped to +/-maxTurnRate. (annodue: CalcTargetTurnRate)
void swrRace_CalcTargetTurnRate(swrRace* player);
// Shows/hides the engine model nodes during a left/right spinout or explosion
// (keys off flags2 0x8000/0x10000).
void swrRace_UpdateSpinoutNodes(swrRace* player);
// Ground-contact / vertical-motion integrator: applies gravity, follows terrain
// and the track spline for hover height, sets groundToPodMeasure (also returned).
float swrRace_UpdateGroundContact(swrRace* player, float* velocity, int param_3, rdVector3* up, int param_5);

// swrObjTest_F3 per-frame model/effects pipeline:
// Resets the pod model-node visibility flags each frame.
void swrRace_ResetModelNodeFlags(swrRace* player);
// Copies a transform and advances its translation along its forward axis by
// speed*dt (used for multiplayer/replay extrapolation).
void swrRace_ExtrapolateTransform(swrRace* player, rdMatrix44* out, rdMatrix44* in, float dt);
// Updates the engine exhaust flames (engineExhaustSizeL/R, node transforms,
// terrain-dependent jitter and color).
void swrRace_UpdateEngineExhaust(swrRace* player, int param_2, float param_3, float param_4);
// Positions the engine/cockpit sub-models with a smoothing ring buffer and tilt.
void swrRace_PoddAnimateEngines(swrRace* player);
// Updates the scrape-spark effect nodes (ScrapeSparkXf) and plays the scrape sound.
void swrRace_UpdateScrapeSparks(swrRace* player);
// Shows/positions the thrust node (unk1994) based on _thrust (0x188).
void swrRace_UpdateThrustNode(swrRace* player);
// Plays the spatial engine loop sound, varying by speed and terrain type.
void swrRace_UpdateEngineSound(swrRace* player);
// Engine fire/smoke effects when engines are damaged, plus a proximity check
// that flags nearby pods.
void swrRace_UpdateEngineDamageFX(swrRace* player);

// pod state + engine secondary-motion helpers:
// Counts down the death timer; on expiry dispatches the 'Snap' event and resets engine health/flags.
void swrRace_HandleDeathSnap(swrRace* player);
// Handles the respawn-pod flag (flags0 0x1000): clears it and resets race state.
void swrRace_HandleRespawnFlag(swrRace* player);
// Detailed per-frame engine audio: RPM/gear-based engine sounds, boost and scrape SFX.
void swrRace_PlayEngineSounds(swrRace* player, float param_2);
// Tilts the engine transforms from pitch (0x2fc) and tilt angle (0x204).
void swrRace_TiltEngines(swrRace* player);
// Spins the engine transforms during a spinout/explosion (flags2 0x8000/0x10000).
void swrRace_AnimateSpinoutEngines(swrRace* player);
// Engine secondary motion: idle sway plus reaction to collision velocity.
void swrRace_AnimateEngineWobble(swrRace* player);
// Recursively collects up to 10 mesh nodes (flags 0x3064) from a node tree into a pool.
void swrRace_CollectMeshNodes(swrModel_Node* node);
// Recursively reassigns mesh nodes (flags 0x3064) to random entries from the collected pool.
void swrRace_AssignRandomMeshNodes(swrModel_Node* node);
// Randomizes the meshes of dst's node tree using the pool collected from src.
void swrRace_RandomizeMeshNodes(swrModel_Node* dst, swrModel_Node* src);

// player/AI/autopilot control + engine-damage helpers:
// Sets the respawn flag (flags0 0x1000) when the player's reset input bit is held.
void swrRace_CheckResetInput(swrRace* player, int playerIndex);
// Returns a bitmask of which engine groups are damaged (1=left trio, 2=right trio).
unsigned int swrRace_GetDamagedEngineSides(swrRace* player);
// Returns the handling penalty accumulated from damaged engines.
float swrRace_GetEngineDamagePenalty(swrRace* player);
// Applies per-engine overheat damage (swrRace_TakeDamage) and triggers rumble.
void swrRace_ApplyEngineDamage(swrRace* player);
// Autopilot steering: follows the track spline via a look-ahead point, setting
// turnRateTarget and thrust (also handles track-specific shortcuts).
void swrRace_AutopilotSteer(swrRace* player);
// Adds a pod-to-pod proximity turn force from nearby racers.
void swrRace_ApplyPodProximityForce(swrRace* player);
// Autopilot/pre-race control: snap events and tilt while not under player input.
void swrRace_UpdateAutopilotControl(swrRace* player);
// Human player control: maps input to turn/pitch/brake/boost, drives force
// feedback and tilt, and sets projTurnRate/pitch/gravityMultiplier.
void swrRace_UpdatePlayerControl(swrRace* player);
// Runs AI steering for AI pods and computes the rubber-band/catch-up multiplier.
void swrRace_UpdateCatchup(swrRace* player);

void swrRace_TriggerHandler(int player, int a, char b);

float swrRace_LapProgress(int a);

bool swrRace_LapCompletion(void* engineData, int param_2);

void swrRace_IncrementFrameTimer(void);

#endif // SWRRACE_H
