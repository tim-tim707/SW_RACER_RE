#ifndef SWRRACE_H
#define SWRRACE_H

#include "types.h"

#define swrRace_SelectProfileMenu_ADDR (0x00401340)

#define swrRace_ReservedSettingsMenu_ADDR (0x0040fb50)

#define swrRace_LoadSaveConfigMenu_ADDR (0x0040ffe0)

#define swrRace_SettingsMenu_ADDR (0x00411950)

#define swrRace_GetSelectedTrack_ADDR (0x0041c4e0)

#define swrRace_PushDebugMenuState_ADDR (0x00429cd0)
#define swrRace_PopDebugMenuState_ADDR (0x00429d10)
#define swrRace_GetDebugVehicleStatEntry_ADDR (0x00429dc0)

#define swrRace_DebugSetVehicleStat_ADDR (0x0042a110)

#define swrRace_GetDebugGameValueEntry_ADDR (0x0042a580)

#define swrRace_InRace_EscMenu_ADDR (0x0042a840)

#define swrRace_DebugSetGameValue_ADDR (0x0042a9f0)

#define swrRace_ActivateDebugGameValueEntry_ADDR (0x0042ab60)
#define swrRace_ActivateEscMenuEntry_ADDR (0x0042ab80)
#define swrRace_GetInRaceMenuEntry_ADDR (0x0042ac70)
#define swrRace_AdjustDebugValue_ADDR (0x0042acf0)
#define swrRace_ActivateInRaceMenuEntry_ADDR (0x0042ad30)
#define swrRace_OpenInRaceMenu_ADDR (0x0042ad60)
#define swrRace_GetInRaceMenuResult_ADDR (0x0042adf0)
#define swrRace_UpdateInRaceMenu_ADDR (0x0042ae00)

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

#define swrRace_ComputeStatBars_ADDR (0x00449330)

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
#define swrRace_CollideTrack_ADDR (0x0044acb0)

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
#define swrRace_SpawnEngineFireball_ADDR (0x0046e950)

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

// collision / ground-contact physics + explosion spawn
#define swrRace_SpawnExplosionEffect_ADDR (0x0046ba30)
#define swrRace_RaycastGround_ADDR (0x004772f0)
#define swrRace_UpdateHoverPads_ADDR (0x00476740)
#define swrRace_ApplySlopeSteering_ADDR (0x004791d0)
#define swrRace_ApplySlopeSteeringMagnet_ADDR (0x00479550)
#define swrRace_ApplyWallCollision_ADDR (0x00479920)

// pod init + death/scrape/collision-toggle helpers
#define swrRace_Init_ADDR (0x00475ad0)
#define swrRace_HandleDeathExplosion_ADDR (0x00474970)
#define swrRace_SetupScrapeSpray_ADDR (0x00477850)
#define swrRace_DetectWallScrape_ADDR (0x00477940)
#define swrRace_UpdateCollisionToggles_ADDR (0x0047a930)

// pod model beams + wall/pod collision
#define swrRace_BuildStretchedQuad_ADDR (0x0046f0e0)
#define swrRace_UpdateEnergyBinder_ADDR (0x00472750)
#define swrRace_UpdateWallContact_ADDR (0x0047a200)
#define swrRace_ResolvePodCollision_ADDR (0x0047b0c0)

#define swrRace_TriggerHandler_ADDR (0x0047ce60)

#define swrRace_LapProgress_ADDR (0x0047f810)

#define swrRace_LapCompletion_ADDR (0x0047fdd0)

#define swrRace_UpdateRaceProgress_ADDR (0x0047ffb0)

#define swrRace_InitFrameTimer_ADDR (0x004804c0)

#define swrRace_IncrementFrameTimer_ADDR (0x00480540)

// Save / profile persistence (player tournament data -> .\data\player\tgfd.dat).
// The on-disk image is a 0xfd4-byte blob: [0x00] CRC32 checksum, [0x04..] 0xfd0 data bytes
// (records, unlock bitfields, and the embedded saved-profile table), prefixed on disk by
// a 4-byte version magic (0x10003). Original engine module name: "elfSaveLoad".
#define swrRace_InitGameData_ADDR (0x00421810)
#define swrRace_SaveProfile_ADDR (0x004219d0)
#define swrRace_ResetGameData_ADDR (0x00421b20)
#define swrRace_LoadGameData_ADDR (0x00421b90)
#define swrRace_SaveGameData_ADDR (0x00421c90)
#define swrRace_IsGameDataUninitialized_ADDR (0x00421d80)
#define swrRace_ResetAllProfiles_ADDR (0x0043d970)
#define swrRace_CheatUnlockAll_ADDR (0x0043d9a0)
#define swrRace_InitDefaultGameData_ADDR (0x0044e320)
#define swrRace_ComputeSaveChecksum_ADDR (0x0044e440)
#define swrRace_Crc32_ADDR (0x0044e460)
#define swrRace_InitCrc32Table_ADDR (0x0044e4a0)
#define swrRace_BackupGameData_ADDR (0x0044e4e0)
#define swrRace_CopyProfileFromSave_ADDR (0x0044e500)
#define swrRace_CopyProfileToSave_ADDR (0x0044e530)
#define swrRace_SaveCurrentProfile_ADDR (0x0044e560)

int swrRace_SelectProfileMenu(void* param_1, unsigned int param_2, unsigned int param_3, int param_4);

void swrRace_ReservedSettingsMenu(swrUI_unk* param_1);

void swrRace_LoadSaveConfigMenu(swrUI_unk* param_1);

int swrRace_SettingsMenu(void);

swrRace_TRACK swrRace_GetSelectedTrack(void);

// In-race ESC / debug menu, driven by DebugMenuState (0=debug game-values,
// 1=vehicle-stat editor, 2=ESC menu) with a push/pop state stack. The three
// Get*Entry accessors share InRace_EscMenu's (index -> name/value) signature.
void swrRace_PushDebugMenuState(int state);
void swrRace_PopDebugMenuState(void);
int swrRace_GetDebugVehicleStatEntry(int index, char* nameOut, char* unk, int* c, float* d);

void swrRace_DebugSetVehicleStat(unsigned int id, float value);

int swrRace_GetDebugGameValueEntry(int index, char* nameOut, char* unk, int* c, float* d);

int swrRace_InRace_EscMenu(int textIndex, char* textBuffer, char* unk, int* c, float* d);

void swrRace_DebugSetGameValue(int id, float value);

// Activators (per state), value-adjust dispatch, per-frame tick + open/result.
void swrRace_ActivateDebugGameValueEntry(int index);
void swrRace_ActivateEscMenuEntry(int index);
int swrRace_GetInRaceMenuEntry(int index, char* nameOut, char* unk, int* c, float* d);
void swrRace_AdjustDebugValue(unsigned int id, float delta);
void swrRace_ActivateInRaceMenuEntry(int index);
void swrRace_OpenInRaceMenu(void);
int swrRace_GetInRaceMenuResult(void);
void swrRace_UpdateInRaceMenu(void);

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

void swrRace_ComputeStatBars(PodHandlingData* out_stats, PodHandlingData* stats);

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

void swrRace_TakeDamage(int player, int engineIndex, float amount);

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
void swrRace_MainSpeed(swrRace* player, rdVector3* b, rdVector3* c, rdVector3* d);

// One iteration of swept track collision: tests the segment prevPos->curPos against the
// collision model, and on a hit pushes curPos back out along the surface normal (also
// written to outNormal). Returns nonzero when it resolved a collision. (was FUN_0044acb0)
int swrRace_CollideTrack(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal);

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
void swrRace_SpawnEngineFireball(swrRace* player, int engineSlot, rdVector3* pos, float scale);

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

// collision / ground-contact physics + explosion spawn:
// Spawns the explosion effect (type-8 Smok) and destruction sounds for the pod.
void swrRace_SpawnExplosionEffect(swrRace* player);
// Raycasts the terrain collision mesh; sets terrainModel (0x140) and ground height, returns distance.
float swrRace_RaycastGround(swrRace* player, rdVector3* param_2, int* param_3);
// Samples the 4 hover-pad ground heights and builds the shadow transforms (0x1290); returns hover height.
float swrRace_UpdateHoverPads(swrRace* player, rdVector3* param_2, int param_3, float param_4, float* param_5);
// Slope steering: turns the pod along the ground slope (sets 0x1f8) and slope velocity (0x1c4).
void swrRace_ApplySlopeSteering(swrRace* player, int param_2, int param_3, float param_4, rdVector3* normal, rdVector3* out1, rdVector3* out2);
// Magnet/tube variant of slope steering (flags1 0x400).
void swrRace_ApplySlopeSteeringMagnet(swrRace* player, int param_2, int param_3, float param_4, rdVector3* normal, rdVector3* out1, rdVector3* out2);
// Wall collision response: reflects velocity off the wall normal into velocityCollision and dispatches hit/scrape events.
void swrRace_ApplyWallCollision(swrRace* player, rdVector3* normal, rdVector3* dir);

// pod init + death/scrape/collision-toggle helpers:
// Initializes a pod for a race: loads stats from the racer data, sets the spawn
// transform, resets all runtime state, and refreshes model nodes.
void swrRace_Init(swrRace* player, float param_2, int param_3, void* model, int param_5, float* spawnTransform, int param_7, int param_8, int param_9, int param_10);
// Death/explosion sequence: 'Deth' camera event, explosion + debris + sounds,
// engine-health reset and rumble (AI pods are placed back on track instead).
void swrRace_HandleDeathExplosion(swrRace* player);
// Builds a scrape spray/spark billboard transform on an engine slot.
void swrRace_SetupScrapeSpray(swrRace* player, float scale, int param_3, int param_4, int param_5, float side);
// Raycasts sideways for nearby walls and spawns scrape spray on contact.
void swrRace_DetectWallScrape(swrRace* player, float* param_2, float* param_3);
// Computes the collisionToggles bitmask (0x26c) from the pod's position.
void swrRace_UpdateCollisionToggles(swrRace* player);

// pod model beams + wall/pod collision:
// Builds the energy-binder plasma beam transform stretched between the engines.
void swrRace_UpdateEnergyBinder(swrRace* player, float side, rdVector3* pointA, rdVector3* pointB);
// Builds a quad transform stretched between two engine matrices (beam/connector segment).
void swrRace_BuildStretchedQuad(rdMatrix44* a, rdMatrix44* b, float param_3, float param_4, int keyframeIdx, rdMatrix44* out);
// Wall-contact dispatch: wall-scrape + collision response when fast/airborne, else terrain follow.
float swrRace_UpdateWallContact(swrRace* player, float* param_2, float* param_3, rdVector3* param_4);
// Pod-to-pod collision: finds a nearby pod and resolves the 2D collision (push apart + DeathSpeed).
void swrRace_ResolvePodCollision(swrRace* player);

void swrRace_TriggerHandler(int player, int a, char b);

float swrRace_LapProgress(int a);

bool swrRace_LapCompletion(void* engineData, int param_2);

// Per-racer race-progress update (called per racer from swrObjJdge_F2): advances the spline
// cursor, recomputes the current checkpoint segment, runs swrRace_LapCompletion, and ticks the
// lap counter / off-track recovery timer.
void swrRace_UpdateRaceProgress(void* engineData, int param_2, int incrementLap, int offTrackTick);

void swrRace_IncrementFrameTimer(void);

// 0x004804c0. Resets the frame timer / delta-time state (sibling of IncrementFrameTimer):
// sets the fixed-step default and samples the initial system time.
void swrRace_InitFrameTimer(void);

// Save / profile persistence.
// Boot entry: load tgfd.dat; on failure rebuild defaults and write a fresh file.
void swrRace_InitGameData(void);
// Read .\data\player\tgfd.dat, verify the 0x10003 version magic, load the 0xfd4-byte image.
bool swrRace_LoadGameData(void);
// Create .\data\player\ and write the version magic + 0xfd4-byte image to tgfd.dat.
bool swrRace_SaveGameData(void);
// Rebuild the in-memory save image from defaults. resetCurrentPlayer != 0 also clears the
// active player slot/name; == 0 preserves the current player's profile record.
int swrRace_ResetGameData(int resetCurrentPlayer);
// Export a single profile record to .\data\player\<playerName> (extension swapped).
bool swrRace_SaveProfile(char* playerName);
// True when the loaded image looks empty/uninitialized (unlock bitfield == 0); gates a reset.
bool swrRace_IsGameDataUninitialized(void);
// Sync the live working profile into the save image and persist it. Called after any change
// that must survive (shop purchase, race result, settings, name entry) and at shutdown.
void swrRace_SaveCurrentProfile(void);
// Build the default save image in place (records, "AAA" record-holder names, default unlock
// bitfield, default profiles) and store its checksum.
void swrRace_InitDefaultGameData(void* saveImage);
// Reset all 20 working slots + 4 saved-image profile slots via swrRace_GenerateDefaultDataSAV.
void swrRace_ResetAllProfiles(void);
// "All Pods & tracks unlocked!!!" cheat: sets every unlock bitfield in the save image
// (incl. the field IsGameDataUninitialized tests) and autosaves via SaveCurrentProfile.
void swrRace_CheatUnlockAll(void);
// Copy the current save image to the backup buffer (0xfd4 bytes).
void swrRace_BackupGameData(void);
// Copy a profile out of the save image into a live working slot (load direction).
void swrRace_CopyProfileFromSave(int workingSlot, int savedSlot);
// Copy a live working profile into the save image (save direction).
void swrRace_CopyProfileToSave(int savedSlot, int workingSlot);
// CRC32 over the 0xfd0-byte payload at saveImage+4 (the checksummed region).
unsigned int swrRace_ComputeSaveChecksum(void* saveImage);
// Generic CRC32 (polynomial 0x04C11DB7), lazily building the lookup table on first use.
unsigned int swrRace_Crc32(void* data, int length);
// Build the 256-entry CRC32 lookup table.
void swrRace_InitCrc32Table(void);

#endif // SWRRACE_H
