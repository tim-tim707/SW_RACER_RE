#ifndef SWRRACE_H
#define SWRRACE_H

#include "types.h"

#define swrRace_SelectProfileMenu_ADDR (0x00401340)

#define swrRace_ReservedSettingsMenu_ADDR (0x0040fb50)

#define swrRace_LoadSaveConfigMenu_ADDR (0x0040ffe0)
#define swrRace_BuildProfileSelectMenu_ADDR (0x00410230)
#define swrRace_PollScreenshotKey_ADDR (0x00410430)

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

// Part-shop + stats-menu UI (upgrade list, holographic part models, stat bars).
#define swrRace_BuildPartMenuList_ADDR (0x0043da10)
#define swrRace_UpdatePartMenuLayout_ADDR (0x0043dba0)
#define swrRace_DrawPartShopScreen_ADDR (0x0043ec10)
#define swrRace_DrawScrollbar_ADDR (0x0043fe90)
#define swrRace_UpdatePartNodeSelection_ADDR (0x004556c0)
#define swrRace_SetupStatsMenuLighting_ADDR (0x00455720)
#define swrRace_DrawStatBar_ADDR (0x004557e0)
#define swrRace_UpdateStatPartModels_ADDR (0x00455dc0)

// ray-collision query: reset/read the global hit-node result (set by the query during traversal)
#define swrRace_ResetCollisionHit_ADDR (0x00441020)
#define swrRace_GetCollisionHit_ADDR (0x00441030)
#define swrRace_RaycastModel_ADDR (0x00444d10)

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
// tilt/orientation alignment helpers (feed CalculateTiltFromTurn)
#define swrRace_ComputeTiltAngles_ADDR (0x00476390)
#define swrRace_AlignToSurface_ADDR (0x004764e0)

#define swrRace_TakeDamage_ADDR (0x00474cd0)

#define swrRace_ActivateTriggersInRange_ADDR (0x00476AC0)
#define swrRace_UpdateSurfaceTag_ADDR (0x00476ea0)

#define swrRace_ApplyGravity_ADDR (0x004774f0)

// 0x00477c27 was a bogus {return;} mis-identification (no xrefs); the real per-frame orientation
// integrator the name refers to is at 0x00477c30 (called by swrObjTest_UpdatePhysicsContact).
#define swrRace_UpdateTurn2_ADDR (0x00477c30)

#define swrRace_UpdateSpeed_ADDR (0x004783e0)
#define swrRace_ApplyBoost_ADDR (0x004787f0)
#define swrRace_UpdateHeat_ADDR (0x004788c0)
#define swrRace_ApplyTraction_ADDR (0x00478a70)
#define swrRace_IntegrateMotion_ADDR (0x00478d80)
#define swrRace_CollideBlockMove_ADDR (0x0044abc0)
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
#define swrRace_UpdateReflectionNode_ADDR (0x004709a0)
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

// engine-fire FX + spline-cursor track following (per-pod, run during the race tick)
#define swrRace_UpdateFireEffects_ADDR (0x0047e450)
#define swrRace_InitFireEffects_ADDR (0x0047e580)
#define swrRace_AdvanceSplineCursor_ADDR (0x0047f8e0)
#define swrRace_UpdateSplineBinding_ADDR (0x0047fbb0)
#define swrRace_ComputeTrackOffset_ADDR (0x0047fca0)

// Save / profile persistence (player tournament data -> .\data\player\tgfd.dat).
// The on-disk image is a 0xfd4-byte blob: [0x00] CRC32 checksum, [0x04..] 0xfd0 data bytes
// (records, unlock bitfields, and the embedded saved-profile table), prefixed on disk by
// a 4-byte version magic (0x10003). Original engine module name: "elfSaveLoad".
#define swrRace_InitGameData_ADDR (0x00421810)
#define swrRace_LoadProfileFromFile_Maybe_ADDR (0x00421850)
#define swrRace_SaveProfile_ADDR (0x004219d0)
#define swrRace_ResetGameData_ADDR (0x00421b20)
#define swrRace_LoadGameData_ADDR (0x00421b90)
#define swrRace_SaveGameData_ADDR (0x00421c90)
#define swrRace_IsGameDataUninitialized_ADDR (0x00421d80)
#define swrRace_GetLensFlareEnabled_ADDR (0x004376b0)
#define swrRace_DrawRecordText_Maybe_ADDR (0x00439c70)
#define swrRace_ResetAllProfiles_ADDR (0x0043d970)
#define swrRace_CheatUnlockAll_ADDR (0x0043d9a0)
#define swrRace_ComputeUpgradePrices_ADDR (0x0043eb50)
#define swrRace_GetEngineNodeOffsetPos_Maybe_ADDR (0x0044afb0)
#define swrRace_SetEngineNodeRotScale_Maybe_ADDR (0x0044b180)
#define swrRace_SetEngineNodeTranslation_Maybe_ADDR (0x0044b270)
#define swrRace_InitDefaultGameData_ADDR (0x0044e320)
#define swrRace_ComputeSaveChecksum_ADDR (0x0044e440)
#define swrRace_Crc32_ADDR (0x0044e460)
#define swrRace_InitCrc32Table_ADDR (0x0044e4a0)
#define swrRace_BackupGameData_ADDR (0x0044e4e0)
#define swrRace_CopyProfileFromSave_ADDR (0x0044e500)
#define swrRace_CopyProfileToSave_ADDR (0x0044e530)
#define swrRace_SaveCurrentProfile_ADDR (0x0044e560)
#define swrRace_GetProfileRecordVec3_Maybe_ADDR (0x0044e5a0)
#define swrRace_UpdatePitDroidModels_Maybe_ADDR (0x00456200)
#define swrRace_UpdateAIGlidePitch_ADDR (0x0046aec0)
#define swrRace_SendFlameEvent_Maybe_ADDR (0x0046bb30)
#define swrRace_SpawnExplosionByIndex_Maybe_ADDR (0x0046bb50)
#define swrRace_GetEngineUiBarColor_Maybe_ADDR (0x0046bc50)
#define swrRace_UpdateEngineFireballNode_Maybe_ADDR (0x0046ebf0)
#define swrRace_ApplyEngineProximityPush_Maybe_ADDR (0x0046ecd0)
#define swrRace_SpawnGroundDustKick_Maybe_ADDR (0x0046fd60)
#define swrRace_SmoothEngineExhaustSize_Maybe_ADDR (0x00470510)
#define swrRace_ResetGravityDown_Maybe_ADDR (0x004764a0)
#define swrRace_HandleWallScrapeHit_Maybe_ADDR (0x00479d40)
#define swrRace_UpdateScrapeContact_Maybe_ADDR (0x0047a3a0)
#define swrRace_UpdateSplineOrientation_Maybe_ADDR (0x0047a610)
#define swrRace_GetSplineProgressValue_Maybe_ADDR (0x0047f890)

int swrRace_SelectProfileMenu(void* param_1, unsigned int param_2, unsigned int param_3, int param_4);

void swrRace_ReservedSettingsMenu(swrUI_unk* param_1);

void swrRace_LoadSaveConfigMenu(swrUI_unk* param_1);

// Builds the profile-select menu list with Create/Remove-Racer and Current-Player entries.
void swrRace_BuildProfileSelectMenu(swrUI_unk* param_1);

// Polls the screenshot key and, when pressed, plays a UI sound and captures a screenshot.
void swrRace_PollScreenshotKey(void);

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

// Returns whether the lens-flare video option is enabled.
int swrRace_GetLensFlareEnabled(void);

void swrRace_HangarMenu(swrObjHang* hang);

// Formats a record entry and creates the text entry that displays it (best guess).
void swrRace_DrawRecordText_Maybe(int x, int y, void* recordFields);

void swrRace_ResultsMenu(swrObjHang* hang);

void swrRace_CourseSelectionMenu(void);

void swrRace_CourseInfoMenu(swrObjHang* hang);

void swrRace_UpdatePartsHealth(void);

void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot);

// Computes which pod upgrades are affordable against the player's current truguts.
void swrRace_ComputeUpgradePrices(void);

void swrRace_BuyPitdroidsMenu(swrObjHang* hang);

// Part-shop + stats-menu UI (upgrade list, holographic part models, stat bars):
void swrRace_BuildPartMenuList(swrObjHang* hang);
void swrRace_UpdatePartMenuLayout(swrObjHang* hang);
void swrRace_DrawPartShopScreen(swrObjHang* hang);
void swrRace_DrawScrollbar(short x, short y, int height);
void swrRace_UpdatePartNodeSelection(void);
void swrRace_SetupStatsMenuLighting(void);
void swrRace_DrawStatBar(swrObjHang* hang, short x, short y, float value, float lo, float mid, float hi);
void swrRace_UpdateStatPartModels(void);

// Randomizes and positions the pit-droid models and sets the stats-menu light (best guess).
void swrRace_UpdatePitDroidModels_Maybe(void);

// ray = {origin.xyz, dir.xyz, maxDist}; returns hit distance (<0 = miss), fills outHit/outNormal.
float swrRace_RaycastModel(swrModel_Node* model, float* ray, rdVector3* outHit, rdVector3* outNormal);
void swrRace_ResetCollisionHit(void);
swrModel_Node* swrRace_GetCollisionHit(void);

void swrRace_ComputeStatBars(PodHandlingData* out_stats, PodHandlingData* stats);

void swrRace_ApplyUpgradesToStats(PodHandlingData* pActiveStats, PodHandlingData* pBaseStats, char* pUpgradeLevels, char* pUpgradeHealths);

void swrRace_CalculateUpgradedStat(PodHandlingData* podHandlingData, int upgradeCategory, int upgradeLevel, float upgradeHealth);

void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6);

void swrRace_SetAngleFromTurnRate(float* out_tilt, float cur_turnrate, void* unused, float max_turnrate, float max_angle);

// Reads an engine node's world translation and offsets it by the paired node's Y position (best guess).
void swrRace_GetEngineNodeOffsetPos_Maybe(void** nodePair, rdVector3* outPos);

// Builds a rotation and scale transform for an engine node, offset by the paired node's Y (best guess).
void swrRace_SetEngineNodeRotScale_Maybe(void** nodePair, float scale, float angle);

// Copies an engine node's transform and sets its translation minus the paired node's Y offset (best guess).
void swrRace_SetEngineNodeTranslation_Maybe(void** nodePair, rdVector3* pos);

void swrRace_ReplaceMarsGuoWithJinnReeso(void);
void swrRace_ReplaceBullseyeWithCyYunga(void);

void swrRace_VehicleStatisticsSubMenu(void* param_1, float param_2, float param_3);

void swrRace_InRaceTimer(void* param_1, void* param_2);

void swrRace_InRaceEngineUI(void* param_1, int param_2);

void swrRace_InRaceEndStatistics(void* param_1, void* param_2);

void swrRace_Repair(swrRace* player);

// Sets the pod death-pitch field based on a speed or flag threshold (best guess).
void swrRace_UpdateAIGlidePitch(swrRace* player, rdVector3* lookaheadPos, rdVector3* splinePos, int useGroundClearance);

void swrRace_Tilt(swrRace* player, float b);

void swrRace_AI(int player);

void swrRace_TakeDamage(int player, int engineIndex, float amount);

void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2);
void swrRace_UpdateSurfaceTag(swrRace* test);

void swrRace_ApplyGravity(swrRace* player, float* a, float b);

int swrRace_BoostCharge(int player);

void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot);

// Extracts pitch + signed-roll angles of a forward/right basis relative to a reference (down) vector.
void swrRace_ComputeTiltAngles(rdVector3* fwd, rdVector3* right, rdVector3* ref, rdVector3* out);

// Resets the pod's gravity field and down-reference vector to negative Z (best guess).
void swrRace_ResetGravityDown_Maybe(int player);
// Builds a surface-aligned basis from the pod forward + surface normal and accumulates the heading/tilt
// correction into pRDot (turn input). The +-85 deg pitch clamp + the magnet (flags1 0x400) gating live here.
void swrRace_AlignToSurface(swrRace* player, rdVector3* up, rdVector3* fwd_vB, rdVector3* vA_fallback,
                            rdVector3* down_ref, float groundDist, float hoverHi, float hoverLo, rdVector3* pRDot);

void swrRace_UpdateTurn2(swrRace* player, rdVector3* pos, rdVector3* turnInput);

float swrRace_UpdateSpeed(swrRace* player);
float swrRace_ApplyBoost(swrRace* player);
void swrRace_UpdateHeat(swrRace* player);
void swrRace_ApplyTraction(swrRace* player, float b, rdVector3* c, rdVector3* d);
void swrRace_IntegrateMotion(swrRace* player, rdVector3* b, rdVector3* c, rdVector3* d);

// One iteration of swept track collision: tests the segment prevPos->curPos against the
// collision model, and on a hit pushes curPos back out along the surface normal (also
// written to outNormal). Returns nonzero when it resolved a collision. (was FUN_0044acb0)
// Collision step that BLOCKS the move (snaps curPos back to prevPos) on hit, vs CollideTrack which pushes out.
int swrRace_CollideBlockMove(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal);
int swrRace_CollideTrack(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal);

void swrRace_DeathSpeed(swrRace* player, float a, float b);

// Computes the projected/target turn rate (projTurnRate) and gravity multiplier
// for the frame, clamped to +/-maxTurnRate. (annodue: CalcTargetTurnRate)
void swrRace_CalcTargetTurnRate(swrRace* player);
// Shows/hides the engine model nodes during a left/right spinout or explosion
// (keys off flags1 0x8000/0x10000).
void swrRace_UpdateSpinoutNodes(swrRace* player);
// Ground-contact / vertical-motion integrator: applies gravity, follows terrain
// and the track spline for hover height, sets groundToPodMeasure (also returned).
float swrRace_UpdateGroundContact(swrRace* player, float* velocity, int scrapeData, rdVector3* up, int hoverPadState);

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
// Draws the pod's planar ground reflection: mirrors reflectionNode across the ground plane
// (Z = 2*groundZ), shown only on reflective (ON_MIRR) surfaces, hidden otherwise.
void swrRace_UpdateReflectionNode(swrRace* player);
// Plays the spatial engine loop sound, varying by speed and terrain type.
void swrRace_UpdateEngineSound(swrRace* player);
// Engine fire/smoke effects when engines are damaged, plus a proximity check
// that flags nearby pods.
void swrRace_UpdateEngineDamageFX(swrRace* player);

// Spawns a per-planet ground dust kick with a scrape sound during a vehicle reaction (best guess).
void swrRace_SpawnGroundDustKick_Maybe(swrRace* player, float* transform, float sx, float sy, float sz, float param_6, int param_7);

// Smooths a per-side engine exhaust size toward a target over time (best guess).
void swrRace_SmoothEngineExhaustSize_Maybe(int player, float side, float a, float b, float c, float rate, int param_7, int param_8);

// pod state + engine secondary-motion helpers:
// Counts down the death timer; on expiry dispatches the 'Snap' event and resets engine health/flags.
void swrRace_HandleDeathSnap(swrRace* player);
// Handles the respawn-pod flag (flags0 0x1000): clears it and resets race state.
void swrRace_HandleRespawnFlag(swrRace* player);
// Detailed per-frame engine audio: RPM/gear-based engine sounds, boost and scrape SFX.
void swrRace_PlayEngineSounds(swrRace* player, float param_2);
// Tilts the engine transforms from pitch (0x2fc) and tilt angle (0x204).
void swrRace_TiltEngines(swrRace* player);
// Spins the engine transforms during a spinout/explosion (flags1 0x8000/0x10000).
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

// Animates the engine fireball node's transform and hides it when its animation finishes (best guess).
void swrRace_UpdateEngineFireballNode_Maybe(int player);

// Projects a relative position onto the two engine bases to push pods apart in proximity (best guess).
void swrRace_ApplyEngineProximityPush_Maybe(swrRace* player, float* otherPos, rdVector3* out);

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
// turnRateTarget and throttle (also handles track-specific shortcuts).
void swrRace_AutopilotSteer(swrRace* player);
// Adds a pod-to-pod proximity turn force from nearby racers.
void swrRace_ApplyPodProximityForce(swrRace* player);
// Autopilot/pre-race control: snap events and tilt while not under player input.
void swrRace_UpdateAutopilotControl(swrRace* player);

// Fills the HUD engine-bar color and fill amount from the pod's engine state.
void swrRace_GetEngineUiBarColor_Maybe(int player, uint8_t* outRgb, uint8_t* outRgba, float* outFill);
// Human player control: maps input to turn/pitch/brake/boost, drives force
// feedback and tilt, and sets projTurnRate/pitch/throttle.
void swrRace_UpdatePlayerControl(swrRace* player);
// Runs AI steering for AI pods and computes the rubber-band/catch-up multiplier.
void swrRace_UpdateCatchup(swrRace* player);

// collision / ground-contact physics + explosion spawn:
// Spawns the explosion effect (type-8 Smok) and destruction sounds for the pod.
void swrRace_SpawnExplosionEffect(swrRace* player);

// Sends a 'flam' flame multiplayer event for the given player (best guess).
void swrRace_SendFlameEvent_Maybe(int player, double param_2, void* param_3, void* param_4, int param_5);

// Spawn the explosion effect for the racer at the given index (best guess).
void swrRace_SpawnExplosionByIndex_Maybe(int racerIndex);
// Raycasts the terrain collision mesh; sets terrainModel (0x140) and ground height, returns distance.
float swrRace_RaycastGround(swrRace* player, rdVector3* pos, int* outSurfaceNormal);
// Samples the 4 hover-pad ground heights and builds the shadow transforms (0x1290); returns hover height.
float swrRace_UpdateHoverPads(swrRace* player, rdVector3* pos, int padFlags, float groundDist, float* up);
// Slope steering: turns the pod along the ground slope (sets 0x1f8) and slope velocity (0x1c4).
void swrRace_ApplySlopeSteering(swrRace* player, int velocity, int scrapeData, float groundDist, rdVector3* normal, rdVector3* out1, rdVector3* out2);
// Magnet/tube variant of slope steering (flags1 0x400).
void swrRace_ApplySlopeSteeringMagnet(swrRace* player, int velocity, int scrapeData, float groundDist, rdVector3* normal, rdVector3* out1, rdVector3* out2);
// Wall collision response: reflects velocity off the wall normal into velocityCollision and dispatches hit/scrape events.
void swrRace_ApplyWallCollision(swrRace* player, rdVector3* normal, rdVector3* dir);

// Handles a wall-scrape hit: spawns spray and sends the scrape multiplayer event (best guess).
void swrRace_HandleWallScrapeHit_Maybe(swrRace* player);

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
void swrRace_DetectWallScrape(swrRace* player, float* velocity, float* scrapeOut);
// Computes the collisionToggles bitmask (0x26c) from the pod's position.
void swrRace_UpdateCollisionToggles(swrRace* player);

// pod model beams + wall/pod collision:
// Builds the energy-binder plasma beam transform stretched between the engines.
void swrRace_UpdateEnergyBinder(swrRace* player, float side, rdVector3* pointA, rdVector3* pointB);
// Builds a quad transform stretched between two engine matrices (beam/connector segment).
void swrRace_BuildStretchedQuad(rdMatrix44* a, rdMatrix44* b, float param_3, float param_4, int keyframeIdx, rdMatrix44* out);
// Wall-contact dispatch: wall-scrape + collision response when fast/airborne, else terrain follow.
float swrRace_UpdateWallContact(swrRace* player, float* param_2, float* param_3, rdVector3* param_4);

// Decays the scrape timer, finds nearby smoke, and computes the scrape reflection force (best guess).
void swrRace_UpdateScrapeContact_Maybe(int player, int param_2);

// Integrates spline-bound pod orientation, rebuilding the basis and applying turn, pitch, and roll (best guess).
void swrRace_UpdateSplineOrientation_Maybe(int player, rdVector3* up);
// Pod-to-pod collision: finds a nearby pod and resolves the 2D collision (push apart + DeathSpeed).
void swrRace_ResolvePodCollision(swrRace* player);

void swrRace_TriggerHandler(int player, int a, char b);

float swrRace_LapProgress(int a);

// Returns a component of the spline progress values for a spline cursor (best guess).
float swrRace_GetSplineProgressValue_Maybe(void* splineCursor);

bool swrRace_LapCompletion(void* engineData, int param_2);

// Per-racer race-progress update (called per racer from swrObjJdge_F2): advances the spline
// cursor, recomputes the current checkpoint segment, runs swrRace_LapCompletion, and ticks the
// lap counter / off-track recovery timer.
void swrRace_UpdateRaceProgress(void* engineData, int param_2, int incrementLap, int offTrackTick);

void swrRace_IncrementFrameTimer(void);

// 0x004804c0. Resets the frame timer / delta-time state (sibling of IncrementFrameTimer):
// sets the fixed-step default and samples the initial system time.
void swrRace_InitFrameTimer(void);

// engine-fire FX + spline-cursor track following (per-pod, run during the race tick):
void swrRace_UpdateFireEffects(swrRace* player);
void swrRace_InitFireEffects(int racer, float reset);
void swrRace_AdvanceSplineCursor(swrRace* player, float* outProgress, int* outForward, int* outBackward);
int swrRace_UpdateSplineBinding(swrRace* player);
void swrRace_ComputeTrackOffset(swrRace* player);

// Save / profile persistence.
// Boot entry: load tgfd.dat; on failure rebuild defaults and write a fresh file.
void swrRace_InitGameData(void);

// Loads a player profile file, validates its magic, reads the profile blob, and copies it into the save image (best guess).
bool swrRace_LoadProfileFromFile_Maybe(int playerId);
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

// Reads a vec3 field from an indexed save/profile record (best guess).
void swrRace_GetProfileRecordVec3_Maybe(int base, int index, float* out3);
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
