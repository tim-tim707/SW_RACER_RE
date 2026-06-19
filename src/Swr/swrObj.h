#ifndef SWROBJ_H
#define SWROBJ_H

#include "types.h"

#define swrObjHang_SetHangar2Splash_ADDR (0x004336a0)
#define swrObjHang_SetHangar2State_ADDR (0x004336d0)
#define swrObjHang_SetHangar2_ADDR (0x004336f0)
#define swrObjHang_SetUnused_ADDR (0x00433700)
#define swrObjHang_UpdateLoadScreen_ADDR (0x00434ea0)
#define swrObjHang_UpdateLegalScreen_ADDR (0x00434ec0)
#define swrObjHang_UpdateSplashScreen_ADDR (0x00435240)
#define DrawTracks_ADDR (0x004360e0)
#define swrObjHang_UpdateEnterName_ADDR (0x004367c0)
#define swrObjHang_UpdateMainMenu_ADDR (0x00436860)
#define swrObjHang_UpdateWattoShop_ADDR (0x004376c0)
#define swrObjHang_UpdateLookAtVehicle_ADDR (0x00437f70)
#define swrObjHang_UpdateJunkyard_ADDR (0x0043abc0)
#define swrObjHang_UpdateVehicleSelectIntro_ADDR (0x0043c6f0)
#define swrObjHang_UpdateTauntScene_ADDR (0x0043ca30)
#define swrObjHang_UpdatePlanetSelectIntro_ADDR (0x0043ceb0)
#define swrObjHang_UpdateResultsIntro_ADDR (0x0043d4e0)
#define swrObjHang_UpdateScreenTransition_ADDR (0x0043da90)
#define swrObjHang_UpdateHoloBillboardMatrix_ADDR (0x0043e210)
#define swrObjHang_SwapSelectedPart_ADDR (0x00440800)
#define GetRequiredPlaceToProceed_ADDR (0x00440a00)
#define isTrackUnlocked_ADDR (0x00440a20)
#define isTrackPlayable_ADDR (0x00440aa0)
#define VerifySelectedTrack_ADDR (0x00440af0)
#define swrObjHang_IsCameraMoving_ADDR (0x00440b50)
#define swrObjJudge_PollPause_ADDR (0x00445680)
#define GetPauseState_ADDR (0x00445690)
#define requestPause_ADDR (0x004456B0)
#define swrObj_Free_ADDR (0x00450e30)
#define swrObjcMan_UpdateLighting_ADDR (0x00451160)
#define swrObjcMan_LoadLightingFromBehavior_ADDR (0x00451800)
#define swrObjcMan_UpdateTerrainVisuals_ADDR (0x00451a80)
#define swrObjcMan_F0_ADDR (0x00451cd0)
#define swrObjcMan_F2_ADDR (0x00451d40)
#define swrObjcMan_CommitStagedCamera_ADDR (0x00451d60)
#define swrObjcMan_RestoreMode_ADDR (0x00451ec0)
#define swrObjcMan_UpdatePreRaceSweep_ADDR (0x00451ef0)
#define swrObjcMan_EndPreRaceSweep_ADDR (0x004525d0)
#define swrObjcMan_UpdateDeathCamera_ADDR (0x00452600)
#define swrObjcMan_UpdateFirstPersonCamera_ADDR (0x004528b0)
#define swrObjcMan_UpdateChaseCamera_ADDR (0x00452aa0)
#define swrObjcMan_UpdateSplineCamera_ADDR (0x004533a0)
#define swrObjcMan_UpdateFogAndViewport_ADDR (0x004538d0)
#define swrObjcMan_UpdateCamera_ADDR (0x00453e00)
#define DrawTerrainTypeDebugText_ADDR (0x00454060)
#define swrObjcMan_F3_ADDR (0x004542e0)
#define swrObjcMan_F4_ADDR (0x004543f0)
#define swrObjScene_F0_ADDR (0x00454a10)
#define swrObjScene_F4_ADDR (0x00454a30)
#define swrModel_clearSceneModelsAndChildren_ADDR (0x00454cc0)
#define swrObjHang_InitSceneRootNode_ADDR (0x00454D10)
#define swrObjHang_SetMenuState_ADDR (0x00454d40)
#define swrObjHang_OrderHoloRacerIcons_ADDR (0x004565e0)
#define DrawHoloPlanet_ADDR (0x00456800)
#define DrawTrackPreview_ADDR (0x00456c70)
#define swrObjHang_LoadScreen_ADDR (0x00457410)
#define swrObjHang_ShowAllSceneNodes_ADDR (0x004575a0)
#define swrObjHang_F0_ADDR (0x00457620)
#define swrObjHang_F2_ADDR (0x00457b00)
#define swrObjHang_F3_ADDR (0x00457b90)
#define swrObjHang_LoadAllPilotSprites_ADDR (0x00457bd0)
#define swrObjHang_InitTrackSprites_ADDR (0x004584a0)
#define swrObjHang_F4_ADDR (0x0045a040)
#define swrObjHang_Init_ADDR (0x0045ab50)
#define swrObjHang_AssignRacerCameras_ADDR (0x0045b210)
#define swrObjHang_StartRace_ADDR (0x0045b290)
#define swrObjHang_InitCameraAssignments_ADDR (0x0045b5d0)
#define swrObjHang_BuildRosterMultiplayer_ADDR (0x0045b610)
#define swrObjHang_BuildRosterSinglePlayer_ADDR (0x0045b7d0)
#define swrObjHang_FindPlayerRacerSlot_ADDR (0x0045bab0)
#define swrObjHang_InitRacerList_ADDR (0x0045bd90)
#define swrObjHang_NavigateMenu_ADDR (0x0045bde0)
#define swrObjHang_FocusMenuItem_ADDR (0x0045bee0)
#define swrObjHang_PositionPlayerPuppets_ADDR (0x0045bf20)
#define swrObjHang_SetHoloCameraTarget_ADDR (0x0045c010)
#define swrObjHang_LerpHoloCamera_ADDR (0x0045c0b0)
#define swrObjHang_UpdateHoloCamera_ADDR (0x0045c3c0)
#define swrObjHang_StepCameraToward_ADDR (0x0045c560)
#define swrObjHang_UpdateIdleCamera_ADDR (0x0045c810)
#define swrObjHang_BeginCameraMove_ADDR (0x0045c9d0)
#define swrObjHang_ComputeCameraEye_ADDR (0x0045cb80)
#define swrObjHang_GenerateJunkyardStock_ADDR (0x0045cd50)
#define swrObjHang_CullElmoAssets_ADDR (0x0045ce90)
#define swrObjHang_ComputeUpgradedStats_ADDR (0x0045cf60)
#define swrObjJdge_Clear_ADDR (0x0045d0b0)
#define swrObjJdge_ScrollCredits_ADDR (0x0045d130)
#define NumLocalPlayers_ADDR (0x0045D350)
#define swrRace_GetLapProgressIfAvailable_ADDR (0x0045D390)
#define GetLocalPlayerNumberFromScore_ADDR (0x0045D3D0)
#define swrObjJdge_GetRacerProgress_ADDR (0x0045d410)
#define swrObjJdge_GetRacerRankValue_ADDR (0x0045d480)
#define swrObjJdge_UpdateStandings_ADDR (0x0045d4a0)
#define swrObjJdge_UpdateViewportLayout_ADDR (0x0045dad0)
#define swrObjJdge_TeardownRace_ADDR (0x0045dd80)
#define swrObjJdge_StartPostRaceSequence_ADDR (0x0045dfe0)
#define KeyDownForPlayer1Or2_ADDR (0x0045E120)
#define swrObjJdge_CycleHudMode_ADDR (0x0045e1a0)
#define swrObjJdge_F0_ADDR (0x0045e200)
#define swrObjJdge_UpdateSplineGuideNodes_ADDR (0x0045e970)
#define swrObjJdge_F2_ADDR (0x0045ea30)
#define swrObjJdge_UpdateOvertakeSounds_ADDR (0x0045ef70)
#define swrObjJdge_DrawRaceHUD_ADDR (0x0045f230)
#define swrObjJdge_DrawHudBar_ADDR (0x00460320)
#define swrObjJdge_DrawSplitDivider_ADDR (0x004610f0)
#define swrObjJdge_HideEngineUI_ADDR (0x00461150)
#define swrObjJdge_IsRacerRacing_ADDR (0x00462a70)
#define swrObjJdge_UpdatePlayerHUD_ADDR (0x00462b20)
#define swrObjJdge_CheckIfPauseRequested_ADDR (0x00462D40)
#define swrObjJdge_UpdateCountdownLights_ADDR (0x00462da0)
#define swrObjJdge_UpdateMinimap_ADDR (0x004634a0)
#define swrObjJdge_F3_ADDR (0x00463580)
#define swrObjJdge_F4_ADDR (0x00463a50)
#define SetPlanetIdAndTrackNumber_ADDR (0x00463FF0)
#define swrObjJdge_SetupTrackEnvironment_ADDR (0x00464b90)
#define swrModel_LoadBeamAndSparkModels_ADDR (0x004651a0)
#define swrObjJdge_AddTriggersToScene_ADDR (0x004651F0)
#define swrObjToss_AddDustKickModelsToScene_ADDR (0x00465230)
#define swrObjSmok_AddFireballModelsToScene_ADDR (0x00465310)
#define AddFireballToModelScene_ADDR (0x004653F0)
#define GetTrackModelRoot_ADDR (0x00465500)
#define LoadTrackModels_ADDR (0x00465510)
#define swrObjJdge_GetSpawnTransform_ADDR (0x00465840)
#define swrObjJdge_SpawnRacer_ADDR (0x00465980)
#define swrObjJdge_InitSplineCursor_ADDR (0x00465CB0)
#define LoadTrackSpline_ADDR (0x00465D00)
#define swrObjJdge_SetupStartingGrid_ADDR (0x00465d50)
#define InitPrimaryLight_ADDR (0x00466370)
#define swrObjJdge_SpawnRacers_ADDR (0x004663e0)
#define InitAISettingsForTrack_ADDR (0x004667E0)
#define swrObjJdge_InitTrack_ADDR (0x00466BD0)
#define swrObjElmo_SetAnimState_ADDR (0x00466ec0)
#define swrObjElmo_F0_ADDR (0x00467cd0)
#define swrObjElmo_F3_ADDR (0x00468570)
#define swrObjElmo_F4_ADDR (0x00468660)
#define swrObjElmo_GetAnimTiming_ADDR (0x00468a30)
#define swrObjElmo_CheckReachedTarget_ADDR (0x00468d00)
#define swrObjElmo_UpdateMovement_ADDR (0x00468d50)
#define swrObjElmo_GetWaypointIndex_ADDR (0x004691c0)
#define swrObjElmo_SetTargetWaypoint_ADDR (0x00469200)
#define swrObjElmo_TryTransition_ADDR (0x00469230)
#define swrObjElmo_TurnToFaceTarget_ADDR (0x004692a0)
#define swrObjSmok_Free_ADDR (0x00469e70)
#define swrObjSmok_F0_ADDR (0x00469ed0)
#define swrObjSmok_F3_ADDR (0x00469fb0)
#define swrObjSmok_F4_ADDR (0x0046a500)
#define swrObjSmok_SetFireballChildNodesPtr_ADDR (0x0046A5E0)
#define swrObjSmok_Spawn_ADDR (0x0046a5f0)
#define swrObjSmok_SetPosition_ADDR (0x0046a920)
#define swrObjSmok_SetVelocity_ADDR (0x0046a940)
#define swrObjSmok_SetLifetime_ADDR (0x0046a960)
#define swrObjSmok_SetOwnerHandle_ADDR (0x0046a970)
#define swrObjTest_F0_ADDR (0x0046d170)
#define swrObjTest_F3_ADDR (0x00470610)
#define swrRace_PoddAnimateVariousThings_ADDR (0x00471760)
#define swrRace_PoddAnimateSteeringParts_ADDR (0x00472A50)
#define swrRace_GetSplineLookahead_ADDR (0x00473e40)
#define swrRace_ResetToSpline_ADDR (0x00473f40)
#define swrRace_Explode_ADDR (0x004741D0)
#define swrRace_UpdateSplineCursor_ADDR (0x004744b0)
#define swrRace_PlaceOnTrack_ADDR (0x004746b0)
#define swrObjTest_F4_ADDR (0x00474d80)
#define swrObjTest_TurnResponse_ADDR (0x0047ab40)
#define swrObjTest_SuperUnk_ADDR (0x0047b520)
#define swrObjToss_F2_ADDR (0x0047b9e0)
#define swrObjToss_F3_ADDR (0x0047ba30)
#define swrObjToss_F4_ADDR (0x0047bba0)
#define swrRace_SpawnDustKickObject_ADDR (0x0047BC40)
#define swrObjToss_SetDustKickChildNodesPtr_ADDR (0x0047BCD0)
#define swrObjTrig_EnableFXAnimation_ADDR (0x0047bea0)
#define swrObjTrig_StopFXAnimation_ADDR (0x0047bee0)
#define swrObjTrig_AnimationActive_ADDR (0x0047BF20)
#define swrObjTrig_MaybeResetAnimation_ADDR (0x0047BF70)
#define swrObjTrig_MaybeResetAnimationByTriggerType_ADDR (0x0047C080)
#define swrObjTrig_FindNode_ADDR (0x0047C0F0)
#define swrObjTrig_InitNodeForTrigger_ADDR (0x0047C130)
#define swrObjTrig_Unk_ADDR (0x0047C190)
#define swrObjTrig_MaybeResetCameraShake_ADDR (0x0047C330)
#define swrObjTrig_F0_ADDR (0x0047c390)
#define swrObjTrig_F2_ADDR (0x0047c500)
#define swrObjTrig_F4_ADDR (0x0047c710)
#define swrObjTrig_FindOrCreate_ADDR (0x0047C7D0)
#define swrObjTrig_HandleTrigger108_ADDR (0x0047C920)
#define swrObjTrig_HandleCrashHitTrigger_ADDR (0x0047CA90)
#define swrObjTrig_Handle314Or501Trigger_ADDR (0x0047CD90)
#define swrObjTrig_AddNodeToScene_ADDR (0x0047D310)
#define swrObjTrig_FindAndInitializeTriggersInNode_ADDR (0x0047DC40)
#define swrObjTrig_CreateTriggerSceneNode_ADDR (0x0047DD90)
#define swrObjTrig_LoadAndInitializeTriggerModels_ADDR (0x0047DDC0)
#define swrObjTrig_AddTriggerDescription_ADDR (0x0047E760)
#define swrObjTrig_FindTriggerDescriptionIndex_ADDR (0x0047E790)
#define swrObjTrig_GetTriggerDescription_ADDR (0x0047E7C0)
#define swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_ADDR (0x0047E7E0)
#define swrObjTrig_SendMultiplayerTriggerEvent_ADDR (0x0047E830)
#define GetCustomStartTransform_ADDR (0x004800c0)

// swrScene: scene / world bootstrap (alloc asset buffer, load objects, init cameras/fog).
#define swrScene_Startup_ADDR (0x00445a50)
#define swrScene_LoadPreviewModel_ADDR (0x00448d90)
#define swrScene_LoadObjects_ADDR (0x00448f40)
#define swrScene_InitFog_ADDR (0x00449000)
#define swrScene_InitWorld_ADDR (0x00449040)
#define swrScene_InitCameras_ADDR (0x004490a0)
#define swrScene_Init_ADDR (0x004491f0)
#define swrScene_SetObjectsLoaded_ADDR (0x004804a0)
#define swrScene_ResetRenderState_ADDR (0x004834b0)

void swrObjHang_SetHangar2State(swrObjHang_STATE state);

void swrObjHang_SetHangar2Splash(void);

void swrObjHang_SetHangar2(swrObjHang* hang);

void swrObjHang_SetUnused(void);

void DrawTracks(swrObjHang* hang, char param_2);

// hangar front-end per-screen update handlers (dispatched by swrObjHang_F0 on swrObjHang_STATE):
void swrObjHang_UpdateLegalScreen(swrObjHang* hang);
void swrObjHang_UpdateSplashScreen(swrObjHang* hang);
void swrObjHang_UpdateEnterName(swrObjHang* hang);
void swrObjHang_UpdateMainMenu(swrObjHang* hang);
void swrObjHang_UpdateWattoShop(swrObjHang* hang); // parts / pit-droid shop
void swrObjHang_UpdateLookAtVehicle(swrObjHang* hang); // view-pod 3D screen
void swrObjHang_UpdateJunkyard(swrObjHang* hang); // used-parts screen

// hangar menu navigation + shop (parts/truguts):
// Pans the camera into a screen, then commits the queued state transition; returns 1 when done.
int swrObjHang_UpdateScreenTransition(swrObjHang* hang, int param_2, int param_3);
// Swaps the selected part between the pod and the junkyard inventory (models + truguts).
void swrObjHang_SwapSelectedPart(swrObjHang* hang);
// Whether the hangar camera is still moving toward its target menu position.
int swrObjHang_IsCameraMoving(swrObjHang* hang);
// Moves the menu selection/camera to the adjacent valid item in the current room.
void swrObjHang_NavigateMenu(swrObjHang* hang, short dir, int param_3);
// Focuses a specific menu item (sets the camera index and queues the next state).
void swrObjHang_FocusMenuItem(swrObjHang* hang, int itemIndex, swrObjHang_STATE nextState, int param_4);

// hangar transition/cutscene state handlers (swrObjHang_STATE 14-18) + screen loader (best-effort):
// Reloads the current hangar screen scene; plays the planet cinematic on first visit.
void swrObjHang_LoadScreen(swrObjHang* hang, int param_2, int param_3);
// State 14: (re)loads the screen via swrObjHang_LoadScreen.
void swrObjHang_UpdateLoadScreen(swrObjHang* hang);
// State 15: opponent taunt scene (pilot voice lines).
void swrObjHang_UpdateTauntScene(swrObjHang* hang);
// State 16: camera fly-through into planet selection.
void swrObjHang_UpdatePlanetSelectIntro(swrObjHang* hang);
// State 17: camera transition into the post-race results.
void swrObjHang_UpdateResultsIntro(void);
// State 18: holo-planet + camera cutscene into vehicle selection.
void swrObjHang_UpdateVehicleSelectIntro(swrObjHang* hang);

char GetRequiredPlaceToProceed(char circuitIdx, char trackIdx);
int isTrackUnlocked(char circuitId, char trackId);
bool isTrackPlayable(swrObjHang* hang, char circuitIdx, char trackIdx);
int VerifySelectedTrack(swrObjHang* hang, int selectedTrackIdx);

void swrObjJudge_PollPause();
int GetPauseState();
int requestPause();

void swrObj_Free(swrObj* obj);

void swrObjcMan_F0(swrObjcMan* cman);

void swrObjcMan_F2(swrObjcMan* cman);

// Snapshots the live camera/focus transforms (0x20/0x108) into the staging
// transforms (0x224/0x264) and sets the camera mode. Tail-called by the
// pre-race sweep when it reaches its final stage.
void swrObjcMan_CommitStagedCamera(swrObjcMan* cman, int mode);
// Cinematic pre-race camera sweep: eases the camera along per-pod keyframes
// (mystery array at 0x4c7088, stride 0x6c) over animTimer (0x70), 3 stages.
void swrObjcMan_UpdatePreRaceSweep(swrObjcMan* cman);
// First-person/cockpit camera: builds the view + focus transform from the
// associated pod (unkf4_objTest), writing transform (0x20) and focusTransform (0x108).
void swrObjcMan_UpdateFirstPersonCamera(swrObjcMan* cman);
// Per-frame camera update + mode dispatch (switch on mode_type 0x7c); also
// drives the auto-cycling spectator camera and post-step viewport/weather/fog.
void swrObjcMan_UpdateCamera(swrObjcMan* cman);
// Default 3rd-person chase camera (mode_type 1/2): velocity-follow with
// smoothing, split-screen offsets, and banking from the pod transform.
void swrObjcMan_UpdateChaseCamera(swrObjcMan* cman);
// Death/respawn camera (mode_type 8/9): spline-driven recovery from the pod's
// lap-completion position, ends by granting respawn invincibility.
void swrObjcMan_UpdateDeathCamera(swrObjcMan* cman);
// Snaps the pre-race sweep to its end pose (animTimer 8.0) and finalizes it.
void swrObjcMan_EndPreRaceSweep(swrObjcMan* cman);
// Applies mode_respawn (0x80) to mode_type (0x7c); commits staged on sweep modes.
void swrObjcMan_RestoreMode(swrObjcMan* cman);
// Per-frame fog/lighting/terrain-flag update from the pod's current surface
// (via swrModel_MeshGetBehavior).
void swrObjcMan_UpdateTerrainVisuals(swrObjcMan* cman);
// Spectator/track-following camera (mode_type 6): positions a cinematic view
// along the track spline relative to the pod.
void swrObjcMan_UpdateSplineCamera(swrObjcMan* cman);
// Applies FOV/near/far to the viewport and updates fog color/distance and the
// clear color each frame (swrViewport_SetCameraParameters + SetFogParameters).
void swrObjcMan_UpdateFogAndViewport(swrObjcMan* cman);
// Interpolates and applies the scene lighting (color + direction) for the pod's
// light index, with a timed blend and a random flicker.
void swrObjcMan_UpdateLighting(swrObjcMan* cman, swrRace* pod);
// Loads the target light colors/directions from the pod's current terrain
// mesh-behavior block into cMan's light slots (0x330/0x364).
void swrObjcMan_LoadLightingFromBehavior(swrObjcMan* cman, swrRace* pod, void* meshBehavior);

// Debug overlay: prints the active terrain-type flags (On/Off/Fast/Slow/...)
// for a mesh-behavior block via swrText. Drawn from the camera update.
void DrawTerrainTypeDebugText(void* meshBehavior);

void swrObjcMan_F3(swrObjcMan* cman);

int swrObjcMan_F4(swrObjcMan* cman, int* subEvents, int p3);

void swrObjScene_F0(swrObjScen* scene);
int swrObjScene_F4(swrObjScen* scene, int* subEvents);

void swrObjHang_InitSceneRootNode();
void swrObjHang_SetMenuState(swrObjHang* hang, swrObjHang_STATE state);

void DrawHoloPlanet(swrObjHang* hang, int planetIdx, float scale);

void DrawTrackPreview(void* unused, int TrackID, float param_3);

void swrObjHang_F0(swrObjHang* hang);

void swrObjHang_F2(swrObjHang* hang);

void swrObjHang_F3(swrObjHang* hang);

void swrObjHang_LoadAllPilotSprites(void);

void swrObjHang_InitTrackSprites(swrObjHang* hang, int initTracks);

int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5);

// Galaxy-map / planet-select hologram screen.
// One-time init of the whole swrObjHang object: resets the working game data to defaults,
// builds the holographic galaxy-map scene, names the 8 planets, and sets up the racer list.
void swrObjHang_Init(swrObjHang* hang);
// Sub-init: selection/cursor state plus the 23-entry racer index list (the opponent roster).
void swrObjHang_InitRacerList(swrObjHang* hang);
// Depth-sort the racer icons orbiting a planet and assign their name-label sprite ids so the
// front icons draw over the back ones.
void swrObjHang_OrderHoloRacerIcons(int planetIdx);
// Recompute the camera-facing billboard rotation matrix for the hologram from the
// viewer -> planet direction.
void swrObjHang_UpdateHoloBillboardMatrix(void);
// Make every loaded front-end scene model node visible (run at the top of each F0 frame).
void swrObjHang_ShowAllSceneNodes(void);
// Unload/clear the front-end scene's model nodes and clear scene animations.
void swrModel_clearSceneModelsAndChildren(void);
// Set the target position/look-at (and transition mode) for the holo-scene camera move.
void swrObjHang_SetHoloCameraTarget(rdVector3* pos, rdVector3* lookAt, short mode, int param_4, int reset);

// Race start: build the roster (SP/MP) then fire the 'Begn' scene/judge events to spin up the race.
void swrObjHang_StartRace(swrObjHang* hang, int* param_2, int param_3);
void* swrObjHang_BuildRosterSinglePlayer(swrObjHang* hang, int* out);
void* swrObjHang_BuildRosterMultiplayer(swrObjHang* hang, int* out);
int swrObjHang_FindPlayerRacerSlot(swrObjHang* hang);
// Assign a cMan camera to each local-human racer ('NAsn' sub-event); set up the camera->player map.
void swrObjHang_AssignRacerCameras(swrObjHang* hang);
void swrObjHang_InitCameraAssignments(swrObjHang* hang);
// Holo-scene camera: time-lerp / converge update, idle sway, and the framing math behind them.
void swrObjHang_LerpHoloCamera(swrObjHang* hang);
void swrObjHang_UpdateHoloCamera(swrObjHang* hang);
int swrObjHang_StepCameraToward(swrObjHang* hang, float* progress, rdVector3* target, rdVector3* from, rdVector3* to, float speed);
void swrObjHang_UpdateIdleCamera(swrObjHang* hang);
void swrObjHang_BeginCameraMove(swrObjHang* hang, int mode);
void swrObjHang_ComputeCameraEye(swrObjHang* hang, int mode);
// Position each local player's pilot-puppet (Elmo slot 0x1c + i) using the computed camera.
void swrObjHang_PositionPlayerPuppets(swrObjHang* hang);
// Generate the junkyard's random part stock (consumed by swrObjHang_UpdateJunkyard).
void swrObjHang_GenerateJunkyardStock(swrObjHang* hang);
// Reset the asset buffer + hide scene 'Elmo' entities whose models fell out of it.
void swrObjHang_CullElmoAssets(int assetCheckpoint);
// Compute a pod's displayed stats with upgrades applied (vehicle-select preview).
void swrObjHang_ComputeUpgradedStats(int podIndex, int upgradeSlot, char upgradeType, char upgradeLevel);

void swrObjJdge_Clear(swrObjJdge* jdge, int event);

int NumLocalPlayers();
double swrRace_GetLapProgressIfAvailable();
int GetLocalPlayerNumberFromScore(swrScore*);

int KeyDownForPlayer1Or2(int);

void swrObjJdge_F0(swrObjJdge* jdge);

void swrObjJdge_F2(swrObjJdge* jdge);

int swrObjJdge_CheckIfPauseRequested();

void swrObjJdge_F3(swrObjJdge* jdge);
int swrObjJdge_F4(swrObjJdge* jdge, int* subEvents, int p3);

int SetPlanetIdAndTrackNumber(int, int);

void swrObjJdge_AddTriggersToScene(swrObjJdge* a1);
void swrObjToss_AddDustKickModelsToScene();
void swrObjSmok_AddFireballModelsToScene();
void AddFireballToModelScene();

void LoadTrackModels(swrObjJdge* judge);

void swrObjJdge_InitSplineCursor(swrObjJdge* judge);

void LoadTrackSpline(swrObjJdge*);

void InitPrimaryLight();

void InitAISettingsForTrack(swrObjJdge*);

unsigned int swrObjJdge_InitTrack(swrObjJdge* judge, swrScore* scores);

// track/level load pipeline (called from swrObjJdge_InitTrack):
// Selects the track spline by planet/track, loads it, and sets fog/clear color + start camera.
void swrObjJdge_SetupTrackEnvironment(swrObjJdge* judge, int* anims, int model);
// Loads the beam and spark models used during the race.
void swrModel_LoadBeamAndSparkModels(void);
// Computes a racer's starting-grid spawn transform from the spline (4-3-4-3 grid).
void swrObjJdge_GetSpawnTransform(swrObjJdge* judge, rdMatrix44* out, int gridIndex);
// Spawns one racer: allocates the Test pod, sets up its models, and calls swrRace_Init.
void swrObjJdge_SpawnRacer(swrObjJdge* judge, swrScore* score, int gridPos, void* podModel, int param_5, int param_6, int param_7, int param_8);
// Places the starting-grid position nodes from the start-line transform.
void swrObjJdge_SetupStartingGrid(swrObjJdge* judge);
// Loads every racer's pod model and spawns all racers (random grid order).
void swrObjJdge_SpawnRacers(swrObjJdge* judge, swrScore* scores);
// Returns the loaded track model root node.
void* GetTrackModelRoot(void);
// Copies the track's override start-grid transform into out if defined; returns 1 if present.
int GetCustomStartTransform(rdMatrix44* out);

// race-manager HUD / display / state helpers:
// "3-2-1-Go" countdown lights, start-gate node colors, and countdown sounds.
void swrObjJdge_UpdateCountdownLights(swrObjJdge* jdge);
// Per-racer minimap position dots.
void swrObjJdge_UpdateMinimap(swrObjJdge* jdge);
// Configures the viewport(s)/cameras for the current screen (in-race vs results, 1P vs 2P split).
void swrObjJdge_UpdateViewportLayout(swrObjJdge* jdge, int mode);
// End-of-game credits scroll; clears the judge when finished.
void swrObjJdge_ScrollCredits(swrObjJdge* jdge);
// Standings/position HUD + full-screen minimap state machine (keyed on hud_mode).
void swrObjJdge_DrawRaceHUD(swrObjJdge* jdge);
// Draws a centered HUD meter sprite (id 0x1a) sized/colored by a race metric (_DAT_00e9824c),
// hidden below threshold. Exact metric uncertain (boost/charge-like bar).
void swrObjJdge_DrawHudBar(void);
// Per-racer HUD: in-race timer, engine UI, finish statistics and the lap marker.
void swrObjJdge_UpdatePlayerHUD(swrObjJdge* jdge, swrScore* score);
// Whether a racer is still actively racing (not finished / at the finish line).
int swrObjJdge_IsRacerRacing(swrObjJdge* jdge, swrRace* racer);
// Draws the 2-player split-screen divider bar.
void swrObjJdge_DrawSplitDivider(void);
// Returns a racer's race progress (laps + fractional checkpoint) for placement/standings.
float swrObjJdge_GetRacerProgress(swrScore* score);
// Tears down the race: clears all entities, resets HUD/cameras, then restarts the track or returns to the hangar.
void swrObjJdge_TeardownRace(swrObjJdge* jdge, int event);
// Begins the post-race sequence (camera 'Swee' sweep + state/viewport transition).
void swrObjJdge_StartPostRaceSequence(swrObjJdge* jdge);
// Cycles the standings/HUD display mode (hud_mode) on the HUD button.
void swrObjJdge_CycleHudMode(swrObjJdge* jdge);
// Hides a racer's engine-health UI sprites.
void swrObjJdge_HideEngineUI(swrScore* score);

// Sort key for a racer: live race progress while racing, or an inverse-finish-time value once
// finished (so finishers always sort ahead of still-racing pods).
float swrObjJdge_GetRacerRankValue(swrScore* score);
// Recomputes the field standings: ranks all racers by GetRacerRankValue, assigns each its
// position (+0x5c) and the gap-to-leader / gap-ahead / gap-behind values, and sets catch-up flags.
void swrObjJdge_UpdateStandings(swrObjJdge* jdge);
// Places the 7 fading guide nodes that trail along the spline behind a racer.
void swrObjJdge_UpdateSplineGuideNodes(int nodeOwner, swrScore* score);
// On a position change, finds the adjacent racer and plays the positional overtake/taunt SFX.
void swrObjJdge_UpdateOvertakeSounds(swrObjJdge* jdge);

void swrObjElmo_F0(swrObjElmo* elmo);

void swrObjElmo_F3(swrObjElmo* elmo);

int swrObjElmo_F4(swrObjElmo* elmo, int* subEvents);

// swrObjElmo behavior/animation (pit-droid / hangar character AI):
// Sets the current animation state (maps a state command to an anim id, plays sounds).
void swrObjElmo_SetAnimState(swrObjElmo* elmo, int animCmd);
// Looks up the playback rate and duration for the current animation (per character type).
void swrObjElmo_GetAnimTiming(swrObjElmo* elmo, float* outRate, float* outDuration);
// Sets the arrived flag when within range of the walk target.
void swrObjElmo_CheckReachedTarget(swrObjElmo* elmo);
// Turns toward the target and, once aligned, starts the type-specific walk animation.
void swrObjElmo_UpdateMovement(swrObjElmo* elmo);
// Returns the waypoint index matching the current position, or -1.
int swrObjElmo_GetWaypointIndex(swrObjElmo* elmo);
// Sets the target position to the given waypoint.
void swrObjElmo_SetTargetWaypoint(swrObjElmo* elmo, int waypoint);
// Picks the next waypoint (or despawns); returns 1 if it transitioned.
int swrObjElmo_TryTransition(swrObjElmo* elmo);
// Smoothly turns the character's facing toward the target.
void swrObjElmo_TurnToFaceTarget(swrObjElmo* elmo);

// Frees a particle object: hides its model nodes, clears the node-array backref, swrObj_Free.
void swrObjSmok_Free(swrObj* smok);

void swrObjSmok_F0(swrObjSmok* smok);

void swrObjSmok_F3(swrObjSmok* smok);

int swrObjSmok_F4(swrObjSmok* smok, int* subEvents);

void swrObjSmok_SetFireballChildNodesPtr(swrModel_Node**);

// swrObjSmok particle create/setter API (smoke/fire/spark/explosion):
// Allocates and configures a particle by type (2/3 sparks, 6 fire, 8 explosion); returns the object.
void* swrObjSmok_Spawn(int type, int param_2, float lifetime, rdVector3* pos, float scale);
void swrObjSmok_SetPosition(swrObjSmok* smok, rdVector3* pos);
void swrObjSmok_SetVelocity(swrObjSmok* smok, rdVector3* vel);
void swrObjSmok_SetLifetime(swrObjSmok* smok, float lifetime);
void swrObjSmok_SetOwnerHandle(swrObjSmok* smok, void* ownerHandle);

void swrObjTest_F0(swrRace* player);

void swrObjTest_F3(swrRace* player);

void swrRace_PoddAnimateVariousThings(swrRace* arg0);

void swrRace_PoddAnimateSteeringParts(swrRace* a1);

// Compute a steering/target point one segment ahead on the spline (raised and
// terrain-adjusted); used by swrObjTest_F4.
void swrRace_GetSplineLookahead(rdVector3* out, swrRace* racer);

// Snap the racer's position + orientation onto its spline cursor at offset t
// and zero its momentum/physics state (respawn / reset primitive).
void swrRace_ResetToSpline(swrRace* racer, float t);

void swrRace_Explode(swrRace*, char);

// Per-frame: advance the racer's spline cursor along the track (by speed, or
// re-sync from position when mode != 0), validating the track surface.
void swrRace_UpdateSplineCursor(swrRace* racer, rdMatrix44* out, int mode);

// One-time placement of the racer onto the spline at race start.
void swrRace_PlaceOnTrack(swrRace* racer);

int swrObjTest_F4(swrRace* player, int* subEvent, int ghost);

void swrObjTest_TurnResponse(swrRace* player);

void swrObjTest_SuperUnk(swrRace* player);
void swrObjToss_F2(swrObjToss* toss);
void swrObjToss_F3(swrObjToss* toss);
int swrObjToss_F4(swrObjToss* toss);
void swrRace_SpawnDustKickObject(rdMatrix44* in, uint8_t r, uint8_t g, uint8_t b, int a, float life_time, int);
void swrObjToss_SetDustKickChildNodesPtr(swrModel_Node**);
void swrObjTrig_EnableFXAnimation(int index);
void swrObjTrig_StopFXAnimation(int index);

swrModel_Animation* swrObjTrig_AnimationActive(int);
void swrObjTrig_MaybeResetAnimation(swrObjTrig*);
void swrObjTrig_MaybeResetAnimationByTriggerType(int);
swrModel_NodeTransformedWithPivot* swrObjTrig_FindNode(swrModel_TriggerDescription* a1);
swrModel_NodeTransformedWithPivot* swrObjTrig_InitNodeForTrigger(swrModel_TriggerDescription*);
void swrObjTrig_Unk(swrObjTrig* obj, int index);
void swrObjTrig_MaybeResetCameraShake(swrObjTrig* obj);
void swrObjTrig_F0(swrObjTrig* trig);
void swrObjTrig_F2(swrObjTrig* trig);
int swrObjTrig_F4(swrObjTrig* trig, int* subEvents);
swrObjTrig* swrObjTrig_FindOrCreate(swrModel_TriggerDescription*);
void swrObjTrig_HandleTrigger108(swrObjTrig* a1, swrRace* a2);
void swrObjTrig_HandleCrashHitTrigger(swrObjTrig* a1, swrRace* a2);
void swrObjTrig_Handle314Or501Trigger(swrObjTrig* obj, int index);

swrModel_Node* swrObjTrig_AddNodeToScene(swrModel_TriggerDescription*, int, int);

void swrObjTrig_FindAndInitializeTriggersInNode(swrModel_NodeTransformed* node);
swrModel_Node* swrObjTrig_CreateTriggerSceneNode();
void swrObjTrig_LoadAndInitializeTriggerModels(int planet_id, int a2, swrModel_NodeTransformed* a3);

void swrObjTrig_AddTriggerDescription(swrModel_TriggerDescription* description);
int swrObjTrig_FindTriggerDescriptionIndex(swrModel_TriggerDescription* description);
swrModel_TriggerDescription* swrObjTrig_GetTriggerDescription(int index);
void swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent(int trigger_index, int player_index);
void swrObjTrig_SendMultiplayerTriggerEvent(swrModel_TriggerDescription* trigger_description, swrRace* player);

// swrScene: scene / world bootstrap (alloc asset buffer, load objects, init cameras/fog):
void swrScene_Startup(void);
void swrScene_LoadPreviewModel(void);
void swrScene_LoadObjects(void);
void swrScene_InitFog(void);
void swrScene_InitWorld(int param_1, int param_2);
void swrScene_InitCameras(void);
void swrScene_Init(int param_1, int param_2);
// Sets the scene-objects-loaded flag; called by swrObjJdge_F4 at 'Begn'.
void swrScene_SetObjectsLoaded(void);
void swrScene_ResetRenderState(void);

#endif // SWROBJ_H
