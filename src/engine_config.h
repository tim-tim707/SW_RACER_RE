#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#define RDCACHE_MAX_VERTICES (0x14000U) // something wrong with references
#define RDCACHE_MAX_TRIS (0x400)
// Free vertex-pool headroom rdCache_GetProcEntry keeps in reserve so the
// worst-case single face returned by it always fits before the next flush.
#define RDCACHE_MIN_FREE_VERTICES (0x50)

// Geometry of the stdControl axis table (stdControl_aAxisPos / stdControl_aJoysticks): device N's
// axes occupy [N * STDCONTROL_AXES_PER_JOYSTICK, +STDCONTROL_AXES_PER_JOYSTICK). The table is not a
// whole number of bands -- the last device's band is clipped by the table size.
#define STDCONTROL_NUM_AXIS_SLOTS (15)
#define STDCONTROL_AXES_PER_JOYSTICK (6)
// Stride of the joystick device records starting at stdControlJoystickDevice (0x9d dwords);
// the record's first field is the LPDIRECTINPUTDEVICEA.
#define STDCONTROL_JOYSTICK_RECORD_DWORDS (0x9d)
#define STDCONTROL_JOYSTICK_RECORD_SIZE (STDCONTROL_JOYSTICK_RECORD_DWORDS * 4)
// Joystick N's buttons (then hat directions) occupy stdControl_aKeyInfos
// [STDCONTROL_JOYSTICK_KEY_BASE + N * STDCONTROL_KEYS_PER_JOYSTICK, +STDCONTROL_KEYS_PER_JOYSTICK).
#define STDCONTROL_JOYSTICK_KEY_BASE (0x100)
#define STDCONTROL_KEYS_PER_JOYSTICK (0x20)
// Within a joystick's key band, hat directions follow the buttons, four per POV.
#define STDCONTROL_JOYSTICK_POV_KEY_BASE (0x10)
#define STDCONTROL_KEYS_PER_POV (4)
// Mouse buttons occupy stdControl_aKeyInfos[STDCONTROL_MOUSE_KEY_BASE + N].
#define STDCONTROL_MOUSE_KEY_BASE (0x200)
// Keyboard keys (DIK_* scancodes) occupy stdControl_aKeyInfos[0, STDCONTROL_NUM_KEYBOARD_KEYS).
#define STDCONTROL_NUM_KEYBOARD_KEYS (0x100)

// swrControl binding tables (swrControl_bindingsJoystick/Mouse/Keyboard): 64 bindings + terminator.
#define SWR_CONTROL_BINDINGS_PER_DEVICE (65)
#define SWR_CONTROL_BINDING_END (0xff)
// Per-action arrays (*ButtonPressedInput, the button-state array at swrControl_viewButton, hold times).
#define SWR_CONTROL_NUM_ACTIONS (15)
#define STDCONTROL_MOUSE_NUM_KEYS (4)
// Capacity of the DirectInputMouses / DirectInputKeyboards / DirectInputJoysticks record arrays.
#define STDCONTROL_MAX_MOUSE_DEVICES (4)
#define STDCONTROL_MAX_KEYBOARD_DEVICES (4)
#define STDCONTROL_MAX_JOYSTICK_DEVICES (8)
#define STDCONTROL_MAX_AXES (0x3c) // stdControl_aAxes capacity
// stdControl_EnableAxisRead: axes below this index turn on the joystick read.
#define STDCONTROL_NUM_JOYSTICK_AXES (0xc)
#define STDCONTROL_AXIS_MIN_VALUE (1e-05f) // stdControl_ReadAxis: |axis| at or below this reads 0 (0x004ae2d4)
#define STDCONTROL_MOUSE_AXIS_BASE (0x30) // stdControl_aAxes index of mouse X (Y, Z follow)
#define STDCONTROL_MOUSE_NUM_AXES (3)
#define STDCONTROL_AXIS_AS_KEY_THRESHOLD (0.5f) // stdControl_ReadAxisAsKeyEx: |axis| above this = pressed (0x004ae2d8)
#define STDCONTROL_MOUSE_X_EXTENT (250.0f) // stdControl_SetMouseRange (0x004ae2dc)
#define STDCONTROL_MOUSE_Y_EXTENT (200.0f) // (0x004ae2e0)
#define STDCONTROL_DEVICE_DATA_BUFFER_SIZE (0x20) // DIDEVICEOBJECTDATA events read per device per frame
#define STDCONTROL_JOYSTICK_NUM_BUTTONS (16) // DIJOYSTATE.rgbButtons entries mapped to keys
#define STDCONTROL_JOYSTICK_MAX_POVS (4)
// stdControl_ReadJoysticks: POV direction arcs, in hundredths of a degree
#define STDCONTROL_POV_45 (4500)
#define STDCONTROL_POV_135 (13500)
#define STDCONTROL_POV_225 (22500)
#define STDCONTROL_POV_315 (31500)
#define STDCONTROL_MOUSE_WHEEL_EXTENT (20) // stdControl_InitMouse: mouse Z axis range
#define STDCONTROL_JOYSTICK_DEADZONE (0.15f) // stdControl_InitJoysticks: RegisterAxis deadzone fraction for every stick axis
#define STDCONTROL_DIRECTINPUT_VERSION (0x0500) // stdControl_Startup requests DirectInput 5
#define STDCONTROL_MOUSE_SMOOTH_MAX_MS (25) // stdControl_ReadMouse averages X/Y with the previous read below this frame time
#define SWR_CONTROL_AXIS_STEER (2) // analog action index of swrRace_SteeringInput
#define SWR_CONTROL_BINDING_DIRECTION_MASK (0xf0) // swrControlBinding flags above the kind bits (POSITIVE/NEGATIVE/...)
#define SWR_CONTROL_SCAN_NONE (0xffff) // swrControl_ScanPressedButtons: nothing pressed
#define SWR_CONTROL_NUM_RESERVED_KEYS (16) // swrConfig_aControlKeyStrings entries
#define SWR_CONTROL_CAPTURE_JOYSTICK_AXIS_MIN (0.5) // swrControl_FindMovedAxis (0x004ac330)
#define SWR_CONTROL_CAPTURE_AXIS_MIN (0.1) // mouse axes (0x004ac338)
#define SWR_CONTROL_CAPTURE_AXIS_MIN_DELTA (0.05) // (0x004ac340)
#define SWR_CONTROL_WHEEL_ACCEPT_AXIS_MIN (0.1) // swrControl_PollAccept wheel throttle (0x004ac338)
#define SWR_UI_INPUT_STATE_DWORDS (11) // swrUI_inputChangeFlags block
#define SWR_CONTROL_ACTION_BRAKE (2) // action index of swrControl_brakeButton
#define SWR_CONTROL_ACTION_ROLL_LEFT (6)
#define SWR_CONTROL_ACTION_ROLL_RIGHT (7)
// swrControl_MappingsMenu element ids (keyboard/joystick/mouse settings pages)
#define SWR_UI_MAPPING_BUTTON_ACCEPT (2)
#define SWR_UI_MAPPING_BUTTON_BACK (4)
#define SWR_UI_MAPPING_BUTTON_DEFAULTS (0x25)
#define SWR_UI_MAPPING_BUTTON_UNDO (0x26)
#define SWR_UI_MAPPING_ROW_FIRST (0x27) // 10 digital actions x 2 binding slots
#define SWR_UI_MAPPING_ROW_ANALOG_BRAKE (0x3b) // then analog brake, roll, throttle, turn, pitch
#define SWR_UI_MAPPING_ROW_ANALOG_PITCH (0x3f)
#define SWR_UI_MAPPING_ROW_LAST (0x4b) // then pitch up/down, turn left/right x 3 binding slots
#define SWR_UI_MAPPING_BUTTON_RESERVED_KEYS (0x4c)
#define SWR_UI_MAPPING_DEADZONE_SLIDER (0x4d)
#define SWR_UI_MAPPING_SENSITIVITY_SLIDER (0x4e)
#define SWR_UI_MAPPING_TOGGLE_ENABLED (0x54)
#define SWR_UI_MAPPING_TOGGLE_FLIP_X (0x55) // then flip y, flip z
#define SWR_UI_MAPPING_RADIO_A_FIRST (0x30d43) // and 0x30d44
#define SWR_UI_MAPPING_RADIO_B_FIRST (0x30d45)
#define SWR_UI_MAPPING_RADIO_B_LAST (0x30d48)
#define SWR_UI_MAPPING_RADIO_A (0x30d52) // enables group B, disables group A
#define SWR_UI_MAPPING_RADIO_B (0x30d53)
#define SWR_CONTROL_ACTION_ESCAPE (10) // action fed by the fixed Esc keyboard binding stdConfFile_readAndApplyConf appends
#define SWR_CONTROL_NUM_ANALOG_ACTIONS (4) // *AxisInput arrays: throttle, unk, steer, pitch
#define SWR_CONTROL_NUM_RECORD_ACTIONS (16) // action bytes in inRaceLocalPlayerInputRecord (swrControl_inputRecordActions)
#define SWR_CONTROL_AXIS_DIGITAL_THRESHOLD (0.8f) // axis bound as a button with an AXIS_RANGE (0x3f4ccccd)
#define SWR_CONTROL_MOUSE_AXIS_DIGITAL_THRESHOLD (0.5f) // mouse axis bound as a button without an AXIS_RANGE
#define SWR_CONTROL_STEER_RECORD_SCALE (100.0f) // steer axes -> inRaceLocalPlayerInputRecord shorts (0x004ac328)
#define SWR_CONTROL_STEER_RECORD_MAX (0x100)
#define SWR_CONTROL_NUM_INPUT_RECORDS (4) // inRaceLocalPlayerInputRecord entries (one per local player)
// updateInRaceInputBitsets: record axis short -> [-1, 1] stick value, then digital thresholds.
#define SWR_CONTROL_RECORD_AXIS_SCALE (0.01f) // (0x004aca28)
#define SWR_CONTROL_RECORD_AXIS_FULL (0.3) // (0x004aca30 / 0x004aca38)
#define SWR_CONTROL_RECORD_AXIS_CENTER (0.2) // (0x004aca48 / 0x004aca40)
#define SWR_CONFIG_MAPPING_ROW_TRIMMED (0x3c) // swrConfig_SetMappingRowText: this row drops the first char of texts longer than 3
// swrControl_SetDefaultMappings: joystick default bindings stop at this many buttons when a hat is present.
#define SWR_CONTROL_DEFAULT_BUTTONS_WITH_POV (4)

// daAlloc arena allocator (stdMemory.c).
#define DAALLOC_PAGE_SIZE (0x7c00)       // bytes per arena page, malloc'd on demand
#define DAALLOC_ARENA_COUNT (0x421)      // number of daAlloc_struct arena slots (1057)
#define DAALLOC_SMALL_ALLOC_MAX (0x1000) // requests larger than this bypass the arena (daSmallAlloc)

// Save / profile persistence (elfSaveLoad, swrRace.c).
#define ELFSAVE_VERSION_MAGIC (0x10003) // 4-byte magic prefixed to tgfd.dat and .sav profile exports
#define ELFSAVE_NB_TRACKS (25) // tracks in the record tables (x2 slots each: normal + mirror)
#define ELFSAVE_RECORD_TIME_EMPTY (3599.99f) // record-slot default; at/above this the UI shows "--:--.---"
#define ELFSAVE_DEFAULT_PILOTS (0x22e01) // pilot-unlock bitfield of a fresh profile
#define ELFSAVE_DEFAULT_TRUGUTS (400) // starting currency of a fresh profile
#define ELFSAVE_NB_PROFILE_SLOTS (4) // swrSaveData::profiles
#define RDMODEL_SCENE_MAX_DEPTH (0x20) // rdModel_sceneNodeDepth past which transformed nodes skip the matrix-stack push
#define RDMODEL_ROOT_MAX_MESHES (6000) // swr_rootModel_ptr mesh pool (rdModel_rootGeoSet->aMeshes) and hierarchy-node pool
// Player-upgradeable PodHandlingData categories (traction..repair); also the number
// of garage stat bars swrRace_ComputeStatBars writes.
#define SWR_UPGRADE_CATEGORY_COUNT (7)
// swrObjJdge_ScrollCredits (0x0045d130): per-page line counts the EXE walks
#define SWR_CREDITS_PAGE1_LINES (0x49)
#define SWR_CREDITS_PAGE2_LINES (0x6f)
#define SWR_CREDITS_PAGE3_LINES (0x3b)
#define SWR_CREDITS_PAGE4_LINES (0xb1)
#define SWR_CREDITS_PAGE5_LINES (0x4b)
// swrRace_UpdatePartsHealth (0x0043d720): cap on one race's damage points (6 * 255)
#define SWR_PART_DAMAGE_MAX (0x5fa)

// swr_sceneModels slot of the first front-end holo-table model; swrObjHang_PositionHoloNode(n, ...)
// places slot SWROBJHANG_HOLO_MODEL_SLOT_BASE + n.
#define SWROBJHANG_HOLO_MODEL_SLOT_BASE (83)

#define SWR_CIRCUIT_COUNT (4)
#define SWR_TRACKS_PER_CIRCUIT (7)
// Hangar track-grid sprites: window id = BASE + circuit * SWR_TRACKS_PER_CIRCUIT + track,
// its selection frame at id + SELECT_OFFSET. swrObjHang_InitTrackSprites also resets the
// whitesquare sprite range [FIRST, END).
#define SWROBJHANG_TRACK_GRID_SPRITE_BASE (99)
#define SWROBJHANG_TRACK_GRID_SELECT_OFFSET (0x1c)
#define SWROBJHANG_WHITESQUARE_SPRITE_FIRST (0x82)
#define SWROBJHANG_WHITESQUARE_SPRITE_END (0xa2)
// swrRace human-input -> pod-control tuning (swrRace_UpdatePlayerControl @0x46bec0 /
// swrRace_CalcTargetTurnRate). Values read from the retail .rdata constant pool
// (0x004ad7xx..0x004ad9xx). Doubles are loaded as qword compares; floats as dword.
#define SWR_CTL_RAND_NORM (4.656612873e-10f) // 2^-31, normalizes swrUtils_Rand() to [0,1)
#define SWR_CTL_HALF (0.5f)                    // generic 0.5 (0x004ad774)
#define SWR_CTL_ONE (1.0f)                     // generic 1.0 (0x004ad7f4)
#define SWR_CTL_NEG_ONE (-1.0f)                // generic -1.0 (0x004ad80c)
#define SWR_CTL_HALF_HOLD (0.5)                // 0.5s button-hold threshold (0x004ad778, double)
#define SWR_CTL_NEG_HALF (-0.5)                // -0.5: slide+ easing step; idle-throttle pitch gate (0x004ad928, double)
#define SWR_CTL_STEER_DEADZONE (0.05f)         // |steer|/|pitch| below this -> turn target zeroed
#define SWR_CTL_STEER_SQUARE_GAIN (1.25f)      // pre-square gain on steer/pitch before squaring
#define SWR_CTL_STEER_SCALE (0.8f)             // steer/pitch output scale; also the analog pitch clamp
#define SWR_CTL_NEG_HALF (-0.5f)               // generic -0.5; dual-control mirrored steer scale + stick threshold (0x004ad8e0)
#define SWR_CTL_PITCH_HI (0.1f)                // pitch above this (nose down) trims turn rate/throttle (0x004ad76c)
#define SWR_CTL_PITCH_LO (-0.1f)               // pitch below this (nose up) trims turn rate/throttle (0x004ad770)
#define SWR_CTL_PITCH_TRIM (0.4f)              // pitch -> turn-rate and idle-throttle factor (0x004ad938)
#define SWR_CTL_PITCH_THROTTLE_TRIM (-0.4f)    // pitch -> throttle trim subtrahend (0x004ad940)
#define SWR_CTL_THROTTLE_SETTLE_MIN (0.3f)     // throttle above this (wallHitCooldown<=0) sets THROTTLE_SETTLED; dual-control throttle gate
#define SWR_CTL_ANALOG_THROTTLE_GAIN (1.176468f) // analog reverse/throttle remap gain (0x004ad920)
#define SWR_CTL_IDLE_SPEED (20.0)              // below this speed, idle throttle follows pitch*trim (0x004ad930, double)
#define SWR_CTL_SLIDE_SPEED (100.0f)           // slide2 easing speed threshold (0x004ad93c)
#define SWR_CTL_BRAKE_SETTLE_SPEED (70.0)      // braking below this speed also clears THROTTLE_SETTLED (0x004ad918, double)
#define SWR_CTL_BOOST_THROTTLE (0.6)           // throttle above this + boost input opens the boost window (0x004ad8c8, double)
#define SWR_CTL_BOOST_WINDOW (0.2)             // boost-start input timing window upper bound (0x004ad908, double)
#define SWR_CTL_BOOST_WINDOW_LO (0.0)          // boost-start window lower bound (0x004ad830, double)
#define SWR_CTL_BOOST_CANCEL_SPEED (290.0f)    // speed above which a pending boost-start is cancelled (0x004ad910)
#define SWR_CTL_BOOST_TAP_TIMEOUT (0.25)       // double-tap window for flame-attack / boost (0x004ad8d0, double)
#define SWR_CTL_FLAT_THROTTLE_FLOOR (1.2f)     // flags0 0x400000 overdrive: minimum throttle (0x004ad944)
#define SWR_CTL_DMG_PEN_GAIN (1.5f)            // engine-damage steering-penalty gain (0x004ad8f0)
#define SWR_CTL_DMG_PEN_LEFT (-0.2f)           // penalty offset when left engines are the damaged side (0x004ad8e8)
#define SWR_CTL_DMG_PEN_RIGHT (0.2f)           // penalty offset when right engines are the damaged side (0x004ad8ec)
#define SWR_CTL_DMG_STEER_PULL (-0.6f)         // damage penalty -> steer-pull factor; also dual-control brake pitch gate (0x004ad8e4)
#define SWR_CTL_FF_MAG_BASE (60.0f)            // damage force-feedback magnitude base (0x004ad8f8)
#define SWR_CTL_FF_MAG_SLOPE (-30.0f)          // damage force-feedback magnitude slope (0x004ad8f4)
#define SWR_CTL_SCRIPT5_LAP_MIN (0.063f)       // ai_track_script==5 scripted-zone lapComp bounds
#define SWR_CTL_SCRIPT5_LAP_MAX (0.072f)
#define SWR_CTL_SCRIPT6_LAP_MIN (0.093f)       // ai_track_script==6 scripted-zone lapComp bounds
#define SWR_CTL_SCRIPT6_LAP_MAX (0.108f)

// Asset buffer (swrScene_InitWorld @0x00449040): one allocation, held for the process, that every
// track model, spline and texture is read into. Retail's 8 MiB can be filled by a custom track
// alone, leaving no room for the pods; overrunning it spins forever in
// swrAssetBuffer_CheckOverflow. Sized from settings.ini ([settings] asset_buffer_mb), bounded
// below by retail because a smaller buffer would overflow where stock does not.
#define SWR_ASSET_BUFFER_SIZE_RETAIL (0x800000U) // 8 MiB, the size retail mallocs
#define SWR_ASSET_BUFFER_MB_DEFAULT (16) // used when settings.ini says nothing
#define SWR_ASSET_BUFFER_MB_MAX (256) // ceiling, so a typo can't request the unbackable

// swrSound_RegisterSound (0x004227e0): wavs with more PCM data than this are streamed from disk
#define SWR_SOUND_STREAM_THRESHOLD (0x81330)
#define SWR_SOUND_MASTER_GAIN_SCALE (32000.0f) // swrSound_SetMasterGain (0x004acb90)
#define SWR_SOUND_EVICT_HEADROOM (0x19000) // swrSound_LoadSound: extra bytes freed beyond the new sample
#define SWR_SOUND_EVICT_RECHECK_FRAMES (2) // swrSound_EvictSounds -> swrSound_evictRecheckFrames
#define SWR_SOUND_EVICT_MAX_WRAPS (2) // swrSound_EvictSounds restarts the bank scan at most this many times
#define SWR_SOUND_DEFAULT_BANK_SIZE (87) // swrSound_defaultBankFiles entries, allocated when sounds.map is missing
#define SWR_SOUND_HASHTABLE_SIZE (1200) // swrSound_Startup: buckets in swrSoundHashTable
#define SWR_SOUND_NUM_VOICES (8) // swrSound_voicesRequested entries
#define SWR_CAM_HALF_TURN (180.0f) // swrCam_CamState_ApplyToViewport angle unwrapping (0x004ac4fc)
#define SWR_CAM_FULL_TURN (360.0f) // (0x004ac500)
#define SWR_NUM_CAMERAS (32) // unkCameraArray entries
#define SWR_CAM_BLEND_DEFAULT_DURATION (10.0f) // swrCam_blendDuration after swrCam_CamState_InitMatrices
#define SWR_CAM_LOOKAHEAD_SCALE (40.0) // swrViewport_UpdateCameras behavior 4: look-ahead per |forward.z| (0x004ac510)
#define SWR_SOUND_VOLUME_SCALE (1.0f / 255.0f) // 0..255 volume byte -> gain (0x004ac474)
#define SWR_SOUND_GAIN_SCALE (32767.0f) // playASoundImpl: gain -> swrSound.volume (0x004ac484)
#define SWR_SOUND_LOOPING_PRIORITY (8) // playASoundImpl voice-steal priority of looping sfx
#define SWR_SOUND_PAN_POSITIONAL (-999) // swrSound.pan: 3D positional, use pos
#define SWR_SOUND_VOICE_GAIN_SCALE (3.051851e-05f) // swrSound.volume -> SetGain, ~1/32767 (0x004acba8)
#define SWR_SOUND_FADE_RATE (42666.666666666664) // swrSound_Update: volume units/s for voice fade-in/out (0x004acb98)
#define SWR_SOUND_REQUEST_FADE_RATE (64000.0) // swrSound_Update: volume units/s a released looping request fades by (0x004acbb0)
#define SWR_SOUND_MIN_PITCH (0.05) // swrSound_Update clamps pitch before SetPitch(2 * pitch) (0x004acbc8)
#define SWR_SOUND_RENDERMODE_NATIVE (0x20) // A3D source render mode: plain 2D/panned playback, no 3D positioning
#define SWR_SOUND_PAN_CENTER (0x40) // swrSound.pan forced in mono

// swrObjHang_SelectCreditsTracks (0x00440c10): length of the end-credits track playlist
#define SWR_CREDITS_TRACK_COUNT (5)

// swrRace_BuyPitdroidsMenu: truguts per extra pit droid
#define SWR_PITDROID_PRICE (1000)

// swrScores[] capacity (0x00e29bc0); swrObjHang_BuildRosterMultiplayer clears all of them
#define SWR_MAX_RACERS (20)
#define SWR_PLANET_COUNT (8) // swrPlanetTable entries
#define SWR_PLANET_OOVO_IV (6) // no suns/moons; spins 5x faster and keeps its rolled tilt
// swrObjJdge_InitTrack's asset-buffer tally assumes a 4 MiB buffer (swrObjJdge_raceBufferSlack)
#define SWR_RACE_BUFFER_TALLY_SIZE (0x400000)
// selectable pilots/pods: swrRacer_PodData[] / swrRacer_PodHandlingData[] entries
#define SWR_PILOT_COUNT (23)
#define SWR_PILOT_DUD_BOLT (10) // first-person camera pushed 3 units forward
#define SWR_PILOT_NEVA_KEE (14) // fused engines; low first-person camera, no binder

// swrRace_DrawScrollbar (0x0043fe90): arrow glow fade rate (alpha/sec) and its ceiling
#define SWR_SCROLLBAR_ARROW_FADE_RATE (838.2f)
#define SWR_SCROLLBAR_ARROW_ALPHA_MAX (254.0f)

// swrRace_UpdateFireEffects (0x0047e450): number of track flames (swrRace_FireTimer / FireLocation)
#define SWR_FIRE_EFFECT_COUNT (8)

// swrModel_clearSceneModelsAndChildren (0x00454cc0): swr_sceneModels slots below this survive a scene clear
#define SWR_SCENE_PERSISTENT_MODEL_SLOTS (5)
#define SWR_SCENE_MODEL_SLOT_COUNT (151)
#define SWRWEATHER_MAX_PARTICLES (80) // swrWeather_particle* array length; caps swrWeather_particleCap
// swrWeather_RenderParticles (0x0042cca0)
#define SWRWEATHER_SPAWN_CHANCE (0.7f) // a free slot respawns when rand01 is above this (0x004ac58c)
#define SWRWEATHER_SPAWN_SIDE_RANGE (800.0f) // +-400 along the camera's first basis row (0x004ac604 / 0x004ac5d0)
#define SWRWEATHER_SPAWN_SIDE_HALF (400.0f)
#define SWRWEATHER_SPAWN_FORWARD_RANGE (340.0f) // 10..350 along the second row (0x004ac608 / 0x004ac60c)
#define SWRWEATHER_SPAWN_UP_RANGE (190.0f) // 10..200 along the third row (0x004ac610)
#define SWRWEATHER_SPAWN_MIN_DIST (10.0f)
#define SWRWEATHER_SIZE_NUMERATOR (100.0f) // sprite size = this / depth (0x004ac5f4)
#define SWRWEATHER_SIZE_MIN (0.01f) // (0x004ac614)
#define SWRWEATHER_SIZE_SCALE (0.15f) // (0x004ac618)
#define SWRWEATHER_FAST_VELOCITY (100.0f) // velocityY above this caps the size at SWRWEATHER_FAST_SIZE_MAX
#define SWRWEATHER_FAST_SIZE_MAX (0.04f) // (0x004ac61c)
#define SWRWEATHER_MEDIUM_VELOCITY (300.0f) // (0x004ac620) -- compared after the fast case, so never reached
#define SWRWEATHER_MEDIUM_SIZE_MAX (0.1f) // (0x004ac5ec)
#define SWRWEATHER_SLOW_SIZE_MAX (0.15f)
#define SWRWEATHER_STREAK_MIN_PIXELS (3) // shorter streaks draw as a plain dot
#define SWRWEATHER_PAUSED_ALPHA_SCALE (0.5f) // (0x004ac568)
#define SWR_MINIMAP_MAX_DOTS (190) // miniMapPositions / miniMapDotTypes length
#define SWROBJHANG_MENU_SPRITE_COUNT (0xb8) // front-end sprite ids 0..0xb7, hidden by swrObjHang_F0 every frame

// swrObjHang_CullElmoAssets (0x0045ce90): size of the 'Elmo' event pool
#define SWR_SCENE_CMAN_COUNT (6) // 'cMan' objects swrScene_LoadObjects allocates
#define SWR_SCENE_FOG_START (996) // swrScene_LoadObjects front-end fog range
#define SWR_SCENE_FOG_END (1000)
#define SWR_SCENE_FIXED_CAMERA_COUNT (10) // swrScene_InitCameras: camera states fed by swrCam_fixedCameraMatrices
#define SWR_SCENE_CMAN_CAMERA_BASE (7) // first camera state taken over by a 'cMan' object
#define SWR_CAM_STATE_COUNT (32) // unkCameraArray entries
#define SWR_VIEWPORT_COUNT (4) // swrViewport_array entries
#define SWR_RENDER_DISPLAY_LIST_BYTES (80000) // one frame of swrRender_displayListArena (double-buffered by swrViewport_frameParity)
#define SWR_RENDER_MAX_CAMERA_POSITIONS (31) // swrPlayerHUD_RenderAllViewports bound on swrRender_cameraCount
#define SWR_ELMO_POOL_SIZE (60)
#define SWR_ELMO_NUM_WAYPOINTS (16) // swrObjElmo_waypoints entries scanned by swrObjElmo_GetWaypointIndex
#define SWR_ELMO_PIT_DROID_ANIM_WELD (20) // swrObjElmo_animFramesPitDroid entry of the welding loop (sparks + light flicker)
#define SWR_ENGINE_SFX_MAX_GEAR (3) // swrRace_engineGear range 0..3 (swrRace_PlayEngineSounds)
#define SWR_LZSS_WINDOW_SIZE (0x1000) // swrLoader_DecompressLZSS ring buffer, placed just before the input
#define SWR_MESH_MATERIAL_PROP_TEXTURE (2) // swrModel_MeshMaterialSetTexture property id
#define SWR_SPLINE_MAX_SEGMENTS (250) // swrSpline_Build skips larger splines; size of its progress-order table

// swrAssetBuffer_ResetToIndex (0x00445aa0): highest asset-buffer checkpoint index
#define SWR_ASSET_BUFFER_MAX_INDEX (9)
#define SWR_ASSET_BUFFER_REGION_A_SIZE (0x4b000) // swrAssetBuffer_ReserveRegionA_Maybe, plus 0x40 alignment slack
#define SWR_ASSET_BUFFER_REGION_B_SIZE (0x10000) // swrAssetBuffer_ReserveRegionB_Maybe, plus 0x40 alignment slack
// swrModel_LoadTextureDataAndPalette: pixel data and palette each start on a 64-byte boundary;
// the free-space check reserves room for both alignment pads
#define SWR_TEXTURE_DATA_ALIGN (64)
#define SWR_TEXTURE_LOAD_HEADROOM (0x80)
// swrModel_RegisterRootMaterial (0x00408fb0): swrModel3_root_materials entries (0x2000-byte block)
#define SWR_ROOT_MATERIAL_CAPACITY (0x800)

// swrConfig_ControlToString (0x00407b00): DIK scan code -> GetKeyNameText lParam bits 16..24
#define SWR_DIK_EXTENDED_BIT (0x80)
#define SWR_DIK_SCANCODE_MASK (0x7f)
#define WINDOW_KEY_SCANCODE_EXT_MASK (0x1ff) // WM_KEY* lParam high word: 8-bit scan code + extended-key bit
#define SWR_TEXTURE_BUFFER_SIZE (1700) // texture_buffer entries; swrAssetBuffer_InvalidateTexturesBelow scans them all

// swrObjHang_SetState5_Maybe (0x004337d0): frames swrRace_AnimateDisplayPod spends in its reset path after a scene load
#define SWR_DISPLAY_POD_RESET_FRAMES (5)

// swrRace_ComputeUpgradePrices (0x0043eb50): float32 at 0x004ac9d8, -1/255 rounded toward zero
#define SWR_UPGRADE_PRICE_HEALTH_SCALE (-0.0039215684f)

// swrRace.partNodes layout used by swrRace_ResetModelNodeFlags (0x0046d4c0)
#define SWR_POD_PART_NODE_COUNT (75)
#define SWR_POD_PART_SHADOW_FIRST (0x3d)
#define SWR_POD_PART_SHADOW_LAST (0x40)
#define SWR_PODD_CABLE_SIN_LUT_SIZE (64) // poddConnectionMesh_sinLookupTable entries (one sine period)
#define SWR_POD_TRANSFORM_HISTORY (18) // swrRace.transformHistory ring size (PoddAnimateEngines)
#define SWR_POD_MODEL_UNIT_SCALE (0.004f) // pod model units -> world (shadow quads, cable width, debug model)

// LoadUpgradeModelsIntoScene_Maybe (0x0043e840)
#define SWR_UPGRADE_LEVEL_COUNT (6) // levels per upgrade type; upgradeInfos index = type * 6 + level
#define SWR_SHOP_STARTING_TRACKS (3) // unlocked tracks a new profile starts with; not counted toward shop unlocks
#define SWR_SCENE_SLOT_SHOP_PARTS (0x62) // swr_sceneModels slot of the first shop/junkyard part model
#define SWR_SCENE_SLOT_TRACK_PREVIEWS (0x62) // holotable track models, one per track id (DrawTrackPreview); same slots as the shop parts
#define SWR_SCENE_SLOT_INSTALLED_PARTS (0x8e) // swr_sceneModels slot of the first installed part model

// swrObjHang_LoadScreenAssets (0x004586e0): swr_sceneModels / puppet slots of the hangar scenes
#define SWR_SCENE_SLOT_POD_MODELS (0xf) // pod models, one per local player; header entry 0x3c holds the pilot id
#define SWR_SCENE_POD_PILOT_ENTRY (0x3c)
#define SWR_SCENE_SLOT_PILOT_PUPPETS (0x1c) // pilot puppets, one per local player / podium place; also their elmo ids
#define SWR_SCENE_SLOT_HANGAR_DROIDS (0x38) // .. 0x3a: the three hangar pit droids (elmo ids match)
#define SWR_HANGAR_DROID_COUNT (3)
#define SWR_SCENE_SLOT_PIT_DROIDS (0x34)
#define SWR_SCENE_SLOT_SHADOW_CIRCLES (0x7)
#define SWR_SCENE_SLOT_SHADOW_SQUARES (0xb)
#define SWR_SCENE_SLOT_AWARD_PLATFORMS (0x4d)
#define SWR_SCENE_SLOT_CANTINA_PILOT (0x38)
#define SWR_SCENE_SLOT_CANTINA_GUEST (0x39)
#define SWR_MAX_PIT_DROIDS (4)

// swrObjHang_UpdateLookAtVehicle (0x00437f70)
#define SWROBJHANG_DISPLAY_POD_STRIDE (0x28) // bytes between per-player swrObjHang_displayPodPos entries
#define SWR_SCENE_SLOT_LOOK_AT_PROPS (0x55) // .. 0x58: four props the look-at-vehicle screen lays out beside the pod
#define SWR_LOOK_AT_PROP_COUNT (4)
#define SWR_PIT_DROID_NODE_CHAIN_LEN (10) // swrObjHang_pitDroidNodeChains entries per droid (= FindClosestPointOnModel depth)
#define SWR_PIT_DROID_SPOT_TRIES (20) // extra re-rolls of an engine-spot point that lands too low
#define SWR_POD_ENTRY_ENGINE_R (1) // pod-model header entries the pit droids frame (5 when the entry is empty)
#define SWR_POD_ENTRY_ENGINE_L (2)
#define SWR_POD_ENTRY_ENGINE_FALLBACK (5)
#define SWR_POD_ENTRY_COCKPIT (5)
#define SWR_POD_ENTRY_SURFACE_A (0x11) // surface entries searched with ENGINE_R / ENGINE_L (0x2d when that entry is empty)
#define SWR_POD_ENTRY_SURFACE_B (0x1f)
#define SWR_POD_ENTRY_SURFACE_FALLBACK (0x2d)
#define SWR_POD_ENTRY_COCKPIT_SURFACE (0x2d)
#define SWR_CANTINA_PILOT_POOL (0x7ffff) // pilots 0..18; the cantina guest is a pit droid once any is unlocked

// swrObjHang_NavigateVehicleSelect (0x00469c30): held left/right auto-repeat
#define SWR_MENU_REPEAT_DELAY (0.6f) // seconds before the first repeat
#define SWR_MENU_REPEAT_INTERVAL (0.1f) // repeat interval once repeating, divided by the speed arg
#define SWR_MENU_SLIDE_RATE (3.3f) // swrRace_Transition rate (x speed) for the left/right slide

// swrObjHang_LayoutVehicleSelectIcons (0x0045a840)
#define SWR_SHOP_LIST_CAPACITY (35) // uiUpgradeInfos2 entries
#define SWR_HANGAR_ICON_COUNT (8) // uiUpgradeInfos entries
#define SWR_JUNKYARD_SLOT_COUNT (16) // swrObjHang_junkyardStock entries
#define SWR_JUNKYARD_PLACEMENT_FIRST (4) // maybeUICameraPlacements row of junkyard slot 0
#define SWR_JUNKYARD_PART_COUNT (7) // parts swrObjHang_GenerateJunkyardStock scatters over the slots

// swrRace_UpdatePartMenuLayout (0x0043dba0): part-icon glide duration (seconds)
#define SWR_PART_LERP_TIME (0.2f)
#define SWR_PART_LERP_TIME_CAMERA_MOVE (0.5f) // while a front-end camera move is running

// swrObjHang_UpdateWattoShop (0x004376c0)
#define SWR_PIT_DROID_PRICE (1000)
#define SWR_ELMO_ID_PIT_DROID_BASE (0x33) // elmo id of pit droid n (1-based) = base + n
#define SWR_SHOP_SWING_PHASE_RATE (50.0f) // swrObjHang_shopSwingPhase gain per second while scrolling
#define SWR_SHOP_SWING_PHASE_MAX (1.5f)
#define SWR_SHOP_SWING_LEAN_RATE (5.5f)

// swrRace_UpdateStatPartModels (0x00455dc0): part model scales
#define SWR_PART_ICON_SCALE (0.05f) // part icons on the shop ring / junkyard / hangar wall
#define SWR_PART_DETAIL_SCALE (0.010000001f) // the selected part while its detail view is open or closing
#define SWR_PART_INSTALLED_PREVIEW_SCALE (0.004f) // the installed part shown beside it for comparison

// swrRace_DrawStatBar (0x004557e0): first garage stat-bar sprite id
#define SWR_STAT_BAR_SPRITE_BASE (0x90)
#define SWR_SPRITE_ID_SUN_GLARE (-0x68) // pseudo sprite id swrSprite_SetVisible/SetColor route to the full-screen sun glare tint (swrSprite_unk2_*)
#define SWR_SUN_OCCLUDED_COVERAGE (50) // UpdateSunAndLensFlareSprites2: sun_occlusionCoverage at or above this hides the sun and its flares
// swrPlayerHUD_SampleOcclusion (0x0042be60)
#define SWR_SUN_COUNT (2) // sunSpriteIds / sun_occlusionSample* entries
#define SWR_SUN_OFFSCREEN_X (-500) // sun_occlusionSampleX below this = sun not projected this frame
#define SWR_SUN_OCCLUSION_SAMPLE_SIZE (8) // z-buffer square sampled around each sun
#define SWR_HUD_NO_DEPTH (-1000.0f) // depth stored for a marker with no on-screen sample
#define SWR_HUD_PLAYER_SPRITE_COUNT (20) // player_sprite_* entries
#define SWR_HUD_LIGHT_STREAK_COUNT (40) // light_streak_* entries
// in-race engine damage panel (swrRace_InRaceEngineUI): 6 part icons + 2 brackets per local player
#define SWR_HUD_ENGINE_SPRITE_FIRST (0x1b)
#define SWR_HUD_ENGINE_BRACKET_LEFT (0x21)
#define SWR_HUD_ENGINE_BRACKET_RIGHT (0x22)
#define SWR_HUD_ENGINE_SPRITE_P2_OFFSET (8) // local player 2 uses 0x23..0x2a

// swrMultiplayer chat overlay (0x0041e800 AddChatMessage, 0x0041e880 TickRacerListOverlay)
#define SWR_MP_CHAT_LINE_COUNT (15) // swrMultiplayer_chatLines entries
#define SWR_MP_CHAT_LINE_LIFETIME_MS (10000)
#define SWR_MP_CHAT_LINE_SPACING (15) // pixels between overlay lines
#define SWR_MP_CHAT_INPUT_SIZE (0x400) // swrMultiplayer_chatInput bytes
#define SWR_MP_CHAT_INPUT_PREFIX_LEN (4) // "~F0]" font/colour prefix ahead of the typed text
#define SWR_MP_CHAT_VISIBLE_LINES (6) // rows shown by the lobby chat list before it scrolls
#define SWR_MP_CHAT_TEXT_MAX (0x80) // chat text length cap in swrMultiplayer_ApplyChat
#define SWR_UI_ID_MP_CHAT_LIST (0x186b4) // lobby chat list widget
// multiplayer menu elements (swrMultiplayer_Build*UI)
#define SWR_UI_ID_MP_HOST_BUTTON (0x186a6)
#define SWR_UI_ID_MP_JOIN_BUTTON (0x186a7)
#define SWR_UI_ID_MP_CREATE_PLAYER_NAME (0x186ac)
#define SWR_UI_ID_MP_CREATE_GAME_NAME (0x186ad)
#define SWR_UI_ID_MP_CREATE_PASSWORD (0x186ae)
#define SWR_UI_ID_MP_JOIN_PLAYER_NAME (0x186af)
#define SWR_UI_ID_MP_JOIN_PASSWORD (0x186b1)
#define SWR_UI_ID_MP_GAME_LIST (0x186b2) // join page: sessions found
#define SWR_UI_ID_MP_PLAYER_LIST (0x186b3) // race setup: connected players
#define SWR_UI_ID_MP_RETIRE (0x186b6)
#define SWR_UI_ID_MP_RACER_NAME (0x186b9) // race setup: selected player's pod name
#define SWR_UI_ID_MP_TRACK_NAME (0x186ba)
#define SWR_UI_ID_MP_CHAT_ENTRY (0x186bb)
#define SWR_UI_ID_MP_TRACKS (0x7d)
#define SWR_UI_ID_MP_PODRACER (0x7e)
#define SWR_UI_ID_MP_BOOT (0x80)
#define SWR_UI_ID_MP_LAPS (0x8b)
#define SWR_UI_ID_MP_RESULTS_LIST (0x30d42) // racer-list page
#define SWR_UI_ID_MP_SETUP_TAB (0x30d54) // race setup: 3-patch title tab
#define SWR_UI_ID_OK_BUTTON (2) // swrUI_AddOkButton
#define SWR_UI_ELEMENT_HASH_BUCKETS (0x100) // swrUI_elementHashtable_Maybe
// swrUI_Initialize (0x00410fd0): CPU benchmark that disables page transitions on slow machines
#define SWR_UI_BENCH_INNER_LOOPS (2500)
#define SWR_UI_BENCH_TICKS (30) // runs until more than this many timer ticks pass
#define SWR_UI_BENCH_SCALE (0.0004f) // 0x004ac3d8
#define SWR_UI_BENCH_MIN_SCORE (20.0f) // 0x004ac3dc
#define SWR_UI_ID_BACK_BUTTON (4)
// main menu (swrUI_Menu_Main)
#define SWR_UI_ID_MAIN_FREEPLAY (0xc)
#define SWR_UI_ID_MAIN_MULTIPLAYER (0xd)
#define SWR_UI_ID_MAIN_TOURNAMENT (0xe)
#define SWR_UI_ID_MAIN_SETTINGS (0xf)
#define SWR_UI_ID_MAIN_QUIT (0x10)
#define SWR_UI_ID_MAIN_COPYRIGHT (1)
#define SWR_UI_ID_DEV_PHOTO_NAME_FIRST (10000) // developer-photo name labels, shown instead of the menu
#define SWR_UI_DEV_PHOTO_NAME_COUNT (0x1a)
// settings hub (swrUI_Menu_SettingsHub)
#define SWR_UI_ID_SETTINGS_VIDEO (0x1d)
#define SWR_UI_ID_SETTINGS_AUDIO (0x1e)
#define SWR_UI_ID_SETTINGS_JOYSTICK (0x1f)
#define SWR_UI_ID_SETTINGS_MOUSE (0x20)
#define SWR_UI_ID_SETTINGS_KEYBOARD (0x21)
#define SWR_UI_ID_SETTINGS_FORCE_FEEDBACK (0x22)
#define SWR_UI_ID_SETTINGS_LOAD_SAVE (0x23)
// file-list pages (config files, player profiles)
#define SWR_UI_ID_FILE_NAME_ENTRY (0x2731)
#define SWR_UI_ID_FILE_LIST (0x2732)
#define SWR_UI_ID_FILE_LIST_ITEM (0x2733)
#define SWR_UI_ID_FILE_SAVE (0x2734)
#define SWR_UI_ID_FILE_LOAD (0x2735)
#define SWR_UI_ID_FILE_REMOVE (0x2738)
#define SWR_UI_ID_CURRENT_PLAYER_LABEL (0x273a)
#define SWR_UI_ID_PROFILE_CREATE (0x2737) // profile select: CREATE RACER
#define SWR_UI_ID_PROFILE_NAV (0x2748) // profile select: back nav button
#define SWR_UI_ID_PROFILE_SELECT_UNUSED (0x2739) // profile select: handled like OK, but no element is built with it
#define SWR_CONTROL_AXIS_Z (2) // bit index in swrControl_{joystick,mouse}AxisMask: device has a Z axis
#define SWR_UI_DIALOG_MIN_BUTTON_WIDTH (0x96) // swrUI_NewDialog
#define SWR_UI_DIALOG_RESULT_CANCEL (0xffff) // swrUI_confirmDialogResult after Back/Escape
#define SWR_UI_CONFIG_NAME_MAX_LENGTH (0x18) // settings-file name entry (swrRace_LoadSaveConfigMenu)
// clickable arrow sprites on the hangar nav-overlay pages (swrUI_BuildAuxPages); a click injects the matching swrUI_INPUT_MENU_* bit
#define SWR_UI_ID_HANGAR_VEHICLE_ARROW_LEFT (700000)
#define SWR_UI_ID_HANGAR_VEHICLE_ARROW_RIGHT (700001)
#define SWR_UI_ID_HANGAR_PLANET_ARROW_LEFT (700002)
#define SWR_UI_ID_HANGAR_PLANET_ARROW_RIGHT (700003)
#define SWR_UI_ID_HANGAR_PLANET_ARROW_UP (700004)
#define SWR_UI_ID_HANGAR_PLANET_ARROW_DOWN (700005)
#define SWR_UI_ID_HANGAR_WATTO_ARROW_LEFT (700006)
#define SWR_UI_ID_HANGAR_WATTO_ARROW_RIGHT (700007)
#define SWR_UI_ID_HANGAR_JUNKYARD_ARROW_LEFT (700008)
#define SWR_UI_ID_HANGAR_JUNKYARD_ARROW_RIGHT (700009)
#define SWR_UI_TEXT_ENTRY_STYLE_MASK (0xffff0000) // flag bits swrUI_NewTextEntry keeps as entry_style
#define SWR_UI_TEXT_ENTRY_MAX_LENGTH (0x400)
#define SWR_UI_TEXT_FLAGS_MASK (0xffff0000) // ctor flag bits swrUI_NewButton / swrUI_NewScreenText keep as text_flags
#define SWR_UI_FRAMED_TEXT_VALUE_MASK (0xff) // flags2 low byte: explicit radio option value
#define SWR_UI_MAX_TIMERS (10) // swrUI_timers slots (0x004d8160..0x004d8200)
#define SWR_UI_CARET_SPRITE_ID (0xfa)
#define SWR_UI_DESIGN_WIDTH (640) // UI design space the swrText clip rects are given in
#define SWR_UI_DESIGN_HEIGHT (480)

// swrDisplay_SetSettingsFromRegistry (0x00424180): registry fallbacks + the only bpp FindMatchingVideoMode accepts
#define SWR_DISPLAY_DEFAULT_WIDTH (640)
#define SWR_DISPLAY_DEFAULT_HEIGHT (480)
#define SWR_DISPLAY_BPP (16)
#define SWR_RGB555_RED_MASK (0x7c00) // back-buffer pixel format that gets the Smush RGB565 -> RGB555 table
#define SWR_RGB555_GREEN_MASK (0x3e0)
#define SWR_RGB555_BLUE_MASK (0x1f)
#define SWR_SMUSH_VIDEO_WIDTH (640) // Smush cinematic frame size (Window_PlayCinematic)
#define SWR_SMUSH_VIDEO_HEIGHT (480)
#define SWR_SMUSH_VIDEO_ASPECT (0.75f) // height / width (0x004ac448)
#define SWR_SMUSH_VIDEO_ASPECT_INV (1.3333334f) // width / height (0x004b7a40)
#define SWR_SMUSH_MAX_VOLUME (127)
#define SWR_SMUSH_PLAY_FLAGS (0xf)
#define SWR_SMUSH_FRAME_RATE_SCALE (1000000)
#define WINDOW_CD_PLANETG_ZNM_SIZE (0x11214e7) // byte size of \Data\Anims\PlanetG.znm on the install CD (Window_CDCheck)

// swrSprite_GetTextureFromTGA (0x004114d0)
#define SWR_TGA_HEADER_SIZE (18)
#define SWR_TGA_IMAGE_TYPE_RLE_FIRST (9) // image types 9..11 are run-length encoded
#define SWR_UI_PAGE_TRANSITION_STAGGER (250) // swrUI_StartPageTransition: per-child delay of the vertical drop
#define SWR_TEXT_MAX_ENTRIES (128) // swrTextEntries1* capacity
#define SWR_TEXT_BBOX_RESET (1000) // swrText_RenderString: bbox min/max start at +/- this (empty)
#define SWR_FONT_PAGE_WIDTH (64) // swrText_InitFonts: glyph-page texture size
#define SWR_FONT_PAGE_HEIGHT (128)
#define SWR_FONT_SLOT_COUNT (7) // swrText_fontsByIndex entries
#define SWR_TEXT_PAGE_NONE (-2) // swrText_DrawString: glyph absent, never matches a pass
#define SWR_TEXT_PAGE_NO_ACCENT (-5) // swrText_DrawString: character has no accent glyph
#define SWR_UI_DISABLED_TEXT_ALPHA (100) // swrUI_DrawText alpha for disabled elements
#define SWR_UI_FONT_LOW_BASELINE (6) // swrUI_DrawText draws font 6 this many pixels lower
#define SWR_UI_LIST_MAX_ITEMS (200) // swrUI_RefreshListLayout frees the oldest items beyond this
#define SWR_UI_CARET_BLINK_MS (250)
#define SWR_SCANCODE_MINUS (0x0c) // '-' key, also accepted by swrUI_HandleSliderKey
#define SWR_SCANCODE_EQUALS (0x0d) // '=' / '+' key
#define SWR_UI_CARET_WIDE_SCREEN_WIDTH (512) // the caret is stretched 1.25x at this screen width
#define SWR_UI_FRAME_NATIVE_SCREEN_WIDTH (640) // panel/frame edges are widened by two edge sprites at any other width
#define SWR_HUD_WORLD_SPRITE_MAX_DIST (1500.0f)
#define SWR_HUD_RACER_LABEL_NONE (-9999) // player_sprite_unknown_values: no label for this slot
#define SWR_HUD_RACER_LABEL_MIN_DIST (40.0f) // swrPlayerHUD_RenderDistanceText: hidden closer than this
#define SWR_HUD_RACER_LABEL_FADE_DIST (400.0f) // fades out from here to SWR_HUD_WORLD_SPRITE_MAX_DIST
#define SWR_HUD_RACER_LABEL_FADE_SCALE (0.000909090915f) // 1 / (1500 - 400)
#define SWR_HUD_RACER_LABEL_MAX_ALPHA (128.0f)

// swrObjTest_F4 'Hitt' event (0x00474d80)
#define SWR_OBJTEST_HIT_LOG_SIZE (8) // swrObjTest_hitKindLog / swrObjTest_hitAmountLog ring entries
#define SWR_POD_HIT_SOUND_MAX_LOD (500) // impact sound / rumble only while swrRace.lodDistance is below this

// swrControl force feedback (0x00409d70 LoadForceEffects .. 0x0040b5e0 UpdateImpactForceEffect)
#define SWR_FF_EFFECT_SLOTS (6) // cifr_EffectSet.slots
#define SWR_FF_DEVICE_NONE (9) // swrControl_forceEffectsDeviceType: no bundle loaded; valid device types are 0..8

// swrSprite_AddDirtyRect (0x00484020)
#define SWR_SPRITE_DYNAMIC_FIRST (251) // swrSprite_FindFreeId: dynamic ids sit above the named/static sprites
#define SWR_SPRITE_DYNAMIC_END (399)
#define SWR_SPRITE_MAX_DIRTY_RECTS (31) // swrSprite_dirtyRects holds 31 x {x1,y1,x2,y2}
#define SWR_SPRITE_TEXEL_STEP_ONE (0x400) // swrSprite_Draw1 texel step of exactly one texel per pixel (1/1024 units), used on clamped axes
#define SWR_SPRITE_PAGE_CURSOR_START (9000) // swrSprite_Draw1: initial far page edge, so the first page always starts a new row
#define SWR_SPRITE_DIRTY_RECT_REF_WIDTH (320.0) // rects are scaled by screen size / 320x240
#define SWR_SPRITE_DIRTY_RECT_REF_HEIGHT (240.0)

// swrMultiplayer_PublishPodState (0x0041d930)
#define SWR_MP_PARKED_POD_Z (-9000.0f) // 0xc60ca000: z an AI pod waits at before it joins
#define SWR_MP_POD_STATUS_PARKED (666) // swrMultiplayer_aPodStatus[slot][0] of a parked AI pod
#define SWR_MP_POD_STATE_RECORD_INTS (28) // ints per pod record in the player-states message (swrMultiplayer_ApplyPlayerStates)
#define SWR_MP_NO_SLOT (111111) // 0x1b207: 'none found' sentinel of swrMultiplayer_SendRejoin / lowestLostSlot
#define SWR_MP_WIRE_NAME_LEN (15) // name characters sent per string in the player name/list/join messages
#define SWR_UI_RACE_RESULT_RETIRED (666) // swrUI_unk::sort_key of a retired racer's result row

// sithMulti guaranteed-send queue (sithMulti_aPendingMessages)
#define SITH_MULTI_MAX_PENDING_MESSAGES (32) // 0x10500 bytes cleared by sithMulti_ResetCallbackState / 0x828

// swrModel_NodeSelectLOD (0x004827b0): LOD picked as if viewed from this fixed distance (0x004ae078)
#define SWR_MODEL_LOD_SELECT_DISTANCE (20.0f)
#define SWR_MODEL_LOD_MAX (8) // swrModel_NodeLODSelector.lod_distances length
// swrModel_PointInTriangle2 (0x00480a70): degenerate-cross thresholds on |x|+|y|+|z|
#define SWR_MODEL_TRI_CROSS_EPS (1e-4f) // 0x004adfbc
#define SWR_MODEL_TRI_ON_EDGE_EPS (0.001f) // 0x004adfc8
// swrModel_FindClosestPointOnModel (0x00482c40)
#define SWR_MODEL_CLOSEST_POINT_MAX_DEPTH (20) // swrModel_closestPointNodeStack length (maxNodeDepth clamp)
#define SWR_MODEL_CLOSEST_POINT_START_DIST_SQ (100000000.0f) // initial minDistSq (0x4cbebc20)

// sithMessage_SendMessage idTo that sithMessage_NetWrite fans out to every active player
#define SITH_MESSAGE_TO_ALL ((DPID)0xffffffff)

// rdMaterial texture filters (0x00431cf0..0x004320b0): 16-bit texel channel masks
#define RD_TEXEL_4444_ALPHA_MASK (0xf000)
#define RD_TEXEL_4444_COLOR_MASK (0x0fff)
#define RD_TEXEL_5551_ALPHA_MASK (0x8000)
// rdMaterial_LoadEntry (0x0048e6d0)
#define RD_MATERIAL_FILE_REVISION (0x32) // rdMaterialHeader.revision accepted

// rdPuppet_BuildJointMatrices (0x00493310)
#define RDPUPPET_MAX_TRACKS (8) // RdPuppet::aTracks length

// rdModel_ConvertSwrModelMesh (0x00432d30)
#define RDMODEL_CONVERT_MAX_FACES (2047) // stack face array, fills the 0x2404c-byte frame
#define N64_CCMUX_PRIMITIVE (3) // swrModel_Material combine-mode mux byte selecting the primitive color

// DirectDraw/Direct3D enumeration tables (DirectDraw_EnumDisplayModes_Callback, Direct3d_Enum*_Callback)
#define STD_DISPLAY_MAX_VIDEO_MODES (64) // stdDisplay_aVideoModes length
#define STD_DISPLAY_MAX_DEVICES (16) // stdDisplay_aDisplayDevices length
#define STD3D_MAX_DEVICES (4) // std3D_aDevices length
#define STD3D_MAX_TEXTURE_FORMATS (8) // std3D_aTextureFormats length

// stdComm DirectPlay session/player tables
#define STDCOMM_MAX_SESSIONS (32) // stdCommSessionSettings length
#define STDCOMM_MAX_CONNECTIONS (16) // stdComm_Connections length
#define STDCOMM_RECV_MAX_SIZE (0x804) // bytes sithMulti_HandleIncomingPacket receives (tSithMessage from callbackId)
#define SWR_MP_SEEN_MESSAGE_COUNT (128) // swrMultiplayer_aSeenMessages ring length
#define STDCOMM_MAX_PLAYERS (20) // stdComm_aPlayerInfos length

#endif // ENGINE_CONFIG_H
