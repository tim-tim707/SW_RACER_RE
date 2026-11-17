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
// Joystick N's buttons (then hat directions) occupy stdControl_aKeyInfos
// [STDCONTROL_JOYSTICK_KEY_BASE + N * STDCONTROL_KEYS_PER_JOYSTICK, +STDCONTROL_KEYS_PER_JOYSTICK).
#define STDCONTROL_JOYSTICK_KEY_BASE (0x100)
#define STDCONTROL_KEYS_PER_JOYSTICK (0x20)

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
#define SWR_SOUND_DEFAULT_BANK_SIZE (87) // swrSound_defaultBankFiles entries, allocated when sounds.map is missing
#define SWR_SOUND_HASHTABLE_SIZE (1200) // swrSound_Startup: buckets in swrSoundHashTable

// swrObjHang_SelectCreditsTracks (0x00440c10): length of the end-credits track playlist
#define SWR_CREDITS_TRACK_COUNT (5)

// swrRace_DrawScrollbar (0x0043fe90): arrow glow fade rate (alpha/sec) and its ceiling
#define SWR_SCROLLBAR_ARROW_FADE_RATE (838.2f)
#define SWR_SCROLLBAR_ARROW_ALPHA_MAX (254.0f)

// swrRace_UpdateFireEffects (0x0047e450): number of track flames (swrRace_FireTimer / FireLocation)
#define SWR_FIRE_EFFECT_COUNT (8)

// swrModel_clearSceneModelsAndChildren (0x00454cc0): swr_sceneModels slots below this survive a scene clear
#define SWR_SCENE_PERSISTENT_MODEL_SLOTS (5)
#define SWR_SCENE_MODEL_SLOT_COUNT (151)

// swrObjHang_CullElmoAssets (0x0045ce90): size of the 'Elmo' event pool
#define SWR_ELMO_POOL_SIZE (60)

// swrAssetBuffer_ResetToIndex (0x00445aa0): highest asset-buffer checkpoint index
#define SWR_ASSET_BUFFER_MAX_INDEX (9)
#define SWR_TEXTURE_BUFFER_SIZE (1700) // texture_buffer entries; swrAssetBuffer_InvalidateTexturesBelow scans them all

// swrObjHang_SetState5_Maybe (0x004337d0): frames swrRace_AnimateDisplayPod spends in its reset path after a scene load
#define SWR_DISPLAY_POD_RESET_FRAMES (5)

// swrRace_ComputeUpgradePrices (0x0043eb50): float32 at 0x004ac9d8, -1/255 rounded toward zero
#define SWR_UPGRADE_PRICE_HEALTH_SCALE (-0.0039215684f)

// swrRace.partNodes layout used by swrRace_ResetModelNodeFlags (0x0046d4c0)
#define SWR_POD_PART_NODE_COUNT (75)
#define SWR_POD_PART_SHADOW_FIRST (0x3d)
#define SWR_POD_PART_SHADOW_LAST (0x40)

// LoadUpgradeModelsIntoScene_Maybe (0x0043e840)
#define SWR_UPGRADE_LEVEL_COUNT (6) // levels per upgrade type; upgradeInfos index = type * 6 + level
#define SWR_SHOP_STARTING_TRACKS (3) // unlocked tracks a new profile starts with; not counted toward shop unlocks
#define SWR_SCENE_SLOT_SHOP_PARTS (0x62) // swr_sceneModels slot of the first shop/junkyard part model
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

// swrMultiplayer chat overlay (0x0041e800 AddChatMessage, 0x0041e880 TickRacerListOverlay)
#define SWR_MP_CHAT_LINE_COUNT (15) // swrMultiplayer_chatLines entries
#define SWR_MP_CHAT_LINE_LIFETIME_MS (10000)
#define SWR_MP_CHAT_LINE_SPACING (15) // pixels between overlay lines
#define SWR_MP_CHAT_INPUT_SIZE (0x400) // swrMultiplayer_chatInput bytes
#define SWR_MP_CHAT_INPUT_PREFIX_LEN (4) // "~F0]" font/colour prefix ahead of the typed text
#define SWR_MP_CHAT_VISIBLE_LINES (6) // rows shown by the lobby chat list before it scrolls
#define SWR_UI_ID_MP_CHAT_LIST (0x186b4) // lobby chat list widget

#endif // ENGINE_CONFIG_H
