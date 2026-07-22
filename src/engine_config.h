#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#define RDCACHE_MAX_VERTICES (0x14000U) // something wrong with references
#define RDCACHE_MAX_TRIS (0x400)
// Free vertex-pool headroom rdCache_GetProcEntry keeps in reserve so the
// worst-case single face returned by it always fits before the next flush.
#define RDCACHE_MIN_FREE_VERTICES (0x50)

// daAlloc arena allocator (stdMemory.c).
#define DAALLOC_PAGE_SIZE (0x7c00)       // bytes per arena page, malloc'd on demand
#define DAALLOC_ARENA_COUNT (0x421)      // number of daAlloc_struct arena slots (1057)
#define DAALLOC_SMALL_ALLOC_MAX (0x1000) // requests larger than this bypass the arena (daSmallAlloc)

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
#define SWR_CTL_DEMO_STEER_SCALE (-0.5f)       // demo-replay steer scale / bank threshold (0x004ad8e0)
#define SWR_CTL_PITCH_HI (0.1f)                // pitch above this (nose down) trims turn rate/throttle (0x004ad76c)
#define SWR_CTL_PITCH_LO (-0.1f)               // pitch below this (nose up) trims turn rate/throttle (0x004ad770)
#define SWR_CTL_PITCH_TRIM (0.4f)              // pitch -> turn-rate and idle-throttle factor (0x004ad938)
#define SWR_CTL_PITCH_THROTTLE_TRIM (-0.4f)    // pitch -> throttle trim subtrahend (0x004ad940)
#define SWR_CTL_UNDERPOWER_THROTTLE (0.3f)     // throttle above this (unk12_1<=0) sets UNDER_POWER; demo input gate
#define SWR_CTL_ANALOG_THROTTLE_GAIN (1.176468f) // analog reverse/throttle remap gain (0x004ad920)
#define SWR_CTL_IDLE_SPEED (20.0)              // below this speed, idle throttle follows pitch*trim (0x004ad930, double)
#define SWR_CTL_SLIDE_SPEED (100.0f)           // slide2 easing speed threshold (0x004ad93c)
#define SWR_CTL_BRAKE_UNDERPOWER_SPEED (70.0)  // braking below this speed also clears UNDER_POWER (0x004ad918, double)
#define SWR_CTL_BOOST_THROTTLE (0.6)           // throttle above this + boost input opens the boost window (0x004ad8c8, double)
#define SWR_CTL_BOOST_WINDOW (0.2)             // boost-start input timing window upper bound (0x004ad908, double)
#define SWR_CTL_BOOST_WINDOW_LO (0.0)          // boost-start window lower bound (0x004ad830, double)
#define SWR_CTL_BOOST_CANCEL_SPEED (290.0f)    // speed above which a pending boost-start is cancelled (0x004ad910)
#define SWR_CTL_BOOST_TAP_TIMEOUT (0.25)       // double-tap window for flame-attack / boost (0x004ad8d0, double)
#define SWR_CTL_FLAT_THROTTLE_FLOOR (1.2f)     // flags0 0x400000 overdrive: minimum throttle (0x004ad944)
#define SWR_CTL_DMG_PEN_GAIN (1.5f)            // engine-damage steering-penalty gain (0x004ad8f0)
#define SWR_CTL_DMG_PEN_LEFT (-0.2f)           // penalty offset when left engines are the damaged side (0x004ad8e8)
#define SWR_CTL_DMG_PEN_RIGHT (0.2f)           // penalty offset when right engines are the damaged side (0x004ad8ec)
#define SWR_CTL_DMG_STEER_PULL (-0.6f)         // damage penalty -> steer-pull factor; also demo-replay brake pitch gate (0x004ad8e4)
#define SWR_CTL_FF_MAG_BASE (60.0f)            // damage force-feedback magnitude base (0x004ad8f8)
#define SWR_CTL_FF_MAG_SLOPE (-30.0f)          // damage force-feedback magnitude slope (0x004ad8f4)
#define SWR_CTL_SCRIPT5_LAP_MIN (0.063f)       // ai_track_script==5 scripted-zone lapComp bounds
#define SWR_CTL_SCRIPT5_LAP_MAX (0.072f)
#define SWR_CTL_SCRIPT6_LAP_MIN (0.093f)       // ai_track_script==6 scripted-zone lapComp bounds
#define SWR_CTL_SCRIPT6_LAP_MAX (0.108f)

#endif // ENGINE_CONFIG_H
