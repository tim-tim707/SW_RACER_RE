/*---------------------------------------------------------------------------
 *
 * A3D COM Interface Header File.
 *
 *---------------------------------------------------------------------------
 */

#ifndef _IA3DAPI_H_
#define _IA3DAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

// A3D 1.0 Class ID {D8F1EEE0-F634-11cf-8700-00A0245D918B}
DEFINE_GUID(CLSID_A3d, 0xd8f1eee0, 0xf634, 0x11cf, 0x87, 0x0, 0x0, 0xa0, 0x24, 0x5d, 0x91, 0x8b);

// A3D 2.0 Class ID {92FA2C24-253C-11d2-90FB-006008A1F441}
DEFINE_GUID(CLSID_A3dApi, 0x92fa2c24, 0x253c, 0x11d2, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

//===================================================================
// A3D 2.0 Interfaces
//===================================================================

// Forward declaration of COM interfaces
#ifdef __cplusplus
// 'struct' not 'class' per the way DECLARE_INTERFACE_ is defined
struct IA3d3;
struct IA3d4;
struct IA3d5;
struct IA3dGeom;
struct IA3dGeom2;
struct IA3dSource;
struct IA3dSource2;
struct IA3dListener;
struct IA3dList;
struct IA3dMaterial;
struct IA3dEnvironment;
struct IA3dPropertySet;
struct IA3dReverb;
struct IA3dReflection;

#endif // __cplusplus

typedef struct IA3d3			*LPA3D3;
typedef struct IA3d4			*LPA3D4;
typedef struct IA3d5			*LPA3D5;
typedef struct IA3dGeom			*LPA3DGEOM;
typedef struct IA3dGeom2		*LPA3DGEOM2;
typedef struct IA3dSource		*LPA3DSOURCE;
typedef struct IA3dSource2		*LPA3DSOURCE2;
typedef struct IA3dListener		*LPA3DLISTENER;
typedef struct IA3dList			*LPA3DLIST;
typedef struct IA3dMaterial		*LPA3DMATERIAL;
typedef struct IA3dEnvironment	*LPA3DENVIRONMENT;
typedef struct IA3dPropertySet  *LPA3DPROPERTYSET;
typedef struct IA3dReverb		*LPA3DREVERB;
typedef struct IA3dReflection	*LPA3DREFLECTION;


//===================================================================
// Defined values
//===================================================================

// Feature flags
#define A3D_1ST_REFLECTIONS				0x00000002
#define A3D_DIRECT_PATH_A3D				0x00000008
#define A3D_DIRECT_PATH_GENERIC			0x00000020
#define A3D_OCCLUSIONS					0x00000040
#define A3D_DISABLE_SPLASHSCREEN		0x00000080
#define A3D_REVERB						0x00000100
#define A3D_GEOMETRIC_REVERB			0x00000200
#define A3D_DISABLE_FOCUS_MUTE			0x00000400

// Rendering modes
#define A3D_FASTEST						0x00000001
#define A3D_QUICK						0x00000002
#define A3D_NICEST						0x00000004

// Primitive input modes
#define A3D_INVALID_INPUTMODE			0xFFFFFFFF

#define A3D_LINES						0x00000002
#define A3D_TRIANGLES					0x00000003
#define A3D_QUADS						0x00000004
#define A3D_MATERIAL					0x00000005

#define A3D_SUBFACE						0x80000000
#define A3D_VERTEX_MASK					0x0000000F

#define A3D_SUB_LINES					(A3D_LINES     | A3D_SUBFACE)
#define A3D_SUB_TRIANGLES				(A3D_TRIANGLES | A3D_SUBFACE)
#define A3D_SUB_QUADS					(A3D_QUADS     | A3D_SUBFACE)

// Wall flags
#define A3D_SHELL_WALL					0x00000001
#define A3D_TRANSPARENT_WALL			0x00000002

// Data types
typedef float A3DVAL, *LPA3DVAL;

typedef A3DVAL A3DVECTOR[4];
typedef A3DVAL A3DVERTEX[4];
 
/*
 * NOTE: A3D matrices are column major. Indices are like this:
 *
 *     | 0  4  8 12 |
 *     | 1  5  9 13 |
 *     | 2  6 10 14 |
 *     | 3  7 11 15 |
 *
 * Indexing is (column*4)+row.
 *
*/
typedef A3DVAL A3DMATRIX[16];

#define A3D_TRUE								1
#define A3D_FALSE								0

// Epsilon good as zero gets
#define A3D_EPSILON								(1.0e-6f)
#define A3D_EPSILON_SQUARED						(1.0e-12f)

#define A3D_DEFAULT								0

// Play options
#define A3D_SINGLE								0
#define A3D_LOOPED								1

// Audio File Types
#define A3DSOURCE_FORMAT_AUTO					0x00000000
#define A3DSOURCE_FORMAT_WAVE					0x00000001
#define A3DSOURCE_FORMAT_MP3					0x00000002
#define A3DSOURCE_FORMAT_AC3					0x00000004
#define	A3DSOURCE_STREAMING						0x00010000

// Audio Streaming Thread Priority
#define A3D_STREAMING_PRIORITY_NORMAL			0
#define A3D_STREAMING_PRIORITY_HIGH				1
#define A3D_STREAMING_PRIORITY_HIGHEST			2

// Scene Types
#define A3D_SCENE_2D							2
#define A3D_SCENE_3D							3

#define A3DSTATUS_PLAYING_DIRECTPATH			0x00000001 // Renamed in IA3d5
#define A3DSTATUS_PLAYING						A3DSTATUS_PLAYING_DIRECTPATH // Old name.
#define A3DSTATUS_BUFFERLOST					0x00000002
#define A3DSTATUS_LOOPING						0x00000004
#define A3DSTATUS_PLAYING_REFLECTION			0x00000008 // Created in IA3d5
#define A3DSTATUS_WAITING_FOR_FLUSH				0x00001000
  // Created in IA3d5
#define A3DSTATUS_HARDWARE						0x00010000
#define A3DSTATUS_SOFTWARE						0x00020000
#define A3DSTATUS_VIRTUAL						0x00040000

// Coordinate system
#define A3D_RIGHT_HANDED_CS						0x00000000
#define A3D_LEFT_HANDED_CS						0x00000001

// Cooperative Level
#define A3D_CL_NORMAL							0x00000001
#define A3D_CL_EXCLUSIVE						0x00000003

// MaxMinDistance flags
#define A3D_AUDIBLE								0x00000000
#define A3D_MUTE								0x00000001

// Init render modes
#define A3DRENDERPREFS_A3D						0x00000000
#define A3DRENDERPREFS_DEFAULT					A3DRENDERPREFS_A3D
#define A3DRENDERPREFS_DISABLE_DS3D				0x00000001
#define A3DRENDERPREFS_DISABLE_DS				0x00000002

#define A3DSOURCE_TRANSFORMMODE_NORMAL			0x00000000
#define A3DSOURCE_TRANSFORMMODE_HEADRELATIVE	0x00000001

#define A3DREFLECTION_TRANSFORMMODE_NORMAL			0x00000000
#define A3DREFLECTION_TRANSFORMMODE_HEADRELATIVE	0x00000001

#define A3DSOURCE_RENDERMODE_A3D				0x00000000
#define A3DSOURCE_RENDERMODE_MONO				0x00000001
#define A3DSOURCE_RENDERMODE_1ST_REFLECTIONS	0x00000004
#define A3DSOURCE_RENDERMODE_OCCLUSIONS			0x00000008
#define A3DSOURCE_RENDERMODE_NATIVE				0x00000020

#define A3DSOURCE_RENDERMODE_DEFAULT			(A3DSOURCE_RENDERMODE_A3D | \
												 A3DSOURCE_RENDERMODE_1ST_REFLECTIONS | \
												 A3DSOURCE_RENDERMODE_OCCLUSIONS)

// Notification
#define A3DSOURCE_WAVEEVENT_STOP				0xFFFFFFFF
#define A3DSOURCE_WAVEEVENT_NULL				0xFFFFFFFE

// Polygon render mode
#define A3DPOLY_RENDERMODE_1ST_REFLECTIONS		A3D_1ST_REFLECTIONS
#define A3DPOLY_RENDERMODE_OCCLUSIONS			A3D_OCCLUSIONS

#define A3DSOURCE_INITIAL_RENDERMODE_A3D		0x00000000
#define A3DSOURCE_INITIAL_RENDERMODE_NATIVE		0x00000001
#define A3DSOURCE_TYPEUNMANAGED					0x00000002
#define A3DSOURCE_TYPESTREAMED					0x00000004
#define A3DSOURCE_AC3_HARDWARE					0x00000008
#define A3DSOURCE_TYPEDEFAULT					A3DSOURCE_INITIAL_RENDERMODE_A3D

// Property Set
#define A3DPROPSET_APPENDTOCACHE				0x00000001
#define A3DPROPSET_WAITFORRESULTS				0x00000002


// Values for bOutputMode
#define OUTPUT_MODE_STEREO						0x00000001
#define OUTPUT_MODE_QUAD						0x00000002

// Values for FrontXtalkMode and bRearXtalkMode
#define OUTPUT_HEADPHONES						0x00000001
#define OUTPUT_SPEAKERS_WIDE					0x00000002
#define OUTPUT_SPEAKERS_NARROW					0x00000003

// Values for Resource Management Mode
#define A3D_RESOURCE_MODE_OFF					0x00000000
#define A3D_RESOURCE_MODE_NOTIFY				0x00000001
#define A3D_RESOURCE_MODE_DYNAMIC				0x00000002
#define A3D_RESOURCE_MODE_DYNAMIC_LOOPERS		0x00000003
#define A3D_RESOURCE_MODE_LAST					A3D_RESOURCE_MODE_DYNAMIC_LOOPERS

// A3d Source Lock modes
#define A3D_ENTIREBUFFER						0x00000002

// Version Definitions for A3DCAPS 
#define A3D_CURRENT_VERSION						IA3DVERSION_RELEASE20

#define IA3DVERSION_RELEASE10					10
#define IA3DVERSION_RELEASE12					12
#define IA3DVERSION_RELEASE20					20
#define IA3DVERSION_RELEASE30					30

// A3d Caps structure for A3d2 interface
// If Fail to get IA3d2 interface, version of DLL is IA3DVERSION_PRE12

typedef struct __A3DCAPS_SOFTWARE
{
   DWORD dwSize;        // Use for internal version control
   DWORD dwVersion;     // For Backwards capablities purposes
   DWORD dwFlags;
   DWORD dwReserved;
   DWORD dwReserved2;
   DWORD dwOutputChannels;
   DWORD dwMinSampleRate;
   DWORD dwMaxSampleRate;
   DWORD dwMax2DBuffers;
   DWORD dwMax3DBuffers;
}  A3DCAPS_SOFTWARE, *LPA3DCAPS_SOFTWARE;

typedef struct __A3DCAPS_HARDWARE
{
   DWORD dwSize;        // Use for internal version control
   DWORD dwFlags;
   DWORD dwReserved;
   DWORD dwReserved2;
   DWORD dwOutputChannels;
   DWORD dwMinSampleRate;
   DWORD dwMaxSampleRate;
   DWORD dwMax2DBuffers;
   DWORD dwMax3DBuffers;
}  A3DCAPS_HARDWARE, *LPA3DCAPS_HARDWARE;

// A3d Enumerate Callback type
typedef BOOL (CALLBACK *LPA3DENUMCALLBACK)(LPGUID, LPCWSTR, LPCWSTR, LPVOID);

enum
{
    A3DREVERB_PRESET_GENERIC,                // factory default
    A3DREVERB_PRESET_PADDEDCELL,
    A3DREVERB_PRESET_ROOM,              // standard environments
    A3DREVERB_PRESET_BATHROOM,
    A3DREVERB_PRESET_LIVINGROOM,
    A3DREVERB_PRESET_STONEROOM,
    A3DREVERB_PRESET_AUDITORIUM,
    A3DREVERB_PRESET_CONCERTHALL,
    A3DREVERB_PRESET_CAVE,
    A3DREVERB_PRESET_ARENA,
    A3DREVERB_PRESET_HANGAR,
    A3DREVERB_PRESET_CARPETEDHALLWAY,
    A3DREVERB_PRESET_HALLWAY,
    A3DREVERB_PRESET_STONECORRIDOR,
    A3DREVERB_PRESET_ALLEY,
    A3DREVERB_PRESET_FOREST,
    A3DREVERB_PRESET_CITY,
    A3DREVERB_PRESET_MOUNTAINS,
    A3DREVERB_PRESET_QUARRY,
    A3DREVERB_PRESET_PLAIN,
    A3DREVERB_PRESET_PARKINGLOT,
    A3DREVERB_PRESET_SEWERPIPE,
    A3DREVERB_PRESET_UNDERWATER,
    A3DREVERB_PRESET_DRUGGED,
    A3DREVERB_PRESET_DIZZY,
    A3DREVERB_PRESET_PSYCHOTIC,

    A3DREVERB_PRESET_COUNT           // total number of environments
};

#define A3DREVERB_MAX_PRESET (A3DREVERB_PRESET_COUNT - 1)

typedef struct A3DVOLSRCDAMPINFO_s
{
	DWORD   dwSize;					
	A3DVAL  fAzimuthPan;			
	A3DVAL  fSizeDampMin;
	A3DVAL  fDampWeighting;
	int		nTestPointsMax;
	BOOL	bMonoInside;
} A3DVOLSRCDAMPINFO;

typedef struct
{
	DWORD   dwSize;				// Fill this, before calling SetAllProperties()
	DWORD   dwEnvPreset;
	A3DVAL  fVolume;
	A3DVAL  fDecayTime;
	A3DVAL  fDamping;
} A3DREVERB_PRESET;

typedef struct
{
	DWORD dwSize;				// Fill this, before calling SetAllProperties()
	LONG  lRoom;				// [-10000, 0] default: -10000 mB
	LONG  lRoomHF;				// [-10000, 0] default: 0 mB
	FLOAT flRoomRolloffFactor;	// [0.0, 10.0] default: 0.0
	FLOAT flDecayTime;			// [0.1, 20.0] default: 1.0 s
	FLOAT flDecayHFRatio;		// [0.1, 2.0] default: 0.5
	LONG lReflections;			// [-10000, 1000] default: -10000 mB
	FLOAT flReflectionsDelay;	// [0.0, 0.3] default: 0.02 s
	LONG lReverb;				// [-10000, 2000] default: -10000 mB
	FLOAT flReverbDelay;		// [0.0, 0.1] default: 0.04 s
	FLOAT flDiffusion;			// [0.0, 100.0] default: 100.0 %
	FLOAT flDensity;			// [0.0, 100.0] default: 100.0 %
	FLOAT flHFReference;		// [20.0, 20000.0] default: 5000.0 Hz
} A3DREVERB_CUSTOM;

#define A3DREVERB_TYPE_PRESET   1
#define A3DREVERB_TYPE_CUSTOM   2

typedef struct 
{
	DWORD	dwSize;				// Fill this, before calling SetAllProperties()
	DWORD   dwType;				// A3DREVERB_TYPE_PRESET or A3DREVERB_TYPE_CUSTOM
	union
	{
		A3DREVERB_PRESET preset;
		A3DREVERB_CUSTOM custom;
	} uval;
} A3DREVERB_PROPERTIES;

//
// IA3dSource2 Caps Structures
//

typedef struct
{
	DWORD dwSize;
    WORD  nChannels; 
    DWORD nSamplesPerSec; 
    DWORD nAvgBytesPerSec; 
    WORD  nBlockAlign; 
    WORD  wBitsPerSample; 
} A3DSOURCE_WAVEFORMAT, *LPA3DSOURCE_WAVEFORMAT;

typedef struct
{ 
	DWORD dwSize;
	
	// This is encoded information. This isn't necessarily the number of
	// channels or the sample rate the output buffer is playing at.
	// GetAudioFormat() gives you that information.
    INT    nMpegLayer;
    INT    nMpegVersion; 
    INT    nBitrate;            // Encoded bitrate
    INT    nChannels;           // Encoded channels
    INT    nSamplerate;         // Encoded samplerate
    INT    nBitsPerSample;
	
	FLOAT      fTotalPlayLength;    // Time of mp3 playback in seconds.
	
} A3DSOURCE_MP3INFO, *LPA3DSOURCE_MP3INFO; 

typedef struct
{
	DWORD dwSize;
	BOOL bPlayingInHardware;
} A3DSOURCE_AC3INFO, *LPA3DSOURCE_AC3INFO; 

typedef struct __A3DCAPS_SOURCE
{
    DWORD  dwSize;
    DWORD  dwType;    // A3DSOURCE_FORMAT_WAVE, A3DSOURCE_FORMAT_MP3, A3DSOURCE_FORMAT_AC3

	char *szFilename; 
    union
	{
		A3DSOURCE_WAVEFORMAT	waveFormat;
        A3DSOURCE_MP3INFO		mp3Info; 
		A3DSOURCE_AC3INFO		ac3Info; 
    } data;
} A3DCAPS_SOURCE, *LPA3DCAPS_SOURCE;


//===================================================================
// IA3d
//
// The original IA3d interface.
//===================================================================

// {D8F1EEE1-F634-11cf-8700-00A0245D918B}
DEFINE_GUID(IID_IA3d, 0xd8f1eee1, 0xf634, 0x11cf, 0x87, 0x0, 0x0, 0xa0, 0x24, 0x5d, 0x91, 0x8b);

#undef INTERFACE
#define INTERFACE IA3d

typedef struct IA3d *LPIA3D;

DECLARE_INTERFACE_(IA3d, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3d Methods.
	STDMETHOD(SetOutputMode)				(THIS_ DWORD, DWORD, DWORD) PURE;
	STDMETHOD(GetOutputMode)				(THIS_ LPDWORD, LPDWORD, LPDWORD) PURE;
	STDMETHOD(SetResourceManagerMode)		(THIS_ DWORD) PURE;
	STDMETHOD(GetResourceManagerMode)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetHFAbsorbFactor)			(THIS_ FLOAT) PURE;
	STDMETHOD(GetHFAbsorbFactor)			(THIS_ FLOAT *) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d_QueryInterface(p,a,b)			(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3d_AddRef(p)						(p)->lpVtbl->AddRef(p)
#define IA3d_Release(p)						(p)->lpVtbl->Release(p)
#define IA3d_SetOutputMode(p,a,b,c)			(p)->lpVtbl->SetOutputMode(p,a,b,c)
#define IA3d_GetOutputMode(p,a,b,c)			(p)->lpVtbl->GetOutputMode(p,a,b,c)
#define IA3d_SetResourceManagerMode(p,a)	(p)->lpVtbl->SetResourceManagerMode(p,a)
#define IA3d_GetResourceManagerMode(p,a)	(p)->lpVtbl->GetResourceManagerMode(p,a)
#define IA3d_SetHFAbsorbFactor(p,a)			(p)->lpVtbl->SetHFAbsorbFactor(p,a)
#define IA3d_GetHFAbsorbFactor(p,a)			(p)->lpVtbl->GetHFAbsorbFactor(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d_QueryInterface(p,a,b)			(p)->QueryInterface(a,b)
#define IA3d_AddRef(p)						(p)->AddRef()
#define IA3d_Release(p)						(p)->Release()
#define IA3d_SetOutputMode(p,a,b,c)			(p)->SetOutputMode(a,b,c)
#define IA3d_GetOutputMode(p,a,b,c)			(p)->GetOutputMode(a,b,c)
#define IA3d_SetResourceManagerMode(p,a)	(p)->SetResourceManagerMode(a)
#define IA3d_GetResourceManagerMode(p,a)	(p)->GetResourceManagerMode(a)
#define IA3d_SetHFAbsorbFactor(p,a)			(p)->SetHFAbsorbFactor(a)
#define IA3d_GetHFAbsorbFactor(p,a)			(p)->GetHFAbsorbFactor(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)



//===================================================================
// IA3d2
//
// IA3d2 Interface definition.
//===================================================================

// {fb80d1e0-98d3-11d1-90fb-006008a1f441}
DEFINE_GUID(IID_IA3d2, 0xfb80d1e0, 0x98d3, 0x11d1, 0x90, 0xfb, 0x00, 0x60, 0x08, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3d2

typedef struct IA3d2 *LPIA3D2;

DECLARE_INTERFACE_(IA3d2, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3d Methods.
	STDMETHOD(SetOutputMode)				(THIS_ DWORD, DWORD, DWORD) PURE;
	STDMETHOD(GetOutputMode)				(THIS_ LPDWORD, LPDWORD, LPDWORD) PURE;
	STDMETHOD(SetResourceManagerMode)		(THIS_ DWORD) PURE;
	STDMETHOD(GetResourceManagerMode)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetHFAbsorbFactor)			(THIS_ FLOAT) PURE;
	STDMETHOD(GetHFAbsorbFactor)			(THIS_ FLOAT *) PURE;

	// IA3d2 Methods.
	STDMETHOD(RegisterVersion)				(THIS_ DWORD) PURE;     
	STDMETHOD(GetSoftwareCaps)				(THIS_ LPA3DCAPS_SOFTWARE) PURE;
	STDMETHOD(GetHardwareCaps)				(THIS_ LPA3DCAPS_HARDWARE) PURE;
};

// The library function that gets things going.  It returns an interface
// pointer to DirectSound.

#define A3D_OK			1	    // A3dCreate returns this upon detection of A3D Dll.
#define A3D_OK_OLD_DLL	2	    // A3dCreate returns this upon detection of A3D Dll but user's version is older than expected.

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d2_QueryInterface(p,a,b)       (p)->lpVtbl->QueryInterface(p,a,b)
#define IA3d2_AddRef(p)                   (p)->lpVtbl->AddRef(p)
#define IA3d2_Release(p)                  (p)->lpVtbl->Release(p)
#define IA3d2_SetOutputMode(p,a,b,c)      (p)->lpVtbl->SetOutputMode(p,a,b,c)
#define IA3d2_GetOutputMode(p,a,b,c)      (p)->lpVtbl->GetOutputMode(p,a,b,c)
#define IA3d2_SetResourceManagerMode(p,a) (p)->lpVtbl->SetResourceManagerMode(p,a)
#define IA3d2_GetResourceManagerMode(p,a) (p)->lpVtbl->GetResourceManagerMode(p,a)
#define IA3d2_SetHFAbsorbFactor(p,a)      (p)->lpVtbl->SetHFAbsorbFactor(p,a)
#define IA3d2_GetHFAbsorbFactor(p,a)      (p)->lpVtbl->GetHFAbsorbFactor(p,a)
#define IA3d2_RegisterVersion(p,a)        (p)->lpVtbl->RegisterVersion(p,a)
#define IA3d2_GetSoftwareCaps(p,a)        (p)->lpVtbl->GetSoftwareCaps(p,a)
#define IA3d2_GetHardwareCaps(p,a)        (p)->lpVtbl->GetHardwareCaps(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d2_QueryInterface(p,a,b)       (p)->QueryInterface(a,b)
#define IA3d2_AddRef(p)                   (p)->AddRef()
#define IA3d2_Release(p)                  (p)->Release()
#define IA3d2_SetOutputMode(p,a,b,c)      (p)->SetOutputMode(a,b,c)
#define IA3d2_GetOutputMode(p,a,b,c)      (p)->GetOutputMode(a,b,c)
#define IA3d2_SetResourceManagerMode(p,a) (p)->SetResourceManagerMode(a)
#define IA3d2_GetResourceManagerMode(p,a) (p)->GetResourceManagerMode(a)
#define IA3d2_SetHFAbsorbFactor(p,a)      (p)->SetHFAbsorbFactor(a)
#define IA3d2_GetHFAbsorbFactor(p,a)      (p)->GetHFAbsorbFactor(a)
#define IA3d2_RegisterVersion(p,a)        (p)->RegisterVersion(a)
#define IA3d2_GetSoftwareCaps(p,a)        (p)->GetSoftwareCaps(a)
#define IA3d2_GetHardwareCaps(p,a)        (p)->GetHardwareCaps(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)


//===================================================================
// IA3d3
//
// The root object in A3D.
//===================================================================

// {C398E560-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3d3, 0xc398e560, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3d3

typedef struct IA3d3 *LPIA3D3;

DECLARE_INTERFACE_(IA3d3, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3d Methods.
	STDMETHOD(SetOutputMode)				(THIS_ DWORD, DWORD, DWORD) PURE;
	STDMETHOD(GetOutputMode)				(THIS_ LPDWORD, LPDWORD, LPDWORD) PURE;
	STDMETHOD(SetResourceManagerMode)		(THIS_ DWORD) PURE;
	STDMETHOD(GetResourceManagerMode)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetHFAbsorbFactor)			(THIS_ FLOAT) PURE;
	STDMETHOD(GetHFAbsorbFactor)			(THIS_ FLOAT *) PURE;

	// IA3d2 Methods.
	STDMETHOD(RegisterVersion)				(THIS_ DWORD) PURE;     
	STDMETHOD(GetSoftwareCaps)				(THIS_ LPA3DCAPS_SOFTWARE) PURE;
	STDMETHOD(GetHardwareCaps)				(THIS_ LPA3DCAPS_HARDWARE) PURE;

	// IA3d3 Methods.
	STDMETHOD(Clear)						(THIS) PURE;
	STDMETHOD(Flush)						(THIS) PURE;
	STDMETHOD(Compat)						(THIS_ DWORD, DWORD) PURE;
	STDMETHOD(Init)							(THIS_ LPGUID, DWORD, DWORD) PURE;
	STDMETHOD(IsFeatureAvailable)			(THIS_ DWORD) PURE;
	STDMETHOD(NewSource)					(THIS_ DWORD, LPA3DSOURCE *) PURE;
	STDMETHOD(DuplicateSource)				(THIS_ LPA3DSOURCE, LPA3DSOURCE *) PURE;
	STDMETHOD(SetCooperativeLevel)			(THIS_ HWND, DWORD) PURE;
	STDMETHOD(GetCooperativeLevel)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetMaxReflectionDelayTime)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetMaxReflectionDelayTime)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetCoordinateSystem)			(THIS_ DWORD) PURE;
	STDMETHOD(GetCoordinateSystem)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetOutputGain)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetOutputGain)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetNumFallbackSources)		(THIS_ DWORD) PURE;
	STDMETHOD(GetNumFallbackSources)		(THIS_ LPDWORD) PURE;		
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d3_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3d3_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3d3_Release(p)						(p)->lpVtbl->Release(p)
#define IA3d3_SetOutputMode(p,a,b,c)			(p)->lpVtbl->SetOutputMode(p,a,b,c)
#define IA3d3_GetOutputMode(p,a,b,c)			(p)->lpVtbl->GetOutputMode(p,a,b,c)
#define IA3d3_SetResourceManagerMode(p,a)		(p)->lpVtbl->SetResourceManagerMode(p,a)
#define IA3d3_GetResourceManagerMode(p,a)		(p)->lpVtbl->GetResourceManagerMode(p,a)
#define IA3d3_SetHFAbsorbFactor(p,a)			(p)->lpVtbl->SetHFAbsorbFactor(p,a)
#define IA3d3_GetHFAbsorbFactor(p,a)			(p)->lpVtbl->GetHFAbsorbFactor(p,a)
#define IA3d3_RegisterVersion(p,a)				(p)->lpVtbl->RegisterVersion(p,a)
#define IA3d3_GetSoftwareCaps(p,a)				(p)->lpVtbl->GetSoftwareCaps(p,a)
#define IA3d3_GetHardwareCaps(p,a)				(p)->lpVtbl->GetHardwareCaps(p,a)
#define IA3d3_Clear(p)							(p)->lpVtbl->Clear(p)
#define IA3d3_Flush(p)							(p)->lpVtbl->Flush(p)
#define IA3d3_Compat(p,a,b)						(p)->lpVtbl->Compat(p,a,b)
#define IA3d3_Init(p,a,b,c)						(p)->lpVtbl->Init(p,a,b,c)
#define IA3d3_IsFeatureAvailable(p,a)			(p)->lpVtbl->IsFeatureAvailable(p,a)
#define IA3d3_NewSource(p,a,b)					(p)->lpVtbl->NewSource(p,a,b)
#define IA3d3_DuplicateSource(p,a,b)			(p)->lpVtbl->DuplicateSource(p,a,b)
#define IA3d3_SetCooperativeLevel(p,a,b)		(p)->lpVtbl->SetCooperativeLevel(p,a,b)
#define IA3d3_GetCooperativeLevel(p,a)			(p)->lpVtbl->GetCooperativeLevel(p,a)
#define IA3d3_SetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->SetMaxReflectionDelayTime(p,a)
#define IA3d3_GetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->GetMaxReflectionDelayTime(p,a)
#define IA3d3_SetCoordinateSystem(p,a)			(p)->lpVtbl->SetCoordinateSystem(p,a)
#define IA3d3_GetCoordinateSystem(p,a)			(p)->lpVtbl->GetCoordinateSystem(p,a)
#define IA3d3_SetOutputGain(p,a)				(p)->lpVtbl->SetOutputGain(p,a)
#define IA3d3_GetOutputGain(p,a)				(p)->lpVtbl->GetOutputGain(p,a)
#define IA3d3_SetNumFallbackSources(p,a)		(p)->lpVtbl->SetNumFallbackSources(p,a)
#define IA3d3_GetNumFallbackSources(p,a)		(p)->lpVtbl->GetNumFallbackSources(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d3_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3d3_AddRef(p)							(p)->AddRef()
#define IA3d3_Release(p)						(p)->Release()
#define IA3d3_SetOutputMode(p,a,b,c)			(p)->SetOutputMode(a,b,c)
#define IA3d3_GetOutputMode(p,a,b,c)			(p)->GetOutputMode(a,b,c)
#define IA3d3_SetResourceManagerMode(p,a)		(p)->SetResourceManagerMode(a)
#define IA3d3_GetResourceManagerMode(p,a)		(p)->GetResourceManagerMode(a)
#define IA3d3_SetHFAbsorbFactor(p,a)			(p)->SetHFAbsorbFactor(a)
#define IA3d3_GetHFAbsorbFactor(p,a)			(p)->GetHFAbsorbFactor(a)
#define IA3d3_RegisterVersion(p,a)				(p)->RegisterVersion(a)
#define IA3d3_GetSoftwareCaps(p,a)				(p)->GetSoftwareCaps(a)
#define IA3d3_GetHardwareCaps(p,a)				(p)->GetHardwareCaps(a)
#define IA3d3_Clear(p)							(p)->Clear()
#define IA3d3_Flush(p)							(p)->Flush()
#define IA3d3_Compat(p,a,b)						(p)->Compat(a,b)
#define IA3d3_Init(p,a,b,c)						(p)->Init(a,b,c)
#define IA3d3_IsFeatureAvailable(p,a)			(p)->IsFeatureAvailable(a)
#define IA3d3_NewSource(p,a,b)					(p)->NewSource(a,b)
#define IA3d3_DuplicateSource(p,a,b)			(p)->DuplicateSource(a,b)
#define IA3d3_SetCooperativeLevel(p,a,b)		(p)->SetCooperativeLevel(a,b)
#define IA3d3_GetCooperativeLevel(p,a)			(p)->GetCooperativeLevel(a)
#define IA3d3_SetMaxReflectionDelayTime(p,a)	(p)->SetMaxReflectionDelayTime(a)
#define IA3d3_GetMaxReflectionDelayTime(p,a)	(p)->GetMaxReflectionDelayTime(a)
#define IA3d3_SetCoordinateSystem(p,a)			(p)->SetCoordinateSystem(a)
#define IA3d3_GetCoordinateSystem(p,a)			(p)->GetCoordinateSystem(a)
#define IA3d3_SetOutputGain(p,a)				(p)->SetOutputGain(a)
#define IA3d3_GetOutputGain(p,a)				(p)->GetOutputGain(a)
#define IA3d3_SetNumFallbackSources(p,a)		(p)->SetNumFallbackSources(a)
#define IA3d3_GetNumFallbackSources(p,a)		(p)->GetNumFallbackSources(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)



//===================================================================
// IA3d4
//
// The root object in A3D.
//===================================================================

// {E4C40280-CCBA-11d2-9DCF-00500411582F}
DEFINE_GUID(IID_IA3d4, 0xe4c40280, 0xccba, 0x11d2, 0x9d, 0xcf, 0x0, 0x50, 0x4, 0x11, 0x58, 0x2f);

#undef INTERFACE
#define INTERFACE IA3d4

DECLARE_INTERFACE_(IA3d4, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3d Methods.
	STDMETHOD(SetOutputMode)				(THIS_ DWORD, DWORD, DWORD) PURE;
	STDMETHOD(GetOutputMode)				(THIS_ LPDWORD, LPDWORD, LPDWORD) PURE;
	STDMETHOD(SetResourceManagerMode)		(THIS_ DWORD) PURE;
	STDMETHOD(GetResourceManagerMode)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetHFAbsorbFactor)			(THIS_ FLOAT) PURE;
	STDMETHOD(GetHFAbsorbFactor)			(THIS_ FLOAT *) PURE;

	// IA3d2 Methods.
	STDMETHOD(RegisterVersion)				(THIS_ DWORD) PURE;     
	STDMETHOD(GetSoftwareCaps)				(THIS_ LPA3DCAPS_SOFTWARE) PURE;
	STDMETHOD(GetHardwareCaps)				(THIS_ LPA3DCAPS_HARDWARE) PURE;

	// IA3d3 Methods.
	STDMETHOD(Clear)						(THIS) PURE;
	STDMETHOD(Flush)						(THIS) PURE;
	STDMETHOD(Compat)						(THIS_ DWORD, DWORD) PURE;
	STDMETHOD(Init)							(THIS_ LPGUID, DWORD, DWORD) PURE;
	STDMETHOD(IsFeatureAvailable)			(THIS_ DWORD) PURE;
	STDMETHOD(NewSource)					(THIS_ DWORD, LPA3DSOURCE *) PURE;
	STDMETHOD(DuplicateSource)				(THIS_ LPA3DSOURCE, LPA3DSOURCE *) PURE;
	STDMETHOD(SetCooperativeLevel)			(THIS_ HWND, DWORD) PURE;
	STDMETHOD(GetCooperativeLevel)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetMaxReflectionDelayTime)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetMaxReflectionDelayTime)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetCoordinateSystem)			(THIS_ DWORD) PURE;
	STDMETHOD(GetCoordinateSystem)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetOutputGain)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetOutputGain)				(THIS_ LPA3DVAL) PURE;

	// IA3d4 Methods
	STDMETHOD(SetNumFallbackSources)		(THIS_ DWORD) PURE;
	STDMETHOD(GetNumFallbackSources)		(THIS_ LPDWORD) PURE;		
	STDMETHOD(SetRMPriorityBias)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetRMPriorityBias)			(THIS_ LPA3DVAL) PURE;		
	STDMETHOD(DisableViewer)				(THIS) PURE;
	STDMETHOD(SetUnitsPerMeter) 			(THIS_ A3DVAL) PURE;		
	STDMETHOD(GetUnitsPerMeter)				(THIS_ LPA3DVAL) PURE;		
	STDMETHOD(SetDopplerScale)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDopplerScale)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDistanceModelScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDistanceModelScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetEq)						(THIS_ A3DVAL) PURE;
	STDMETHOD(GetEq)						(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Shutdown)						(THIS) PURE;		
	STDMETHOD(RegisterApp)					(THIS_ REFIID) PURE;		
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d4_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3d4_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3d4_Release(p)						(p)->lpVtbl->Release(p)
#define IA3d4_SetOutputMode(p,a,b,c)			(p)->lpVtbl->SetOutputMode(p,a,b,c)
#define IA3d4_GetOutputMode(p,a,b,c)			(p)->lpVtbl->GetOutputMode(p,a,b,c)
#define IA3d4_SetResourceManagerMode(p,a)		(p)->lpVtbl->SetResourceManagerMode(p,a)
#define IA3d4_GetResourceManagerMode(p,a)		(p)->lpVtbl->GetResourceManagerMode(p,a)
#define IA3d4_SetHFAbsorbFactor(p,a)			(p)->lpVtbl->SetHFAbsorbFactor(p,a)
#define IA3d4_GetHFAbsorbFactor(p,a)			(p)->lpVtbl->GetHFAbsorbFactor(p,a)
#define IA3d4_RegisterVersion(p,a)				(p)->lpVtbl->RegisterVersion(p,a)
#define IA3d4_GetSoftwareCaps(p,a)				(p)->lpVtbl->GetSoftwareCaps(p,a)
#define IA3d4_GetHardwareCaps(p,a)				(p)->lpVtbl->GetHardwareCaps(p,a)
#define IA3d4_Clear(p)							(p)->lpVtbl->Clear(p)
#define IA3d4_Flush(p)							(p)->lpVtbl->Flush(p)
#define IA3d4_Compat(p,a,b)						(p)->lpVtbl->Compat(p,a,b)
#define IA3d4_Init(p,a,b,c)						(p)->lpVtbl->Init(p,a,b,c)
#define IA3d4_IsFeatureAvailable(p,a)			(p)->lpVtbl->IsFeatureAvailable(p,a)
#define IA3d4_NewSource(p,a,b)					(p)->lpVtbl->NewSource(p,a,b)
#define IA3d4_DuplicateSource(p,a,b)			(p)->lpVtbl->DuplicateSource(p,a,b)
#define IA3d4_SetCooperativeLevel(p,a,b)		(p)->lpVtbl->SetCooperativeLevel(p,a,b)
#define IA3d4_GetCooperativeLevel(p,a)			(p)->lpVtbl->GetCooperativeLevel(p,a)
#define IA3d4_SetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->SetMaxReflectionDelayTime(p,a)
#define IA3d4_GetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->GetMaxReflectionDelayTime(p,a)
#define IA3d4_SetCoordinateSystem(p,a)			(p)->lpVtbl->SetCoordinateSystem(p,a)
#define IA3d4_GetCoordinateSystem(p,a)			(p)->lpVtbl->GetCoordinateSystem(p,a)
#define IA3d4_SetOutputGain(p,a)				(p)->lpVtbl->SetOutputGain(p,a)
#define IA3d4_GetOutputGain(p,a)				(p)->lpVtbl->GetOutputGain(p,a)
#define IA3d4_SetNumFallbackSources(p,a)		(p)->lpVtbl->SetNumFallbackSources(p,a)
#define IA3d4_GetNumFallbackSources(p,a)		(p)->lpVtbl->GetNumFallbackSources(p,a)
#define IA3d4_SetRMPriorityBias(p,a)			(p)->lpVtbl->SetRMPriorityBias(p,a)
#define IA3d4_GetRMPriorityBias(p,a)			(p)->lpVtbl->GetRMPriorityBias(p,a)
#define IA3d4_DisableViewer(p)					(p)->lpVtbl->DisableViewer(p)
#define IA3d4_SetUnitsPerMeter(p,a)				(p)->lpVtbl->SetUnitsPerMeter(p,a)
#define IA3d4_GetUnitsPerMeter(p,a)				(p)->lpVtbl->GetUnitsPerMeter(p,a)
#define IA3d4_SetDopplerScale(p,a)				(p)->lpVtbl->SetDopplerScale(p,a)
#define IA3d4_GetDopplerScale(p,a)				(p)->lpVtbl->GetDopplerScale(p,a)
#define IA3d4_SetDistanceModelScale(p,a)		(p)->lpVtbl->SetDistanceModelScale(p,a)
#define IA3d4_GetDistanceModelScale(p,a)		(p)->lpVtbl->GetDistanceModelScale(p,a)
#define IA3d4_SetEq(p,a)						(p)->lpVtbl->SetEq(p,a)
#define IA3d4_GetEq(p,a)						(p)->lpVtbl->GetEq(p,a)
#define IA3d4_Shutdown(p)						(p)->lpVtbl->Shutdown(p)
#define IA3d4_RegisterApp(p,a)					(p)->lpVtbl->RegisterApp(p,a)

#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d4_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3d4_AddRef(p)							(p)->AddRef()
#define IA3d4_Release(p)						(p)->Release()
#define IA3d4_SetOutputMode(p,a,b,c)			(p)->SetOutputMode(a,b,c)
#define IA3d4_GetOutputMode(p,a,b,c)			(p)->GetOutputMode(a,b,c)
#define IA3d4_SetResourceManagerMode(p,a)		(p)->SetResourceManagerMode(a)
#define IA3d4_GetResourceManagerMode(p,a)		(p)->GetResourceManagerMode(a)
#define IA3d4_SetHFAbsorbFactor(p,a)			(p)->SetHFAbsorbFactor(a)
#define IA3d4_GetHFAbsorbFactor(p,a)			(p)->GetHFAbsorbFactor(a)
#define IA3d4_RegisterVersion(p,a)				(p)->RegisterVersion(a)
#define IA3d4_GetSoftwareCaps(p,a)				(p)->GetSoftwareCaps(a)
#define IA3d4_GetHardwareCaps(p,a)				(p)->GetHardwareCaps(a)
#define IA3d4_Clear(p)							(p)->Clear()
#define IA3d4_Flush(p)							(p)->Flush()
#define IA3d4_Compat(p,a,b)						(p)->Compat(a,b)
#define IA3d4_Init(p,a,b,c)						(p)->Init(a,b,c)
#define IA3d4_IsFeatureAvailable(p,a)			(p)->IsFeatureAvailable(a)
#define IA3d4_NewSource(p,a,b)					(p)->NewSource(a,b)
#define IA3d4_DuplicateSource(p,a,b)			(p)->DuplicateSource(a,b)
#define IA3d4_SetCooperativeLevel(p,a,b)		(p)->SetCooperativeLevel(a,b)
#define IA3d4_GetCooperativeLevel(p,a)			(p)->GetCooperativeLevel(a)
#define IA3d4_SetMaxReflectionDelayTime(p,a)	(p)->SetMaxReflectionDelayTime(a)
#define IA3d4_GetMaxReflectionDelayTime(p,a)	(p)->GetMaxReflectionDelayTime(a)
#define IA3d4_SetCoordinateSystem(p,a)			(p)->SetCoordinateSystem(a)
#define IA3d4_GetCoordinateSystem(p,a)			(p)->GetCoordinateSystem(a)
#define IA3d4_SetOutputGain(p,a)				(p)->SetOutputGain(a)
#define IA3d4_GetOutputGain(p,a)				(p)->GetOutputGain(a)
#define IA3d4_SetNumFallbackSources(p,a)		(p)->SetNumFallbackSources(a)
#define IA3d4_GetNumFallbackSources(p,a)		(p)->GetNumFallbackSources(a)
#define IA3d4_SetRMPriorityBias(p,a)			(p)->SetRMPriorityBias(a)
#define IA3d4_GetRMPriorityBias(p,a)			(p)->GetRMPriorityBias(a)
#define IA3d4_DisableViewer(p)					(p)->DisableViewer()
#define IA3d4_SetUnitsPerMeter(p,a)				(p)->SetUnitsPerMeter(a)
#define IA3d4_GetUnitsPerMeter(p,a)				(p)->GetUnitsPerMeter(a)
#define IA3d4_SetDopplerScale(p,a)				(p)->SetDopplerScale(a)
#define IA3d4_GetDopplerScale(p,a)				(p)->GetDopplerScale(a)
#define IA3d4_SetDistanceModelScale(p,a)		(p)->SetDistanceModelScale(a)
#define IA3d4_GetDistanceModelScale(p,a)		(p)->GetDistanceModelScale(a)
#define IA3d4_SetEq(p,a)						(p)->SetEq(a)
#define IA3d4_GetEq(p,a)						(p)->GetEq(a)
#define IA3d4_Shutdown(p)						(p)->Shutdown()
#define IA3d4_RegisterApp(p,a)					(p)->RegisterApp(a)

#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3d5
//
// The root object in A3D. Version 5
//===================================================================

// {9AE07221-8AC4-11d3-B6AA-00600879F3EE}
DEFINE_GUID(IID_IA3d5, 0x9ae07221, 0x8ac4, 0x11d3, 0xb6, 0xaa, 0x0, 0x60, 0x8, 0x79, 0xf3, 0xee);

#undef INTERFACE
#define INTERFACE IA3d5

DECLARE_INTERFACE_(IA3d5, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3d Methods.
	STDMETHOD(SetOutputMode)				(THIS_ DWORD, DWORD, DWORD) PURE;
	STDMETHOD(GetOutputMode)				(THIS_ LPDWORD, LPDWORD, LPDWORD) PURE;
	STDMETHOD(SetResourceManagerMode)		(THIS_ DWORD) PURE;
	STDMETHOD(GetResourceManagerMode)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetHFAbsorbFactor)			(THIS_ FLOAT) PURE;
	STDMETHOD(GetHFAbsorbFactor)			(THIS_ FLOAT *) PURE;

	// IA3d2 Methods.
	STDMETHOD(RegisterVersion)				(THIS_ DWORD) PURE;     
	STDMETHOD(GetSoftwareCaps)				(THIS_ LPA3DCAPS_SOFTWARE) PURE;
	STDMETHOD(GetHardwareCaps)				(THIS_ LPA3DCAPS_HARDWARE) PURE;

	// IA3d3 Methods.
	STDMETHOD(Clear)						(THIS) PURE;
	STDMETHOD(Flush)						(THIS) PURE;
	STDMETHOD(Compat)						(THIS_ DWORD, DWORD) PURE;
	STDMETHOD(Init)							(THIS_ LPGUID, DWORD, DWORD) PURE;
	STDMETHOD(IsFeatureAvailable)			(THIS_ DWORD) PURE;
	STDMETHOD(NewSource)					(THIS_ DWORD, LPA3DSOURCE2 *) PURE;
	STDMETHOD(DuplicateSource)				(THIS_ LPA3DSOURCE2, LPA3DSOURCE2 *) PURE;
	STDMETHOD(SetCooperativeLevel)			(THIS_ HWND, DWORD) PURE;
	STDMETHOD(GetCooperativeLevel)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetMaxReflectionDelayTime)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetMaxReflectionDelayTime)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetCoordinateSystem)			(THIS_ DWORD) PURE;
	STDMETHOD(GetCoordinateSystem)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetOutputGain)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetOutputGain)				(THIS_ LPA3DVAL) PURE;

	// IA3d4 Methods
	STDMETHOD(SetNumFallbackSources)		(THIS_ DWORD) PURE;
	STDMETHOD(GetNumFallbackSources)		(THIS_ LPDWORD) PURE;		
	STDMETHOD(SetRMPriorityBias)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetRMPriorityBias)			(THIS_ LPA3DVAL) PURE;		
	STDMETHOD(DisableViewer)				(THIS) PURE;
	STDMETHOD(SetUnitsPerMeter) 			(THIS_ A3DVAL) PURE;		
	STDMETHOD(GetUnitsPerMeter)				(THIS_ LPA3DVAL) PURE;		
	STDMETHOD(SetDopplerScale)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDopplerScale)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDistanceModelScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDistanceModelScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetEq)						(THIS_ A3DVAL) PURE;
	STDMETHOD(GetEq)						(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Shutdown)						(THIS) PURE;		
	STDMETHOD(RegisterApp)					(THIS_ REFIID) PURE;		

	// IA3d5 Methods
	STDMETHOD(InitEx)						(THIS_ LPGUID, DWORD, DWORD, HWND, DWORD) PURE;		
	STDMETHOD(NewReverb)					(THIS_ LPA3DREVERB *) PURE;		
	STDMETHOD(BindReverb)					(THIS_ LPA3DREVERB ) PURE;		
	STDMETHOD(GetStreamingProperties)		(THIS_ DWORD *, DWORD *) PURE;
	STDMETHOD(SetStreamingProperties)		(THIS_ DWORD, DWORD) PURE;
	STDMETHOD(A3dEnumerate)					(THIS_ LPA3DENUMCALLBACK, LPVOID) PURE;
	STDMETHOD(UnlockFallbackAC3Decoder)		(THIS_ LPSTR , DWORD ) PURE;
	STDMETHOD(SetMaxHardwareSources)		(THIS_ DWORD) PURE;
	STDMETHOD(GetMaxHardwareSources)		(THIS_ LPDWORD) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d5_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3d5_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3d5_Release(p)						(p)->lpVtbl->Release(p)
#define IA3d5_SetOutputMode(p,a,b,c)			(p)->lpVtbl->SetOutputMode(p,a,b,c)
#define IA3d5_GetOutputMode(p,a,b,c)			(p)->lpVtbl->GetOutputMode(p,a,b,c)
#define IA3d5_SetResourceManagerMode(p,a)		(p)->lpVtbl->SetResourceManagerMode(p,a)
#define IA3d5_GetResourceManagerMode(p,a)		(p)->lpVtbl->GetResourceManagerMode(p,a)
#define IA3d5_SetHFAbsorbFactor(p,a)			(p)->lpVtbl->SetHFAbsorbFactor(p,a)
#define IA3d5_GetHFAbsorbFactor(p,a)			(p)->lpVtbl->GetHFAbsorbFactor(p,a)
#define IA3d5_RegisterVersion(p,a)				(p)->lpVtbl->RegisterVersion(p,a)
#define IA3d5_GetSoftwareCaps(p,a)				(p)->lpVtbl->GetSoftwareCaps(p,a)
#define IA3d5_GetHardwareCaps(p,a)				(p)->lpVtbl->GetHardwareCaps(p,a)
#define IA3d5_Clear(p)							(p)->lpVtbl->Clear(p)
#define IA3d5_Flush(p)							(p)->lpVtbl->Flush(p)
#define IA3d5_Compat(p,a,b)						(p)->lpVtbl->Compat(p,a,b)
#define IA3d5_Init(p,a,b,c)						(p)->lpVtbl->Init(p,a,b,c)
#define IA3d5_IsFeatureAvailable(p,a)			(p)->lpVtbl->IsFeatureAvailable(p,a)
#define IA3d5_NewSource(p,a,b)					(p)->lpVtbl->NewSource(p,a,b)
#define IA3d5_DuplicateSource(p,a,b)			(p)->lpVtbl->DuplicateSource(p,a,b)
#define IA3d5_SetCooperativeLevel(p,a,b)		(p)->lpVtbl->SetCooperativeLevel(p,a,b)
#define IA3d5_GetCooperativeLevel(p,a)			(p)->lpVtbl->GetCooperativeLevel(p,a)
#define IA3d5_SetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->SetMaxReflectionDelayTime(p,a)
#define IA3d5_GetMaxReflectionDelayTime(p,a)	(p)->lpVtbl->GetMaxReflectionDelayTime(p,a)
#define IA3d5_SetCoordinateSystem(p,a)			(p)->lpVtbl->SetCoordinateSystem(p,a)
#define IA3d5_GetCoordinateSystem(p,a)			(p)->lpVtbl->GetCoordinateSystem(p,a)
#define IA3d5_SetOutputGain(p,a)				(p)->lpVtbl->SetOutputGain(p,a)
#define IA3d5_GetOutputGain(p,a)				(p)->lpVtbl->GetOutputGain(p,a)
#define IA3d5_SetNumFallbackSources(p,a)		(p)->lpVtbl->SetNumFallbackSources(p,a)
#define IA3d5_GetNumFallbackSources(p,a)		(p)->lpVtbl->GetNumFallbackSources(p,a)
#define IA3d5_SetRMPriorityBias(p,a)			(p)->lpVtbl->SetRMPriorityBias(p,a)
#define IA3d5_GetRMPriorityBias(p,a)			(p)->lpVtbl->GetRMPriorityBias(p,a)
#define IA3d5_DisableViewer(p)					(p)->lpVtbl->DisableViewer(p)
#define IA3d5_SetUnitsPerMeter(p,a)				(p)->lpVtbl->SetUnitsPerMeter(p,a)
#define IA3d5_GetUnitsPerMeter(p,a)				(p)->lpVtbl->GetUnitsPerMeter(p,a)
#define IA3d5_SetDopplerScale(p,a)				(p)->lpVtbl->SetDopplerScale(p,a)
#define IA3d5_GetDopplerScale(p,a)				(p)->lpVtbl->GetDopplerScale(p,a)
#define IA3d5_SetDistanceModelScale(p,a)		(p)->lpVtbl->SetDistanceModelScale(p,a)
#define IA3d5_GetDistanceModelScale(p,a)		(p)->lpVtbl->GetDistanceModelScale(p,a)
#define IA3d5_SetEq(p,a)						(p)->lpVtbl->SetEq(p,a)
#define IA3d5_GetEq(p,a)						(p)->lpVtbl->GetEq(p,a)
#define IA3d5_Shutdown(p)						(p)->lpVtbl->Shutdown(p)
#define IA3d5_RegisterApp(p,a)					(p)->lpVtbl->RegisterApp(p,a)
#define IA3d5_InitEx(p,a,b,c,d,e)				(p)->lpVtbl->InitEx(p,a,b,c,d,e)
#define IA3d5_NewReverb(p,a)					(p)->lpVtbl->NewReverb(p,a)
#define IA3d5_BindReverb(p,a)					(p)->lpVtbl->BindReverb(p,a)
#define IA3d5_GetStreamingProperties(p, a, b)	(p)->lpVtbl->GetStreamingProperties(p, a, b)
#define IA3d5_SetStreamingProperties(p, a, b)	(p)->lpVtbl->SetStreamingProperties(p, a, b)
#define IA3d5_A3dEnumerate(p, a, b)				(p)->lpVtbl->A3dEnumerate(p, a, b)
#define IA3d5_UnlockFallbackAC3Decoder(p,a,b)	(p)->lpVtbl->UnlockFallbackAC3Decoder(p,a,b)
#define IA3d5_SetMaxHardwareSources(p,a)		(p)->lpVtbl->SetMaxHardwareSources(p,a)
#define IA3d5_GetMaxHardwareSources(p,a)		(p)->lpVtbl->GetMaxHardwareSources(p,a)

#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3d5_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3d5_AddRef(p)							(p)->AddRef()
#define IA3d5_Release(p)						(p)->Release()
#define IA3d5_SetOutputMode(p,a,b,c)			(p)->SetOutputMode(a,b,c)
#define IA3d5_GetOutputMode(p,a,b,c)			(p)->GetOutputMode(a,b,c)
#define IA3d5_SetResourceManagerMode(p,a)		(p)->SetResourceManagerMode(a)
#define IA3d5_GetResourceManagerMode(p,a)		(p)->GetResourceManagerMode(a)
#define IA3d5_SetHFAbsorbFactor(p,a)			(p)->SetHFAbsorbFactor(a)
#define IA3d5_GetHFAbsorbFactor(p,a)			(p)->GetHFAbsorbFactor(a)
#define IA3d5_RegisterVersion(p,a)				(p)->RegisterVersion(a)
#define IA3d5_GetSoftwareCaps(p,a)				(p)->GetSoftwareCaps(a)
#define IA3d5_GetHardwareCaps(p,a)				(p)->GetHardwareCaps(a)
#define IA3d5_Clear(p)							(p)->Clear()
#define IA3d5_Flush(p)							(p)->Flush()
#define IA3d5_Compat(p,a,b)						(p)->Compat(a,b)
#define IA3d5_Init(p,a,b,c)						(p)->Init(a,b,c)
#define IA3d5_IsFeatureAvailable(p,a)			(p)->IsFeatureAvailable(a)
#define IA3d5_NewSource(p,a,b)					(p)->NewSource(a,b)
#define IA3d5_DuplicateSource(p,a,b)			(p)->DuplicateSource(a,b)
#define IA3d5_SetCooperativeLevel(p,a,b)		(p)->SetCooperativeLevel(a,b)
#define IA3d5_GetCooperativeLevel(p,a)			(p)->GetCooperativeLevel(a)
#define IA3d5_SetMaxReflectionDelayTime(p,a)	(p)->SetMaxReflectionDelayTime(a)
#define IA3d5_GetMaxReflectionDelayTime(p,a)	(p)->GetMaxReflectionDelayTime(a)
#define IA3d5_SetCoordinateSystem(p,a)			(p)->SetCoordinateSystem(a)
#define IA3d5_GetCoordinateSystem(p,a)			(p)->GetCoordinateSystem(a)
#define IA3d5_SetOutputGain(p,a)				(p)->SetOutputGain(a)
#define IA3d5_GetOutputGain(p,a)				(p)->GetOutputGain(a)
#define IA3d5_SetNumFallbackSources(p,a)		(p)->SetNumFallbackSources(a)
#define IA3d5_GetNumFallbackSources(p,a)		(p)->GetNumFallbackSources(a)
#define IA3d5_SetRMPriorityBias(p,a)			(p)->SetRMPriorityBias(a)
#define IA3d5_GetRMPriorityBias(p,a)			(p)->GetRMPriorityBias(a)
#define IA3d5_DisableViewer(p)					(p)->DisableViewer()
#define IA3d5_SetUnitsPerMeter(p,a)				(p)->SetUnitsPerMeter(a)
#define IA3d5_GetUnitsPerMeter(p,a)				(p)->GetUnitsPerMeter(a)
#define IA3d5_SetDopplerScale(p,a)				(p)->SetDopplerScale(a)
#define IA3d5_GetDopplerScale(p,a)				(p)->GetDopplerScale(a)
#define IA3d5_SetDistanceModelScale(p,a)		(p)->SetDistanceModelScale(a)
#define IA3d5_GetDistanceModelScale(p,a)		(p)->GetDistanceModelScale(a)
#define IA3d5_SetEq(p,a)						(p)->SetEq(a)
#define IA3d5_GetEq(p,a)						(p)->GetEq(a)
#define IA3d5_Shutdown(p)						(p)->Shutdown()
#define IA3d5_RegisterApp(p,a)					(p)->RegisterApp(a)
#define IA3d5_InitEx(p,a,b,c,d,e)				(p)->InitEx(a,b,c,d,e)
#define IA3d5_NewReverb(p,a)					(p)->NewReverb(a)
#define IA3d5_BindReverb(p,a)					(p)->BindReverb(a)
#define IA3d5_GetStreamingProperties(p, a, b)	(p)->GetStreamingProperties(a, b)
#define IA3d5_SetStreamingProperties(p, a, b)	(p)->SetStreamingProperties(a, b)
#define IA3d5_A3dEnumerate(p, a, b)				(p)->A3dEnumerate(a, b)
#define IA3d5_UnlockFallbackAC3Decoder(p,a,b)	(p)->UnlockFallbackAC3Decoder(a,b)
#define IA3d5_SetMaxHardwareSources(p,a)		(p)->SetMaxHardwareSources(a)
#define IA3d5_GetMaxHardwareSources(p,a)		(p)->GetMaxHardwareSources(a)

#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dGeom
//
// The low level geometry renderer.
//===================================================================

// {C398E561-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3dGeom, 0xc398e561, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3dGeom

DECLARE_INTERFACE_(IA3dGeom, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3dGeom Methods.
	STDMETHOD(Enable)						(THIS_ DWORD) PURE;
	STDMETHOD(Disable)						(THIS_ DWORD) PURE;
	STDMETHOD_(BOOL, IsEnabled)				(THIS_ DWORD) PURE;
	STDMETHOD(SetOcclusionMode)				(THIS_ DWORD) PURE;
	STDMETHOD(GetOcclusionMode)				(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetReflectionMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionGainScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionGainScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionDelayScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionDelayScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD_(ULONG, PushMatrix)			(THIS) PURE;
	STDMETHOD_(ULONG, PopMatrix)			(THIS) PURE;
	STDMETHOD(LoadIdentity)					(THIS) PURE;
	STDMETHOD(LoadMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(GetMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(MultMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(Translate3f)					(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Translate3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Rotate3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Rotate3fv)					(THIS_ A3DVAL, LPA3DVAL) PURE;
	STDMETHOD(Scale3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Scale3fv)						(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Begin)						(THIS_ DWORD) PURE;
	STDMETHOD(End)							(THIS) PURE;
	STDMETHOD(Vertex3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Vertex3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Normal3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Normal3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Tag)							(THIS_ DWORD) PURE;
    STDMETHOD(SetOpeningFactorf)			(THIS_ A3DVAL ) PURE;
    STDMETHOD(SetOpeningFactorfv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(NewMaterial)					(THIS_ LPA3DMATERIAL *) PURE;
	STDMETHOD(BindMaterial)					(THIS_ LPA3DMATERIAL) PURE;
	STDMETHOD(NewList)						(THIS_ LPA3DLIST *) PURE;
	STDMETHOD(BindListener)					(THIS) PURE;
	STDMETHOD(BindSource)					(THIS_ LPA3DSOURCE2) PURE;
	STDMETHOD(NewEnvironment)				(THIS_ LPA3DENVIRONMENT *) PURE;
	STDMETHOD(BindEnvironment)				(THIS_ LPA3DENVIRONMENT ) PURE;
	STDMETHOD(SetRenderMode)				(THIS_ DWORD) PURE;
	STDMETHOD(GetRenderMode)				(THIS_ LPDWORD) PURE;
	STDMETHOD(SetPolygonBloatFactor)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPolygonBloatFactor)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionUpdateInterval)	(THIS_ DWORD) PURE;
	STDMETHOD(GetReflectionUpdateInterval)	(THIS_ LPDWORD) PURE;
	STDMETHOD(SetOcclusionUpdateInterval)	(THIS_ DWORD) PURE;
	STDMETHOD(GetOcclusionUpdateInterval)	(THIS_ LPDWORD) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dGeom_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dGeom_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3dGeom_Release(p)							(p)->lpVtbl->Release(p)
#define IA3dGeom_Enable(p,a)						(p)->lpVtbl->Enable(p,a)
#define IA3dGeom_Disable(p,a)						(p)->lpVtbl->Disable(p,a)
#define IA3dGeom_IsEnabled(p,a)						(p)->lpVtbl->IsEnabled(p,a)
#define IA3dGeom_SetOcclusionMode(p,a)				(p)->lpVtbl->SetOcclusionMode(p,a)
#define IA3dGeom_GetOcclusionMode(p,a)				(p)->lpVtbl->GetOcclusionMode(p,a)
#define IA3dGeom_SetReflectionMode(p,a)				(p)->lpVtbl->SetReflectionMode(p,a)
#define IA3dGeom_GetReflectionMode(p,a)				(p)->lpVtbl->GetReflectionMode(p,a)
#define IA3dGeom_SetReflectionGainScale(p,a)		(p)->lpVtbl->SetReflectionGainScale(p,a)
#define IA3dGeom_GetReflectionGainScale(p,a)		(p)->lpVtbl->GetReflectionGainScale(p,a)
#define IA3dGeom_SetReflectionDelayScale(p,a)		(p)->lpVtbl->SetReflectionDelayScale(p,a)
#define IA3dGeom_GetReflectionDelayScale(p,a)		(p)->lpVtbl->GetReflectionDelayScale(p,a)
#define IA3dGeom_PushMatrix(p)						(p)->lpVtbl->PushMatrix(p)
#define IA3dGeom_PopMatrix(p)						(p)->lpVtbl->PopMatrix(p)
#define IA3dGeom_LoadIdentity(p)					(p)->lpVtbl->LoadIdentity(p)
#define IA3dGeom_LoadMatrix(p,a)					(p)->lpVtbl->LoadMatrix(p,a)
#define IA3dGeom_GetMatrix(p,a)						(p)->lpVtbl->GetMatrix(p,a)
#define IA3dGeom_MultMatrix(p,a)					(p)->lpVtbl->MultMatrix(p,a)
#define IA3dGeom_Translate3f(p,a,b,c)				(p)->lpVtbl->Translate3f(p,a,b,c)
#define IA3dGeom_Translate3fv(p,a)					(p)->lpVtbl->Translate3fv(p,a)
#define IA3dGeom_Rotate3f(p,a,b,c,d)				(p)->lpVtbl->Rotate3f(p,a,b,c,d)
#define IA3dGeom_Rotate3fv(p,a,b)					(p)->lpVtbl->Rotate3fv(p,a,b)
#define IA3dGeom_Scale3f(p,a,b,c)					(p)->lpVtbl->Scale3f(p,a,b,c)
#define IA3dGeom_Scale3fv(p,a)						(p)->lpVtbl->Scale3fv(p,a)
#define IA3dGeom_Begin(p,a)							(p)->lpVtbl->Begin(p,a)
#define IA3dGeom_End(p)								(p)->lpVtbl->End(p)
#define IA3dGeom_Vertex3f(p,a,b,c)					(p)->lpVtbl->Vertex3f(p,a,b,c)
#define IA3dGeom_Vertex3fv(p,a)						(p)->lpVtbl->Vertex3fv(p,a)
#define IA3dGeom_Normal3f(p,a,b,c)					(p)->lpVtbl->Normal3f(p,a,b,c)
#define IA3dGeom_Normal3fv(p,a)						(p)->lpVtbl->Normal3fv(p,a)
#define IA3dGeom_Tag(p,a)							(p)->lpVtbl->Tag(p,a)
#define IA3dGeom_SetOpeningFactorf(p,a)				(p)->lpVtbl->SetOpeningFactorf(p,a)
#define IA3dGeom_SetOpeningFactorfv(p,a)			(p)->lpVtbl->SetOpeningFactorfv(p,a)
#define IA3dGeom_NewMaterial(p,a)					(p)->lpVtbl->NewMaterial(p,a)
#define IA3dGeom_BindMaterial(p,a)					(p)->lpVtbl->BindMaterial(p,a)
#define IA3dGeom_NewList(p,a)						(p)->lpVtbl->NewList(p,a)
#define IA3dGeom_BindListener(p)					(p)->lpVtbl->BindListener(p)
#define IA3dGeom_BindSource(p,a)					(p)->lpVtbl->BindSource(p,a)
#define IA3dGeom_NewEnvironment(p,a)				(p)->lpVtbl->NewEnvironment(p,a)
#define IA3dGeom_BindEnvironment(p,a)				(p)->lpVtbl->BindEnvironment(p,a)
#define IA3dGeom_SetRenderMode(p,a)					(p)->lpVtbl->SetRenderMode(p,a)
#define IA3dGeom_GetRenderMode(p,a)					(p)->lpVtbl->GetRenderMode(p,a)
#define IA3dGeom_SetPolygonBloatFactor(p,a)			(p)->lpVtbl->SetPolygonBloatFactor(p,a)
#define IA3dGeom_GetPolygonBloatFactor(p,a)			(p)->lpVtbl->GetPolygonBloatFactor(p,a)
#define IA3dGeom_SetReflectionUpdateInterval(p,a)	(p)->lpVtbl->SetReflectionUpdateInterval(p,a)
#define IA3dGeom_GetReflectionUpdateInterval(p,a)	(p)->lpVtbl->GetReflectionUpdateInterval(p,a)
#define IA3dGeom_SetOcclusionUpdateInterval(p,a)	(p)->lpVtbl->SetOcclusionUpdateInterval(p,a)
#define IA3dGeom_GetOcclusionUpdateInterval(p,a)	(p)->lpVtbl->GetOcclusionUpdateInterval(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dGeom_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3dGeom_AddRef(p)							(p)->AddRef()
#define IA3dGeom_Release(p)							(p)->Release()
#define IA3dGeom_Enable(p,a)						(p)->Enable(a)
#define IA3dGeom_Disable(p,a)						(p)->Disable(a)
#define IA3dGeom_IsEnabled(p,a)						(p)->IsEnabled(a)
#define IA3dGeom_SetOcclusionMode(p,a)				(p)->SetOcclusionMode(a)
#define IA3dGeom_GetOcclusionMode(p,a)				(p)->GetOcclusionMode(a)
#define IA3dGeom_SetReflectionMode(p,a)				(p)->SetReflectionMode(a)
#define IA3dGeom_GetReflectionMode(p,a)				(p)->GetReflectionMode(a)
#define IA3dGeom_SetReflectionGainScale(p,a)		(p)->SetReflectionGainScale(a)
#define IA3dGeom_GetReflectionGainScale(p,a)		(p)->GetReflectionGainScale(a)
#define IA3dGeom_SetReflectionDelayScale(p,a)		(p)->SetReflectionDelayScale(a)
#define IA3dGeom_GetReflectionDelayScale(p,a)		(p)->GetReflectionDelayScale(a)
#define IA3dGeom_PushMatrix(p)						(p)->PushMatrix()
#define IA3dGeom_PopMatrix(p)						(p)->PopMatrix()
#define IA3dGeom_LoadIdentity(p)					(p)->LoadIdentity()
#define IA3dGeom_LoadMatrix(p,a)					(p)->LoadMatrix(a)
#define IA3dGeom_GetMatrix(p,a)						(p)->GetMatrix(a)
#define IA3dGeom_MultMatrix(p,a)					(p)->MultMatrix(a)
#define IA3dGeom_Translate3f(p,a,b,c)				(p)->Translate3f(a,b,c)
#define IA3dGeom_Translate3fv(p,a)					(p)->Translate3fv(a)
#define IA3dGeom_Rotate3f(p,a,b,c,d)				(p)->Rotate3f(a,b,c,d)
#define IA3dGeom_Rotate3fv(p,a,b)					(p)->Rotate3fv(a,b)
#define IA3dGeom_Scale3f(p,a,b,c)					(p)->Scale3f(a,b,c)
#define IA3dGeom_Scale3fv(p,a)						(p)->Scale3fv(a)
#define IA3dGeom_Begin(p,a)							(p)->Begin(a)
#define IA3dGeom_End(p)								(p)->End()
#define IA3dGeom_Vertex3f(p,a,b,c)					(p)->Vertex3f(a,b,c)
#define IA3dGeom_Vertex3fv(p,a)						(p)->Vertex3fv(a)
#define IA3dGeom_Normal3f(p,a,b,c)					(p)->Normal3f(a,b,c)
#define IA3dGeom_Normal3fv(p,a)						(p)->Normal3fv(a)
#define IA3dGeom_Tag(p,a)							(p)->Tag(a)
#define IA3dGeom_SetOpeningFactorf(p,a)				(p)->SetOpeningFactorf(p,a)
#define IA3dGeom_SetOpeningFactorfv(p,a)			(p)->SetOpeningFactorfv(p,a)
#define IA3dGeom_NewMaterial(p,a)					(p)->NewMaterial(a)
#define IA3dGeom_BindMaterial(p,a)					(p)->BindMaterial(a)
#define IA3dGeom_NewList(p,a)						(p)->NewList(a)
#define IA3dGeom_BindListener(p)					(p)->BindListener()
#define IA3dGeom_BindSource(p,a)					(p)->BindSource(a)
#define IA3dGeom_NewEnvironment(p,a)				(p)->NewEnvironment(a)
#define IA3dGeom_BindEnvironment(p,a)				(p)->BindEnvironment(a)
#define IA3dGeom_SetRenderMode(p,a)					(p)->SetRenderMode(a)
#define IA3dGeom_GetRenderMode(p,a)					(p)->GetRenderMode(a)
#define IA3dGeom_SetPolygonBloatFactor(p,a)			(p)->SetPolygonBloatFactor(a)
#define IA3dGeom_GetPolygonBloatFactor(p,a)			(p)->GetPolygonBloatFactor(a)
#define IA3dGeom_SetReflectionUpdateInterval(p,a)	(p)->SetReflectionUpdateInterval(a)
#define IA3dGeom_GetReflectionUpdateInterval(p,a)	(p)->GetReflectionUpdateInterval(a)
#define IA3dGeom_SetOcclusionUpdateInterval(p,a)	(p)->SetOcclusionUpdateInterval(a)
#define IA3dGeom_GetOcclusionUpdateInterval(p,a)	(p)->GetOcclusionUpdateInterval(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)

typedef enum
{
	A3DAXIS_X,
	A3DAXIS_Y,
	A3DAXIS_Z
} A3DAXIS;

typedef struct 
{
	DWORD		dwSize;							// sizeof structure, fill out before calling Set/GetGeomReverbParam
	float      	fGeomScaling;					// default 1.f	(0.f - infinitiy)
	float		fEffectScaling;					// default 1.f	(0.f - infinity)
	A3DAXIS		nVerticalAxis;					// by default up is the y-axis, nVerticalAxis = A3DAXIS_Y.
} A3DGEOMREVERBPARAM, *LPA3DGEOMREVERBPARAM;

//===================================================================
// IA3dGeom2
//
// The low level geometry renderer. version 2
//===================================================================

// {4730C6C2-B797-11d3-A33D-00104B67D10E}
DEFINE_GUID(IID_IA3dGeom2,0x4730c6c2, 0xb797, 0x11d3, 0xa3, 0x3d, 0x0, 0x10, 0x4b, 0x67, 0xd1, 0xe);

#undef INTERFACE
#define INTERFACE IA3dGeom2

DECLARE_INTERFACE_(IA3dGeom2, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)				(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)				(THIS) PURE;
	STDMETHOD_(ULONG,Release)				(THIS) PURE;

	// IA3dGeom Methods.
	STDMETHOD(Enable)						(THIS_ DWORD) PURE;
	STDMETHOD(Disable)						(THIS_ DWORD) PURE;
	STDMETHOD_(BOOL, IsEnabled)				(THIS_ DWORD) PURE;
	STDMETHOD(SetOcclusionMode)				(THIS_ DWORD) PURE;
	STDMETHOD(GetOcclusionMode)				(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetReflectionMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionGainScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionGainScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionDelayScale)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionDelayScale)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD_(ULONG, PushMatrix)			(THIS) PURE;
	STDMETHOD_(ULONG, PopMatrix)			(THIS) PURE;
	STDMETHOD(LoadIdentity)					(THIS) PURE;
	STDMETHOD(LoadMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(GetMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(MultMatrix)					(THIS_ A3DMATRIX) PURE;
	STDMETHOD(Translate3f)					(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Translate3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Rotate3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Rotate3fv)					(THIS_ A3DVAL, LPA3DVAL) PURE;
	STDMETHOD(Scale3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Scale3fv)						(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Begin)						(THIS_ DWORD) PURE;
	STDMETHOD(End)							(THIS) PURE;
	STDMETHOD(Vertex3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Vertex3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Normal3f)						(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(Normal3fv)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(Tag)							(THIS_ DWORD) PURE;
    STDMETHOD(SetOpeningFactorf)			(THIS_ A3DVAL ) PURE;
    STDMETHOD(SetOpeningFactorfv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(NewMaterial)					(THIS_ LPA3DMATERIAL *) PURE;
	STDMETHOD(BindMaterial)					(THIS_ LPA3DMATERIAL) PURE;
	STDMETHOD(NewList)						(THIS_ LPA3DLIST *) PURE;
	STDMETHOD(BindListener)					(THIS) PURE;
	STDMETHOD(BindSource)					(THIS_ LPA3DSOURCE2) PURE;
	STDMETHOD(NewEnvironment)				(THIS_ LPA3DENVIRONMENT *) PURE;
	STDMETHOD(BindEnvironment)				(THIS_ LPA3DENVIRONMENT ) PURE;
	STDMETHOD(SetRenderMode)				(THIS_ DWORD) PURE;
	STDMETHOD(GetRenderMode)				(THIS_ LPDWORD) PURE;
	STDMETHOD(SetPolygonBloatFactor)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPolygonBloatFactor)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionUpdateInterval)	(THIS_ DWORD) PURE;
	STDMETHOD(GetReflectionUpdateInterval)	(THIS_ LPDWORD) PURE;
	STDMETHOD(SetOcclusionUpdateInterval)	(THIS_ DWORD) PURE;
	STDMETHOD(GetOcclusionUpdateInterval)	(THIS_ LPDWORD) PURE;

	// IA3dGeom2 Methods
	STDMETHOD(SetGeomReverbParam)			(THIS_ LPA3DGEOMREVERBPARAM ) PURE;
	STDMETHOD(GetGeomReverbParam)			(THIS_ LPA3DGEOMREVERBPARAM ) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dGeom2_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dGeom2_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3dGeom2_Release(p)						(p)->lpVtbl->Release(p)
#define IA3dGeom2_Enable(p,a)						(p)->lpVtbl->Enable(p,a)
#define IA3dGeom2_Disable(p,a)						(p)->lpVtbl->Disable(p,a)
#define IA3dGeom2_IsEnabled(p,a)					(p)->lpVtbl->IsEnabled(p,a)
#define IA3dGeom2_SetOcclusionMode(p,a)				(p)->lpVtbl->SetOcclusionMode(p,a)
#define IA3dGeom2_GetOcclusionMode(p,a)				(p)->lpVtbl->GetOcclusionMode(p,a)
#define IA3dGeom2_SetReflectionMode(p,a)			(p)->lpVtbl->SetReflectionMode(p,a)
#define IA3dGeom2_GetReflectionMode(p,a)			(p)->lpVtbl->GetReflectionMode(p,a)
#define IA3dGeom2_SetReflectionGainScale(p,a)		(p)->lpVtbl->SetReflectionGainScale(p,a)
#define IA3dGeom2_GetReflectionGainScale(p,a)		(p)->lpVtbl->GetReflectionGainScale(p,a)
#define IA3dGeom2_SetReflectionDelayScale(p,a)		(p)->lpVtbl->SetReflectionDelayScale(p,a)
#define IA3dGeom2_GetReflectionDelayScale(p,a)		(p)->lpVtbl->GetReflectionDelayScale(p,a)
#define IA3dGeom2_PushMatrix(p)						(p)->lpVtbl->PushMatrix(p)
#define IA3dGeom2_PopMatrix(p)						(p)->lpVtbl->PopMatrix(p)
#define IA3dGeom2_LoadIdentity(p)					(p)->lpVtbl->LoadIdentity(p)
#define IA3dGeom2_LoadMatrix(p,a)					(p)->lpVtbl->LoadMatrix(p,a)
#define IA3dGeom2_GetMatrix(p,a)					(p)->lpVtbl->GetMatrix(p,a)
#define IA3dGeom2_MultMatrix(p,a)					(p)->lpVtbl->MultMatrix(p,a)
#define IA3dGeom2_Translate3f(p,a,b,c)				(p)->lpVtbl->Translate3f(p,a,b,c)
#define IA3dGeom2_Translate3fv(p,a)					(p)->lpVtbl->Translate3fv(p,a)
#define IA3dGeom2_Rotate3f(p,a,b,c,d)				(p)->lpVtbl->Rotate3f(p,a,b,c,d)
#define IA3dGeom2_Rotate3fv(p,a,b)					(p)->lpVtbl->Rotate3fv(p,a,b)
#define IA3dGeom2_Scale3f(p,a,b,c)					(p)->lpVtbl->Scale3f(p,a,b,c)
#define IA3dGeom2_Scale3fv(p,a)						(p)->lpVtbl->Scale3fv(p,a)
#define IA3dGeom2_Begin(p,a)						(p)->lpVtbl->Begin(p,a)
#define IA3dGeom2_End(p)							(p)->lpVtbl->End(p)
#define IA3dGeom2_Vertex3f(p,a,b,c)					(p)->lpVtbl->Vertex3f(p,a,b,c)
#define IA3dGeom2_Vertex3fv(p,a)					(p)->lpVtbl->Vertex3fv(p,a)
#define IA3dGeom2_Normal3f(p,a,b,c)					(p)->lpVtbl->Normal3f(p,a,b,c)
#define IA3dGeom2_Normal3fv(p,a)					(p)->lpVtbl->Normal3fv(p,a)
#define IA3dGeom2_Tag(p,a)							(p)->lpVtbl->Tag(p,a)
#define IA3dGeom2_SetOpeningFactorf(p,a)			(p)->lpVtbl->SetOpeningFactorf(p,a)
#define IA3dGeom2_SetOpeningFactorfv(p,a)			(p)->lpVtbl->SetOpeningFactorfv(p,a)
#define IA3dGeom2_NewMaterial(p,a)					(p)->lpVtbl->NewMaterial(p,a)
#define IA3dGeom2_BindMaterial(p,a)					(p)->lpVtbl->BindMaterial(p,a)
#define IA3dGeom2_NewList(p,a)						(p)->lpVtbl->NewList(p,a)
#define IA3dGeom2_BindListener(p)					(p)->lpVtbl->BindListener(p)
#define IA3dGeom2_BindSource(p,a)					(p)->lpVtbl->BindSource(p,a)
#define IA3dGeom2_NewEnvironment(p,a)				(p)->lpVtbl->NewEnvironment(p,a)
#define IA3dGeom2_BindEnvironment(p,a)				(p)->lpVtbl->BindEnvironment(p,a)
#define IA3dGeom2_SetRenderMode(p,a)				(p)->lpVtbl->SetRenderMode(p,a)
#define IA3dGeom2_GetRenderMode(p,a)				(p)->lpVtbl->GetRenderMode(p,a)
#define IA3dGeom2_SetPolygonBloatFactor(p,a)		(p)->lpVtbl->SetPolygonBloatFactor(p,a)
#define IA3dGeom2_GetPolygonBloatFactor(p,a)		(p)->lpVtbl->GetPolygonBloatFactor(p,a)
#define IA3dGeom2_SetReflectionUpdateInterval(p,a)	(p)->lpVtbl->SetReflectionUpdateInterval(p,a)
#define IA3dGeom2_GetReflectionUpdateInterval(p,a)	(p)->lpVtbl->GetReflectionUpdateInterval(p,a)
#define IA3dGeom2_SetOcclusionUpdateInterval(p,a)	(p)->lpVtbl->SetOcclusionUpdateInterval(p,a)
#define IA3dGeom2_GetOcclusionUpdateInterval(p,a)	(p)->lpVtbl->GetOcclusionUpdateInterval(p,a)
#define IA3dGeom2_SetGeomReverbParam(p,a)			(p)->lpVtbl->SetGeomReverbParam(p,a)
#define IA3dGeom2_GetGeomReverbParam(p,a)			(p)->lpVtbl->GetGeomReverbParam(p,a)

#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dGeom2_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3dGeom2_AddRef(p)							(p)->AddRef()
#define IA3dGeom2_Release(p)						(p)->Release()
#define IA3dGeom2_Enable(p,a)						(p)->Enable(a)
#define IA3dGeom2_Disable(p,a)						(p)->Disable(a)
#define IA3dGeom2_IsEnabled(p,a)					(p)->IsEnabled(a)
#define IA3dGeom2_SetOcclusionMode(p,a)				(p)->SetOcclusionMode(a)
#define IA3dGeom2_GetOcclusionMode(p,a)				(p)->GetOcclusionMode(a)
#define IA3dGeom2_SetReflectionMode(p,a)			(p)->SetReflectionMode(a)
#define IA3dGeom2_GetReflectionMode(p,a)			(p)->GetReflectionMode(a)
#define IA3dGeom2_SetReflectionGainScale(p,a)		(p)->SetReflectionGainScale(a)
#define IA3dGeom2_GetReflectionGainScale(p,a)		(p)->GetReflectionGainScale(a)
#define IA3dGeom2_SetReflectionDelayScale(p,a)		(p)->SetReflectionDelayScale(a)
#define IA3dGeom2_GetReflectionDelayScale(p,a)		(p)->GetReflectionDelayScale(a)
#define IA3dGeom2_PushMatrix(p)						(p)->PushMatrix()
#define IA3dGeom2_PopMatrix(p)						(p)->PopMatrix()
#define IA3dGeom2_LoadIdentity(p)					(p)->LoadIdentity()
#define IA3dGeom2_LoadMatrix(p,a)					(p)->LoadMatrix(a)
#define IA3dGeom2_GetMatrix(p,a)					(p)->GetMatrix(a)
#define IA3dGeom2_MultMatrix(p,a)					(p)->MultMatrix(a)
#define IA3dGeom2_Translate3f(p,a,b,c)				(p)->Translate3f(a,b,c)
#define IA3dGeom2_Translate3fv(p,a)					(p)->Translate3fv(a)
#define IA3dGeom2_Rotate3f(p,a,b,c,d)				(p)->Rotate3f(a,b,c,d)
#define IA3dGeom2_Rotate3fv(p,a,b)					(p)->Rotate3fv(a,b)
#define IA3dGeom2_Scale3f(p,a,b,c)					(p)->Scale3f(a,b,c)
#define IA3dGeom2_Scale3fv(p,a)						(p)->Scale3fv(a)
#define IA3dGeom2_Begin(p,a)						(p)->Begin(a)
#define IA3dGeom2_End(p)							(p)->End()
#define IA3dGeom2_Vertex3f(p,a,b,c)					(p)->Vertex3f(a,b,c)
#define IA3dGeom2_Vertex3fv(p,a)					(p)->Vertex3fv(a)
#define IA3dGeom2_Normal3f(p,a,b,c)					(p)->Normal3f(a,b,c)
#define IA3dGeom2_Normal3fv(p,a)					(p)->Normal3fv(a)
#define IA3dGeom2_Tag(p,a)							(p)->Tag(a)
#define IA3dGeom2_SetOpeningFactorf(p,a)			(p)->SetOpeningFactorf(a)
#define IA3dGeom2_SetOpeningFactorfv(p,a)			(p)->SetOpeningFactorfv(a)
#define IA3dGeom2_NewMaterial(p,a)					(p)->NewMaterial(a)
#define IA3dGeom2_BindMaterial(p,a)					(p)->BindMaterial(a)
#define IA3dGeom2_NewList(p,a)						(p)->NewList(a)
#define IA3dGeom2_BindListener(p)					(p)->BindListener()
#define IA3dGeom2_BindSource(p,a)					(p)->BindSource(a)
#define IA3dGeom2_NewEnvironment(p,a)				(p)->NewEnvironment(a)
#define IA3dGeom2_BindEnvironment(p,a)				(p)->BindEnvironment(a)
#define IA3dGeom2_SetRenderMode(p,a)				(p)->SetRenderMode(a)
#define IA3dGeom2_GetRenderMode(p,a)				(p)->GetRenderMode(a)
#define IA3dGeom2_SetPolygonBloatFactor(p,a)		(p)->SetPolygonBloatFactor(a)
#define IA3dGeom2_GetPolygonBloatFactor(p,a)		(p)->GetPolygonBloatFactor(a)
#define IA3dGeom2_SetReflectionUpdateInterval(p,a)	(p)->SetReflectionUpdateInterval(a)
#define IA3dGeom2_GetReflectionUpdateInterval(p,a)	(p)->GetReflectionUpdateInterval(a)
#define IA3dGeom2_SetOcclusionUpdateInterval(p,a)	(p)->SetOcclusionUpdateInterval(a)
#define IA3dGeom2_GetOcclusionUpdateInterval(p,a)	(p)->GetOcclusionUpdateInterval(a)
#define IA3dGeom2_SetGeomReverbParam(p,a)			(p)->SetGeomReverbParam(a)
#define IA3dGeom2_GetGeomReverbParam(p,a)			(p)->GetGeomReverbParam(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dSource
//
// A sound source.
//===================================================================

// {C398E562-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3dSource, 0xc398e562, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3dSource

DECLARE_INTERFACE_(IA3dSource, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)			(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)			(THIS) PURE;
	STDMETHOD_(ULONG,Release)			(THIS) PURE;

	// IA3dSource Methods.
	STDMETHOD(LoadWaveFile)				(THIS_ LPSTR) PURE;
	STDMETHOD(LoadWaveData)				(THIS_ LPVOID, DWORD) PURE;
	STDMETHOD(AllocateWaveData)			(THIS_ INT) PURE;
	STDMETHOD(FreeWaveData)				(THIS) PURE;
	STDMETHOD(SetWaveFormat)			(THIS_ LPVOID) PURE;
	STDMETHOD(GetWaveFormat)			(THIS_ LPVOID) PURE;
	STDMETHOD(GetWaveSize)				(THIS) PURE;
	STDMETHOD(GetType)					(THIS_ LPDWORD) PURE;
	STDMETHOD(Lock)						(THIS_ DWORD, DWORD, LPVOID *, LPDWORD, LPVOID *, LPDWORD, DWORD) PURE;
	STDMETHOD(Unlock)					(THIS_ LPVOID, DWORD, LPVOID, DWORD) PURE;
	STDMETHOD(Play)						(THIS_ INT) PURE;
	STDMETHOD(Stop)						(THIS) PURE;
	STDMETHOD(Rewind)					(THIS) PURE;
	STDMETHOD(SetWaveTime)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetWaveTime)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetWavePosition)			(THIS_ DWORD) PURE;
	STDMETHOD(GetWavePosition)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetPosition3f)			(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetPosition3f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetPosition3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetPosition3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3f)	(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3f)	(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6f)			(THIS_ A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientation6f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientation6fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3f)			(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetVelocity3f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetVelocity3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetCone)					(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetCone)					(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetMinMaxDistance)		(THIS_ A3DVAL, A3DVAL, DWORD) PURE;
	STDMETHOD(GetMinMaxDistance)		(THIS_ LPA3DVAL, LPA3DVAL, LPDWORD) PURE;
	STDMETHOD(SetGain)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetGain)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPitch)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPitch)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDopplerScale)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDopplerScale)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDistanceModelScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDistanceModelScale)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetEq)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetEq)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPriority)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPriority)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetRenderMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetRenderMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(GetAudibility)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOcclusionFactor)		(THIS_ LPA3DVAL) PURE;
    STDMETHOD(GetStatus)				(THIS_ LPDWORD) PURE;
    STDMETHOD(SetPanValues)				(THIS_ DWORD, LPA3DVAL) PURE;
    STDMETHOD(GetPanValues)				(THIS_ DWORD, LPA3DVAL) PURE;
	STDMETHOD(SetWaveEvent)				(THIS_ DWORD, HANDLE) PURE;
	STDMETHOD(ClearWaveEvents)			(THIS) PURE;
	STDMETHOD(SetTransformMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetTransformMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionDelayScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionDelayScale)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionGainScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionGainScale)	(THIS_ LPA3DVAL) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dSource_QueryInterface(p,a,b)			(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dSource_AddRef(p)						(p)->lpVtbl->AddRef(p)
#define IA3dSource_Release(p)						(p)->lpVtbl->Release(p)
#define IA3dSource_LoadWaveFile(p,a)				(p)->lpVtbl->LoadWaveFile(p,a)
#define IA3dSource_LoadWaveData(p,a,b)				(p)->lpVtbl->LoadWaveData(p,a,b)
#define IA3dSource_AllocateWaveData(p,a)			(p)->lpVtbl->AllocateWaveData(p,a)
#define IA3dSource_FreeWaveData(p)					(p)->lpVtbl->FreeWaveData(p)
#define IA3dSource_SetWaveFormat(p,a)				(p)->lpVtbl->SetWaveFormat(p,a)
#define IA3dSource_GetWaveFormat(p,a)				(p)->lpVtbl->GetWaveFormat(p,a)
#define IA3dSource_GetWaveSize(p)					(p)->lpVtbl->GetWaveSize(p)
#define IA3dSource_GetType(p,a)						(p)->lpVtbl->GetType(p,a)
#define IA3dSource_Lock(p,a,b,c,d,e,f,g)			(p)->lpVtbl->Lock(p,a,b,c,d,e,f,g)
#define IA3dSource_Unlock(p,a,b,c,d)				(p)->lpVtbl->Unlock(p,a,b,c,d)
#define IA3dSource_Play(p,a)						(p)->lpVtbl->Play(p,a)
#define IA3dSource_Stop(p)							(p)->lpVtbl->Stop(p)
#define IA3dSource_Rewind(p)						(p)->lpVtbl->Rewind(p)
#define IA3dSource_SetWaveTime(p,a)					(p)->lpVtbl->SetWaveTime(p,a)
#define IA3dSource_GetWaveTime(p,a)					(p)->lpVtbl->GetWaveTime(p,a)
#define IA3dSource_SetWavePosition(p,a)				(p)->lpVtbl->SetWavePosition(p,a)
#define IA3dSource_GetWavePosition(p,a)				(p)->lpVtbl->GetWavePosition(p,a)
#define IA3dSource_SetPosition3f(p,a,b,c)			(p)->lpVtbl->SetPosition3f(p,a,b,c)
#define IA3dSource_GetPosition3f(p,a,b,c)			(p)->lpVtbl->GetPosition3f(p,a,b,c)
#define IA3dSource_SetPosition3fv(p,a)				(p)->lpVtbl->SetPosition3fv(p,a)
#define IA3dSource_GetPosition3fv(p,a)				(p)->lpVtbl->GetPosition3fv(p,a)
#define IA3dSource_SetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->SetOrientationAngles3f(p,a,b,c)
#define IA3dSource_GetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->GetOrientationAngles3f(p,a,b,c)
#define IA3dSource_SetOrientationAngles3fv(p,a)		(p)->lpVtbl->SetOrientationAngles3fv(p,a)
#define IA3dSource_GetOrientationAngles3fv(p,a)		(p)->lpVtbl->GetOrientationAngles3fv(p,a)
#define IA3dSource_SetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->SetOrientation6f(p,a,b,c,d,e,f)
#define IA3dSource_GetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->GetOrientation6f(p,a,b,c,d,e,f)
#define IA3dSource_SetOrientation6fv(p,a)			(p)->lpVtbl->SetOrientation6fv(p,a)
#define IA3dSource_GetOrientation6fv(p,a)			(p)->lpVtbl->GetOrientation6fv(p,a)
#define IA3dSource_SetVelocity3f(p,a,b,c)			(p)->lpVtbl->SetVelocity3f(p,a,b,c)
#define IA3dSource_GetVelocity3f(p,a,b,c)			(p)->lpVtbl->GetVelocity3f(p,a,b,c)
#define IA3dSource_SetVelocity3fv(p,a)				(p)->lpVtbl->SetVelocity3fv(p,a)
#define IA3dSource_GetVelocity3fv(p,a)				(p)->lpVtbl->GetVelocity3fv(p,a)
#define IA3dSource_SetCone(p,a,b,c)					(p)->lpVtbl->SetCone(p,a,b,c)
#define IA3dSource_GetCone(p,a,b,c)					(p)->lpVtbl->GetCone(p,a,b,c)
#define IA3dSource_SetMinMaxDistance(p,a,b,c)		(p)->lpVtbl->SetMinMaxDistance(p,a,b,c)
#define IA3dSource_GetMinMaxDistance(p,a,b,c)		(p)->lpVtbl->GetMinMaxDistance(p,a,b,c)
#define IA3dSource_SetGain(p,a)						(p)->lpVtbl->SetGain(p,a)
#define IA3dSource_GetGain(p,a)						(p)->lpVtbl->GetGain(p,a)
#define IA3dSource_SetPitch(p,a)					(p)->lpVtbl->SetPitch(p,a)
#define IA3dSource_GetPitch(p,a)					(p)->lpVtbl->GetPitch(p,a)
#define IA3dSource_SetDopplerScale(p,a)				(p)->lpVtbl->SetDopplerScale(p,a)
#define IA3dSource_GetDopplerScale(p,a)				(p)->lpVtbl->GetDopplerScale(p,a)
#define IA3dSource_SetDistanceModelScale(p,a)		(p)->lpVtbl->SetDistanceModelScale(p,a)
#define IA3dSource_GetDistanceModelScale(p,a)		(p)->lpVtbl->GetDistanceModelScale(p,a)
#define IA3dSource_SetEq(p,a)						(p)->lpVtbl->SetEq(p,a)
#define IA3dSource_GetEq(p,a)						(p)->lpVtbl->GetEq(p,a)
#define IA3dSource_SetPriority(p,a)					(p)->lpVtbl->SetPriority(p,a)
#define IA3dSource_GetPriority(p,a)					(p)->lpVtbl->GetPriority(p,a)
#define IA3dSource_SetRenderMode(p,a)				(p)->lpVtbl->SetRenderMode(p,a)
#define IA3dSource_GetRenderMode(p,a)				(p)->lpVtbl->GetRenderMode(p,a)
#define IA3dSource_GetAudibility(p,a)				(p)->lpVtbl->GetAudibility(p,a)
#define IA3dSource_GetOcclusionFactor(p,a)			(p)->lpVtbl->GetOcclusionFactor(p,a)
#define IA3dSource_GetStatus(p,a)					(p)->lpVtbl->GetStatus(p,a)
#define IA3dSource_SetPanValues(p,a,b)				(p)->lpVtbl->SetPanValues(p,a,b)
#define IA3dSource_GetPanValues(p,a,b)				(p)->lpVtbl->GetPanValues(p,a,b)
#define IA3dSource_SetWaveEvent(p,a,b)				(p)->lpVtbl->SetWaveEvent(p,a,b)
#define IA3dSource_ClearWaveEvents(p)				(p)->lpVtbl->ClearWaveEvents(p)
#define IA3dSource_SetTransformMode(p,a)			(p)->lpVtbl->SetTransformMode(p,a)
#define IA3dSource_GetTransformMode(p,a)			(p)->lpVtbl->GetTransformMode(p,a)
#define IA3dSource_SetReflectionDelayScale(p,a)		(p)->lpVtbl->SetReflectionDelayScale(p,a)
#define IA3dSource_GetReflectionDelayScale(p,a)		(p)->lpVtbl->GetReflectionDelayScale(p,a)
#define IA3dSource_SetReflectionGainScale(p,a)		(p)->lpVtbl->SetReflectionGainScale(p,a)
#define IA3dSource_GetReflectionGainScale(p,a)		(p)->lpVtbl->GetReflectionGainScale(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dSource_QueryInterface(p,a,b)			(p)->QueryInterface(a,b)
#define IA3dSource_AddRef(p)						(p)->AddRef()
#define IA3dSource_Release(p)						(p)->Release()
#define IA3dSource_LoadWaveFile(p,a)				(p)->LoadWaveFile(a)
#define IA3dSource_LoadWaveData(p,a,b)				(p)->LoadWaveData(a,b)
#define IA3dSource_AllocateWaveData(p,a)			(p)->AllocateWaveData(a)
#define IA3dSource_FreeWaveData(p)					(p)->FreeWaveData()
#define IA3dSource_SetWaveFormat(p,a)				(p)->SetWaveFormat(a)
#define IA3dSource_GetWaveFormat(p,a)				(p)->GetWaveFormat(a)
#define IA3dSource_GetWaveSize(p)					(p)->GetWaveSize()
#define IA3dSource_GetType(p,a)						(p)->GetType(a)
#define IA3dSource_Lock(p,a,b,c,d,e,f,g)			(p)->Lock(a,b,c,d,e,f,g)
#define IA3dSource_Unlock(p,a,b,c,d)				(p)->Unlock(a,b,c,d)
#define IA3dSource_Play(p,a)						(p)->Play(a)
#define IA3dSource_Stop(p)							(p)->Stop()
#define IA3dSource_Rewind(p)						(p)->Rewind()
#define IA3dSource_SetWaveTime(p,a)					(p)->SetWaveTime(a)
#define IA3dSource_GetWaveTime(p,a)					(p)->GetWaveTime(a)
#define IA3dSource_SetWavePosition(p,a)				(p)->SetWavePosition(a)
#define IA3dSource_GetWavePosition(p,a)				(p)->GetWavePosition(a)
#define IA3dSource_SetPosition3f(p,a,b,c)			(p)->SetPosition3f(a,b,c)
#define IA3dSource_GetPosition3f(p,a,b,c)			(p)->GetPosition3f(a,b,c)
#define IA3dSource_SetPosition3fv(p,a)				(p)->SetPosition3fv(a)
#define IA3dSource_GetPosition3fv(p,a)				(p)->GetPosition3fv(a)
#define IA3dSource_SetOrientationAngles3f(p,a,b,c)	(p)->SetOrientationAngles3f(a,b,c)
#define IA3dSource_GetOrientationAngles3f(p,a,b,c)	(p)->GetOrientationAngles3f(a,b,c)
#define IA3dSource_SetOrientationAngles3fv(p,a)		(p)->SetOrientationAngles3fv(a)
#define IA3dSource_GetOrientationAngles3fv(p,a)		(p)->GetOrientationAngles3fv(a)
#define IA3dSource_SetOrientation6f(p,a,b,c,d,e,f)	(p)->SetOrientation6f(a,b,c,d,e,f)
#define IA3dSource_GetOrientation6f(p,a,b,c,d,e,f)	(p)->GetOrientation6f(a,b,c,d,e,f)
#define IA3dSource_SetOrientation6fv(p,a)			(p)->SetOrientation6fv(a)
#define IA3dSource_GetOrientation6fv(p,a)			(p)->GetOrientation6fv(a)
#define IA3dSource_SetVelocity3f(p,a,b,c)			(p)->SetVelocity3f(a,b,c)
#define IA3dSource_GetVelocity3f(p,a,b,c)			(p)->GetVelocity3f(a,b,c)
#define IA3dSource_SetVelocity3fv(p,a)				(p)->SetVelocity3fv(a)
#define IA3dSource_GetVelocity3fv(p,a)				(p)->GetVelocity3fv(a)
#define IA3dSource_SetCone(p,a,b,c)					(p)->SetCone(a,b,c)
#define IA3dSource_GetCone(p,a,b,c)					(p)->GetCone(a,b,c)
#define IA3dSource_SetMinMaxDistance(p,a,b,c)		(p)->SetMinMaxDistance(a,b,c)
#define IA3dSource_GetMinMaxDistance(p,a,b,c)		(p)->GetMinMaxDistance(a,b,c)
#define IA3dSource_SetGain(p,a)						(p)->SetGain(a)
#define IA3dSource_GetGain(p,a)						(p)->GetGain(a)
#define IA3dSource_SetPitch(p,a)					(p)->SetPitch(a)
#define IA3dSource_GetPitch(p,a)					(p)->GetPitch(a)
#define IA3dSource_SetDopplerScale(p,a)				(p)->SetDopplerScale(a)
#define IA3dSource_GetDopplerScale(p,a)				(p)->GetDopplerScale(a)
#define IA3dSource_SetDistanceModelScale(p,a)		(p)->SetDistanceModelScale(a)
#define IA3dSource_GetDistanceModelScale(p,a)		(p)->GetDistanceModelScale(a)
#define IA3dSource_SetEq(p,a)						(p)->SetEq(a)
#define IA3dSource_GetEq(p,a)						(p)->GetEq(a)
#define IA3dSource_SetPriority(p,a)					(p)->SetPriority(a)
#define IA3dSource_GetPriority(p,a)					(p)->GetPriority(a)
#define IA3dSource_SetRenderMode(p,a)				(p)->SetRenderMode(a)
#define IA3dSource_GetRenderMode(p,a)				(p)->GetRenderMode(a)
#define IA3dSource_GetAudibility(p,a)				(p)->GetAudibility(a)
#define IA3dSource_GetOcclusionFactor(p,a)			(p)->GetOcclusionFactor(a)
#define IA3dSource_GetStatus(p,a)					(p)->GetStatus(a)
#define IA3dSource_SetPanValues(p,a,b)				(p)->SetPanValues(a,b)
#define IA3dSource_GetPanValues(p,a,b)				(p)->GetPanValues(a,b)
#define IA3dSource_SetWaveEvent(p,a,b)				(p)->SetWaveEvent(a,b)
#define IA3dSource_ClearWaveEvents(p)				(p)->ClearWaveEvents()
#define IA3dSource_SetTransformMode(p,a)			(p)->SetTransformMode(a)
#define IA3dSource_GetTransformMode(p,a)			(p)->GetTransformMode(a)
#define IA3dSource_SetReflectionDelayScale(p,a)		(p)->SetReflectionDelayScale(a)
#define IA3dSource_GetReflectionDelayScale(p,a)		(p)->GetReflectionDelayScale(a)
#define IA3dSource_SetReflectionGainScale(p,a)		(p)->SetReflectionGainScale(a)
#define IA3dSource_GetReflectionGainScale(p,a)		(p)->GetReflectionGainScale(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dSource2
//
// A sound source version 2
//===================================================================

// {3D54C5C1-2A5C-11d3-A87F-00600879F3EE}
DEFINE_GUID(IID_IA3dSource2,0x3d54c5c1, 0x2a5c, 0x11d3, 0xa8, 0x7f, 0x0, 0x60, 0x8, 0x79, 0xf3, 0xee);

#undef INTERFACE
#define INTERFACE IA3dSource2

DECLARE_INTERFACE_(IA3dSource2, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)			(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)			(THIS) PURE;
	STDMETHOD_(ULONG,Release)			(THIS) PURE;

	// IA3dSource Methods.
	STDMETHOD(LoadWaveFile)				(THIS_ LPSTR) PURE;
	STDMETHOD(LoadWaveData)				(THIS_ LPVOID, DWORD) PURE;
	STDMETHOD(AllocateAudioData)		(THIS_ INT) PURE;
	STDMETHOD(FreeAudioData)			(THIS) PURE;
	STDMETHOD(SetAudioFormat)			(THIS_ LPVOID) PURE;
	STDMETHOD(GetAudioFormat)			(THIS_ LPVOID) PURE;
	STDMETHOD_(DWORD,GetAudioSize)		(THIS) PURE;
	STDMETHOD(GetType)					(THIS_ LPDWORD) PURE;
	STDMETHOD(Lock)						(THIS_ DWORD, DWORD, LPVOID *, LPDWORD, LPVOID *, LPDWORD, DWORD) PURE;
	STDMETHOD(Unlock)					(THIS_ LPVOID, DWORD, LPVOID, DWORD) PURE;
	STDMETHOD(Play)						(THIS_ INT) PURE;
	STDMETHOD(Stop)						(THIS) PURE;
	STDMETHOD(Rewind)					(THIS) PURE;
	STDMETHOD(SetPlayTime)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPlayTime)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPlayPosition)			(THIS_ DWORD) PURE;
	STDMETHOD(GetPlayPosition)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetPosition3f)			(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetPosition3f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetPosition3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetPosition3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3f)	(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3f)	(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6f)			(THIS_ A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientation6f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientation6fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3f)			(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetVelocity3f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetVelocity3fv)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetCone)					(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetCone)					(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetMinMaxDistance)		(THIS_ A3DVAL, A3DVAL, DWORD) PURE;
	STDMETHOD(GetMinMaxDistance)		(THIS_ LPA3DVAL, LPA3DVAL, LPDWORD) PURE;
	STDMETHOD(SetGain)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetGain)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPitch)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPitch)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDopplerScale)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDopplerScale)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDistanceModelScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDistanceModelScale)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetEq)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetEq)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPriority)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPriority)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetRenderMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetRenderMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(GetAudibility)			(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOcclusionFactor)		(THIS_ LPA3DVAL) PURE;
    STDMETHOD(GetStatus)				(THIS_ LPDWORD) PURE;
    STDMETHOD(SetPanValues)				(THIS_ DWORD, LPA3DVAL) PURE;
    STDMETHOD(GetPanValues)				(THIS_ DWORD, LPA3DVAL) PURE;
	STDMETHOD(SetPlayEvent)				(THIS_ DWORD, HANDLE) PURE;
	STDMETHOD(ClearPlayEvents)			(THIS) PURE;
	STDMETHOD(SetTransformMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetTransformMode)			(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectionDelayScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionDelayScale)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetReflectionGainScale)	(THIS_ A3DVAL) PURE;
	STDMETHOD(GetReflectionGainScale)	(THIS_ LPA3DVAL) PURE;

	// IA3dSource2 interface
	STDMETHOD(SetVolumetricBounds)		(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetVolumetricBounds)		(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetVolumetricDamping)		(THIS_ A3DVOLSRCDAMPINFO *) PURE;
	STDMETHOD(GetVolumetricDamping)		(THIS_ A3DVOLSRCDAMPINFO *) PURE;
	STDMETHOD(SetReverbMix)				(THIS_ A3DVAL, A3DVAL) PURE;
    STDMETHOD(GetReverbMix)				(THIS_ A3DVAL *, A3DVAL *) PURE;

	STDMETHOD(NewManualReflection)		(THIS_ LPA3DREFLECTION *) PURE;
	STDMETHOD(FreeManualReflections)	(THIS) PURE;
	STDMETHOD(GetNumManualReflections)	(THIS_ int *) PURE;

	STDMETHOD(LoadFile)					(THIS_ char *szFile, DWORD dwFormat) PURE;
	
	STDMETHOD(GetCaps)					(THIS_ LPA3DCAPS_SOURCE lpSourceCaps) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dSource2_QueryInterface(p,a,b)			(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dSource2_AddRef(p)						(p)->lpVtbl->AddRef(p)
#define IA3dSource2_Release(p)						(p)->lpVtbl->Release(p)
#define IA3dSource2_LoadWaveFile(p,a)				(p)->lpVtbl->LoadWaveFile(p,a)
#define IA3dSource2_LoadWaveData(p,a,b)				(p)->lpVtbl->LoadWaveData(p,a,b)
#define IA3dSource2_AllocateAudioData(p,a)			(p)->lpVtbl->AllocateAudioData(p,a)
#define IA3dSource2_FreeAudioData(p)				(p)->lpVtbl->FreeAudioData(p)
#define IA3dSource2_SetAudioFormat(p,a)				(p)->lpVtbl->SetAudioFormat(p,a)
#define IA3dSource2_GetAudioFormat(p,a)				(p)->lpVtbl->GetAudioFormat(p,a)
#define IA3dSource2_GetAudioSize(p)					(p)->lpVtbl->GetAudioSize(p)
#define IA3dSource2_GetType(p,a)					(p)->lpVtbl->GetType(p,a)
#define IA3dSource2_Lock(p,a,b,c,d,e,f,g)			(p)->lpVtbl->Lock(p,a,b,c,d,e,f,g)
#define IA3dSource2_Unlock(p,a,b,c,d)				(p)->lpVtbl->Unlock(p,a,b,c,d)
#define IA3dSource2_Play(p,a)						(p)->lpVtbl->Play(p,a)
#define IA3dSource2_Stop(p)							(p)->lpVtbl->Stop(p)
#define IA3dSource2_Rewind(p)						(p)->lpVtbl->Rewind(p)
#define IA3dSource2_SetPlayTime(p,a)				(p)->lpVtbl->SetPlayTime(p,a)
#define IA3dSource2_GetPlayTime(p,a)				(p)->lpVtbl->GetPlayTime(p,a)
#define IA3dSource2_SetPlayPosition(p,a)			(p)->lpVtbl->SetPlayPosition(p,a)
#define IA3dSource2_GetPlayPosition(p,a)			(p)->lpVtbl->GetPlayPosition(p,a)
#define IA3dSource2_SetPosition3f(p,a,b,c)			(p)->lpVtbl->SetPosition3f(p,a,b,c)
#define IA3dSource2_GetPosition3f(p,a,b,c)			(p)->lpVtbl->GetPosition3f(p,a,b,c)
#define IA3dSource2_SetPosition3fv(p,a)				(p)->lpVtbl->SetPosition3fv(p,a)
#define IA3dSource2_GetPosition3fv(p,a)				(p)->lpVtbl->GetPosition3fv(p,a)
#define IA3dSource2_SetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->SetOrientationAngles3f(p,a,b,c)
#define IA3dSource2_GetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->GetOrientationAngles3f(p,a,b,c)
#define IA3dSource2_SetOrientationAngles3fv(p,a)	(p)->lpVtbl->SetOrientationAngles3fv(p,a)
#define IA3dSource2_GetOrientationAngles3fv(p,a)	(p)->lpVtbl->GetOrientationAngles3fv(p,a)
#define IA3dSource2_SetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->SetOrientation6f(p,a,b,c,d,e,f)
#define IA3dSource2_GetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->GetOrientation6f(p,a,b,c,d,e,f)
#define IA3dSource2_SetOrientation6fv(p,a)			(p)->lpVtbl->SetOrientation6fv(p,a)
#define IA3dSource2_GetOrientation6fv(p,a)			(p)->lpVtbl->GetOrientation6fv(p,a)
#define IA3dSource2_SetVelocity3f(p,a,b,c)			(p)->lpVtbl->SetVelocity3f(p,a,b,c)
#define IA3dSource2_GetVelocity3f(p,a,b,c)			(p)->lpVtbl->GetVelocity3f(p,a,b,c)
#define IA3dSource2_SetVelocity3fv(p,a)				(p)->lpVtbl->SetVelocity3fv(p,a)
#define IA3dSource2_GetVelocity3fv(p,a)				(p)->lpVtbl->GetVelocity3fv(p,a)
#define IA3dSource2_SetCone(p,a,b,c)				(p)->lpVtbl->SetCone(p,a,b,c)
#define IA3dSource2_GetCone(p,a,b,c)				(p)->lpVtbl->GetCone(p,a,b,c)
#define IA3dSource2_SetMinMaxDistance(p,a,b,c)		(p)->lpVtbl->SetMinMaxDistance(p,a,b,c)
#define IA3dSource2_GetMinMaxDistance(p,a,b,c)		(p)->lpVtbl->GetMinMaxDistance(p,a,b,c)
#define IA3dSource2_SetGain(p,a)					(p)->lpVtbl->SetGain(p,a)
#define IA3dSource2_GetGain(p,a)					(p)->lpVtbl->GetGain(p,a)
#define IA3dSource2_SetPitch(p,a)					(p)->lpVtbl->SetPitch(p,a)
#define IA3dSource2_GetPitch(p,a)					(p)->lpVtbl->GetPitch(p,a)
#define IA3dSource2_SetDopplerScale(p,a)			(p)->lpVtbl->SetDopplerScale(p,a)
#define IA3dSource2_GetDopplerScale(p,a)			(p)->lpVtbl->GetDopplerScale(p,a)
#define IA3dSource2_SetDistanceModelScale(p,a)		(p)->lpVtbl->SetDistanceModelScale(p,a)
#define IA3dSource2_GetDistanceModelScale(p,a)		(p)->lpVtbl->GetDistanceModelScale(p,a)
#define IA3dSource2_SetEq(p,a)						(p)->lpVtbl->SetEq(p,a)
#define IA3dSource2_GetEq(p,a)						(p)->lpVtbl->GetEq(p,a)
#define IA3dSource2_SetPriority(p,a)				(p)->lpVtbl->SetPriority(p,a)
#define IA3dSource2_GetPriority(p,a)				(p)->lpVtbl->GetPriority(p,a)
#define IA3dSource2_SetRenderMode(p,a)				(p)->lpVtbl->SetRenderMode(p,a)
#define IA3dSource2_GetRenderMode(p,a)				(p)->lpVtbl->GetRenderMode(p,a)
#define IA3dSource2_GetAudibility(p,a)				(p)->lpVtbl->GetAudibility(p,a)
#define IA3dSource2_GetOcclusionFactor(p,a)			(p)->lpVtbl->GetOcclusionFactor(p,a)
#define IA3dSource2_GetStatus(p,a)					(p)->lpVtbl->GetStatus(p,a)
#define IA3dSource2_SetPanValues(p,a,b)				(p)->lpVtbl->SetPanValues(p,a,b)
#define IA3dSource2_GetPanValues(p,a,b)				(p)->lpVtbl->GetPanValues(p,a,b)
#define IA3dSource2_SetPlayEvent(p,a,b)				(p)->lpVtbl->SetPlayEvent(p,a,b)
#define IA3dSource2_ClearPlayEvents(p)				(p)->lpVtbl->ClearPlayEvents(p)
#define IA3dSource2_SetTransformMode(p,a)			(p)->lpVtbl->SetTransformMode(p,a)
#define IA3dSource2_GetTransformMode(p,a)			(p)->lpVtbl->GetTransformMode(p,a)
#define IA3dSource2_SetReflectionDelayScale(p,a)	(p)->lpVtbl->SetReflectionDelayScale(p,a)
#define IA3dSource2_GetReflectionDelayScale(p,a)	(p)->lpVtbl->GetReflectionDelayScale(p,a)
#define IA3dSource2_SetReflectionGainScale(p,a)		(p)->lpVtbl->SetReflectionGainScale(p,a)
#define IA3dSource2_GetReflectionGainScale(p,a)		(p)->lpVtbl->GetReflectionGainScale(p,a)
#define IA3dSource2_SetVolumetricBounds(p,a,b,c)	(p)->lpVtbl->SetVolumetricBounds(p,a,b,c)
#define IA3dSource2_GetVolumetricBounds(p,a,b,c)	(p)->lpVtbl->GetVolumetricBounds(p,a,b,c)
#define IA3dSource2_SetVolumetricDamping(p,a)		(p)->lpVtbl->SetVolumetricDamping(p,a)
#define IA3dSource2_GetVolumetricDamping(p,a)		(p)->lpVtbl->GetVolumetricDamping(p,a)
#define IA3dSource2_SetReverbMix(p,a,b)				(p)->lpVtbl->SetReverbMix(p,a,b)
#define IA3dSource2_GetReverbMix(p,a,b)				(p)->lpVtbl->GetReverbMix(p,a,b)
#define IA3dSource2_NewManualReflection(p, a)		(p)->lpVtbl->NewManualReflection(p,a)
#define IA3dSource2_FreeManualReflections(p)		(p)->lpVtbl->FreeManualReflections(p)
#define IA3dSource2_GetNumManualReflections(p, a)	(p)->lpVtbl->GetNumManualReflections(p,a)
#define	IA3dSource2_LoadFile(p,a,b)					(p)->lpVtbl->LoadFile(p,a,b)
#define IA3dSource2_GetCaps(p,a)					(p)->lpVtbl->GetCaps(p,a)


#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dSource2_QueryInterface(p,a,b)			(p)->QueryInterface(a,b)
#define IA3dSource2_AddRef(p)						(p)->AddRef()
#define IA3dSource2_Release(p)						(p)->Release()
#define IA3dSource2_LoadWaveFile(p,a)				(p)->LoadWaveFile(a)
#define IA3dSource2_LoadWaveData(p,a,b)				(p)->LoadWaveData(a,b)
#define IA3dSource2_AllocateAudioData(p,a)			(p)->AllocateAudioData(a)
#define IA3dSource2_FreeAudioData(p)				(p)->FreeAudioData()
#define IA3dSource2_SetAudioFormat(p,a)				(p)->SetAudioFormat(a)
#define IA3dSource2_GetAudioFormat(p,a)				(p)->GetAudioFormat(a)
#define IA3dSource2_GetAudioSize(p)					(p)->GetAudioSize()
#define IA3dSource2_GetType(p,a)					(p)->GetType(a)
#define IA3dSource2_Lock(p,a,b,c,d,e,f,g)			(p)->Lock(a,b,c,d,e,f,g)
#define IA3dSource2_Unlock(p,a,b,c,d)				(p)->Unlock(a,b,c,d)
#define IA3dSource2_Play(p,a)						(p)->Play(a)
#define IA3dSource2_Stop(p)							(p)->Stop()
#define IA3dSource2_Rewind(p)						(p)->Rewind()
#define IA3dSource2_SetPlayTime(p,a)				(p)->SetPlayTime(a)
#define IA3dSource2_GetPlayTime(p,a)				(p)->GetPlayTime(a)
#define IA3dSource2_SetPlayPosition(p,a)			(p)->SetPlayPosition(a)
#define IA3dSource2_GetPlayPosition(p,a)			(p)->GetPlayPosition(a)
#define IA3dSource2_SetPosition3f(p,a,b,c)			(p)->SetPosition3f(a,b,c)
#define IA3dSource2_GetPosition3f(p,a,b,c)			(p)->GetPosition3f(a,b,c)
#define IA3dSource2_SetPosition3fv(p,a)				(p)->SetPosition3fv(a)
#define IA3dSource2_GetPosition3fv(p,a)				(p)->GetPosition3fv(a)
#define IA3dSource2_SetOrientationAngles3f(p,a,b,c)	(p)->SetOrientationAngles3f(a,b,c)
#define IA3dSource2_GetOrientationAngles3f(p,a,b,c)	(p)->GetOrientationAngles3f(a,b,c)
#define IA3dSource2_SetOrientationAngles3fv(p,a)	(p)->SetOrientationAngles3fv(a)
#define IA3dSource2_GetOrientationAngles3fv(p,a)	(p)->GetOrientationAngles3fv(a)
#define IA3dSource2_SetOrientation6f(p,a,b,c,d,e,f)	(p)->SetOrientation6f(a,b,c,d,e,f)
#define IA3dSource2_GetOrientation6f(p,a,b,c,d,e,f)	(p)->GetOrientation6f(a,b,c,d,e,f)
#define IA3dSource2_SetOrientation6fv(p,a)			(p)->SetOrientation6fv(a)
#define IA3dSource2_GetOrientation6fv(p,a)			(p)->GetOrientation6fv(a)
#define IA3dSource2_SetVelocity3f(p,a,b,c)			(p)->SetVelocity3f(a,b,c)
#define IA3dSource2_GetVelocity3f(p,a,b,c)			(p)->GetVelocity3f(a,b,c)
#define IA3dSource2_SetVelocity3fv(p,a)				(p)->SetVelocity3fv(a)
#define IA3dSource2_GetVelocity3fv(p,a)				(p)->GetVelocity3fv(a)
#define IA3dSource2_SetCone(p,a,b,c)				(p)->SetCone(a,b,c)
#define IA3dSource2_GetCone(p,a,b,c)				(p)->GetCone(a,b,c)
#define IA3dSource2_SetMinMaxDistance(p,a,b,c)		(p)->SetMinMaxDistance(a,b,c)
#define IA3dSource2_GetMinMaxDistance(p,a,b,c)		(p)->GetMinMaxDistance(a,b,c)
#define IA3dSource2_SetGain(p,a)					(p)->SetGain(a)
#define IA3dSource2_GetGain(p,a)					(p)->GetGain(a)
#define IA3dSource2_SetPitch(p,a)					(p)->SetPitch(a)
#define IA3dSource2_GetPitch(p,a)					(p)->GetPitch(a)
#define IA3dSource2_SetDopplerScale(p,a)			(p)->SetDopplerScale(a)
#define IA3dSource2_GetDopplerScale(p,a)			(p)->GetDopplerScale(a)
#define IA3dSource2_SetDistanceModelScale(p,a)		(p)->SetDistanceModelScale(a)
#define IA3dSource2_GetDistanceModelScale(p,a)		(p)->GetDistanceModelScale(a)
#define IA3dSource2_SetEq(p,a)						(p)->SetEq(a)
#define IA3dSource2_GetEq(p,a)						(p)->GetEq(a)
#define IA3dSource2_SetPriority(p,a)				(p)->SetPriority(a)
#define IA3dSource2_GetPriority(p,a)				(p)->GetPriority(a)
#define IA3dSource2_SetRenderMode(p,a)				(p)->SetRenderMode(a)
#define IA3dSource2_GetRenderMode(p,a)				(p)->GetRenderMode(a)
#define IA3dSource2_GetAudibility(p,a)				(p)->GetAudibility(a)
#define IA3dSource2_GetOcclusionFactor(p,a)			(p)->GetOcclusionFactor(a)
#define IA3dSource2_GetStatus(p,a)					(p)->GetStatus(a)
#define IA3dSource2_SetPanValues(p,a,b)				(p)->SetPanValues(a,b)
#define IA3dSource2_GetPanValues(p,a,b)				(p)->GetPanValues(a,b)
#define IA3dSource2_SetPlayEvent(p,a,b)				(p)->SetPlayEvent(a,b)
#define IA3dSource2_ClearPlayEvents(p)				(p)->ClearPlayEvents()
#define IA3dSource2_SetTransformMode(p,a)			(p)->SetTransformMode(a)
#define IA3dSource2_GetTransformMode(p,a)			(p)->GetTransformMode(a)
#define IA3dSource2_SetReflectionDelayScale(p,a)	(p)->SetReflectionDelayScale(a)
#define IA3dSource2_GetReflectionDelayScale(p,a)	(p)->GetReflectionDelayScale(a)
#define IA3dSource2_SetReflectionGainScale(p,a)		(p)->SetReflectionGainScale(a)
#define IA3dSource2_GetReflectionGainScale(p,a)		(p)->GetReflectionGainScale(a)
#define IA3dSource2_SetVolumetricBounds(p,a,b,c)	(p)->SetVolumetricBounds(a,b,c)
#define IA3dSource2_GetVolumetricBounds(p,a,b,c)	(p)->GetVolumetricBounds(a,b,c)
#define IA3dSource2_SetVolumetricDamping(p,a)		(p)->SetVolumetricDamping(a)
#define IA3dSource2_GetVolumetricDamping(p,a)		(p)->GetVolumetricDamping(a)
#define IA3dSource2_SetReverbMix(p,a,b)				(p)->SetReverbMix(a,b)
#define IA3dSource2_GetReverbMix(p,a,b)				(p)->GetReverbMix(a,b)
#define IA3dSource2_NewManualReflection(p, a)		(p)->NewManualReflection(a)
#define IA3dSource2_FreeManualReflections(p)		(p)->FreeManualReflections()
#define IA3dSource2_GetNumManualReflections(p, a)	(p)->GetNumManualReflections(a)
#define	IA3dSource2_LoadFile(p,a,b)					(p)->LoadFile(a,b)
#define IA3dSource2_GetCaps(p,a)					(p)->GetCaps(a)

#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dListener
//
// There is only one listener in A3D.
//===================================================================

// {C398E563-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3dListener, 0xc398e563, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3dListener

DECLARE_INTERFACE_(IA3dListener, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)		(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)		(THIS) PURE;
	STDMETHOD_(ULONG,Release)		(THIS) PURE;

	// IA3dListener Methods.
	STDMETHOD(SetPosition3f)		(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetPosition3f)		(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetPosition3fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetPosition3fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3f)	(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3f)	(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientationAngles3fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6f)		(THIS_ A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetOrientation6f)		(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetOrientation6fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetOrientation6fv)	(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3f)		(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetVelocity3f)		(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetVelocity3fv)		(THIS_ LPA3DVAL) PURE;
	STDMETHOD(GetVelocity3fv)		(THIS_ LPA3DVAL) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dListener_QueryInterface(p,a,b)				(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dListener_AddRef(p)							(p)->lpVtbl->AddRef(p)
#define IA3dListener_Release(p)							(p)->lpVtbl->Release(p)
#define IA3dListener_SetPosition3f(p,a,b,c)				(p)->lpVtbl->SetPosition3f(p,a,b,c)
#define IA3dListener_GetPosition3f(p,a,b,c)				(p)->lpVtbl->GetPosition3f(p,a,b,c)
#define IA3dListener_SetPosition3fv(p,a)				(p)->lpVtbl->SetPosition3fv(p,a)
#define IA3dListener_GetPosition3fv(p,a)				(p)->lpVtbl->GetPosition3fv(p,a)
#define IA3dListener_SetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->SetOrientationAngles3f(p,a,b,c)
#define IA3dListener_GetOrientationAngles3f(p,a,b,c)	(p)->lpVtbl->GetOrientationAngles3f(p,a,b,c)
#define IA3dListener_SetOrientationAngles3fv(p,a)		(p)->lpVtbl->SetOrientationAngles3fv(p,a)
#define IA3dListener_GetOrientationAngles3fv(p,a)		(p)->lpVtbl->GetOrientationAngles3fv(p,a)
#define IA3dListener_SetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->SetOrientation6f(p,a,b,c,d,e,f)
#define IA3dListener_GetOrientation6f(p,a,b,c,d,e,f)	(p)->lpVtbl->GetOrientation6f(p,a,b,c,d,e,f)
#define IA3dListener_SetOrientation6fv(p,a)				(p)->lpVtbl->SetOrientation6fv(p,a)
#define IA3dListener_GetOrientation6fv(p,a)				(p)->lpVtbl->GetOrientation6fv(p,a)
#define IA3dListener_SetVelocity3f(p,a,b,c)				(p)->lpVtbl->SetVelocity3f(p,a,b,c)
#define IA3dListener_GetVelocity3f(p,a,b,c)				(p)->lpVtbl->GetVelocity3f(p,a,b,c)
#define IA3dListener_SetVelocity3fv(p,a)				(p)->lpVtbl->SetVelocity3fv(p,a)
#define IA3dListener_GetVelocity3fv(p,a)				(p)->lpVtbl->GetVelocity3fv(p,a)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dListener_QueryInterface(p,a,b)				(p)->QueryInterface(a,b)
#define IA3dListener_AddRef(p)							(p)->AddRef()
#define IA3dListener_Release(p)							(p)->Release()
#define IA3dListener_SetPosition3f(p,a,b,c)				(p)->SetPosition3f(a,b,c)
#define IA3dListener_GetPosition3f(p,a,b,c)				(p)->GetPosition3f(a,b,c)
#define IA3dListener_SetPosition3fv(p,a)				(p)->SetPosition3fv(a)
#define IA3dListener_GetPosition3fv(p,a)				(p)->GetPosition3fv(a)
#define IA3dListener_SetOrientationAngles3f(p,a,b,c)	(p)->SetOrientationAngles3f(a,b,c)
#define IA3dListener_GetOrientationAngles3f(p,a,b,c)	(p)->GetOrientationAngles3f(a,b,c)
#define IA3dListener_SetOrientationAngles3fv(p,a)		(p)->SetOrientationAngles3fv(a)
#define IA3dListener_GetOrientationAngles3fv(p,a)		(p)->GetOrientationAngles3fv(a)
#define IA3dListener_SetOrientation6f(p,a,b,c,d,e,f)	(p)->SetOrientation6f(a,b,c,d,e,f)
#define IA3dListener_GetOrientation6f(p,a,b,c,d,e,f)	(p)->GetOrientation6f(a,b,c,d,e,f)
#define IA3dListener_SetOrientation6fv(p,a)				(p)->SetOrientation6fv(a)
#define IA3dListener_GetOrientation6fv(p,a)				(p)->GetOrientation6fv(a)
#define IA3dListener_SetVelocity3f(p,a,b,c)				(p)->SetVelocity3f(a,b,c)
#define IA3dListener_GetVelocity3f(p,a,b,c)				(p)->GetVelocity3f(a,b,c)
#define IA3dListener_SetVelocity3fv(p,a)				(p)->SetVelocity3fv(a)
#define IA3dListener_GetVelocity3fv(p,a)				(p)->GetVelocity3fv(a)
#endif // !defined(__cplusplus) || defined(CINTERFACE)



//===================================================================
// IA3dList
//
// List of geometry and state data for IA3dGeom.
//===================================================================

// {C398E564-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3dList, 0xc398e564, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3dList

DECLARE_INTERFACE_(IA3dList, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)		(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)		(THIS) PURE;
	STDMETHOD_(ULONG,Release)		(THIS) PURE;

	// IA3dList Methods.
	STDMETHOD(Begin)				(THIS) PURE;
	STDMETHOD(End)					(THIS) PURE;
	STDMETHOD(Call)					(THIS) PURE;
	STDMETHOD(EnableBoundingVol)	(THIS) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dList_QueryInterface(p,a,b)	(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dList_AddRef(p)				(p)->lpVtbl->AddRef(p)
#define IA3dList_Release(p)				(p)->lpVtbl->Release(p)
#define IA3dList_Begin(p)				(p)->lpVtbl->Begin(p)
#define IA3dList_End(p)					(p)->lpVtbl->End(p)
#define IA3dList_Call(p)				(p)->lpVtbl->Call(p)
#define IA3dList_EnableBoundingVol(p)	(p)->lpVtbl->EnableBoundingVol(p)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dList_QueryInterface(p,a,b)	(p)->QueryInterface(a,b)
#define IA3dList_AddRef(p)				(p)->AddRef()
#define IA3dList_Release(p)				(p)->Release()
#define IA3dList_Begin(p)				(p)->Begin()
#define IA3dList_End(p)					(p)->End()
#define IA3dList_Call(p)				(p)->Call()
#define IA3dList_EnableBoundingVol(p)	(p)->EnableBoundingVol()
#endif // !defined(__cplusplus) || defined(CINTERFACE)



//===================================================================
// IA3dMaterial
//
// A material builder.
//===================================================================

// {C398E565-D90B-11d1-90FB-006008A1F441}
DEFINE_GUID(IID_IA3dMaterial, 0xc398e565, 0xd90b, 0x11d1, 0x90, 0xfb, 0x0, 0x60, 0x8, 0xa1, 0xf4, 0x41);

#undef INTERFACE
#define INTERFACE IA3dMaterial

DECLARE_INTERFACE_(IA3dMaterial, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)		(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)		(THIS) PURE;
	STDMETHOD_(ULONG,Release)		(THIS) PURE;

	// IA3dMaterial Methods.
	STDMETHOD(Load)					(THIS_ LPSTR) PURE;
	STDMETHOD(Save)					(THIS_ LPSTR) PURE;
	STDMETHOD(UnSerialize)			(THIS_ LPVOID, UINT) PURE;
	STDMETHOD(Serialize)			(THIS_ LPVOID *, UINT *) PURE;
	STDMETHOD(Duplicate)			(THIS_ LPA3DMATERIAL *) PURE;
	STDMETHOD(SetNameID)			(THIS_ LPSTR) PURE;
	STDMETHOD(GetNameID)			(THIS_ LPSTR, INT) PURE;
	STDMETHOD(SelectPreset)			(THIS_ DWORD) PURE;
	STDMETHOD(GetClosestPreset)		(THIS_ LPDWORD) PURE;
	STDMETHOD(SetReflectance)		(THIS_ A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetReflectance)		(THIS_ LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetTransmittance)		(THIS_ A3DVAL, A3DVAL) PURE;    
	STDMETHOD(GetTransmittance)		(THIS_ LPA3DVAL, LPA3DVAL) PURE;    
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dMaterial_QueryInterface(p,a,b)		(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dMaterial_AddRef(p)					(p)->lpVtbl->AddRef(p)
#define IA3dMaterial_Release(p)					(p)->lpVtbl->Release(p)
#define IA3dMaterial_Load(p,a)					(p)->lpVtbl->Load(p,a)
#define IA3dMaterial_Save(p,a)					(p)->lpVtbl->Save(p,a)
#define IA3dMaterial_UnSerialize(p,a,b)			(p)->lpVtbl->UnSerialize(p,a,b)
#define IA3dMaterial_Serialize(p,a,b)			(p)->lpVtbl->Serialize(p,a,b)
#define IA3dMaterial_Duplicate(p,a)				(p)->lpVtbl->Duplicate(p,a)
#define IA3dMaterial_SetNameID(p,a)				(p)->lpVtbl->SetNameID(p,a)
#define IA3dMaterial_GetNameID(p,a,b)			(p)->lpVtbl->GetNameID(p,a,b)
#define IA3dMaterial_SelectPreset(p,a)			(p)->lpVtbl->SelectPreset(p,a)
#define IA3dMaterial_GetClosestPreset(p,a)		(p)->lpVtbl->GetClosestPreset(p,a)
#define IA3dMaterial_SetReflectance(p,a,b)		(p)->lpVtbl->SetReflectance(p,a,b)
#define IA3dMaterial_GetReflectance(p,a,b)		(p)->lpVtbl->GetReflectance(p,a,b)
#define IA3dMaterial_SetTransmittance(p,a,b)	(p)->lpVtbl->SetTransmittance(p,a,b)
#define IA3dMaterial_GetTransmittance(p,a,b)	(p)->lpVtbl->GetTransmittance(p,a,b)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dMaterial_QueryInterface(p,a,b)		(p)->QueryInterface(a,b)
#define IA3dMaterial_AddRef(p)					(p)->AddRef()
#define IA3dMaterial_Release(p)					(p)->Release()
#define IA3dMaterial_Load(p,a)					(p)->Load(a)
#define IA3dMaterial_Save(p,a)					(p)->Save(a)
#define IA3dMaterial_UnSerialize(p,a,b)			(p)->UnSerialize(a,b)
#define IA3dMaterial_Serialize(p,a,b)			(p)->Serialize(a,b)
#define IA3dMaterial_Duplicate(p,a)				(p)->Duplicate(a)
#define IA3dMaterial_SetNameID(p,a)				(p)->SetNameID(a)
#define IA3dMaterial_GetNameID(p,a,b)			(p)->GetNameID(a,b)
#define IA3dMaterial_SelectPreset(p,a)			(p)->SelectPreset(a)
#define IA3dMaterial_GetClosestPreset(p,a)		(p)->GetClosestPreset(a)
#define IA3dMaterial_SetReflectance(p,a,b)		(p)->SetReflectance(a,b)
#define IA3dMaterial_GetReflectance(p,a,b)		(p)->GetReflectance(a,b)
#define IA3dMaterial_SetTransmittance(p,a,b)	(p)->SetTransmittance(a,b)
#define IA3dMaterial_GetTransmittance(p,a,b)	(p)->GetTransmittance(a,b)
#endif // !defined(__cplusplus) || defined(CINTERFACE)


//===================================================================
// IA3dPropertySet
//
// Property sets.
//===================================================================

// {2A1A0A60-F190-11d2-9DCF-00500411582F}
DEFINE_GUID(IID_IA3dPropertySet, 0x2a1a0a60, 0xf190, 0x11d2, 0x9d, 0xcf, 0x0, 0x50, 0x4, 0x11, 0x58, 0x2f);

#undef INTERFACE
#define INTERFACE IA3dPropertySet

DECLARE_INTERFACE_(IA3dPropertySet, IUnknown)
{
    // IUnknown Methods.
    STDMETHOD(QueryInterface)	(THIS_ REFIID, LPVOID *) PURE;
    STDMETHOD_(ULONG, AddRef)	(THIS) PURE;
    STDMETHOD_(ULONG, Release)	(THIS) PURE;

    // IA3dPropertySet Methods.
    STDMETHOD(QuerySupport)					(THIS_ REFGUID, ULONG, PULONG) PURE;
    STDMETHOD(Get)							(THIS_ REFGUID, ULONG, LPVOID, ULONG, LPVOID, ULONG, PULONG) PURE;
    STDMETHOD(Set)							(THIS_ REFGUID, ULONG, LPVOID, ULONG, LPVOID, ULONG, DWORD) PURE;
    STDMETHOD(AddInitialStateParameters)	(THIS_ REFGUID, ULONG, LPVOID, ULONG, LPVOID, ULONG) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dPropertySet_QueryInterface(p,a,b)       (p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dPropertySet_AddRef(p)					(p)->lpVtbl->AddRef(p)
#define IA3dPropertySet_Release(p)					(p)->lpVtbl->Release(p)
#define IA3dPropertySet_QuerySupport(p,a,b,c)		(p)->lpVtbl->QuerySupport(p,a,b,c)
#define IA3dPropertySet_Get(p,a,b,c,d,e,f,g)		(p)->lpVtbl->Get(p,a,b,c,d,e,f,g)
#define IA3dPropertySet_Set(p,a,b,c,d,e,f,g)		(p)->lpVtbl->Set(p,a,b,c,d,e,f,g)
#define IA3dPropertySet_AddInitialStateParameters(p,a,b,c,d,e,f)		(p)->lpVtbl->AddInitialStateParameters(p,a,b,c,d,e,f)
#else // !defined(__cplusplus) || defined(CINTERFACE)
#define IA3dPropertySet_QueryInterface(p,a,b)		(p)->QueryInterface(a,b)
#define IA3dPropertySet_AddRef(p)					(p)->AddRef()
#define IA3dPropertySet_Release(p)					(p)->Release()
#define IA3dPropertySet_QuerySupport(a,b,c)			(p)->QuerySupport(p,a,b,c)
#define IA3dPropertySet_Get(a,b,c,d,e,f,g)			(p)->Get(p,a,b,c,d,e,f,g)
#define IA3dPropertySet_Set(a,b,c,d,e,f,g)			(p)->Set(p,a,b,c,d,e,f,g)
#define IA3dPropertySet_AddInitialStateParameters(a,b,c,d,e,f)		(p)->AddInitialStateParameters(p,a,b,c,d,e,f)
#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dReverb
//
// The reverb interface.
//===================================================================

// {C38D8C01-44D6-11d3-A87F-00600879F3EE}
DEFINE_GUID(IID_IA3dReverb, 0xc38d8c01, 0x44d6, 0x11d3, 0xa8, 0x7f, 0x0, 0x60, 0x8, 0x79, 0xf3, 0xee);

#undef INTERFACE
#define INTERFACE IA3dReverb

DECLARE_INTERFACE_(IA3dReverb, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)			(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)			(THIS) PURE;
	STDMETHOD_(ULONG,Release)			(THIS) PURE;

	// IA3dReverb Methods
	STDMETHOD(SetReverbPreset)			(THIS_ DWORD) PURE;
	STDMETHOD(GetReverbPreset)			(THIS_ DWORD *) PURE;
	STDMETHOD(SetAllProperties)			(THIS_ A3DREVERB_PROPERTIES *) PURE;
	STDMETHOD(GetAllProperties)			(THIS_ A3DREVERB_PROPERTIES *) PURE;
	STDMETHOD(SetPresetVolume)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPresetVolume)			(THIS_ A3DVAL *) PURE;
	STDMETHOD(SetPresetDecayTime)		(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPresetDecayTime)		(THIS_ A3DVAL *) PURE;
	STDMETHOD(SetPresetDamping)			(THIS_ A3DVAL) PURE;
	STDMETHOD(GetPresetDamping)			(THIS_ A3DVAL *) PURE;

};

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IA3dReverb_QueryInterface(p,a,b)			(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dReverb_AddRef(p)						(p)->lpVtbl->AddRef(p)
#define IA3dReverb_Release(p)						(p)->lpVtbl->Release(p)
#define IA3dReverb_SetReverbPreset(p,a)				(p)->lpVtbl->SetReverbPreset(p,a)
#define IA3dReverb_GetReverbPreset(p,a)				(p)->lpVtbl->GetReverbPreset(p,a)
#define IA3dReverb_SetAllProperties(p,a)			(p)->lpVtbl->SetAllProperties(p,a)
#define IA3dReverb_GetAllProperties(p,a)			(p)->lpVtbl->GetAllProperties(p,a)
#define IA3dReverb_SetPresetVolume(p,a)				(p)->lpVtbl->SetPresetVolume(p,a)
#define IA3dReverb_GetPresetVolume(p,a)				(p)->lpVtbl->GetPresetVolume(p,a)
#define IA3dReverb_SetPresetDecayTime(p,a)			(p)->lpVtbl->SetPresetDecayTime(p,a)
#define IA3dReverb_GetPresetDecayTime(p,a)			(p)->lpVtbl->GetPresetDecayTime(p,a)
#define IA3dReverb_SetPresetDamping(p,a)			(p)->lpVtbl->SetPresetDamping(p,a)
#define IA3dReverb_GetPresetDamping(p,a)			(p)->lpVtbl->GetPresetDamping(p,a)

#else

#define IA3dReverb_QueryInterface(p,a,b)			(p)->QueryInterface(a,b)
#define IA3dReverb_AddRef(p)						(p)->AddRef()
#define IA3dReverb_Release(p)						(p)->Release()
#define IA3dReverb_SetReverbPreset(p,a)				(p)->SetReverbPreset(a)
#define IA3dReverb_GetReverbPreset(p,a)				(p)->GetReverbPreset(a)
#define IA3dReverb_SetAllProperties(p,a)			(p)->SetAllProperties(a)
#define IA3dReverb_GetAllProperties(p,a)			(p)->GetAllProperties(a)
#define IA3dReverb_SetPresetVolume(p,a)				(p)->SetPresetVolume(a)
#define IA3dReverb_GetPresetVolume(p,a)				(p)->GetPresetVolume(a)
#define IA3dReverb_SetPresetDecayTime(p,a)			(p)->SetPresetDecayTime(a)
#define IA3dReverb_GetPresetDecayTime(p,a)			(p)->GetPresetDecayTime(a)
#define IA3dReverb_SetPresetDamping(p,a)			(p)->SetPresetDamping(a)
#define IA3dReverb_GetPresetDamping(p,a)			(p)->GetPresetDamping(a)


#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// IA3dReflection
//
// The manual reflection interface.
//===================================================================

// {1996D3C3-6C43-11d3-A33D-00500488181D}
DEFINE_GUID(IID_IA3dReflection, 0x1996d3c3, 0x6c43, 0x11d3, 0xa3, 0x3d, 0x0, 0x50, 0x4, 0x88, 0x18, 0x1d);

#undef INTERFACE
#define INTERFACE IA3dReflection
DECLARE_INTERFACE_(IA3dReflection, IUnknown)
{
	// IUnknown Methods.
	STDMETHOD(QueryInterface)			(THIS_ REFIID, LPVOID FAR *) PURE;
	STDMETHOD_(ULONG,AddRef)			(THIS) PURE;
	STDMETHOD_(ULONG,Release)			(THIS) PURE;

	// IA3dReflect Methods
	STDMETHOD(SetGainScale)				(THIS_ A3DVAL) PURE;
	STDMETHOD(GetGainScale)				(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetDelay)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetDelay)					(THIS_ LPA3DVAL) PURE;
	STDMETHOD(SetPosition3f)			(THIS_ A3DVAL, A3DVAL, A3DVAL) PURE;
	STDMETHOD(GetPosition3f)			(THIS_ LPA3DVAL, LPA3DVAL, LPA3DVAL) PURE;
	STDMETHOD(SetPosition3fv)			(THIS_ A3DVAL *) PURE;
	STDMETHOD(GetPosition3fv)			(THIS_ A3DVAL *) PURE;
	STDMETHOD(SetTransformMode)			(THIS_ DWORD) PURE;
	STDMETHOD(GetTransformMode)			(THIS_ DWORD *) PURE;
	STDMETHOD(SetEQ)					(THIS_ A3DVAL) PURE;
	STDMETHOD(GetEQ)					(THIS_ LPA3DVAL) PURE;

};

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IA3dReflection_QueryInterface(p,a,b)			(p)->lpVtbl->QueryInterface(p,a,b)
#define IA3dReflection_AddRef(p)						(p)->lpVtbl->AddRef(p)
#define IA3dReflection_Release(p)						(p)->lpVtbl->Release(p)
#define IA3dReflection_SetGainScale(p, a)				(p)->lpVtbl->SetGainScale(p,a)
#define IA3dReflection_GetGainScale(p, a)				(p)->lpVtbl->GetGainScale(p,a)
#define IA3dReflection_SetDelay(p, a)					(p)->lpVtbl->SetDelay(p,a)
#define IA3dReflection_GetDelay(p, a)					(p)->lpVtbl->GetDelay(p,a)
#define IA3dReflection_SetPosition3f(p, a, b, c)		(p)->lpVtbl->SetPosition3f(p,a,b,c)
#define IA3dReflection_GetPosition3f(p, a, b, c)		(p)->lpVtbl->GetPosition3f(p,a,b,c)
#define IA3dReflection_SetPosition3fv(p, a)				(p)->lpVtbl->SetPosition3fv(p,a)
#define IA3dReflection_GetPosition3fv(p, a)				(p)->lpVtbl->GetPosition3fv(p,a)
#define IA3dReflection_SetTransformMode(p, a)			(p)->lpVtbl->SetTransformMode(p,a)
#define IA3dReflection_GetTransformMode(p, a)			(p)->lpVtbl->GetTransformMode(p,a)
#define IA3dReflection_SetEQ(p, a)						(p)->lpVtbl->SetEQ(p,a)
#define IA3dReflection_GetEQ(p, a)						(p)->lpVtbl->GetEQ(p,a)

#else

#define IA3dReflection_QueryInterface(p,a,b)			(p)->QueryInterface(a,b)
#define IA3dReflection_AddRef(p)						(p)->AddRef()
#define IA3dReflection_Release(p)						(p)->Release()
#define IA3dReflection_SetGainScale(p, a)				(p)->SetGainScale(a)
#define IA3dReflection_GetGainScale(p, a)				(p)->GetGainScale(a)
#define IA3dReflection_SetDelay(p, a)					(p)->SetDelay(a)
#define IA3dReflection_GetDelay(p, a)					(p)->GetDelay(a)
#define IA3dReflection_SetPosition3f(p, a, b, c)		(p)->SetPosition3f(a,b,c)
#define IA3dReflection_GetPosition3f(p, a, b, c)		(p)->GetPosition3f(a,b,c)
#define IA3dReflection_SetPosition3fv(p, a)				(p)->SetPosition3fv(a)
#define IA3dReflection_GetPosition3fv(p, a)				(p)->GetPosition3fv(a)
#define IA3dReflection_SetTransformMode(p, a)			(p)->SetTransformMode(a)
#define IA3dReflection_GetTransformMode(p, a)			(p)->GetTransformMode(a)
#define IA3dReflection_SetEQ(p, a)						(p)->SetEQ(a)
#define IA3dReflection_GetEQ(p, a)						(p)->GetEQ(a)

#endif // !defined(__cplusplus) || defined(CINTERFACE)

//===================================================================
// Error Codes
//
// Use macros A3DERROR_CODE(code) for errors and A3DSUCCESS_CODE(code)
// for success codes or predefined universal COM success and failure
// code.
//
// All success codes should be mutally exclusive to all other success other.
//
// All error codes should be mutually exclusive to all other error codes.
//
//===================================================================

#define A3DERROR_CODE(code)     MAKE_HRESULT(1, FACILITY_ITF, code)
#define A3DSUCCESS_CODE(code)   MAKE_HRESULT(0, FACILITY_ITF, code)

// Success Codes
#define A3DOK_BUFFER_IN_SOFTWARE								A3DSUCCESS_CODE(1)

// Error Codes
#define A3DERROR_MEMORY_ALLOCATION								A3DERROR_CODE(1)
#define A3DERROR_FAILED_CREATE_PRIMARY_BUFFER					A3DERROR_CODE(2)
#define A3DERROR_FAILED_CREATE_SECONDARY_BUFFER					A3DERROR_CODE(3)
#define A3DERROR_FAILED_INIT_A3D_DRIVER							A3DERROR_CODE(4)
#define A3DERROR_FAILED_QUERY_DIRECTSOUND						A3DERROR_CODE(5)
#define A3DERROR_FAILED_QUERY_A3D3								A3DERROR_CODE(6)
#define A3DERROR_FAILED_INIT_A3D3								A3DERROR_CODE(7)
#define A3DERROR_FAILED_QUERY_A3D2								A3DERROR_CODE(8)
#define A3DERROR_FAILED_FILE_OPEN								A3DERROR_CODE(9)
#define A3DERROR_FAILED_CREATE_SOUNDBUFFER						A3DERROR_CODE(10)
#define A3DERROR_FAILED_QUERY_3DINTERFACE						A3DERROR_CODE(11)
#define A3DERROR_FAILED_LOCK_BUFFER								A3DERROR_CODE(12)
#define A3DERROR_FAILED_UNLOCK_BUFFER							A3DERROR_CODE(13)
#define A3DERROR_UNRECOGNIZED_FORMAT							A3DERROR_CODE(14)
#define A3DERROR_NO_WAVE_DATA									A3DERROR_CODE(15)
#define A3DERROR_UNKNOWN_PLAYMODE								A3DERROR_CODE(16)
#define A3DERROR_FAILED_PLAY									A3DERROR_CODE(17)
#define A3DERROR_FAILED_STOP									A3DERROR_CODE(18)
#define A3DERROR_NEEDS_FORMAT_INFORMATION						A3DERROR_CODE(19)
#define A3DERROR_FAILED_ALLOCATE_WAVEDATA						A3DERROR_CODE(20)
#define A3DERROR_NOT_VALID_SOURCE								A3DERROR_CODE(21)
#define A3DERROR_FAILED_DUPLICATION								A3DERROR_CODE(22)
#define A3DERROR_FAILED_INIT									A3DERROR_CODE(23)
#define A3DERROR_FAILED_SETCOOPERATIVE_LEVEL					A3DERROR_CODE(24)
#define A3DERROR_FAILED_INIT_QUERIED_INTERFACE					A3DERROR_CODE(25)
#define A3DERROR_GEOMETRY_INPUT_OUTSIDE_BEGIN_END_BLOCK			A3DERROR_CODE(26)
#define A3DERROR_INVALID_NORMAL									A3DERROR_CODE(27)
#define A3DERROR_END_BEFORE_VALID_BEGIN_BLOCK					A3DERROR_CODE(28)
#define A3DERROR_INVALID_BEGIN_MODE								A3DERROR_CODE(29)
#define A3DERROR_INVALID_ARGUMENT								A3DERROR_CODE(30)
#define A3DERROR_INVALID_INDEX									A3DERROR_CODE(31)
#define A3DERROR_INVALID_VERTEX_INDEX							A3DERROR_CODE(32)
#define A3DERROR_INVALID_PRIMITIVE_INDEX						A3DERROR_CODE(33)
#define A3DERROR_MIXING_2D_AND_3D_MODES							A3DERROR_CODE(34)
#define A3DERROR_2DWALL_REQUIRES_EXACTLY_ONE_LINE				A3DERROR_CODE(35)
#define A3DERROR_NO_PRIMITIVES_DEFINED							A3DERROR_CODE(36)
#define A3DERROR_PRIMITIVES_NON_PLANAR							A3DERROR_CODE(37)
#define A3DERROR_PRIMITIVES_OVERLAPPING							A3DERROR_CODE(38)
#define A3DERROR_PRIMITIVES_NOT_ADJACENT						A3DERROR_CODE(39)
#define A3DERROR_OBJECT_NOT_FOUND								A3DERROR_CODE(40)
#define A3DERROR_ROOM_HAS_NO_SHELL_WALLS						A3DERROR_CODE(41)
#define A3DERROR_WALLS_DO_NOT_ENCLOSE_ROOM						A3DERROR_CODE(42)
#define A3DERROR_INVALID_WALL									A3DERROR_CODE(43)
#define A3DERROR_ROOM_HAS_LESS_THAN_4SHELL_WALLS				A3DERROR_CODE(44)
#define A3DERROR_ROOM_HAS_LESS_THAN_3UNIQUE_NORMALS				A3DERROR_CODE(45)
#define A3DERROR_INTERSECTING_WALL_EDGES						A3DERROR_CODE(46)
#define A3DERROR_INVALID_ROOM									A3DERROR_CODE(47)
#define A3DERROR_SCENE_HAS_ROOMS_INSIDE_ANOTHER_ROOMS			A3DERROR_CODE(48)
#define A3DERROR_SCENE_HAS_OVERLAPPING_STATIC_ROOMS				A3DERROR_CODE(49)
#define A3DERROR_DYNAMIC_OBJ_UNSUPPORTED						A3DERROR_CODE(50)
#define A3DERROR_DIR_AND_UP_VECTORS_NOT_PERPENDICULAR			A3DERROR_CODE(51)
#define A3DERROR_INVALID_ROOM_INDEX								A3DERROR_CODE(52)
#define A3DERROR_INVALID_WALL_INDEX								A3DERROR_CODE(53)
#define A3DERROR_SCENE_INVALID									A3DERROR_CODE(54)
#define A3DERROR_UNIMPLEMENTED_FUNCTION							A3DERROR_CODE(55)
#define A3DERROR_NO_ROOMS_IN_SCENE								A3DERROR_CODE(56)
#define A3DERROR_2D_GEOMETRY_UNIMPLEMENTED						A3DERROR_CODE(57)
#define A3DERROR_OPENING_NOT_WALL_COPLANAR						A3DERROR_CODE(58)
#define A3DERROR_OPENING_NOT_VALID								A3DERROR_CODE(59)
#define A3DERROR_INVALID_OPENING_INDEX							A3DERROR_CODE(60)
#define A3DERROR_FEATURE_NOT_REQUESTED							A3DERROR_CODE(61)
#define A3DERROR_FEATURE_NOT_SUPPORTED							A3DERROR_CODE(62)
#define A3DERROR_FUNCTION_NOT_VALID_BEFORE_INIT					A3DERROR_CODE(63)
#define A3DERROR_INVALID_NUMBER_OF_CHANNELS  					A3DERROR_CODE(64)
#define A3DERROR_SOURCE_IN_NATIVE_MODE      					A3DERROR_CODE(65)
#define A3DERROR_SOURCE_IN_A3D_MODE 	      					A3DERROR_CODE(66)
#define A3DERROR_BBOX_CANNOT_ENABLE_AFTER_BEGIN_LIST_CALL		A3DERROR_CODE(67)
#define A3DERROR_CANNOT_CHANGE_FORMAT_FOR_ALLOCATED_BUFFER      A3DERROR_CODE(68)
#define A3DERROR_FAILED_QUERY_DIRECTSOUNDNOTIFY					A3DERROR_CODE(69)
#define A3DERROR_DIRECTSOUNDNOTIFY_FAILED						A3DERROR_CODE(70)
#define A3DERROR_RESOURCE_MANAGER_ALWAYS_ON						A3DERROR_CODE(71)
#define A3DERROR_CLOSED_LIST_CANNOT_BE_CHANGED					A3DERROR_CODE(72)
#define A3DERROR_END_CALLED_BEFORE_BEGIN						A3DERROR_CODE(73)
#define A3DERROR_UNMANAGED_BUFFER								A3DERROR_CODE(74)
#define A3DERROR_COORD_SYSTEM_CAN_ONLY_BE_SET_ONCE				A3DERROR_CODE(75)
#define A3DERROR_BUFFER_IN_SOFTWARE								A3DERROR_CODE(76)
#define A3DERROR_INITIAL_PARAMETERS_NOT_SET						A3DERROR_CODE(77)
#define A3DERROR_INCORRECT_FORMAT_SPECIFIED						A3DERROR_CODE(78)
#define A3DERROR_NO_SOUND_BUFFERS_CREATED						A3DERROR_CODE(79)
#define A3DERROR_SOURCE_IN_USE									A3DERROR_CODE(80)
#define A3DERROR_STREAMING_BUFFER_LENGTH						A3DERROR_CODE(81)
#define A3DERROR_STREAMING_PRIORITY								A3DERROR_CODE(82)
#define A3DERROR_CANT_DUPLICATE_STREAM_SRC						A3DERROR_CODE(83)
#define A3DERROR_CANT_INSTANTIATE_MORE_ONE_INSTANCE				A3DERROR_CODE(84)
#define A3DERROR_CANT_SET_TIME_POSITION_FOR_AC3_STREAM			A3DERROR_CODE(85)
#define A3DERROR_HARDWARE_AC3_OBJECT_DOES_NOT_IMPLEMENT_THIS_MEMBER		A3DERROR_CODE(86)
#define A3DERROR_NO_MORE_THAN_ONE_AC3_SRC_AT_ONCE				A3DERROR_CODE(87)
#define A3DERROR_ENCODED_SOURCE_TYPE_CANNOT_BE_TIME_SEEKED		A3DERROR_CODE(88)
#define A3DERROR_INVALID_AC3_KEY								A3DERROR_CODE(89)
#define A3DERROR_MUST_UNLOCK_SOFTAC3_BEFORE_USE					A3DERROR_CODE(90)
#define A3DERROR_REFLECTIONS_NOT_ENABLED						A3DERROR_CODE(91)
#define A3DERROR_FEATURE_UNSUPPORTED_BY_DECODER					A3DERROR_CODE(92)
#define A3DERROR_AC3_FALLBACK_REQUIRES_DVD_DRIVE				A3DERROR_CODE(93)

#ifdef __cplusplus
};
#endif

#endif	// #ifndef _IA3DAPI_H_

