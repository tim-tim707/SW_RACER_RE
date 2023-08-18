#ifndef TYPES_A3D_H
#define TYPES_A3D_H

// From https://github.com/RazorbladeByte/A3D-Live-/blob/master/ia3dapi.h
// See the api book: http://www.worknd.ru/a3d30ref.pdf

#include <Windows.h>

// Feature flags
#define A3D_1ST_REFLECTIONS 0x00000002
#define A3D_DIRECT_PATH_A3D 0x00000008
#define A3D_DIRECT_PATH_GENERIC 0x00000020
#define A3D_OCCLUSIONS 0x00000040
#define A3D_DISABLE_SPLASHSCREEN 0x00000080
#define A3D_REVERB 0x00000100
#define A3D_GEOMETRIC_REVERB 0x00000200
#define A3D_DISABLE_FOCUS_MUTE 0x00000400

typedef float A3DVAL, *LPA3DVAL;

typedef struct IA3dListener
{
    struct IA3dListenerVtbl* lpVtbl;
} IA3dListener;

typedef struct IA3dListenerVtbl
{
    // IUnknown Methods.
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IA3dListener* This, IID*, LPVOID*);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IA3dListener* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IA3dListener* This);

    // IA3dListener Methods.
    HRESULT(__attribute__((__stdcall__)) * SetPosition3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPosition3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetPosition3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPosition3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientationAngles3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientationAngles3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientationAngles3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientationAngles3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientation6f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientation6f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientation6fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientation6fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetVelocity3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetVelocity3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetVelocity3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetVelocity3fv)(IA3dListener* This, LPA3DVAL);
} IA3dListenerVtbl;

typedef struct IA3dSource
{
    struct IA3dSourceVtbl* lpVtbl;
} IA3dSource;

typedef struct IA3dSource* LPA3DSOURCE;

typedef struct IA3dSourceVtbl
{
    // IUnknown Methods.
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IA3dSource* This, IID* iid, LPVOID*);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IA3dSource* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IA3dSource* This);

    // IA3dSource Methods.
    HRESULT(__attribute__((__stdcall__)) * LoadWaveFile)(IA3dSource* This, LPSTR);
    HRESULT(__attribute__((__stdcall__)) * LoadWaveData)(IA3dSource* This, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * AllocateAudioData)(IA3dSource* This, int);
    HRESULT(__attribute__((__stdcall__)) * FreeWaveData)(IA3dSource* This);
    HRESULT(__attribute__((__stdcall__)) * SetAudioFormat)(IA3dSource* This, LPVOID);
    HRESULT(__attribute__((__stdcall__)) * GetAudioFormat)(IA3dSource* This, LPVOID);
    HRESULT(__attribute__((__stdcall__)) * GetAudioSize)(IA3dSource* This);
    HRESULT(__attribute__((__stdcall__)) * GetType)(IA3dSource* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * Lock)(IA3dSource* This, DWORD, DWORD, LPVOID*, LPDWORD, LPVOID*, LPDWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * Unlock)(IA3dSource* This, LPVOID, DWORD, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * Play)(IA3dSource* This, int);
    HRESULT(__attribute__((__stdcall__)) * Stop)(IA3dSource* This);
    HRESULT(__attribute__((__stdcall__)) * Rewind)(IA3dSource* This);
    HRESULT(__attribute__((__stdcall__)) * SetWaveTime)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetWaveTime)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetWavePosition)(IA3dSource* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetWavePosition)(IA3dSource* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetPosition3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPosition3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetPosition3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPosition3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientationAngles3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientationAngles3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientationAngles3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientationAngles3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientation6f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientation6f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetOrientation6fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOrientation6fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetVelocity3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetVelocity3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetVelocity3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetVelocity3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetCone)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetCone)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetMinMaxDistance)(IA3dSource* This, A3DVAL, A3DVAL, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetMinMaxDistance)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetGain)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetGain)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetPitch)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPitch)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetDopplerScale)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetDopplerScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetDistanceModelScale)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetDistanceModelScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetEq)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetEq)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetPriority)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPriority)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetRenderMode)(IA3dSource* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetRenderMode)(IA3dSource* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetAudibility)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOcclusionFactor)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetStatus)(IA3dSource* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetPanValues)(IA3dSource* This, DWORD, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetPanValues)(IA3dSource* This, DWORD, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetPlayEvent)(IA3dSource* This, DWORD, HANDLE);
    HRESULT(__attribute__((__stdcall__)) * ClearPlayEvents)(IA3dSource* This);
    HRESULT(__attribute__((__stdcall__)) * SetTransformMode)(IA3dSource* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetTransformMode)(IA3dSource* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetReflectionDelayScale)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetReflectionDelayScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetReflectionGainScale)(IA3dSource* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetReflectionGainScale)(IA3dSource* This, LPA3DVAL);
} IA3dSourceVtbl;

typedef struct __A3DCAPS_SOFTWARE
{
    DWORD dwSize; // Use for internal version control
    DWORD dwVersion; // For Backwards capablities purposes
    DWORD dwFlags;
    DWORD dwReserved;
    DWORD dwReserved2;
    DWORD dwOutputChannels;
    DWORD dwMinSampleRate;
    DWORD dwMaxSampleRate;
    DWORD dwMax2DBuffers;
    DWORD dwMax3DBuffers;
} A3DCAPS_SOFTWARE, *LPA3DCAPS_SOFTWARE;

typedef struct __A3DCAPS_HARDWARE
{
    DWORD dwSize; // Use for internal version control
    DWORD dwFlags;
    DWORD dwReserved;
    DWORD dwReserved2;
    DWORD dwOutputChannels;
    DWORD dwMinSampleRate;
    DWORD dwMaxSampleRate;
    DWORD dwMax2DBuffers;
    DWORD dwMax3DBuffers;
} A3DCAPS_HARDWARE, *LPA3DCAPS_HARDWARE;

typedef struct IA3d4
{
    struct IA3d4Vtbl* lpVtbl;
} IA3d4;

typedef struct IA3d4Vtbl
{
    // IUnknown Methods.
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IA3d4* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IA3d4* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IA3d4* This);

    // IA3d Methods.
    HRESULT(__attribute__((__stdcall__)) * SetOutputMode)(IA3d4* This, DWORD, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetOutputMode)(IA3d4* This, LPDWORD, LPDWORD, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetResourceManagerMode)(IA3d4* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetResourceManagerMode)(IA3d4* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetHFAbsorbFactor)(IA3d4* This, float);
    HRESULT(__attribute__((__stdcall__)) * GetHFAbsorbFactor)(IA3d4* This, float*);

    // IA3d2 Methods.
    HRESULT(__attribute__((__stdcall__)) * RegisterVersion)(IA3d4* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetSoftwareCaps)(IA3d4* This, LPA3DCAPS_SOFTWARE);
    HRESULT(__attribute__((__stdcall__)) * GetHardwareCaps)(IA3d4* This, LPA3DCAPS_HARDWARE);

    // IA3d3 Methods.
    HRESULT(__attribute__((__stdcall__)) * Clear)(IA3d4* This);
    HRESULT(__attribute__((__stdcall__)) * Flush)(IA3d4* This);
    HRESULT(__attribute__((__stdcall__)) * Compat)(IA3d4* This, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * Init)(IA3d4* This, GUID*, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * IsFeatureAvailable)(IA3d4* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * NewSource)(IA3d4* This, DWORD, LPA3DSOURCE*);
    HRESULT(__attribute__((__stdcall__)) * DuplicateSource)(IA3d4* This, LPA3DSOURCE, LPA3DSOURCE*);
    HRESULT(__attribute__((__stdcall__)) * SetCooperativeLevel)(IA3d4* This, HWND, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetCooperativeLevel)(IA3d4* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetMaxReflectionDelayTime)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetMaxReflectionDelayTime)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetCoordinateSystem)(IA3d4* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetCoordinateSystem)(IA3d4* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetOutputGain)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetOutputGain)(IA3d4* This, LPA3DVAL);

    // IA3d4 Methods
    HRESULT(__attribute__((__stdcall__)) * SetNumFallbackSources)(IA3d4* This, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetNumFallbackSources)(IA3d4* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * SetRMPriorityBias)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetRMPriorityBias)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * DisableViewer)(IA3d4* This);
    HRESULT(__attribute__((__stdcall__)) * SetUnitsPerMeter)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetUnitsPerMeter)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetDopplerScale)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetDopplerScale)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetDistanceModelScale)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetDistanceModelScale)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * SetEq)(IA3d4* This, A3DVAL);
    HRESULT(__attribute__((__stdcall__)) * GetEq)(IA3d4* This, LPA3DVAL);
    HRESULT(__attribute__((__stdcall__)) * Shutdown)(IA3d4* This);
    HRESULT(__attribute__((__stdcall__)) * RegisterApp)(IA3d4* This, IID*);
} IA3d4Vtbl;

#endif // TYPES_A3D_H
