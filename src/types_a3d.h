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
    HRESULT(__stdcall * QueryInterface)(IA3dListener* This, IID*, LPVOID*);
    ULONG(__stdcall * AddRef)(IA3dListener* This);
    ULONG(__stdcall * Release)(IA3dListener* This);

    // IA3dListener Methods.
    HRESULT(__stdcall * SetPosition3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetPosition3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetPosition3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * GetPosition3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * SetOrientationAngles3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetOrientationAngles3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetOrientationAngles3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * GetOrientationAngles3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * SetOrientation6f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetOrientation6f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetOrientation6fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * GetOrientation6fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * SetVelocity3f)(IA3dListener* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetVelocity3f)(IA3dListener* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetVelocity3fv)(IA3dListener* This, LPA3DVAL);
    HRESULT(__stdcall * GetVelocity3fv)(IA3dListener* This, LPA3DVAL);
} IA3dListenerVtbl;

typedef struct IA3dSource
{
    struct IA3dSourceVtbl* lpVtbl;
} IA3dSource;

typedef struct IA3dSource* LPA3DSOURCE;

typedef struct IA3dSourceVtbl
{
    // IUnknown Methods.
    HRESULT(__stdcall * QueryInterface)(IA3dSource* This, IID* iid, LPVOID*);
    ULONG(__stdcall * AddRef)(IA3dSource* This);
    ULONG(__stdcall * Release)(IA3dSource* This);

    // IA3dSource Methods.
    HRESULT(__stdcall * LoadWaveFile)(IA3dSource* This, LPSTR);
    HRESULT(__stdcall * LoadWaveData)(IA3dSource* This, LPVOID, DWORD);
    HRESULT(__stdcall * AllocateAudioData)(IA3dSource* This, int);
    HRESULT(__stdcall * FreeWaveData)(IA3dSource* This);
    HRESULT(__stdcall * SetAudioFormat)(IA3dSource* This, LPVOID);
    HRESULT(__stdcall * GetAudioFormat)(IA3dSource* This, LPVOID);
    HRESULT(__stdcall * GetAudioSize)(IA3dSource* This);
    HRESULT(__stdcall * GetType)(IA3dSource* This, LPDWORD);
    HRESULT(__stdcall * Lock)(IA3dSource* This, DWORD, DWORD, LPVOID*, LPDWORD, LPVOID*, LPDWORD, DWORD);
    HRESULT(__stdcall * Unlock)(IA3dSource* This, LPVOID, DWORD, LPVOID, DWORD);
    HRESULT(__stdcall * Play)(IA3dSource* This, int);
    HRESULT(__stdcall * Stop)(IA3dSource* This);
    HRESULT(__stdcall * Rewind)(IA3dSource* This);
    HRESULT(__stdcall * SetWaveTime)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetWaveTime)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetWavePosition)(IA3dSource* This, DWORD);
    HRESULT(__stdcall * GetWavePosition)(IA3dSource* This, LPDWORD);
    HRESULT(__stdcall * SetPosition3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetPosition3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetPosition3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetPosition3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetOrientationAngles3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetOrientationAngles3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetOrientationAngles3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetOrientationAngles3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetOrientation6f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetOrientation6f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetOrientation6fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetOrientation6fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetVelocity3f)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetVelocity3f)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetVelocity3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetVelocity3fv)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetCone)(IA3dSource* This, A3DVAL, A3DVAL, A3DVAL);
    HRESULT(__stdcall * GetCone)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPA3DVAL);
    HRESULT(__stdcall * SetMinMaxDistance)(IA3dSource* This, A3DVAL, A3DVAL, DWORD);
    HRESULT(__stdcall * GetMinMaxDistance)(IA3dSource* This, LPA3DVAL, LPA3DVAL, LPDWORD);
    HRESULT(__stdcall * SetGain)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetGain)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetPitch)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetPitch)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetDopplerScale)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetDopplerScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetDistanceModelScale)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetDistanceModelScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetEq)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetEq)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetPriority)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetPriority)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetRenderMode)(IA3dSource* This, DWORD);
    HRESULT(__stdcall * GetRenderMode)(IA3dSource* This, LPDWORD);
    HRESULT(__stdcall * GetAudibility)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetOcclusionFactor)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * GetStatus)(IA3dSource* This, LPDWORD);
    HRESULT(__stdcall * SetPanValues)(IA3dSource* This, DWORD, LPA3DVAL);
    HRESULT(__stdcall * GetPanValues)(IA3dSource* This, DWORD, LPA3DVAL);
    HRESULT(__stdcall * SetPlayEvent)(IA3dSource* This, DWORD, HANDLE);
    HRESULT(__stdcall * ClearPlayEvents)(IA3dSource* This);
    HRESULT(__stdcall * SetTransformMode)(IA3dSource* This, DWORD);
    HRESULT(__stdcall * GetTransformMode)(IA3dSource* This, LPDWORD);
    HRESULT(__stdcall * SetReflectionDelayScale)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetReflectionDelayScale)(IA3dSource* This, LPA3DVAL);
    HRESULT(__stdcall * SetReflectionGainScale)(IA3dSource* This, A3DVAL);
    HRESULT(__stdcall * GetReflectionGainScale)(IA3dSource* This, LPA3DVAL);
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
    HRESULT(__stdcall * QueryInterface)(IA3d4* This, IID* riid, void** ppvObject);
    ULONG(__stdcall * AddRef)(IA3d4* This);
    ULONG(__stdcall * Release)(IA3d4* This);

    // IA3d Methods.
    HRESULT(__stdcall * SetOutputMode)(IA3d4* This, DWORD, DWORD, DWORD);
    HRESULT(__stdcall * GetOutputMode)(IA3d4* This, LPDWORD, LPDWORD, LPDWORD);
    HRESULT(__stdcall * SetResourceManagerMode)(IA3d4* This, DWORD);
    HRESULT(__stdcall * GetResourceManagerMode)(IA3d4* This, LPDWORD);
    HRESULT(__stdcall * SetHFAbsorbFactor)(IA3d4* This, float);
    HRESULT(__stdcall * GetHFAbsorbFactor)(IA3d4* This, float*);

    // IA3d2 Methods.
    HRESULT(__stdcall * RegisterVersion)(IA3d4* This, DWORD);
    HRESULT(__stdcall * GetSoftwareCaps)(IA3d4* This, LPA3DCAPS_SOFTWARE);
    HRESULT(__stdcall * GetHardwareCaps)(IA3d4* This, LPA3DCAPS_HARDWARE);

    // IA3d3 Methods.
    HRESULT(__stdcall * Clear)(IA3d4* This);
    HRESULT(__stdcall * Flush)(IA3d4* This);
    HRESULT(__stdcall * Compat)(IA3d4* This, DWORD, DWORD);
    HRESULT(__stdcall * Init)(IA3d4* This, GUID*, DWORD, DWORD);
    HRESULT(__stdcall * IsFeatureAvailable)(IA3d4* This, DWORD);
    HRESULT(__stdcall * NewSource)(IA3d4* This, DWORD, LPA3DSOURCE*);
    HRESULT(__stdcall * DuplicateSource)(IA3d4* This, LPA3DSOURCE, LPA3DSOURCE*);
    HRESULT(__stdcall * SetCooperativeLevel)(IA3d4* This, HWND, DWORD);
    HRESULT(__stdcall * GetCooperativeLevel)(IA3d4* This, LPDWORD);
    HRESULT(__stdcall * SetMaxReflectionDelayTime)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetMaxReflectionDelayTime)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * SetCoordinateSystem)(IA3d4* This, DWORD);
    HRESULT(__stdcall * GetCoordinateSystem)(IA3d4* This, LPDWORD);
    HRESULT(__stdcall * SetOutputGain)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetOutputGain)(IA3d4* This, LPA3DVAL);

    // IA3d4 Methods
    HRESULT(__stdcall * SetNumFallbackSources)(IA3d4* This, DWORD);
    HRESULT(__stdcall * GetNumFallbackSources)(IA3d4* This, LPDWORD);
    HRESULT(__stdcall * SetRMPriorityBias)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetRMPriorityBias)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * DisableViewer)(IA3d4* This);
    HRESULT(__stdcall * SetUnitsPerMeter)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetUnitsPerMeter)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * SetDopplerScale)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetDopplerScale)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * SetDistanceModelScale)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetDistanceModelScale)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * SetEq)(IA3d4* This, A3DVAL);
    HRESULT(__stdcall * GetEq)(IA3d4* This, LPA3DVAL);
    HRESULT(__stdcall * Shutdown)(IA3d4* This);
    HRESULT(__stdcall * RegisterApp)(IA3d4* This, IID*);
} IA3d4Vtbl;

#endif // TYPES_A3D_H
