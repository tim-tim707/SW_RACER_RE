From the ddraw.h header https://github.com/apitrace/dxsdk/blob/master/Include/ddraw.h

```c
DECLARE_INTERFACE_( IDirectDraw7, IUnknown )
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) PURE; // 0
    STDMETHOD_(ULONG,AddRef) (THIS)  PURE; // 4
    STDMETHOD_(ULONG,Release) (THIS) PURE; // 8
    /*** IDirectDraw methods ***/
    STDMETHOD(Compact)(THIS) PURE; // c
    STDMETHOD(CreateClipper)(THIS_ DWORD, LPDIRECTDRAWCLIPPER FAR*, IUnknown FAR * ) PURE; // 10
    STDMETHOD(CreatePalette)(THIS_ DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE FAR*, IUnknown FAR * ) PURE; // 14
    STDMETHOD(CreateSurface)(THIS_  LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 FAR *, IUnknown FAR *) PURE; // 18
    STDMETHOD(DuplicateSurface)( THIS_ LPDIRECTDRAWSURFACE7, LPDIRECTDRAWSURFACE7 FAR * ) PURE; // 1c
    STDMETHOD(EnumDisplayModes)( THIS_ DWORD, LPDDSURFACEDESC2, LPVOID, LPDDENUMMODESCALLBACK2 ) PURE; // 20
    STDMETHOD(EnumSurfaces)(THIS_ DWORD, LPDDSURFACEDESC2, LPVOID,LPDDENUMSURFACESCALLBACK7 ) PURE; // 24
    STDMETHOD(FlipToGDISurface)(THIS) PURE; // 28
    STDMETHOD(GetCaps)( THIS_ LPDDCAPS, LPDDCAPS) PURE; // 2c
    STDMETHOD(GetDisplayMode)( THIS_ LPDDSURFACEDESC2) PURE; // 30
    STDMETHOD(GetFourCCCodes)(THIS_  LPDWORD, LPDWORD ) PURE; // 34
    STDMETHOD(GetGDISurface)(THIS_ LPDIRECTDRAWSURFACE7 FAR *) PURE; // 38
    STDMETHOD(GetMonitorFrequency)(THIS_ LPDWORD) PURE; // 3c
    STDMETHOD(GetScanLine)(THIS_ LPDWORD) PURE; // 40
    STDMETHOD(GetVerticalBlankStatus)(THIS_ LPBOOL ) PURE; // 44
    STDMETHOD(Initialize)(THIS_ GUID FAR *) PURE; // 48
    STDMETHOD(RestoreDisplayMode)(THIS) PURE; // 4c
    STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) PURE; // 50
    STDMETHOD(SetDisplayMode)(THIS_ DWORD, DWORD,DWORD, DWORD, DWORD) PURE; // 0
    STDMETHOD(WaitForVerticalBlank)(THIS_ DWORD, HANDLE ) PURE; // 0
    /*** Added in the v2 interface ***/
    STDMETHOD(GetAvailableVidMem)(THIS_ LPDDSCAPS2, LPDWORD, LPDWORD) PURE;
    /*** Added in the V4 Interface ***/
    STDMETHOD(GetSurfaceFromDC) (THIS_ HDC, LPDIRECTDRAWSURFACE7 *) PURE;
    STDMETHOD(RestoreAllSurfaces)(THIS) PURE;
    STDMETHOD(TestCooperativeLevel)(THIS) PURE;
    STDMETHOD(GetDeviceIdentifier)(THIS_ LPDDDEVICEIDENTIFIER2, DWORD ) PURE;
    STDMETHOD(StartModeTest)(THIS_ LPSIZE, DWORD, DWORD ) PURE;
    STDMETHOD(EvaluateMode)(THIS_ DWORD, DWORD * ) PURE;
};
```
