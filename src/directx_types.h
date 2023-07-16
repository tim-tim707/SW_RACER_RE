#ifndef DIRECTX_TYPES_H
#define DIRECTX_TYPES_H

#include <windows.h>

typedef WINBOOL(__attribute__((__stdcall__)) * LPDDENUMCALLBACKA)(GUID*, LPSTR, LPSTR, LPVOID);
typedef struct IDirectDraw* LPDIRECTDRAW;
typedef struct IDirectDrawClipper* LPDIRECTDRAWCLIPPER;
typedef struct IDirectDrawPalette* LPDIRECTDRAWPALETTE;
typedef struct IDirectDrawSurface4* LPDIRECTDRAWSURFACE;
typedef struct IDirectDrawSurface4* LPDIRECTDRAWSURFACE4;

#define DD_ROP_SPACE (256 / 32) /* space required to store ROP array */

typedef struct _DDSCAPS
{
    DWORD dwCaps; /* capabilities of surface wanted */
} DDSCAPS, *LPDDSCAPS;

typedef struct _DDSCAPS2
{
    DWORD dwCaps; /* capabilities of surface wanted */
    DWORD dwCaps2; /* additional capabilities */
    DWORD dwCaps3; /* reserved capabilities */
    __extension__ union
    {
        DWORD dwCaps4; /* low word is the depth for a volume texture */
        DWORD dwVolumeDepth;
    } DUMMYUNIONNAME1;
} DDSCAPS2, *LPDDSCAPS2;

typedef struct _DDCAPS_DX5 /* DirectX5 version of caps struct */
{
    DWORD dwSize; /* size of the DDDRIVERCAPS structure */
    DWORD dwCaps; /* driver specific capabilities */
    DWORD dwCaps2; /* more driver specific capabilities */
    DWORD dwCKeyCaps; /* color key capabilities of the surface */
    DWORD dwFXCaps; /* driver specific stretching and effects capabilities */
    DWORD dwFXAlphaCaps; /* alpha driver specific capabilities */
    DWORD dwPalCaps; /* palette capabilities */
    DWORD dwSVCaps; /* stereo vision capabilities */
    DWORD dwAlphaBltConstBitDepths; /* DDBD_2,4,8 */
    DWORD dwAlphaBltPixelBitDepths; /* DDBD_1,2,4,8 */
    DWORD dwAlphaBltSurfaceBitDepths; /* DDBD_1,2,4,8 */
    DWORD dwAlphaOverlayConstBitDepths; /* DDBD_2,4,8 */
    DWORD dwAlphaOverlayPixelBitDepths; /* DDBD_1,2,4,8 */
    DWORD dwAlphaOverlaySurfaceBitDepths; /* DDBD_1,2,4,8 */
    DWORD dwZBufferBitDepths; /* DDBD_8,16,24,32 */
    DWORD dwVidMemTotal; /* total amount of video memory */
    DWORD dwVidMemFree; /* amount of free video memory */
    DWORD dwMaxVisibleOverlays; /* maximum number of visible overlays */
    DWORD dwCurrVisibleOverlays; /* current number of visible overlays */
    DWORD dwNumFourCCCodes; /* number of four cc codes */
    DWORD dwAlignBoundarySrc; /* source rectangle alignment */
    DWORD dwAlignSizeSrc; /* source rectangle byte size */
    DWORD dwAlignBoundaryDest; /* dest rectangle alignment */
    DWORD dwAlignSizeDest; /* dest rectangle byte size */
    DWORD dwAlignStrideAlign; /* stride alignment */
    DWORD dwRops[DD_ROP_SPACE]; /* ROPs supported */
    DDSCAPS ddsCaps; /* DDSCAPS structure has all the general capabilities */
    DWORD dwMinOverlayStretch; /* minimum overlay stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwMaxOverlayStretch; /* maximum overlay stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwMinLiveVideoStretch; /* minimum live video stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwMaxLiveVideoStretch; /* maximum live video stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwMinHwCodecStretch; /* minimum hardware codec stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwMaxHwCodecStretch; /* maximum hardware codec stretch factor multiplied by 1000, eg 1000 == 1.0, 1300 == 1.3 */
    DWORD dwReserved1;
    DWORD dwReserved2;
    DWORD dwReserved3;
    DWORD dwSVBCaps; /* driver specific capabilities for System->Vmem blts */
    DWORD dwSVBCKeyCaps; /* driver color key capabilities for System->Vmem blts */
    DWORD dwSVBFXCaps; /* driver FX capabilities for System->Vmem blts */
    DWORD dwSVBRops[DD_ROP_SPACE]; /* ROPs supported for System->Vmem blts */
    DWORD dwVSBCaps; /* driver specific capabilities for Vmem->System blts */
    DWORD dwVSBCKeyCaps; /* driver color key capabilities for Vmem->System blts */
    DWORD dwVSBFXCaps; /* driver FX capabilities for Vmem->System blts */
    DWORD dwVSBRops[DD_ROP_SPACE]; /* ROPs supported for Vmem->System blts */
    DWORD dwSSBCaps; /* driver specific capabilities for System->System blts */
    DWORD dwSSBCKeyCaps; /* driver color key capabilities for System->System blts */
    DWORD dwSSBFXCaps; /* driver FX capabilities for System->System blts */
    DWORD dwSSBRops[DD_ROP_SPACE]; /* ROPs supported for System->System blts */
    /* the following are the new DirectX 5 members */
    DWORD dwMaxVideoPorts; /* maximum number of usable video ports */
    DWORD dwCurrVideoPorts; /* current number of video ports used */
    DWORD dwSVBCaps2; /* more driver specific capabilities for System->Vmem blts */
    DWORD dwNLVBCaps; /* driver specific capabilities for non-local->local vidmem blts */
    DWORD dwNLVBCaps2; /* more driver specific capabilities non-local->local vidmem blts */
    DWORD dwNLVBCKeyCaps; /* driver color key capabilities for non-local->local vidmem blts */
    DWORD dwNLVBFXCaps; /* driver FX capabilities for non-local->local blts */
    DWORD dwNLVBRops[DD_ROP_SPACE]; /* ROPs supported for non-local->local blts */
} DDCAPS_DX5, *LPDDCAPS_DX5;

typedef DDCAPS_DX5 DDCAPS;
typedef DDCAPS* LPDDCAPS;

typedef struct _DDCOLORKEY
{
    DWORD dwColorSpaceLowValue; /* low boundary of color space that is to
                                 * be treated as Color Key, inclusive
                                 */
    DWORD dwColorSpaceHighValue; /* high boundary of color space that is
                                  * to be treated as Color Key, inclusive
                                  */
} DDCOLORKEY, *LPDDCOLORKEY;

#define MAX_DDDEVICEID_STRING 512
#define DDGDI_GETHOSTIDENTIFIER 1

typedef struct tagDDDEVICEIDENTIFIER
{
    char szDriver[MAX_DDDEVICEID_STRING];
    char szDescription[MAX_DDDEVICEID_STRING];
    LARGE_INTEGER liDriverVersion;
    DWORD dwVendorId;
    DWORD dwDeviceId;
    DWORD dwSubSysId;
    DWORD dwRevision;
    GUID guidDeviceIdentifier;
} DDDEVICEIDENTIFIER, *LPDDDEVICEIDENTIFIER;

typedef struct _DDPIXELFORMAT
{
    DWORD dwSize; /* 0: size of structure */
    DWORD dwFlags; /* 4: pixel format flags */
    DWORD dwFourCC; /* 8: (FOURCC code) */
    __extension__ union
    {
        DWORD dwRGBBitCount; /* C: how many bits per pixel */
        DWORD dwYUVBitCount; /* C: how many bits per pixel */
        DWORD dwZBufferBitDepth; /* C: how many bits for z buffers */
        DWORD dwAlphaBitDepth; /* C: how many bits for alpha channels*/
        DWORD dwLuminanceBitCount;
        DWORD dwBumpBitCount;
        DWORD dwPrivateFormatBitCount;
    } DUMMYUNIONNAME1;
    __extension__ union
    {
        DWORD dwRBitMask; /* 10: mask for red bit*/
        DWORD dwYBitMask; /* 10: mask for Y bits*/
        DWORD dwStencilBitDepth;
        DWORD dwLuminanceBitMask;
        DWORD dwBumpDuBitMask;
        DWORD dwOperations;
    } DUMMYUNIONNAME2;
    __extension__ union
    {
        DWORD dwGBitMask; /* 14: mask for green bits*/
        DWORD dwUBitMask; /* 14: mask for U bits*/
        DWORD dwZBitMask;
        DWORD dwBumpDvBitMask;
        struct
        {
            WORD wFlipMSTypes;
            WORD wBltMSTypes;
        } MultiSampleCaps;
    } DUMMYUNIONNAME3;
    __extension__ union
    {
        DWORD dwBBitMask; /* 18: mask for blue bits*/
        DWORD dwVBitMask; /* 18: mask for V bits*/
        DWORD dwStencilBitMask;
        DWORD dwBumpLuminanceBitMask;
    } DUMMYUNIONNAME4;
    __extension__ union
    {
        DWORD dwRGBAlphaBitMask; /* 1C: mask for alpha channel */
        DWORD dwYUVAlphaBitMask; /* 1C: mask for alpha channel */
        DWORD dwLuminanceAlphaBitMask;
        DWORD dwRGBZBitMask; /* 1C: mask for Z channel */
        DWORD dwYUVZBitMask; /* 1C: mask for Z channel */
    } DUMMYUNIONNAME5;
    /* 20: next structure */
} DDPIXELFORMAT, *LPDDPIXELFORMAT;

typedef struct _DDSURFACEDESC
{
    DWORD dwSize; /* 0: size of the DDSURFACEDESC structure*/
    DWORD dwFlags; /* 4: determines what fields are valid*/
    DWORD dwHeight; /* 8: height of surface to be created*/
    DWORD dwWidth; /* C: width of input surface*/
    __extension__ union
    {
        LONG lPitch; /* 10: distance to start of next line (return value only)*/
        DWORD dwLinearSize;
    } DUMMYUNIONNAME1;
    DWORD dwBackBufferCount; /* 14: number of back buffers requested*/
    __extension__ union
    {
        DWORD dwMipMapCount; /* 18:number of mip-map levels requested*/
        DWORD dwZBufferBitDepth; /*18: depth of Z buffer requested*/
        DWORD dwRefreshRate; /* 18:refresh rate (used when display mode is described)*/
    } DUMMYUNIONNAME2;
    DWORD dwAlphaBitDepth; /* 1C:depth of alpha buffer requested*/
    DWORD dwReserved; /* 20:reserved*/
    LPVOID lpSurface; /* 24:pointer to the associated surface memory*/
    DDCOLORKEY ddckCKDestOverlay; /* 28: CK for dest overlay use*/
    DDCOLORKEY ddckCKDestBlt; /* 30: CK for destination blt use*/
    DDCOLORKEY ddckCKSrcOverlay; /* 38: CK for source overlay use*/
    DDCOLORKEY ddckCKSrcBlt; /* 40: CK for source blt use*/
    DDPIXELFORMAT ddpfPixelFormat; /* 48: pixel format description of the surface*/
    DDSCAPS ddsCaps; /* 68: direct draw surface caps */
} DDSURFACEDESC, *LPDDSURFACEDESC;

typedef struct _DDSURFACEDESC2
{
    DWORD dwSize; /* 0: size of the DDSURFACEDESC2 structure*/
    DWORD dwFlags; /* 4: determines what fields are valid*/
    DWORD dwHeight; /* 8: height of surface to be created*/
    DWORD dwWidth; /* C: width of input surface*/
    __extension__ union
    {
        LONG lPitch; /*10: distance to start of next line (return value only)*/
        DWORD dwLinearSize; /*10: formless late-allocated optimized surface size */
    } DUMMYUNIONNAME1;
    __extension__ union
    {
        DWORD dwBackBufferCount; /* 14: number of back buffers requested */
        DWORD dwDepth; /* The bit-depth if this is a volume texture. */
    } DUMMYUNIONNAME5;
    __extension__ union
    {
        DWORD dwMipMapCount; /* 18:number of mip-map levels requested*/
        DWORD dwRefreshRate; /* 18:refresh rate (used when display mode is described)*/
        DWORD dwSrcVBHandle; /* 18:source used in VB::Optimize */
    } DUMMYUNIONNAME2;
    DWORD dwAlphaBitDepth; /* 1C:depth of alpha buffer requested*/
    DWORD dwReserved; /* 20:reserved*/
    LPVOID lpSurface; /* 24:pointer to the associated surface memory*/
    __extension__ union
    {
        DDCOLORKEY ddckCKDestOverlay; /* 28: CK for dest overlay use*/
        DWORD dwEmptyFaceColor; /* 28: color for empty cubemap faces */
    } DUMMYUNIONNAME3;
    DDCOLORKEY ddckCKDestBlt; /* 30: CK for destination blt use*/
    DDCOLORKEY ddckCKSrcOverlay; /* 38: CK for source overlay use*/
    DDCOLORKEY ddckCKSrcBlt; /* 40: CK for source blt use*/

    __extension__ union
    {
        DDPIXELFORMAT ddpfPixelFormat; /* 48: pixel format description of the surface*/
        DWORD dwFVF; /* 48: vertex format description of vertex buffers */
    } DUMMYUNIONNAME4;
    DDSCAPS2 ddsCaps; /* 68: DDraw surface caps */
    DWORD dwTextureStage; /* 78: stage in multitexture cascade */
} DDSURFACEDESC2, *LPDDSURFACEDESC2;

typedef struct _DDBLTFX
{
    DWORD dwSize; /* size of structure */
    DWORD dwDDFX; /* FX operations */
    DWORD dwROP; /* Win32 raster operations */
    DWORD dwDDROP; /* Raster operations new for DirectDraw */
    DWORD dwRotationAngle; /* Rotation angle for blt */
    DWORD dwZBufferOpCode; /* ZBuffer compares */
    DWORD dwZBufferLow; /* Low limit of Z buffer */
    DWORD dwZBufferHigh; /* High limit of Z buffer */
    DWORD dwZBufferBaseDest; /* Destination base value */
    DWORD dwZDestConstBitDepth; /* Bit depth used to specify Z constant for destination */
    __extension__ union
    {
        DWORD dwZDestConst; /* Constant to use as Z buffer for dest */
        LPDIRECTDRAWSURFACE lpDDSZBufferDest; /* Surface to use as Z buffer for dest */
    } DUMMYUNIONNAME1;
    DWORD dwZSrcConstBitDepth; /* Bit depth used to specify Z constant for source */
    __extension__ union
    {
        DWORD dwZSrcConst; /* Constant to use as Z buffer for src */
        LPDIRECTDRAWSURFACE lpDDSZBufferSrc; /* Surface to use as Z buffer for src */
    } DUMMYUNIONNAME2;
    DWORD dwAlphaEdgeBlendBitDepth; /* Bit depth used to specify constant for alpha edge blend */
    DWORD dwAlphaEdgeBlend; /* Alpha for edge blending */
    DWORD dwReserved;
    DWORD dwAlphaDestConstBitDepth; /* Bit depth used to specify alpha constant for destination */
    __extension__ union
    {
        DWORD dwAlphaDestConst; /* Constant to use as Alpha Channel */
        LPDIRECTDRAWSURFACE lpDDSAlphaDest; /* Surface to use as Alpha Channel */
    } DUMMYUNIONNAME3;
    DWORD dwAlphaSrcConstBitDepth; /* Bit depth used to specify alpha constant for source */
    __extension__ union
    {
        DWORD dwAlphaSrcConst; /* Constant to use as Alpha Channel */
        LPDIRECTDRAWSURFACE lpDDSAlphaSrc; /* Surface to use as Alpha Channel */
    } DUMMYUNIONNAME4;
    __extension__ union
    {
        DWORD dwFillColor; /* color in RGB or Palettized */
        DWORD dwFillDepth; /* depth value for z-buffer */
        DWORD dwFillPixel; /* pixel val for RGBA or RGBZ */
        LPDIRECTDRAWSURFACE lpDDSPattern; /* Surface to use as pattern */
    } DUMMYUNIONNAME5;
    DDCOLORKEY ddckDestColorkey; /* DestColorkey override */
    DDCOLORKEY ddckSrcColorkey; /* SrcColorkey override */
} DDBLTFX, *LPDDBLTFX;

typedef struct _DDBLTBATCH
{
    LPRECT lprDest;
    LPDIRECTDRAWSURFACE lpDDSSrc;
    LPRECT lprSrc;
    DWORD dwFlags;
    LPDDBLTFX lpDDBltFx;
} DDBLTBATCH, *LPDDBLTBATCH;

typedef struct _DDOVERLAYFX
{
    DWORD dwSize; /* size of structure */
    DWORD dwAlphaEdgeBlendBitDepth; /* Bit depth used to specify constant for alpha edge blend */
    DWORD dwAlphaEdgeBlend; /* Constant to use as alpha for edge blend */
    DWORD dwReserved;
    DWORD dwAlphaDestConstBitDepth; /* Bit depth used to specify alpha constant for destination */
    __extension__ union
    {
        DWORD dwAlphaDestConst; /* Constant to use as alpha channel for dest */
        LPDIRECTDRAWSURFACE lpDDSAlphaDest; /* Surface to use as alpha channel for dest */
    } DUMMYUNIONNAME1;
    DWORD dwAlphaSrcConstBitDepth; /* Bit depth used to specify alpha constant for source */
    __extension__ union
    {
        DWORD dwAlphaSrcConst; /* Constant to use as alpha channel for src */
        LPDIRECTDRAWSURFACE lpDDSAlphaSrc; /* Surface to use as alpha channel for src */
    } DUMMYUNIONNAME2;
    DDCOLORKEY dckDestColorkey; /* DestColorkey override */
    DDCOLORKEY dckSrcColorkey; /* DestColorkey override */
    DWORD dwDDFX; /* Overlay FX */
    DWORD dwFlags; /* flags */
} DDOVERLAYFX, *LPDDOVERLAYFX;

typedef HRESULT(__attribute__((__stdcall__)) * LPDDENUMMODESCALLBACK)(LPDDSURFACEDESC, LPVOID);
typedef HRESULT(__attribute__((__stdcall__)) * LPDDENUMSURFACESCALLBACK2)(LPDIRECTDRAWSURFACE4, LPDDSURFACEDESC2, LPVOID);
typedef HRESULT(__attribute__((__stdcall__)) * LPDDENUMSURFACESCALLBACK)(LPDIRECTDRAWSURFACE, LPDDSURFACEDESC, LPVOID);

typedef struct IDirectDrawSurface4
{
    struct IDirectDrawSurface4Vtbl* lpVtbl;
} IDirectDrawSurface4;

typedef struct IDirectDrawSurface4Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectDrawSurface4* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectDrawSurface4* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectDrawSurface4* This);
    /*** IDirectDrawSurface4 methods ***/
    HRESULT(__attribute__((__stdcall__)) * AddAttachedSurface)(IDirectDrawSurface4* This, LPDIRECTDRAWSURFACE4 lpDDSAttachedSurface);
    HRESULT(__attribute__((__stdcall__)) * AddOverlayDirtyRect)(IDirectDrawSurface4* This, LPRECT lpRect);
    HRESULT(__attribute__((__stdcall__)) * Blt)(IDirectDrawSurface4* This, LPRECT lpDestRect, LPDIRECTDRAWSURFACE4 lpDDSrcSurface, LPRECT lpSrcRect, DWORD dwFlags, LPDDBLTFX lpDDBltFx);
    HRESULT(__attribute__((__stdcall__)) * BltBatch)(IDirectDrawSurface4* This, LPDDBLTBATCH lpDDBltBatch, DWORD dwCount, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * BltFast)(IDirectDrawSurface4* This, DWORD dwX, DWORD dwY, LPDIRECTDRAWSURFACE4 lpDDSrcSurface, LPRECT lpSrcRect, DWORD dwTrans);
    HRESULT(__attribute__((__stdcall__)) * DeleteAttachedSurface)(IDirectDrawSurface4* This, DWORD dwFlags, LPDIRECTDRAWSURFACE4 lpDDSAttachedSurface);
    HRESULT(__attribute__((__stdcall__)) * EnumAttachedSurfaces)(IDirectDrawSurface4* This, LPVOID lpContext, LPDDENUMSURFACESCALLBACK2 lpEnumSurfacesCallback);
    HRESULT(__attribute__((__stdcall__)) * EnumOverlayZOrders)(IDirectDrawSurface4* This, DWORD dwFlags, LPVOID lpContext, LPDDENUMSURFACESCALLBACK2 lpfnCallback);
    HRESULT(__attribute__((__stdcall__)) * Flip)(IDirectDrawSurface4* This, LPDIRECTDRAWSURFACE4 lpDDSurfaceTargetOverride, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetAttachedSurface)(IDirectDrawSurface4* This, LPDDSCAPS2 lpDDSCaps, LPDIRECTDRAWSURFACE4* lplpDDAttachedSurface);
    HRESULT(__attribute__((__stdcall__)) * GetBltStatus)(IDirectDrawSurface4* This, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirectDrawSurface4* This, LPDDSCAPS2 lpDDSCaps);
    HRESULT(__attribute__((__stdcall__)) * GetClipper)(IDirectDrawSurface4* This, LPDIRECTDRAWCLIPPER* lplpDDClipper);
    HRESULT(__attribute__((__stdcall__)) * GetColorKey)(IDirectDrawSurface4* This, DWORD dwFlags, LPDDCOLORKEY lpDDColorKey);
    HRESULT(__attribute__((__stdcall__)) * GetDC)(IDirectDrawSurface4* This, HDC* lphDC);
    HRESULT(__attribute__((__stdcall__)) * GetFlipStatus)(IDirectDrawSurface4* This, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetOverlayPosition)(IDirectDrawSurface4* This, LPLONG lplX, LPLONG lplY);
    HRESULT(__attribute__((__stdcall__)) * GetPalette)(IDirectDrawSurface4* This, LPDIRECTDRAWPALETTE* lplpDDPalette);
    HRESULT(__attribute__((__stdcall__)) * GetPixelFormat)(IDirectDrawSurface4* This, LPDDPIXELFORMAT lpDDPixelFormat);
    HRESULT(__attribute__((__stdcall__)) * GetSurfaceDesc)(IDirectDrawSurface4* This, LPDDSURFACEDESC2 lpDDSurfaceDesc);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectDrawSurface4* This, LPDIRECTDRAW lpDD, LPDDSURFACEDESC2 lpDDSurfaceDesc);
    HRESULT(__attribute__((__stdcall__)) * IsLost)(IDirectDrawSurface4* This);
    HRESULT(__attribute__((__stdcall__)) * Lock)(IDirectDrawSurface4* This, LPRECT lpDestRect, LPDDSURFACEDESC2 lpDDSurfaceDesc, DWORD dwFlags, HANDLE hEvent);
    HRESULT(__attribute__((__stdcall__)) * ReleaseDC)(IDirectDrawSurface4* This, HDC hDC);
    HRESULT(__attribute__((__stdcall__)) * Restore)(IDirectDrawSurface4* This);
    HRESULT(__attribute__((__stdcall__)) * SetClipper)(IDirectDrawSurface4* This, LPDIRECTDRAWCLIPPER lpDDClipper);
    HRESULT(__attribute__((__stdcall__)) * SetColorKey)(IDirectDrawSurface4* This, DWORD dwFlags, LPDDCOLORKEY lpDDColorKey);
    HRESULT(__attribute__((__stdcall__)) * SetOverlayPosition)(IDirectDrawSurface4* This, LONG lX, LONG lY);
    HRESULT(__attribute__((__stdcall__)) * SetPalette)(IDirectDrawSurface4* This, LPDIRECTDRAWPALETTE lpDDPalette);
    HRESULT(__attribute__((__stdcall__)) * Unlock)(IDirectDrawSurface4* This, LPRECT lpSurfaceData);
    HRESULT(__attribute__((__stdcall__)) * UpdateOverlay)(IDirectDrawSurface4* This, LPRECT lpSrcRect, LPDIRECTDRAWSURFACE4 lpDDDestSurface, LPRECT lpDestRect, DWORD dwFlags, LPDDOVERLAYFX lpDDOverlayFx);
    HRESULT(__attribute__((__stdcall__)) * UpdateOverlayDisplay)(IDirectDrawSurface4* This, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * UpdateOverlayZOrder)(IDirectDrawSurface4* This, DWORD dwFlags, LPDIRECTDRAWSURFACE4 lpDDSReference);
    /* added in v2 */
    HRESULT(__attribute__((__stdcall__)) * GetDDInterface)(IDirectDrawSurface4* This, LPVOID* lplpDD);
    HRESULT(__attribute__((__stdcall__)) * PageLock)(IDirectDrawSurface4* This, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * PageUnlock)(IDirectDrawSurface4* This, DWORD dwFlags);
    /* added in v3 */
    HRESULT(__attribute__((__stdcall__)) * SetSurfaceDesc)(IDirectDrawSurface4* This, LPDDSURFACEDESC2 lpDDSD, DWORD dwFlags);
    /* added in v4 */
    HRESULT(__attribute__((__stdcall__)) * SetPrivateData)(IDirectDrawSurface4* This, GUID* tag, LPVOID pData, DWORD cbSize, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetPrivateData)(IDirectDrawSurface4* This, GUID* tag, LPVOID pBuffer, LPDWORD pcbBufferSize);
    HRESULT(__attribute__((__stdcall__)) * FreePrivateData)(IDirectDrawSurface4* This, GUID* tag);
    HRESULT(__attribute__((__stdcall__)) * GetUniquenessValue)(IDirectDrawSurface4* This, LPDWORD pValue);
    HRESULT(__attribute__((__stdcall__)) * ChangeUniquenessValue)(IDirectDrawSurface4* This);
} IDirectDrawSurface4Vtbl;

// IDirectDraw4Vtbl
typedef struct IDirectDrawVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectDraw* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectDraw* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectDraw* This);
    /*** IDirectDraw methods ***/
    HRESULT(__attribute__((__stdcall__)) * Compact)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * CreateClipper)(IDirectDraw* This, DWORD dwFlags, LPDIRECTDRAWCLIPPER* lplpDDClipper, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * CreatePalette)(IDirectDraw* This, DWORD dwFlags, LPPALETTEENTRY lpColorTable, LPDIRECTDRAWPALETTE* lplpDDPalette, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * CreateSurface)(IDirectDraw* This, LPDDSURFACEDESC lpDDSurfaceDesc, LPDIRECTDRAWSURFACE* lplpDDSurface, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * DuplicateSurface)(IDirectDraw* This, LPDIRECTDRAWSURFACE lpDDSurface, LPDIRECTDRAWSURFACE* lplpDupDDSurface);
    HRESULT(__attribute__((__stdcall__)) * EnumDisplayModes)(IDirectDraw* This, DWORD dwFlags, LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext, LPDDENUMMODESCALLBACK lpEnumModesCallback);
    HRESULT(__attribute__((__stdcall__)) * EnumSurfaces)(IDirectDraw* This, DWORD dwFlags, LPDDSURFACEDESC lpDDSD, LPVOID lpContext, LPDDENUMSURFACESCALLBACK lpEnumSurfacesCallback);
    HRESULT(__attribute__((__stdcall__)) * FlipToGDISurface)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirectDraw* This, LPDDCAPS lpDDDriverCaps, LPDDCAPS lpDDHELCaps);
    HRESULT(__attribute__((__stdcall__)) * GetDisplayMode)(IDirectDraw* This, LPDDSURFACEDESC lpDDSurfaceDesc);
    HRESULT(__attribute__((__stdcall__)) * GetFourCCCodes)(IDirectDraw* This, LPDWORD lpNumCodes, LPDWORD lpCodes);
    HRESULT(__attribute__((__stdcall__)) * GetGDISurface)(IDirectDraw* This, LPDIRECTDRAWSURFACE* lplpGDIDDSurface);
    HRESULT(__attribute__((__stdcall__)) * GetMonitorFrequency)(IDirectDraw* This, LPDWORD lpdwFrequency);
    HRESULT(__attribute__((__stdcall__)) * GetScanLine)(IDirectDraw* This, LPDWORD lpdwScanLine);
    HRESULT(__attribute__((__stdcall__)) * GetVerticalBlankStatus)(IDirectDraw* This, WINBOOL* lpbIsInVB);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectDraw* This, GUID* lpGUID);
    HRESULT(__attribute__((__stdcall__)) * RestoreDisplayMode)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * SetCooperativeLevel)(IDirectDraw* This, HWND hWnd, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * SetDisplayMode)(IDirectDraw* This, DWORD dwWidth, DWORD dwHeight, DWORD dwBPP);
    HRESULT(__attribute__((__stdcall__)) * WaitForVerticalBlank)(IDirectDraw* This, DWORD dwFlags, HANDLE hEvent);
    /* added in v2 */
    HRESULT(__attribute__((__stdcall__)) * GetAvailableVidMem)(IDirectDraw* This, LPDDSCAPS2 lpDDCaps, LPDWORD lpdwTotal, LPDWORD lpdwFree);
    /* added in v4 */
    HRESULT(__attribute__((__stdcall__)) * GetSurfaceFromDC)(IDirectDraw* This, HDC hdc, LPDIRECTDRAWSURFACE4* pSurf);
    HRESULT(__attribute__((__stdcall__)) * RestoreAllSurfaces)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * TestCooperativeLevel)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * GetDeviceIdentifier)(IDirectDraw* This, LPDDDEVICEIDENTIFIER pDDDI, DWORD dwFlags);
} IDirectDrawVtbl;

// IDirectDraw4
typedef struct IDirectDraw
{
    struct IDirectDrawVtbl* lpVtbl;
} IDirectDraw;

//
// Direct Input
//

typedef struct IDirectInputA* LPDIRECTINPUTA;
typedef struct IDirectInputDeviceA* LPDIRECTINPUTDEVICEA;
typedef WINBOOL(__attribute__((__stdcall__)) * LPDIENUMDEVICESCALLBACKA)(LPCDIDEVICEINSTANCEA, LPVOID);

typedef struct DIDEVICEINSTANCEA
{
    DWORD dwSize;
    GUID guidInstance;
    GUID guidProduct;
    DWORD dwDevType;
    CHAR tszInstanceName[MAX_PATH];
    CHAR tszProductName[MAX_PATH];
    GUID guidFFDriver;
    WORD wUsagePage;
    WORD wUsage;
} DIDEVICEINSTANCEA, *LPDIDEVICEINSTANCEA;
typedef const DIDEVICEINSTANCEA* LPCDIDEVICEINSTANCEA;

typedef struct IDirectInputA
{
    struct IDirectInputAVtbl* lpVtbl;
} IDirectInputA;

typedef struct IDirectInputAVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectInputA* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectInputA* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectInputA* This);
    /*** IDirectInputA methods ***/
    HRESULT(__attribute__((__stdcall__)) * CreateDevice)(IDirectInputA* This, GUID* rguid, LPDIRECTINPUTDEVICEA* lplpDirectInputDevice, LPUNKNOWN pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * EnumDevices)(IDirectInputA* This, DWORD dwDevType, LPDIENUMDEVICESCALLBACKA lpCallback, LPVOID pvRef, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetDeviceStatus)(IDirectInputA* This, GUID* rguidInstance);
    HRESULT(__attribute__((__stdcall__)) * RunControlPanel)(IDirectInputA* This, HWND hwndOwner, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectInputA* This, HINSTANCE hinst, DWORD dwVersion);
} IDirectInputAVtbl;
#endif // DIRECTX_TYPES_H
