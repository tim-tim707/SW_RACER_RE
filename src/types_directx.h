#ifndef TYPES_DIRECTX_H
#define TYPES_DIRECTX_H

// This header is a combination of DirectDraw, DirectInput, Direct3D and DirectPlay specifically for Star Wars Episode I Racer.
// The versions are specific for this game.
// This file is for parsing by Ghidra "parse C source" command and documentation

#include <windows.h>
#include <ole2.h>

#ifdef INCLUDE_DX_HEADERS

#include <ddraw.h>
#include <dinput.h>
#include <d3d.h>
#include <dplay.h>

#else

//
// DirectDraw
// From https://github.com/CnCNet/ts-ddraw/blob/master/ddraw.h
// and https://github.com/apitrace/dxsdk/blob/master/Include/ddraw.h
//

typedef int WINBOOL;
typedef WINBOOL(__attribute__((__stdcall__)) * LPDDENUMCALLBACKA)(GUID*, LPSTR, LPSTR, LPVOID);

typedef struct IDirectDraw4 IDirectDraw;
typedef struct IDirectDraw4Vtbl IDirectDrawVtbl;

typedef IDirectDraw* LPDIRECTDRAW;
typedef struct IDirectDraw4* LPDIRECTDRAW4;
typedef struct IDirectDrawClipper* LPDIRECTDRAWCLIPPER;
typedef struct IDirectDrawPalette* LPDIRECTDRAWPALETTE;
typedef struct IDirectDrawSurface4 IDirectDrawSurface;
typedef struct IDirectDrawSurface4* LPDIRECTDRAWSURFACE;
typedef struct IDirectDrawSurface4* LPDIRECTDRAWSURFACE4;

typedef struct IDirectDrawClipper
{
    struct IDirectDrawClipperVtbl* lpVtbl;
} IDirectDrawClipper;
typedef struct IDirectDrawClipperVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectDrawClipper* This, IID* riid, void** ppvObject);
    HRESULT(__attribute__((__stdcall__)) * AddRef)(IDirectDrawClipper* This);
    HRESULT(__attribute__((__stdcall__)) * Release)(IDirectDrawClipper* This);
    /*** IDirectDrawClipper methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetClipList)(IDirectDrawClipper* This, LPRECT lpRect, LPRGNDATA lpClipList, LPDWORD lpdwSize);
    HRESULT(__attribute__((__stdcall__)) * GetHWnd)(IDirectDrawClipper* This, HWND* lphWnd);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectDrawClipper* This, LPDIRECTDRAW lpDD, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * IsClipListChanged)(IDirectDrawClipper* This, WINBOOL* lpbChanged);
    HRESULT(__attribute__((__stdcall__)) * SetClipList)(IDirectDrawClipper* This, LPRGNDATA lpClipList, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * SetHWnd)(IDirectDrawClipper* This, DWORD dwFlags, HWND hWnd);
} IDirectDrawClipperVtbl;

typedef struct IDirectDrawPalette
{
    struct IDirectDrawPaletteVtbl* lpVtbl;
} IDirectDrawPalette;

typedef struct IDirectDrawPaletteVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectDrawPalette* This, IID* riid, LPVOID* ppvObj);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectDrawPalette* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectDrawPalette* This);
    /*** IDirectDrawPalette methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirectDrawPalette* This, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetEntries)(IDirectDrawPalette* This, DWORD, DWORD, DWORD, LPPALETTEENTRY);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectDrawPalette* This, LPDIRECTDRAW, DWORD, LPPALETTEENTRY);
    HRESULT(__attribute__((__stdcall__)) * SetEntries)(IDirectDrawPalette* This, DWORD, DWORD, DWORD, LPPALETTEENTRY);
} IDirectDrawPaletteVtbl;

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
} DDCAPS_DX5, *LPDDCAPS_DX5; // sizeof(0x16c)

// typedef struct __declspec(align(4)) DDCAPS_DX6 // Jones. Check Sizeof with DX5
typedef struct DDCAPS_DX6 // Jones. Check Sizeof with DX5
{
    DWORD dwSize;
    DWORD dwCaps;
    DWORD dwCaps2;
    DWORD dwCKeyCaps;
    DWORD dwFXCaps;
    DWORD dwFXAlphaCaps;
    DWORD dwPalCaps;
    DWORD dwSVCaps;
    DWORD dwAlphaBltConstBitDepths;
    DWORD dwAlphaBltPixelBitDepths;
    DWORD dwAlphaBltSurfaceBitDepths;
    DWORD dwAlphaOverlayConstBitDepths;
    DWORD dwAlphaOverlayPixelBitDepths;
    DWORD dwAlphaOverlaySurfaceBitDepths;
    DWORD dwZBufferBitDepths;
    DWORD dwVidMemTotal;
    DWORD dwVidMemFree;
    DWORD dwMaxVisibleOverlays;
    DWORD dwCurrVisibleOverlays;
    DWORD dwNumFourCCCodes;
    DWORD dwAlignBoundarySrc;
    DWORD dwAlignSizeSrc;
    DWORD dwAlignBoundaryDest;
    DWORD dwAlignSizeDest;
    DWORD dwAlignStrideAlign;
    DWORD dwRops[8];
    DDSCAPS ddsOldCaps;
    DWORD dwMinOverlayStretch;
    DWORD dwMaxOverlayStretch;
    DWORD dwMinLiveVideoStretch;
    DWORD dwMaxLiveVideoStretch;
    DWORD dwMinHwCodecStretch;
    DWORD dwMaxHwCodecStretch;
    DWORD dwReserved1;
    DWORD dwReserved2;
    DWORD dwReserved3;
    DWORD dwSVBCaps;
    DWORD dwSVBCKeyCaps;
    DWORD dwSVBFXCaps;
    DWORD dwSVBRops[8];
    DWORD dwVSBCaps;
    DWORD dwVSBCKeyCaps;
    DWORD dwVSBFXCaps;
    DWORD dwVSBRops[8];
    DWORD dwSSBCaps;
    DWORD dwSSBCKeyCaps;
    DWORD dwSSBFXCaps;
    DWORD dwSSBRops[8];
    DWORD dwMaxVideoPorts;
    DWORD dwCurrVideoPorts;
    DWORD dwSVBCaps2;
    DWORD dwNLVBCaps;
    DWORD dwNLVBCaps2;
    DWORD dwNLVBCKeyCaps;
    DWORD dwNLVBFXCaps;
    DWORD dwNLVBRops[8];
    DDSCAPS2 ddsCaps;
} DDCAPS_DX6;

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

typedef enum DDPIXELFORMATFLAGS
{
    DDPF_ALPHAPIXELS = 0x00000001l,
    DDPF_ALPHA = 0x00000002l,
    DDPF_FOURCC = 0x00000004l,
    DDPF_PALETTEINDEXED4 = 0x00000008l,
    DDPF_PALETTEINDEXEDTO8 = 0x00000010l,
    DDPF_PALETTEINDEXED8 = 0x00000020l,
    DDPF_RGB = 0x00000040l,
    DDPF_COMPRESSED = 0x00000080l,
    DDPF_RGBTOYUV = 0x00000100l,
    DDPF_YUV = 0x00000200l,
    DDPF_ZBUFFER = 0x00000400l,
    DDPF_PALETTEINDEXED1 = 0x00000800l,
    DDPF_PALETTEINDEXED2 = 0x00001000l,
    DDPF_ZPIXELS = 0x00002000l,
    DDPF_STENCILBUFFER = 0x00004000l,
    DDPF_ALPHAPREMULT = 0x00008000l,
    DDPF_LUMINANCE = 0x00020000l,
    DDPF_BUMPLUMINANCE = 0x00040000l,
    DDPF_BUMPDUDV = 0x00080000l,
} DDPIXELFORMATFLAGS;

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
} DDBLTBATCH, *LPDDBLTBATCH; // sizeof(0x14)

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
    HRESULT(__attribute__((__stdcall__)) * AddAttachedSurface)(IDirectDrawSurface4* This, LPDIRECTDRAWSURFACE4 lpDDSAttachedSurface); // 0xc
    HRESULT(__attribute__((__stdcall__)) * AddOverlayDirtyRect)(IDirectDrawSurface4* This, LPRECT lpRect); // 0x10
    HRESULT(__attribute__((__stdcall__)) * Blt)(IDirectDrawSurface4* This, LPRECT lpDestRect, LPDIRECTDRAWSURFACE4 lpDDSrcSurface, LPRECT lpSrcRect, DWORD dwFlags, LPDDBLTFX lpDDBltFx);
    HRESULT(__attribute__((__stdcall__)) * BltBatch)(IDirectDrawSurface4* This, LPDDBLTBATCH lpDDBltBatch, DWORD dwCount, DWORD dwFlags); // 0x18
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

typedef struct IDirectDraw4Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectDraw* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectDraw* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectDraw* This); // 0x8
    /*** IDirectDraw methods ***/
    HRESULT(__attribute__((__stdcall__)) * Compact)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * CreateClipper)(IDirectDraw* This, DWORD dwFlags, LPDIRECTDRAWCLIPPER* lplpDDClipper, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * CreatePalette)(IDirectDraw* This, DWORD dwFlags, LPPALETTEENTRY lpColorTable, LPDIRECTDRAWPALETTE* lplpDDPalette, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * CreateSurface)(IDirectDraw* This, LPDDSURFACEDESC lpDDSurfaceDesc, LPDIRECTDRAWSURFACE* lplpDDSurface, IUnknown* pUnkOuter);
    HRESULT(__attribute__((__stdcall__)) * DuplicateSurface)(IDirectDraw* This, LPDIRECTDRAWSURFACE lpDDSurface, LPDIRECTDRAWSURFACE* lplpDupDDSurface);
    HRESULT(__attribute__((__stdcall__)) * EnumDisplayModes)(IDirectDraw* This, DWORD dwFlags, LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext, LPDDENUMMODESCALLBACK lpEnumModesCallback);
    HRESULT(__attribute__((__stdcall__)) * EnumSurfaces)(IDirectDraw* This, DWORD dwFlags, LPDDSURFACEDESC lpDDSD, LPVOID lpContext, LPDDENUMSURFACESCALLBACK lpEnumSurfacesCallback);
    HRESULT(__attribute__((__stdcall__)) * FlipToGDISurface)(IDirectDraw* This);
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirectDraw* This, LPDDCAPS lpDDDriverCaps, LPDDCAPS lpDDHELCaps); // 0x2c
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
} IDirectDraw4Vtbl;

typedef struct IDirectDraw4
{
    struct IDirectDraw4Vtbl* lpVtbl;
} IDirectDraw4;

//
// Direct Input
// From https://github.com/project64/project64/blob/b0b6c03eea6ea3ef5bddca32de5fdebd94b0be7e/Source/3rdParty/directx/include/dinput.h
//

typedef struct IDirectInputA* LPDIRECTINPUTA;
typedef struct IDirectInputDeviceA* LPDIRECTINPUTDEVICEA;

typedef enum DIDEVTYPE // DIDEVTYPE for version 5
{
    DIDEVTYPE_DEVICE = 1,
    DIDEVTYPE_MOUSE = 2,
    DIDEVTYPE_KEYBOARD = 3,
    DIDEVTYPE_JOYSTICK = 4,
} DIDEVTYPE;

typedef struct DIDEVICEINSTANCEA
{
    DWORD dwSize;
    GUID guidInstance;
    GUID guidProduct;
    DWORD dwDevType;
    CHAR tszInstanceName[260];
    CHAR tszProductName[260];
    GUID guidFFDriver;
    WORD wUsagePage;
    WORD wUsage;
} DIDEVICEINSTANCEA, *LPDIDEVICEINSTANCEA; // sizeof(0x3c)

typedef struct DIDEVICEINSTANCEW
{
    DWORD dwSize;
    GUID guidInstance;
    GUID guidProduct;
    DWORD dwDevType;
    WCHAR tszInstanceName[MAX_PATH];
    WCHAR tszProductName[MAX_PATH];
    GUID guidFFDriver;
    WORD wUsagePage;
    WORD wUsage;
} DIDEVICEINSTANCEW, *LPDIDEVICEINSTANCEW;

typedef const DIDEVICEINSTANCEA* LPCDIDEVICEINSTANCEA;

typedef WINBOOL(__attribute__((__stdcall__)) * LPDIENUMDEVICESCALLBACKA)(LPCDIDEVICEINSTANCEA, LPVOID);

typedef struct DIDEVCAPS
{
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwDevType;
    DWORD dwAxes;
    DWORD dwButtons;
    DWORD dwPOVs;
    DWORD dwFFSamplePeriod;
    DWORD dwFFMinTimeResolution;
    DWORD dwFirmwareRevision;
    DWORD dwHardwareRevision;
    DWORD dwFFDriverVersion;
} DIDEVCAPS, *LPDIDEVCAPS;

typedef struct DIDEVICEOBJECTINSTANCEA
{
    DWORD dwSize;
    GUID guidType;
    DWORD dwOfs;
    DWORD dwType;
    DWORD dwFlags;
    CHAR tszName[MAX_PATH];
    DWORD dwFFMaxForce;
    DWORD dwFFForceResolution;
    WORD wCollectionNumber;
    WORD wDesignatorIndex;
    WORD wUsagePage;
    WORD wUsage;
    DWORD dwDimension;
    WORD wExponent;
    WORD wReportId;
} DIDEVICEOBJECTINSTANCEA, *LPDIDEVICEOBJECTINSTANCEA;
typedef const DIDEVICEOBJECTINSTANCEA* LPCDIDEVICEOBJECTINSTANCEA;

typedef struct DIPROPHEADER
{
    DWORD dwSize;
    DWORD dwHeaderSize;
    DWORD dwObj;
    DWORD dwHow;
} DIPROPHEADER, *LPDIPROPHEADER;
typedef const DIPROPHEADER* LPCDIPROPHEADER;

typedef struct DIDEVICEOBJECTDATA
{
    DWORD dwOfs;
    DWORD dwData;
    DWORD dwTimeStamp;
    DWORD dwSequence;
} DIDEVICEOBJECTDATA, *LPDIDEVICEOBJECTDATA;
typedef const DIDEVICEOBJECTDATA* LPCDIDEVICEOBJECTDATA;

typedef struct _DIOBJECTDATAFORMAT
{
    const GUID* pguid;
    DWORD dwOfs;
    DWORD dwType;
    DWORD dwFlags;
} DIOBJECTDATAFORMAT, *LPDIOBJECTDATAFORMAT;
typedef const DIOBJECTDATAFORMAT* LPCDIOBJECTDATAFORMAT;

typedef struct _DIDATAFORMAT
{
    DWORD dwSize;
    DWORD dwObjSize;
    DWORD dwFlags;
    DWORD dwDataSize;
    DWORD dwNumObjs;
    LPDIOBJECTDATAFORMAT rgodf;
} DIDATAFORMAT, *LPDIDATAFORMAT;
typedef const DIDATAFORMAT* LPCDIDATAFORMAT;

typedef WINBOOL(__attribute__((__stdcall__)) * LPDIENUMDEVICEOBJECTSCALLBACKA)(LPCDIDEVICEOBJECTINSTANCEA, LPVOID);

typedef struct IDirectInputDeviceA
{
    struct IDirectInputDeviceAVtbl* lpVtbl;
} IDirectInputDeviceA;
typedef struct IDirectInputDeviceAVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectInputDeviceA* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectInputDeviceA* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectInputDeviceA* This);
    /*** IDirectInputDeviceA methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetCapabilities)(IDirectInputDeviceA* This, LPDIDEVCAPS lpDIDevCaps);
    HRESULT(__attribute__((__stdcall__)) * EnumObjects)(IDirectInputDeviceA* This, LPDIENUMDEVICEOBJECTSCALLBACKA lpCallback, LPVOID pvRef, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetProperty)(IDirectInputDeviceA* This, GUID* rguidProp, LPDIPROPHEADER pdiph);
    HRESULT(__attribute__((__stdcall__)) * SetProperty)(IDirectInputDeviceA* This, GUID* rguidProp, LPCDIPROPHEADER pdiph);
    HRESULT(__attribute__((__stdcall__)) * Acquire)(IDirectInputDeviceA* This);
    HRESULT(__attribute__((__stdcall__)) * Unacquire)(IDirectInputDeviceA* This);
    HRESULT(__attribute__((__stdcall__)) * GetDeviceState)(IDirectInputDeviceA* This, DWORD cbData, LPVOID lpvData);
    HRESULT(__attribute__((__stdcall__)) * GetDeviceData)(IDirectInputDeviceA* This, DWORD cbObjectData, LPDIDEVICEOBJECTDATA rgdod, LPDWORD pdwInOut, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * SetDataFormat)(IDirectInputDeviceA* This, LPCDIDATAFORMAT lpdf);
    HRESULT(__attribute__((__stdcall__)) * SetEventNotification)(IDirectInputDeviceA* This, HANDLE hEvent);
    HRESULT(__attribute__((__stdcall__)) * SetCooperativeLevel)(IDirectInputDeviceA* This, HWND hwnd, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetObjectInfo)(IDirectInputDeviceA* This, LPDIDEVICEOBJECTINSTANCEA pdidoi, DWORD dwObj, DWORD dwHow);
    HRESULT(__attribute__((__stdcall__)) * GetDeviceInfo)(IDirectInputDeviceA* This, LPDIDEVICEINSTANCEA pdidi);
    HRESULT(__attribute__((__stdcall__)) * RunControlPanel)(IDirectInputDeviceA* This, HWND hwndOwner, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectInputDeviceA* This, HINSTANCE hinst, DWORD dwVersion, GUID* rguid);
} IDirectInputDeviceAVtbl;

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

typedef struct DIJOYSTATE2
{
    LONG lX; /* x-axis position              */
    LONG lY; /* y-axis position              */
    LONG lZ; /* z-axis position              */
    LONG lRx; /* x-axis rotation              */
    LONG lRy; /* y-axis rotation              */
    LONG lRz; /* z-axis rotation              */
    LONG rglSlider[2]; /* extra axes positions         */
    DWORD rgdwPOV[4]; /* POV directions               */
    BYTE rgbButtons[128]; /* 128 buttons                  */
    LONG lVX; /* x-axis velocity              */
    LONG lVY; /* y-axis velocity              */
    LONG lVZ; /* z-axis velocity              */
    LONG lVRx; /* x-axis angular velocity      */
    LONG lVRy; /* y-axis angular velocity      */
    LONG lVRz; /* z-axis angular velocity      */
    LONG rglVSlider[2]; /* extra axes velocities        */
    LONG lAX; /* x-axis acceleration          */
    LONG lAY; /* y-axis acceleration          */
    LONG lAZ; /* z-axis acceleration          */
    LONG lARx; /* x-axis angular acceleration  */
    LONG lARy; /* y-axis angular acceleration  */
    LONG lARz; /* z-axis angular acceleration  */
    LONG rglASlider[2]; /* extra axes accelerations     */
    LONG lFX; /* x-axis force                 */
    LONG lFY; /* y-axis force                 */
    LONG lFZ; /* z-axis force                 */
    LONG lFRx; /* x-axis torque                */
    LONG lFRy; /* y-axis torque                */
    LONG lFRz; /* z-axis torque                */
    LONG rglFSlider[2]; /* extra axes forces            */
} DIJOYSTATE2, *LPDIJOYSTATE2;

//
// Direct3D3
// https://github.com/apitrace/dxsdk/blob/master/Include/d3dcaps.h
//

typedef struct IDirect3D3* LPDIRECT3D;
typedef struct IDirect3D3* LPDIRECT3D3;
typedef struct IDirect3DDevice3* LPDIRECT3DDEVICE3;
typedef struct IDirect3DLight* LPDIRECT3DLIGHT;
typedef struct IDirect3DVertexBuffer* LPDIRECT3DVERTEXBUFFER;

typedef enum D3DRASTERCAPS
{
    D3DPRASTERCAPS_DITHER = 0x00000001L,
    D3DPRASTERCAPS_ROP2 = 0x00000002L,
    D3DPRASTERCAPS_XOR = 0x00000004L,
    D3DPRASTERCAPS_PAT = 0x00000008L,
    D3DPRASTERCAPS_ZTEST = 0x00000010L,
    D3DPRASTERCAPS_SUBPIXEL = 0x00000020L,
    D3DPRASTERCAPS_SUBPIXELX = 0x00000040L,
    D3DPRASTERCAPS_FOGVERTEX = 0x00000080L,
    D3DPRASTERCAPS_FOGTABLE = 0x00000100L,
    D3DPRASTERCAPS_STIPPLE = 0x00000200L,
    D3DPRASTERCAPS_ANTIALIASSORTDEPENDENT = 0x00000400L,
    D3DPRASTERCAPS_ANTIALIASSORTINDEPENDENT = 0x00000800L,
    D3DPRASTERCAPS_ANTIALIASEDGES = 0x00001000L,
    D3DPRASTERCAPS_MIPMAPLODBIAS = 0x00002000L,
    D3DPRASTERCAPS_ZBIAS = 0x00004000L,
    D3DPRASTERCAPS_ZBUFFERLESSHSR = 0x00008000L,
    D3DPRASTERCAPS_FOGRANGE = 0x00010000L,
    D3DPRASTERCAPS_ANISOTROPY = 0x00020000L,
} D3DRASTERCAPS;

typedef struct _D3dPrimCaps
{
    DWORD dwSize;
    DWORD dwMiscCaps;
    DWORD dwRasterCaps;
    DWORD dwZCmpCaps;
    DWORD dwSrcBlendCaps;
    DWORD dwDestBlendCaps;
    DWORD dwAlphaCmpCaps;
    DWORD dwShadeCaps;
    DWORD dwTextureCaps;
    DWORD dwTextureFilterCaps;
    DWORD dwTextureBlendCaps;
    DWORD dwTextureAddressCaps;
    DWORD dwStippleWidth;
    DWORD dwStippleHeight;
} D3DPRIMCAPS, *LPD3DPRIMCAPS; // sizeof(0x38)

typedef DWORD D3DCOLORMODEL;
typedef struct _D3DFINDDEVICESEARCH
{
    DWORD dwSize;
    DWORD dwFlags;
    WINBOOL bHardware;
    D3DCOLORMODEL dcmColorModel;
    GUID guid;
    DWORD dwCaps;
    D3DPRIMCAPS dpcPrimCaps;
} D3DFINDDEVICESEARCH, *LPD3DFINDDEVICESEARCH;

typedef float D3DVALUE;

typedef struct _D3DTRANSFORMCAPS
{
    DWORD dwSize;
    DWORD dwCaps;
} D3DTRANSFORMCAPS, *LPD3DTRANSFORMCAPS; // sizeof(0x8)

typedef struct _D3DLIGHTINGCAPS
{
    DWORD dwSize;
    DWORD dwCaps;
    DWORD dwLightingModel;
    DWORD dwNumLights;
} D3DLIGHTINGCAPS, *LPD3DLIGHTINGCAPS; // sizeof(0x10)

typedef struct _D3DDeviceDesc
{
    DWORD dwSize;
    DWORD dwFlags; // 0x4
    D3DCOLORMODEL dcmColorModel; // 0x8
    DWORD dwDevCaps; // 0xc
    D3DTRANSFORMCAPS dtcTransformCaps; // 0x10
    WINBOOL bClipping; // 0x18
    D3DLIGHTINGCAPS dlcLightingCaps; // 0x1c
    D3DPRIMCAPS dpcLineCaps; // 0x2c
    D3DPRIMCAPS dpcTriCaps; // 0x64
    DWORD dwDeviceRenderBitDepth; // 0x9c
    DWORD dwDeviceZBufferBitDepth;
    DWORD dwMaxBufferSize;
    DWORD dwMaxVertexCount;

    DWORD dwMinTextureWidth, dwMinTextureHeight;
    DWORD dwMaxTextureWidth, dwMaxTextureHeight;
    DWORD dwMinStippleWidth, dwMaxStippleWidth;
    DWORD dwMinStippleHeight, dwMaxStippleHeight;

    DWORD dwMaxTextureRepeat;
    DWORD dwMaxTextureAspectRatio;
    DWORD dwMaxAnisotropy;

    D3DVALUE dvGuardBandLeft;
    D3DVALUE dvGuardBandTop;
    D3DVALUE dvGuardBandRight;
    D3DVALUE dvGuardBandBottom;

    D3DVALUE dvExtentsAdjust;
    DWORD dwStencilCaps;

    DWORD dwFVFCaps;
    DWORD dwTextureOpCaps;
    WORD wMaxTextureBlendStages;
    WORD wMaxSimultaneousTextures;
} D3DDEVICEDESC, *LPD3DDEVICEDESC; // sizeof(0xfc)

typedef struct _D3DFINDDEVICERESULT
{
    DWORD dwSize;
    GUID guid;
    D3DDEVICEDESC ddHwDesc;
    D3DDEVICEDESC ddSwDesc;
} D3DFINDDEVICERESULT, *LPD3DFINDDEVICERESULT;

typedef HRESULT (*LPD3DENUMDEVICESCALLBACK)(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx);

typedef enum
{
    D3DLIGHT_POINT = 1,
    D3DLIGHT_SPOT = 2,
    D3DLIGHT_DIRECTIONAL = 3,
    D3DLIGHT_PARALLELPOINT = 4,
    D3DLIGHT_GLSPOT = 5,
    D3DLIGHT_FORCE_DWORD = 0x7fffffff
} D3DLIGHTTYPE;

typedef struct _D3DCOLORVALUE
{
    union
    {
        D3DVALUE r;
        D3DVALUE dvR;
    } DUMMYUNIONNAME1;
    union
    {
        D3DVALUE g;
        D3DVALUE dvG;
    } DUMMYUNIONNAME2;
    union
    {
        D3DVALUE b;
        D3DVALUE dvB;
    } DUMMYUNIONNAME3;
    union
    {
        D3DVALUE a;
        D3DVALUE dvA;
    } DUMMYUNIONNAME4;
} D3DCOLORVALUE, *LPD3DCOLORVALUE;

typedef struct _D3DVECTOR
{
    union
    {
        D3DVALUE x;
        D3DVALUE dvX;
    } DUMMYUNIONNAME1;
    union
    {
        D3DVALUE y;
        D3DVALUE dvY;
    } DUMMYUNIONNAME2;
    union
    {
        D3DVALUE z;
        D3DVALUE dvZ;
    } DUMMYUNIONNAME3;
} D3DVECTOR, *LPD3DVECTOR;

typedef struct _D3DLIGHT
{
    DWORD dwSize;
    D3DLIGHTTYPE dltType;
    D3DCOLORVALUE dcvColor;
    D3DVECTOR dvPosition;
    D3DVECTOR dvDirection;
    D3DVALUE dvRange;
    D3DVALUE dvFalloff;
    D3DVALUE dvAttenuation0;
    D3DVALUE dvAttenuation1;
    D3DVALUE dvAttenuation2;
    D3DVALUE dvTheta;
    D3DVALUE dvPhi;
} D3DLIGHT, *LPD3DLIGHT;

typedef struct IDirect3D
{
    struct IDirect3DVtbl* lpVtbl;
} IDirect3D;

struct IDirect3DMaterial;
struct IDirect3DViewport;

typedef struct IDirect3DVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3D* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3D* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3D* This);
    /*** IDirect3D methods ***/
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirect3D* This, IID* riid);
    HRESULT(__attribute__((__stdcall__)) * EnumDevices)(IDirect3D* This, LPD3DENUMDEVICESCALLBACK cb, void* ctx);
    HRESULT(__attribute__((__stdcall__)) * CreateLight)(IDirect3D* This, struct IDirect3DLight** light, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * CreateMaterial)(IDirect3D* This, struct IDirect3DMaterial** material, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * CreateViewport)(IDirect3D* This, struct IDirect3DViewport** viewport, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * FindDevice)(IDirect3D* This, D3DFINDDEVICESEARCH* search, D3DFINDDEVICERESULT* result);
} IDirect3DVtbl;

typedef struct IDirect3DLight
{
    struct IDirect3DLightVtbl* lpVtbl;
} IDirect3DLight;

typedef struct IDirect3DLightVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DLight* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DLight* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DLight* This);
    /*** IDirect3DLight methods ***/
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirect3DLight* This, IDirect3D* d3d);
    HRESULT(__attribute__((__stdcall__)) * SetLight)(IDirect3DLight* This, D3DLIGHT* data);
    HRESULT(__attribute__((__stdcall__)) * GetLight)(IDirect3DLight* This, D3DLIGHT* data);
} IDirect3DLightVtbl;

typedef DWORD D3DMATERIALHANDLE, *LPD3DMATERIALHANDLE;
typedef DWORD D3DTEXTUREHANDLE, *LPD3DTEXTUREHANDLE;

typedef struct _D3DMATERIAL
{
    DWORD dwSize;
    union
    {
        D3DCOLORVALUE diffuse;
        D3DCOLORVALUE dcvDiffuse;
    } DUMMYUNIONNAME;
    union
    {
        D3DCOLORVALUE ambient;
        D3DCOLORVALUE dcvAmbient;
    } DUMMYUNIONNAME1;
    union
    {
        D3DCOLORVALUE specular;
        D3DCOLORVALUE dcvSpecular;
    } DUMMYUNIONNAME2;
    union
    {
        D3DCOLORVALUE emissive;
        D3DCOLORVALUE dcvEmissive;
    } DUMMYUNIONNAME3;
    union
    {
        D3DVALUE power;
        D3DVALUE dvPower;
    } DUMMYUNIONNAME4;
    D3DTEXTUREHANDLE hTexture;
    DWORD dwRampSize;
} D3DMATERIAL, *LPD3DMATERIAL;

typedef struct IDirect3DMaterial3
{
    struct IDirect3DMaterial3Vtbl* lpVtbl;
} IDirect3DMaterial3;

typedef struct IDirect3DMaterial3Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DMaterial3* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DMaterial3* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DMaterial3* This);
    /*** IDirect3DMaterial3 methods ***/
    HRESULT(__attribute__((__stdcall__)) * SetMaterial)(IDirect3DMaterial3* This, D3DMATERIAL* data);
    HRESULT(__attribute__((__stdcall__)) * GetMaterial)(IDirect3DMaterial3* This, D3DMATERIAL* data);
    HRESULT(__attribute__((__stdcall__)) * GetHandle)(IDirect3DMaterial3* This, struct IDirect3DDevice3* device, D3DMATERIALHANDLE* handle);
} IDirect3DMaterial3Vtbl;

typedef struct _D3DVIEWPORT
{
    DWORD dwSize;
    DWORD dwX;
    DWORD dwY;
    DWORD dwWidth;
    DWORD dwHeight;
    D3DVALUE dvScaleX;
    D3DVALUE dvScaleY;
    D3DVALUE dvMaxX;
    D3DVALUE dvMaxY;
    D3DVALUE dvMinZ;
    D3DVALUE dvMaxZ;
} D3DVIEWPORT, *LPD3DVIEWPORT;

typedef struct _D3DHVERTEX
{
    DWORD dwFlags;
    union
    {
        D3DVALUE hx;
        D3DVALUE dvHX;
    } DUMMYUNIONNAME1;
    union
    {
        D3DVALUE hy;
        D3DVALUE dvHY;
    } DUMMYUNIONNAME2;
    union
    {
        D3DVALUE hz;
        D3DVALUE dvHZ;
    } DUMMYUNIONNAME3;
} D3DHVERTEX, *LPD3DHVERTEX;

typedef struct _D3DRECT
{
    union
    {
        LONG x1;
        LONG lX1;
    } DUMMYUNIONNAME1;
    union
    {
        LONG y1;
        LONG lY1;
    } DUMMYUNIONNAME2;
    union
    {
        LONG x2;
        LONG lX2;
    } DUMMYUNIONNAME3;
    union
    {
        LONG y2;
        LONG lY2;
    } DUMMYUNIONNAME4;
} D3DRECT, *LPD3DRECT;

typedef struct _D3DTRANSFORMDATA
{
    DWORD dwSize;
    void* lpIn;
    DWORD dwInSize;
    void* lpOut;
    DWORD dwOutSize;
    D3DHVERTEX* lpHOut;
    DWORD dwClip;
    DWORD dwClipIntersection;
    DWORD dwClipUnion;
    D3DRECT drExtent;
} D3DTRANSFORMDATA, *LPD3DTRANSFORMDATA;

typedef struct _D3DLIGHTINGELEMENT
{
    D3DVECTOR dvPosition;
    D3DVECTOR dvNormal;
} D3DLIGHTINGELEMENT, *LPD3DLIGHTINGELEMENT;

typedef DWORD D3DCOLOR, *LPD3DCOLOR;

typedef struct _D3DTLVERTEX
{
    union
    {
        D3DVALUE sx;
        D3DVALUE dvSX;
    } DUMMYUNIONNAME1;
    union
    {
        D3DVALUE sy;
        D3DVALUE dvSY;
    } DUMMYUNIONNAME2;
    union
    {
        D3DVALUE sz;
        D3DVALUE dvSZ;
    } DUMMYUNIONNAME3;
    union
    {
        D3DVALUE rhw;
        D3DVALUE dvRHW;
    } DUMMYUNIONNAME4;
    union
    {
        D3DCOLOR color;
        D3DCOLOR dcColor;
    } DUMMYUNIONNAME5;
    union
    {
        D3DCOLOR specular;
        D3DCOLOR dcSpecular;
    } DUMMYUNIONNAME6;
    union
    {
        D3DVALUE tu;
        D3DVALUE dvTU;
    } DUMMYUNIONNAME7;
    union
    {
        D3DVALUE tv;
        D3DVALUE dvTV;
    } DUMMYUNIONNAME8;
} D3DTLVERTEX, *LPD3DTLVERTEX;

typedef struct _D3DLIGHTDATA
{
    DWORD dwSize;
    D3DLIGHTINGELEMENT* lpIn;
    DWORD dwInSize;
    D3DTLVERTEX* lpOut;
    DWORD dwOutSize;
} D3DLIGHTDATA, *LPD3DLIGHTDATA;

typedef struct _D3DVIEWPORT2
{
    DWORD dwSize;
    DWORD dwX;
    DWORD dwY;
    DWORD dwWidth;
    DWORD dwHeight;
    D3DVALUE dvClipX;
    D3DVALUE dvClipY;
    D3DVALUE dvClipWidth;
    D3DVALUE dvClipHeight;
    D3DVALUE dvMinZ;
    D3DVALUE dvMaxZ;
} D3DVIEWPORT2, *LPD3DVIEWPORT2;

typedef struct IDirect3DViewport3
{
    struct IDirect3DViewport3Vtbl* lpVtbl;
} IDirect3DViewport3;

typedef struct IDirect3DViewport3Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DViewport3* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DViewport3* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DViewport3* This);
    /*** IDirect3DViewport methods ***/
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirect3DViewport3* This, IDirect3D* d3d);
    HRESULT(__attribute__((__stdcall__)) * GetViewport)(IDirect3DViewport3* This, D3DVIEWPORT* data);
    HRESULT(__attribute__((__stdcall__)) * SetViewport)(IDirect3DViewport3* This, D3DVIEWPORT* data);
    HRESULT(__attribute__((__stdcall__)) * TransformVertices)(IDirect3DViewport3* This, DWORD vertex_count, D3DTRANSFORMDATA* data, DWORD flags, DWORD* offscreen);
    HRESULT(__attribute__((__stdcall__)) * LightElements)(IDirect3DViewport3* This, DWORD element_count, D3DLIGHTDATA* data);
    HRESULT(__attribute__((__stdcall__)) * SetBackground)(IDirect3DViewport3* This, D3DMATERIALHANDLE hMat);
    HRESULT(__attribute__((__stdcall__)) * GetBackground)(IDirect3DViewport3* This, D3DMATERIALHANDLE* material, WINBOOL* valid);
    HRESULT(__attribute__((__stdcall__)) * SetBackgroundDepth)(IDirect3DViewport3* This, IDirectDrawSurface* surface);
    HRESULT(__attribute__((__stdcall__)) * GetBackgroundDepth)(IDirect3DViewport3* This, IDirectDrawSurface** surface, WINBOOL* valid);
    HRESULT(__attribute__((__stdcall__)) * Clear)(IDirect3DViewport3* This, DWORD count, D3DRECT* rects, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * AddLight)(IDirect3DViewport3* This, IDirect3DLight* light);
    HRESULT(__attribute__((__stdcall__)) * DeleteLight)(IDirect3DViewport3* This, IDirect3DLight* light);
    HRESULT(__attribute__((__stdcall__)) * NextLight)(IDirect3DViewport3* This, IDirect3DLight* ref, IDirect3DLight** light, DWORD flags);
    /*** IDirect3DViewport2 methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetViewport2)(IDirect3DViewport3* This, D3DVIEWPORT2* data);
    HRESULT(__attribute__((__stdcall__)) * SetViewport2)(IDirect3DViewport3* This, D3DVIEWPORT2* data);
    /*** IDirect3DViewport3 methods ***/
    HRESULT(__attribute__((__stdcall__)) * SetBackgroundDepth2)(IDirect3DViewport3* This, IDirectDrawSurface4* surface);
    HRESULT(__attribute__((__stdcall__)) * GetBackgroundDepth2)(IDirect3DViewport3* This, IDirectDrawSurface4** surface, WINBOOL* valid);
    HRESULT(__attribute__((__stdcall__)) * Clear2)(IDirect3DViewport3* This, DWORD count, D3DRECT* rects, DWORD flags, DWORD color, D3DVALUE z, DWORD stencil);
} IDirect3DViewport3Vtbl;

typedef struct
{
    DWORD dwSize;
    DWORD dwTrianglesDrawn;
    DWORD dwLinesDrawn;
    DWORD dwPointsDrawn;
    DWORD dwSpansDrawn;
    DWORD dwVerticesProcessed;
} D3DSTATS, *LPD3DSTATS;

typedef HRESULT (*LPD3DENUMPIXELFORMATSCALLBACK)(DDPIXELFORMAT* format, void* ctx);

typedef enum
{
    D3DPT_POINTLIST = 1,
    D3DPT_LINELIST = 2,
    D3DPT_LINESTRIP = 3,
    D3DPT_TRIANGLELIST = 4,
    D3DPT_TRIANGLESTRIP = 5,
    D3DPT_TRIANGLEFAN = 6,
    D3DPT_FORCE_DWORD = 0x7fffffff
} D3DPRIMITIVETYPE;

typedef enum
{
    D3DRENDERSTATE_TEXTUREHANDLE = 1,
    D3DRENDERSTATE_ANTIALIAS = 2,
    D3DRENDERSTATE_TEXTUREADDRESS = 3,
    D3DRENDERSTATE_TEXTUREPERSPECTIVE = 4,
    D3DRENDERSTATE_WRAPU = 5, /* <= d3d6 */
    D3DRENDERSTATE_WRAPV = 6, /* <= d3d6 */
    D3DRENDERSTATE_ZENABLE = 7,
    D3DRENDERSTATE_FILLMODE = 8,
    D3DRENDERSTATE_SHADEMODE = 9,
    D3DRENDERSTATE_LINEPATTERN = 10,
    D3DRENDERSTATE_MONOENABLE = 11, /* <= d3d6 */
    D3DRENDERSTATE_ROP2 = 12, /* <= d3d6 */
    D3DRENDERSTATE_PLANEMASK = 13, /* <= d3d6 */
    D3DRENDERSTATE_ZWRITEENABLE = 14,
    D3DRENDERSTATE_ALPHATESTENABLE = 15,
    D3DRENDERSTATE_LASTPIXEL = 16,
    D3DRENDERSTATE_TEXTUREMAG = 17,
    D3DRENDERSTATE_TEXTUREMIN = 18,
    D3DRENDERSTATE_SRCBLEND = 19,
    D3DRENDERSTATE_DESTBLEND = 20,
    D3DRENDERSTATE_TEXTUREMAPBLEND = 21,
    D3DRENDERSTATE_CULLMODE = 22,
    D3DRENDERSTATE_ZFUNC = 23,
    D3DRENDERSTATE_ALPHAREF = 24,
    D3DRENDERSTATE_ALPHAFUNC = 25,
    D3DRENDERSTATE_DITHERENABLE = 26,
    D3DRENDERSTATE_ALPHABLENDENABLE = 27,
    D3DRENDERSTATE_FOGENABLE = 28,
    D3DRENDERSTATE_SPECULARENABLE = 29,
    D3DRENDERSTATE_ZVISIBLE = 30,
    D3DRENDERSTATE_SUBPIXEL = 31, /* <= d3d6 */
    D3DRENDERSTATE_SUBPIXELX = 32, /* <= d3d6 */
    D3DRENDERSTATE_STIPPLEDALPHA = 33,
    D3DRENDERSTATE_FOGCOLOR = 34,
    D3DRENDERSTATE_FOGTABLEMODE = 35,
    D3DRENDERSTATE_FOGTABLESTART = 36,
    D3DRENDERSTATE_FOGTABLEEND = 37,
    D3DRENDERSTATE_FOGTABLEDENSITY = 38,
    D3DRENDERSTATE_FOGSTART = 36,
    D3DRENDERSTATE_FOGEND = 37,
    D3DRENDERSTATE_FOGDENSITY = 38,
    D3DRENDERSTATE_STIPPLEENABLE = 39, /* <= d3d6 */
    /* d3d5 */
    D3DRENDERSTATE_EDGEANTIALIAS = 40,
    D3DRENDERSTATE_COLORKEYENABLE = 41,
    D3DRENDERSTATE_BORDERCOLOR = 43,
    D3DRENDERSTATE_TEXTUREADDRESSU = 44,
    D3DRENDERSTATE_TEXTUREADDRESSV = 45,
    D3DRENDERSTATE_MIPMAPLODBIAS = 46, /* <= d3d6 */
    D3DRENDERSTATE_ZBIAS = 47,
    D3DRENDERSTATE_RANGEFOGENABLE = 48,
    D3DRENDERSTATE_ANISOTROPY = 49, /* <= d3d6 */
    D3DRENDERSTATE_FLUSHBATCH = 50, /* <= d3d6 */
} D3DRENDERSTATETYPE;

typedef enum
{
    D3DLIGHTSTATE_MATERIAL = 1,
    D3DLIGHTSTATE_AMBIENT = 2,
    D3DLIGHTSTATE_COLORMODEL = 3,
    D3DLIGHTSTATE_FOGMODE = 4,
    D3DLIGHTSTATE_FOGSTART = 5,
    D3DLIGHTSTATE_FOGEND = 6,
    D3DLIGHTSTATE_FOGDENSITY = 7,
    D3DLIGHTSTATE_COLORVERTEX = 8,
    D3DLIGHTSTATE_FORCE_DWORD = 0x7fffffff
} D3DLIGHTSTATETYPE;

typedef enum _D3DTRANSFORMSTATETYPE
{
    D3DTRANSFORMSTATE_WORLD = 1,
    D3DTRANSFORMSTATE_VIEW = 2,
    D3DTRANSFORMSTATE_PROJECTION = 3,
    D3DTRANSFORMSTATE_WORLD1 = 4,
    D3DTRANSFORMSTATE_WORLD2 = 5,
    D3DTRANSFORMSTATE_WORLD3 = 6,
    D3DTRANSFORMSTATE_TEXTURE0 = 16,
    D3DTRANSFORMSTATE_TEXTURE1 = 17,
    D3DTRANSFORMSTATE_TEXTURE2 = 18,
    D3DTRANSFORMSTATE_TEXTURE3 = 19,
    D3DTRANSFORMSTATE_TEXTURE4 = 20,
    D3DTRANSFORMSTATE_TEXTURE5 = 21,
    D3DTRANSFORMSTATE_TEXTURE6 = 22,
    D3DTRANSFORMSTATE_TEXTURE7 = 23,
    D3DTRANSFORMSTATE_FORCE_DWORD = 0x7fffffff
} D3DTRANSFORMSTATETYPE;

typedef struct _D3DMATRIX
{
    D3DVALUE _11, _12, _13, _14;
    D3DVALUE _21, _22, _23, _24;
    D3DVALUE _31, _32, _33, _34;
    D3DVALUE _41, _42, _43, _44;
} D3DMATRIX, *LPD3DMATRIX;

typedef struct _D3DCLIPSTATUS
{
    DWORD dwFlags;
    DWORD dwStatus;
    float minx, maxx;
    float miny, maxy;
    float minz, maxz;
} D3DCLIPSTATUS, *LPD3DCLIPSTATUS;

typedef struct _D3DDP_PTRSTRIDE
{
    void* lpvData;
    DWORD dwStride;
} D3DDP_PTRSTRIDE;

#define D3DDP_MAXTEXCOORD 8

typedef struct _D3DDRAWPRIMITIVESTRIDEDDATA
{
    D3DDP_PTRSTRIDE position;
    D3DDP_PTRSTRIDE normal;
    D3DDP_PTRSTRIDE diffuse;
    D3DDP_PTRSTRIDE specular;
    D3DDP_PTRSTRIDE textureCoords[D3DDP_MAXTEXCOORD];
} D3DDRAWPRIMITIVESTRIDEDDATA, *LPD3DDRAWPRIMITIVESTRIDEDDATA;

typedef enum _D3DTEXTURESTAGESTATETYPE
{
    D3DTSS_COLOROP = 1,
    D3DTSS_COLORARG1 = 2,
    D3DTSS_COLORARG2 = 3,
    D3DTSS_ALPHAOP = 4,
    D3DTSS_ALPHAARG1 = 5,
    D3DTSS_ALPHAARG2 = 6,
    D3DTSS_BUMPENVMAT00 = 7,
    D3DTSS_BUMPENVMAT01 = 8,
    D3DTSS_BUMPENVMAT10 = 9,
    D3DTSS_BUMPENVMAT11 = 10,
    D3DTSS_TEXCOORDINDEX = 11,
    D3DTSS_ADDRESS = 12,
    D3DTSS_ADDRESSU = 13,
    D3DTSS_ADDRESSV = 14,
    D3DTSS_BORDERCOLOR = 15,
    D3DTSS_MAGFILTER = 16,
    D3DTSS_MINFILTER = 17,
    D3DTSS_MIPFILTER = 18,
    D3DTSS_MIPMAPLODBIAS = 19,
    D3DTSS_MAXMIPLEVEL = 20,
    D3DTSS_MAXANISOTROPY = 21,
    D3DTSS_BUMPENVLSCALE = 22,
    D3DTSS_BUMPENVLOFFSET = 23,
    D3DTSS_TEXTURETRANSFORMFLAGS = 24,
    D3DTSS_FORCE_DWORD = 0x7fffffff
} D3DTEXTURESTAGESTATETYPE;

typedef struct IDirect3DTexture2
{
    struct IDirect3DTexture2Vtbl* lpVtbl;
} IDirect3DTexture2;

struct IDirect3DDevice2;

typedef struct IDirect3DTexture2Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DTexture2* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DTexture2* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DTexture2* This);
    /*** IDirect3DTexture2 methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetHandle)(IDirect3DTexture2* This, struct IDirect3DDevice2* device, D3DTEXTUREHANDLE* handle);
    HRESULT(__attribute__((__stdcall__)) * PaletteChanged)(IDirect3DTexture2* This, DWORD dwStart, DWORD dwCount);
    HRESULT(__attribute__((__stdcall__)) * Load)(IDirect3DTexture2* This, IDirect3DTexture2* texture);
} IDirect3DTexture2Vtbl;

typedef struct IDirect3DDevice3
{
    struct IDirect3DDevice3Vtbl* lpVtbl;
} IDirect3DDevice3;

typedef struct IDirect3DDevice3Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DDevice3* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DDevice3* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DDevice3* This);
    /*** IDirect3DDevice3 methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirect3DDevice3* This, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc);
    HRESULT(__attribute__((__stdcall__)) * GetStats)(IDirect3DDevice3* This, D3DSTATS* stats);
    HRESULT(__attribute__((__stdcall__)) * AddViewport)(IDirect3DDevice3* This, IDirect3DViewport3* viewport);
    HRESULT(__attribute__((__stdcall__)) * DeleteViewport)(IDirect3DDevice3* This, IDirect3DViewport3* viewport);
    HRESULT(__attribute__((__stdcall__)) * NextViewport)(IDirect3DDevice3* This, IDirect3DViewport3* ref, IDirect3DViewport3** viewport, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * EnumTextureFormats)(IDirect3DDevice3* This, LPD3DENUMPIXELFORMATSCALLBACK cb, void* ctx);
    HRESULT(__attribute__((__stdcall__)) * BeginScene)(IDirect3DDevice3* This);
    HRESULT(__attribute__((__stdcall__)) * EndScene)(IDirect3DDevice3* This);
    HRESULT(__attribute__((__stdcall__)) * GetDirect3D)(IDirect3DDevice3* This, struct IDirect3D3** d3d);
    /*** DrawPrimitive API ***/
    HRESULT(__attribute__((__stdcall__)) * SetCurrentViewport)(IDirect3DDevice3* This, IDirect3DViewport3* viewport);
    HRESULT(__attribute__((__stdcall__)) * GetCurrentViewport)(IDirect3DDevice3* This, IDirect3DViewport3** viewport);
    HRESULT(__attribute__((__stdcall__)) * SetRenderTarget)(IDirect3DDevice3* This, IDirectDrawSurface4* surface, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * GetRenderTarget)(IDirect3DDevice3* This, IDirectDrawSurface4** surface);
    HRESULT(__attribute__((__stdcall__)) * Begin)(IDirect3DDevice3* This, D3DPRIMITIVETYPE d3dptPrimitiveType, DWORD dwVertexTypeDesc, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * BeginIndexed)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, DWORD fvf, void* vertices, DWORD vertex_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * Vertex)(IDirect3DDevice3* This, void* vertex);
    HRESULT(__attribute__((__stdcall__)) * Index)(IDirect3DDevice3* This, WORD wVertexIndex);
    HRESULT(__attribute__((__stdcall__)) * End)(IDirect3DDevice3* This, DWORD dwFlags);
    HRESULT(__attribute__((__stdcall__)) * GetRenderState)(IDirect3DDevice3* This, D3DRENDERSTATETYPE dwRenderStateType, LPDWORD lpdwRenderState);
    HRESULT(__attribute__((__stdcall__)) * SetRenderState)(IDirect3DDevice3* This, D3DRENDERSTATETYPE dwRenderStateType, DWORD dwRenderState);
    HRESULT(__attribute__((__stdcall__)) * GetLightState)(IDirect3DDevice3* This, D3DLIGHTSTATETYPE dwLightStateType, LPDWORD lpdwLightState);
    HRESULT(__attribute__((__stdcall__)) * SetLightState)(IDirect3DDevice3* This, D3DLIGHTSTATETYPE dwLightStateType, DWORD dwLightState);
    HRESULT(__attribute__((__stdcall__)) * SetTransform)(IDirect3DDevice3* This, D3DTRANSFORMSTATETYPE state, D3DMATRIX* matrix);
    HRESULT(__attribute__((__stdcall__)) * GetTransform)(IDirect3DDevice3* This, D3DTRANSFORMSTATETYPE state, D3DMATRIX* matrix);
    HRESULT(__attribute__((__stdcall__)) * MultiplyTransform)(IDirect3DDevice3* This, D3DTRANSFORMSTATETYPE state, D3DMATRIX* matrix);
    HRESULT(__attribute__((__stdcall__)) * DrawPrimitive)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, DWORD vertex_type, void* vertices, DWORD vertex_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * DrawIndexedPrimitive)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, DWORD fvf, void* vertices, DWORD vertex_count, WORD* indices, DWORD index_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * SetClipStatus)(IDirect3DDevice3* This, D3DCLIPSTATUS* clip_status);
    HRESULT(__attribute__((__stdcall__)) * GetClipStatus)(IDirect3DDevice3* This, D3DCLIPSTATUS* clip_status);
    HRESULT(__attribute__((__stdcall__)) * DrawPrimitiveStrided)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, DWORD fvf, D3DDRAWPRIMITIVESTRIDEDDATA* strided_data, DWORD vertex_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * DrawIndexedPrimitiveStrided)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, DWORD fvf, D3DDRAWPRIMITIVESTRIDEDDATA* strided_data, DWORD vertex_count, WORD* indices, DWORD index_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * DrawPrimitiveVB)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, struct IDirect3DVertexBuffer* vb, DWORD start_vertex, DWORD vertex_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * DrawIndexedPrimitiveVB)(IDirect3DDevice3* This, D3DPRIMITIVETYPE primitive_type, struct IDirect3DVertexBuffer* vb, WORD* indices, DWORD index_count, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * ComputeSphereVisibility)(IDirect3DDevice3* This, D3DVECTOR* centers, D3DVALUE* radii, DWORD sphere_count, DWORD flags, DWORD* ret);
    HRESULT(__attribute__((__stdcall__)) * GetTexture)(IDirect3DDevice3* This, DWORD stage, IDirect3DTexture2** texture);
    HRESULT(__attribute__((__stdcall__)) * SetTexture)(IDirect3DDevice3* This, DWORD stage, IDirect3DTexture2* texture);
    HRESULT(__attribute__((__stdcall__)) * GetTextureStageState)(IDirect3DDevice3* This, DWORD dwStage, D3DTEXTURESTAGESTATETYPE d3dTexStageStateType, LPDWORD lpdwState);
    HRESULT(__attribute__((__stdcall__)) * SetTextureStageState)(IDirect3DDevice3* This, DWORD dwStage, D3DTEXTURESTAGESTATETYPE d3dTexStageStateType, DWORD dwState);
    HRESULT(__attribute__((__stdcall__)) * ValidateDevice)(IDirect3DDevice3* This, LPDWORD lpdwPasses);
} IDirect3DDevice3Vtbl;

typedef struct _D3DVERTEXBUFFERDESC
{
    DWORD dwSize;
    DWORD dwCaps;
    DWORD dwFVF;
    DWORD dwNumVertices;
} D3DVERTEXBUFFERDESC, *LPD3DVERTEXBUFFERDESC;

typedef struct IDirect3DVertexBuffer
{
    struct IDirect3DVertexBufferVtbl* lpVtbl;
} IDirect3DVertexBuffer;

typedef struct IDirect3DVertexBufferVtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3DVertexBuffer* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3DVertexBuffer* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3DVertexBuffer* This);
    /*** IDirect3DVertexBuffer methods ***/
    HRESULT(__attribute__((__stdcall__)) * Lock)(IDirect3DVertexBuffer* This, DWORD flags, void** data, DWORD* data_size);
    HRESULT(__attribute__((__stdcall__)) * Unlock)(IDirect3DVertexBuffer* This);
    HRESULT(__attribute__((__stdcall__)) * ProcessVertices)(IDirect3DVertexBuffer* This, DWORD vertex_op, DWORD dst_idx, DWORD count, IDirect3DVertexBuffer* src_buffer, DWORD src_idx, IDirect3DDevice3* device, DWORD flags);
    HRESULT(__attribute__((__stdcall__)) * GetVertexBufferDesc)(IDirect3DVertexBuffer* This, D3DVERTEXBUFFERDESC* desc);
    HRESULT(__attribute__((__stdcall__)) * Optimize)(IDirect3DVertexBuffer* This, IDirect3DDevice3* device, DWORD flags);
} IDirect3DVertexBufferVtbl;

typedef struct IDirect3D3
{
    struct IDirect3D3Vtbl* lpVtbl;
} IDirect3D3;

typedef struct IDirect3D3Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirect3D3* This, IID* riid, void** ppvObject);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirect3D3* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirect3D3* This);
    /*** IDirect3D3 methods ***/
    HRESULT(__attribute__((__stdcall__)) * EnumDevices)(IDirect3D3* This, LPD3DENUMDEVICESCALLBACK cb, void* ctx);
    HRESULT(__attribute__((__stdcall__)) * CreateLight)(IDirect3D3* This, struct IDirect3DLight** light, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * CreateMaterial)(IDirect3D3* This, struct IDirect3DMaterial3** material, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * CreateViewport)(IDirect3D3* This, struct IDirect3DViewport3** viewport, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * FindDevice)(IDirect3D3* This, D3DFINDDEVICESEARCH* search, D3DFINDDEVICERESULT* result);
    HRESULT(__attribute__((__stdcall__)) * CreateDevice)(IDirect3D3* This, IID* rclsid, IDirectDrawSurface4* surface, struct IDirect3DDevice3** device, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * CreateVertexBuffer)(IDirect3D3* This, D3DVERTEXBUFFERDESC* desc, struct IDirect3DVertexBuffer** buffer, DWORD flags, IUnknown* outer);
    HRESULT(__attribute__((__stdcall__)) * EnumZBufferFormats)(IDirect3D3* This, IID* device_iid, LPD3DENUMPIXELFORMATSCALLBACK cb, void* ctx);
    HRESULT(__attribute__((__stdcall__)) * EvictManagedTextures)(IDirect3D3* This);
} IDirect3D3Vtbl;

//
// DirectPlay dplayx.dll https://github.com/Olde-Skuul/burgerlib/blob/387d4039de1cd976d738fd133db8165d450cf0d4/sdks/windows/dplay/include/dplay.h
// https://github.com/wine-mirror/wine/blob/master/include/dplay.h
//

/*
 * A new player or group has been created in the session
 * Use DPMSG_CREATEPLAYERORGROUP.  Check dwPlayerType to see if it
 * is a player or a group.
 */
#define DPSYS_CREATEPLAYERORGROUP 0x0003

/*
 * A player has been deleted from the session
 * Use DPMSG_DESTROYPLAYERORGROUP
 */
#define DPSYS_DESTROYPLAYERORGROUP 0x0005

/*
 * A player has been added to a group
 * Use DPMSG_ADDPLAYERTOGROUP
 */
#define DPSYS_ADDPLAYERTOGROUP 0x0007

/*
 * A player has been removed from a group
 * Use DPMSG_DELETEPLAYERFROMGROUP
 */
#define DPSYS_DELETEPLAYERFROMGROUP 0x0021

/*
 * This DirectPlay object lost its connection with all the
 * other players in the session.
 * Use DPMSG_SESSIONLOST.
 */
#define DPSYS_SESSIONLOST 0x0031

/*
 * The current host has left the session.
 * This DirectPlay object is now the host.
 * Use DPMSG_HOST.
 */
#define DPSYS_HOST 0x0101

/*
 * The remote data associated with a player or
 * group has changed. Check dwPlayerType to see
 * if it is a player or a group
 * Use DPMSG_SETPLAYERORGROUPDATA
 */
#define DPSYS_SETPLAYERORGROUPDATA 0x0102

/*
 * The name of a player or group has changed.
 * Check dwPlayerType to see if it is a player
 * or a group.
 * Use DPMSG_SETPLAYERORGROUPNAME
 */
#define DPSYS_SETPLAYERORGROUPNAME 0x0103

/*
 * The session description has changed.
 * Use DPMSG_SETSESSIONDESC
 */
#define DPSYS_SETSESSIONDESC 0x0104

/*
 * A group has been added to a group
 * Use DPMSG_ADDGROUPTOGROUP
 */
#define DPSYS_ADDGROUPTOGROUP 0x0105

/*
 * A group has been removed from a group
 * Use DPMSG_DELETEGROUPFROMGROUP
 */
#define DPSYS_DELETEGROUPFROMGROUP 0x0106

/*
 * A secure player-player message has arrived.
 * Use DPMSG_SECUREMESSAGE
 */
#define DPSYS_SECUREMESSAGE 0x0107

/*
 * Start a new session.
 * Use DPMSG_STARTSESSION
 */
#define DPSYS_STARTSESSION 0x0108

/*
 * A chat message has arrived
 * Use DPMSG_CHAT
 */
#define DPSYS_CHAT 0x0109

/*
 * The owner of a group has changed
 * Use DPMSG_SETGROUPOWNER
 */
#define DPSYS_SETGROUPOWNER 0x010A

/*
 * An async send has finished, failed or been cancelled
 * Use DPMSG_SENDCOMPLETE
 */
#define DPSYS_SENDCOMPLETE 0x010d

typedef struct
{
    DWORD dwType; // Message type
} DPMSG_GENERIC, *LPDPMSG_GENERIC;

typedef struct IDirectPlay4* LPDIRECTPLAY4;
typedef struct IDirectPlay4* LPDIRECTPLAY4A;
typedef struct IDirectPlay4 IDirectPlay4A;

typedef DWORD DPID, *LPDPID;

typedef struct
{
    DWORD dwSize; // Size of structure
    DWORD dwFlags; // Not used. Must be zero.
    union
    { // The short or friendly name
        LPWSTR lpszShortName; // Unicode
        LPSTR lpszShortNameA; // ANSI
    };
    union
    { // The long or formal name
        LPWSTR lpszLongName; // Unicode
        LPSTR lpszLongNameA; // ANSI
    };

} DPNAME, *LPDPNAME;

typedef const DPNAME* LPCDPNAME;

typedef BOOL(__attribute__((__stdcall__)) * LPDPENUMPLAYERSCALLBACK2)(DPID dpId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

typedef struct
{
    DWORD dwSize; // Size of structure, in bytes
    DWORD dwFlags; // DPCAPS_xxx flags
    DWORD dwMaxBufferSize; // Maximum message size, in bytes,  for this service provider
    DWORD dwMaxQueueSize; // Obsolete.
    DWORD dwMaxPlayers; // Maximum players/groups (local + remote)
    DWORD dwHundredBaud; // Bandwidth in 100 bits per second units;
                         // i.e. 24 is 2400, 96 is 9600, etc.
    DWORD dwLatency; // Estimated latency; 0 = unknown
    DWORD dwMaxLocalPlayers; // Maximum # of locally created players allowed
    DWORD dwHeaderLength; // Maximum header length, in bytes, on messages
                          // added by the service provider
    DWORD dwTimeout; // Service provider's suggested timeout value
                     // This is how long DirectPlay will wait for
                     // responses to system messages
} DPCAPS, *LPDPCAPS;

typedef struct
{
    DWORD dwSize; // Size of structure
    DWORD dwFlags; // DPSESSION_xxx flags
    GUID guidInstance; // ID for the session instance
    GUID guidApplication; // GUID of the DirectPlay application.
                          // GUID_NULL for all applications.
    DWORD dwMaxPlayers; // Maximum # players allowed in session
    DWORD dwCurrentPlayers; // Current # players in session (read only)
    union
    { // Name of the session
        LPWSTR lpszSessionName; // Unicode
        LPSTR lpszSessionNameA; // ANSI
    };
    union
    { // Password of the session (optional)
        LPWSTR lpszPassword; // Unicode
        LPSTR lpszPasswordA; // ANSI
    };
    DWORD dwReserved1; // Reserved for future MS use.
    DWORD dwReserved2;
    DWORD dwUser1; // For use by the application
    DWORD dwUser2;
    DWORD dwUser3;
    DWORD dwUser4;
} DPSESSIONDESC2, *LPDPSESSIONDESC2;

typedef DPSESSIONDESC2* volatile LPDPSESSIONDESC2_V;
typedef DPSESSIONDESC2* LPCDPSESSIONDESC2;

typedef BOOL(__attribute__((__stdcall__)) * LPDPENUMSESSIONSCALLBACK2)(LPCDPSESSIONDESC2 lpThisSD, LPDWORD lpdwTimeOut, DWORD dwFlags, LPVOID lpContext);
typedef BOOL(__attribute__((__stdcall__)) * LPDPENUMCONNECTIONSCALLBACK)(GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

typedef struct
{
    DWORD dwSize; // Size of structure
    DWORD dwFlags; // Not used. Must be zero.
    union
    { // SSPI provider name
        LPWSTR lpszSSPIProvider; // Unicode
        LPSTR lpszSSPIProviderA; // ANSI
    };
    union
    { // CAPI provider name
        LPWSTR lpszCAPIProvider; // Unicode
        LPSTR lpszCAPIProviderA; // ANSI
    };
    DWORD dwCAPIProviderType; // Crypto Service Provider type
    DWORD dwEncryptionAlgorithm; // Encryption Algorithm type
} DPSECURITYDESC, *LPDPSECURITYDESC;

typedef DPSECURITYDESC* LPCDPSECURITYDESC;

typedef struct
{
    DWORD dwSize; // Size of structure
    DWORD dwFlags; // Not used. Must be zero.
    union
    { // User name of the account
        LPWSTR lpszUsername; // Unicode
        LPSTR lpszUsernameA; // ANSI
    };
    union
    { // Password of the account
        LPWSTR lpszPassword; // Unicode
        LPSTR lpszPasswordA; // ANSI
    };
    union
    { // Domain name of the account
        LPWSTR lpszDomain; // Unicode
        LPSTR lpszDomainA; // ANSI
    };
} DPCREDENTIALS, *LPDPCREDENTIALS;

typedef DPCREDENTIALS* LPCDPCREDENTIALS;

typedef struct
{
    DWORD dwSize;
    DWORD dwFlags;
    union
    { // Message string
        LPWSTR lpszMessage; // Unicode
        LPSTR lpszMessageA; // ANSI
    };
} DPCHAT, *LPDPCHAT;

typedef struct
{
    DWORD dwSize; // Size of this structure
    DWORD dwFlags; // Flags specific to this structure
    LPDPSESSIONDESC2 lpSessionDesc; // Pointer to session desc to use on connect
    LPDPNAME lpPlayerName; // Pointer to Player name structure
    GUID guidSP; // GUID of the DPlay SP to use
    LPVOID lpAddress; // Address for service provider
    DWORD dwAddressSize; // Size of address data
} DPLCONNECTION, *LPDPLCONNECTION;

typedef struct IDirectPlay4
{
    struct IDirectPlay4Vtbl* lpVtbl;
} IDirectPlay4;

typedef struct IDirectPlay4Vtbl
{
    /*** IUnknown methods ***/
    HRESULT(__attribute__((__stdcall__)) * QueryInterface)(IDirectPlay4* This, IID* riid, LPVOID* ppvObj);
    ULONG(__attribute__((__stdcall__)) * AddRef)(IDirectPlay4* This);
    ULONG(__attribute__((__stdcall__)) * Release)(IDirectPlay4* This);
    /*** IDirectPlay2 methods ***/
    HRESULT(__attribute__((__stdcall__)) * AddPlayerToGroup)(IDirectPlay4* This, DPID, DPID);
    HRESULT(__attribute__((__stdcall__)) * Close)(IDirectPlay4* This);
    HRESULT(__attribute__((__stdcall__)) * CreateGroup)(IDirectPlay4* This, LPDPID, LPDPNAME, LPVOID, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * CreatePlayer)(IDirectPlay4* This, LPDPID, LPDPNAME, HANDLE, LPVOID, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * DeletePlayerFromGroup)(IDirectPlay4* This, DPID, DPID);
    HRESULT(__attribute__((__stdcall__)) * DestroyGroup)(IDirectPlay4* This, DPID);
    HRESULT(__attribute__((__stdcall__)) * DestroyPlayer)(IDirectPlay4* This, DPID);
    HRESULT(__attribute__((__stdcall__)) * EnumGroupPlayers)(IDirectPlay4* This, DPID, GUID*, LPDPENUMPLAYERSCALLBACK2, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * EnumGroups)(IDirectPlay4* This, GUID*, LPDPENUMPLAYERSCALLBACK2, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * EnumPlayers)(IDirectPlay4* This, GUID*, LPDPENUMPLAYERSCALLBACK2, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * EnumSessions)(IDirectPlay4* This, LPDPSESSIONDESC2, DWORD, LPDPENUMSESSIONSCALLBACK2, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetCaps)(IDirectPlay4* This, LPDPCAPS, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetGroupData)(IDirectPlay4* This, DPID, LPVOID, LPDWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetGroupName)(IDirectPlay4* This, DPID, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetMessageCount)(IDirectPlay4* This, DPID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerAddress)(IDirectPlay4* This, DPID, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerCaps)(IDirectPlay4* This, DPID, LPDPCAPS, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerData)(IDirectPlay4* This, DPID, LPVOID, LPDWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerName)(IDirectPlay4* This, DPID, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetSessionDesc)(IDirectPlay4* This, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * Initialize)(IDirectPlay4* This, GUID*);
    HRESULT(__attribute__((__stdcall__)) * Open)(IDirectPlay4* This, LPDPSESSIONDESC2, DWORD);
    HRESULT(__attribute__((__stdcall__)) * Receive)(IDirectPlay4* This, LPDPID, LPDPID, DWORD, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * Send)(IDirectPlay4* This, DPID, DPID, DWORD, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SetGroupData)(IDirectPlay4* This, DPID, LPVOID, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SetGroupName)(IDirectPlay4* This, DPID, LPDPNAME, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SetPlayerData)(IDirectPlay4* This, DPID, LPVOID, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SetPlayerName)(IDirectPlay4* This, DPID, LPDPNAME, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SetSessionDesc)(IDirectPlay4* This, LPDPSESSIONDESC2, DWORD);
    /*** IDirectPlay3 methods ***/
    HRESULT(__attribute__((__stdcall__)) * AddGroupToGroup)(IDirectPlay4* This, DPID, DPID);
    HRESULT(__attribute__((__stdcall__)) * CreateGroupInGroup)(IDirectPlay4* This, DPID, LPDPID, LPDPNAME, LPVOID, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * DeleteGroupFromGroup)(IDirectPlay4* This, DPID, DPID);
    HRESULT(__attribute__((__stdcall__)) * EnumConnections)(IDirectPlay4* This, GUID*, LPDPENUMCONNECTIONSCALLBACK, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * EnumGroupsInGroup)(IDirectPlay4* This, DPID, GUID*, LPDPENUMPLAYERSCALLBACK2, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * GetGroupConnectionSettings)(IDirectPlay4* This, DWORD, DPID, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * InitializeConnection)(IDirectPlay4* This, LPVOID, DWORD);
    HRESULT(__attribute__((__stdcall__)) * SecureOpen)(IDirectPlay4* This, LPCDPSESSIONDESC2, DWORD, LPCDPSECURITYDESC, LPCDPCREDENTIALS);
    HRESULT(__attribute__((__stdcall__)) * SendChatMessage)(IDirectPlay4* This, DPID, DPID, DWORD, LPDPCHAT);
    HRESULT(__attribute__((__stdcall__)) * SetGroupConnectionSettings)(IDirectPlay4* This, DWORD, DPID, LPDPLCONNECTION);
    HRESULT(__attribute__((__stdcall__)) * StartSession)(IDirectPlay4* This, DWORD, DPID);
    HRESULT(__attribute__((__stdcall__)) * GetGroupFlags)(IDirectPlay4* This, DPID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetGroupParent)(IDirectPlay4* This, DPID, LPDPID);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerAccount)(IDirectPlay4* This, DPID, DWORD, LPVOID, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * GetPlayerFlags)(IDirectPlay4* This, DPID, LPDWORD);
    /*** IDirectPlay4 methods ***/
    HRESULT(__attribute__((__stdcall__)) * GetGroupOwner)(IDirectPlay4* This, DPID, LPDPID);
    HRESULT(__attribute__((__stdcall__)) * SetGroupOwner)(IDirectPlay4* This, DPID, DPID);
    HRESULT(__attribute__((__stdcall__)) * SendEx)(IDirectPlay4* This, DPID, DPID, DWORD, LPVOID, DWORD, DWORD, DWORD, LPVOID, DWORD*);
    HRESULT(__attribute__((__stdcall__)) * GetMessageQueue)(IDirectPlay4* This, DPID, DPID, DWORD, LPDWORD, LPDWORD);
    HRESULT(__attribute__((__stdcall__)) * CancelMessage)(IDirectPlay4* This, DWORD, DWORD);
    HRESULT(__attribute__((__stdcall__)) * CancelPriority)(IDirectPlay4* This, DWORD, DWORD, DWORD);
} IDirectPlay4Vtbl;

#endif

#endif // TYPES_DIRECTX_H
