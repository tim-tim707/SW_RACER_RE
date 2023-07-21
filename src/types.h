#ifndef TYPES_H
#define TYPES_H

// Ghidra: File -> Parse C Source -> Add types.h -> Parse to Program -> Use open archive

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "types_directx.h"
#include "types_enums.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef FILE* stdFile_t;

    typedef struct rdVector2
    {
        float x;
        float y;
    } rdVector2;

    typedef struct rdVector3
    {
        float x;
        float y;
        float z;
    } rdVector3;

    typedef struct rdVector4
    {
        float x;
        float y;
        float z;
        float w;
    } rdVector4;

    typedef struct rdMatrix33
    {
        rdVector3 rvec;
        rdVector3 lvec;
        rdVector3 uvec;
    } rdMatrix33;

    typedef struct rdMatrix34
    {
        rdVector3 rvec;
        rdVector3 lvec;
        rdVector3 uvec;
        rdVector3 scale;
    } rdMatrix34;

    typedef struct rdMatrix44
    {
        rdVector4 vA;
        rdVector4 vB;
        rdVector4 vC;
        rdVector4 vD;
    } rdMatrix44;

    typedef struct rdClipFrustum
    {
        rdVector3 v; // 0x0
        float orthoLeft; // 0x4
        float orthoTop; // 0x8
        float orthoRight; // 0xc
        float orthoBottom; // 0x10
        float farTop; // 0x14
        float bottom; // 0x18
        float farLeft; // 0x1c
        float right; // 0x20
        float nearTop;
        float nearLeft;
    } rdClipFrustum;

    typedef struct rdLight
    {
        uint32_t id;
        int32_t type;
        uint32_t active;
        rdVector3 direction;
        float intensity;
        uint32_t color;

        // #ifdef JKM_LIGHTING
        //         float angleX;
        //         float cosAngleX;
        //         float angleY;
        //         float cosAngleY;
        //         float lux;
        // #else
        uint32_t dword20;
        uint32_t dword24;
        // #endif
        float falloffMin;
        float falloffMax;
    } rdLight;

    typedef struct rdTexformat
    {
        uint32_t is16bit;
        uint32_t bpp;
        uint32_t r_bits;
        uint32_t g_bits;
        uint32_t b_bits;
        uint32_t r_shift;
        uint32_t g_shift;
        uint32_t b_shift;
        uint32_t r_bitdiff;
        uint32_t g_bitdiff;
        uint32_t b_bitdiff;
        uint32_t unk_40;
        uint32_t unk_44;
        uint32_t unk_48;
    } rdTexformat;

    typedef struct stdVBufferTexFmt
    {
        int32_t width;
        int32_t height;
        uint32_t texture_size_in_bytes;
        uint32_t width_in_bytes;
        uint32_t width_in_pixels;
        rdTexformat format;
    } stdVBufferTexFmt;

    typedef struct rdDDrawSurface
    {
        void* lpVtbl; // IDirectDrawSurfaceVtbl *lpVtbl
        uint32_t direct3d_tex;
        uint8_t surface_desc[0x6c];
        uint32_t texture_id;
        uint32_t texture_loaded;
        uint32_t is_16bit;
        uint32_t width;
        uint32_t height;
        uint32_t texture_area;
        uint32_t gpu_accel_maybe;
        rdDDrawSurface* tex_prev;
        rdDDrawSurface* tex_next;
    } rdDDrawSurface;

    typedef struct stdVBuffer
    {
        uint32_t bSurfaceLocked;
        uint32_t lock_cnt;
        uint32_t gap8;
        stdVBufferTexFmt format;
        void* palette;
        char* surface_lock_alloc;
        uint32_t transparent_color;
        rdDDrawSurface* ddraw_surface;
        void* ddraw_palette; // LPDIRECTDRAWPALETTE
        uint8_t desc[0x6c];
    } stdVBuffer;

    typedef struct rdCanvas
    {
        // OpenJKDF2
        // uint32_t bIdk;
        // stdVBuffer* vbuffer;
        // float screen_height_half;
        // float screen_width_half;
        // stdVBuffer* d3d_vbuf;
        // uint32_t field_14;
        // int xStart;
        // int yStart;
        // int widthMinusOne;
        // int heightMinusOne;

        uint32_t bIdk;
        stdVBuffer* vbuffer;
        float screen_height_half;
        float screen_width_half;
        int xStart; // 0x10
        int yStart; // 0x14
        int widthMinusOne; // 0x18
        int heightMinusOne; // 0x1c
    } rdCanvas;
    typedef struct rdCamera
    {
        rdCameraProjectType projectType; // 0x0
        rdCanvas* canvas; // 0x4
        rdMatrix34 view_matrix;
        float fov;
        float fov_y;
        float screenAspectRatio; // 0x14
        float orthoScale; // 0x18
        rdClipFrustum* pClipFrustum; // 0x1c
        void (*fnProject)(rdVector3*, rdVector3*); // 0x20
        void (*fnProjectLst)(rdVector3*, rdVector3*, unsigned int); // 0x24
        float ambientLight; // incorrect position (BuildFOV)
        int numLights; // incorrect position (BuildFOV)
        // rdLight* lights[64];
        void* lights[64];
        rdVector3 lightPositions[64];
        float attenuationMin;
        float attenuationMax;
    } rdCamera;

    typedef struct swr_translation_rotation
    {
        rdVector3 translation;
        // rotation
        float yaw;
        float roll;
        float pitch;
    } swr_translation_rotation;

    typedef struct HostServices
    {
        float some_float;
        int (*messagePrint)(const char*, ...);
        int (*statusPrint)(const char*, ...);
        int (*warningPrint)(const char*, ...);
        int (*errorPrint)(const char*, ...);
        int (*debugPrint)(const char*, ...);
        void (*assert)(const char*, const char*, int);
        uint32_t unk_0;
        void* (*alloc)(unsigned int);
        void (*free)(void*);
        void* (*realloc)(void*, unsigned int);
        uint32_t (*getTimerTick)();
        stdFile_t (*fileOpen)(const char*, const char*);
        int (*fileClose)(stdFile_t);
        size_t (*fileRead)(stdFile_t, void*, size_t);
        char* (*fileGets)(stdFile_t, char*, size_t);
        size_t (*fileWrite)(stdFile_t, void*, size_t);
        int (*feof)(stdFile_t);
        int (*ftell)(stdFile_t);
        int (*fseek)(stdFile_t, int, int);
        int (*fileSize)(stdFile_t);
        int (*filePrintf)(stdFile_t, const char*, ...);
        wchar_t* (*fileGetws)(stdFile_t, wchar_t*, size_t);
        void* (*allocHandle)(size_t);
        void (*freeHandle)(void*);
        void* (*reallocHandle)(void*, size_t);
        uint32_t (*lockHandle)(uint32_t);
        void (*unlockHandle)(uint32_t);
    } HostServices;

    typedef LRESULT (*Window_MSGHANDLER)(HWND, UINT, WPARAM, LPARAM, UINT*);
    typedef Window_MSGHANDLER* Window_MSGHANDLER_ptr;

#ifdef __cplusplus
}
#endif
#endif // TYPES_H
