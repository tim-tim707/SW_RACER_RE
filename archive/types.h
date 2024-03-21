#ifndef TYPES_H
#define TYPES_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef struct rdVector2i
{
    int x;
    int y;
} rdVector2i;

typedef struct rdVector3i
{
    int x;
    int y;
    int z;
} rdVector3i;

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
} rdTexformat; // 0x38 == 56 bytes

typedef struct stdVBufferTexFmt
{
    int32_t width;
    int32_t height;
    uint32_t texture_size_in_bytes;
    uint32_t width_in_bytes;
    uint32_t width_in_pixels;
    rdTexformat format;
} stdVBufferTexFmt; // 0x4c = 20 + 56 bytes

typedef struct rdDDrawSurface
{
    void *lpVtbl; // IDirectDrawSurfaceVtbl *lpVtbl
    uint32_t direct3d_tex;
    uint8_t surface_desc[0x6c];
    uint32_t texture_id;
    uint32_t texture_loaded;
    uint32_t is_16bit;
    uint32_t width;
    uint32_t height;
    uint32_t texture_area;
    uint32_t gpu_accel_maybe;
    rdDDrawSurface *tex_prev;
    rdDDrawSurface *tex_next;
} rdDDrawSurface;

typedef struct stdVBuffer
{
    uint32_t bSurfaceLocked;
    uint32_t lock_cnt;
    uint32_t gap8;
    stdVBufferTexFmt format;
    void *palette;
    char *surface_lock_alloc;
    uint32_t transparent_color;
    rdDDrawSurface *ddraw_surface;
    void *ddraw_palette; // LPDIRECTDRAWPALETTE
    uint8_t desc[0x6c];
} stdVBuffer; // 0xd8  = 32 + 76 + 108. Look like we are missing 8 bytes (malloc). Padding ?

typedef struct rdCamera
{
    int projectType;
    rdCanvas *canvas;
    rdMatrix34 view_matrix;
    float fov;
    float fov_y;
    float screenAspectRatio;
    float orthoScale;
    rdClipFrustum *cameraClipFrustum;
    void (*project)(rdVector3 *, rdVector3 *);
    void (*projectLst)(rdVector3 *, rdVector3 *, unsigned int);
    float ambientLight;
    int numLights;
    rdLight *lights[64];
    rdVector3 lightPositions[64];
    float attenuationMin;
    float attenuationMax;
} rdCamera;

typedef struct rdCanvas
{
    uint32_t bIdk;
    stdVBuffer *vbuffer; // 0x4
    float screen_height_half;
    float screen_width_half;
    stdVBuffer *d3d_vbuf;
    uint32_t field_14;
    int xStart; // 0x10
    int yStart; // 0x14
    int widthMinusOne; // 0x18
    int heightMinusOne; // 0x1c
} rdCanvas;

typedef intptr_t stdFile_t;

typedef struct HostServices
{
    uint32_t some_float;
    int (*messagePrint)(const char *, ...); // 0x4
    int (*statusPrint)(const char *, ...); // 0x8
    int (*warningPrint)(const char *, ...); // 0xc
    int (*errorPrint)(const char *, ...); // 0x10
    int (*debugPrint)(const char *, ...); // 0x14
    void (*assert)(const char *, const char *, int); // 0x18
    uint32_t unk; // 1c
    void *(*alloc)(unsigned int); // 0x20
    void (*free)(void *); // 0x24
    void *(*realloc)(void *, unsigned int); // 0x28
    uint32_t (*getTimerTick)(); // 0x2c
    stdFile_t (*fileOpen)(const char *, const char *); // 0x30
    int (*fileClose)(stdFile_t); // 0x34
    size_t (*fileRead)(stdFile_t, void *, size_t); // 0x38
    char *(*fileGets)(stdFile_t, char *, size_t); // 0x3c
    size_t (*fileWrite)(stdFile_t, void *, size_t); // 0x40
    int (*feof)(stdFile_t); // 0x44
    int (*ftell)(stdFile_t); // 0x48
    int (*fseek)(stdFile_t, int, int); // 0x4c
    int (*fileSize)(stdFile_t); // 0x50
    int (*filePrintf)(stdFile_t, const char *, ...); // 0x54
    wchar_t *(*fileGetws)(stdFile_t, wchar_t *, size_t); // 0x58
    void *(*allocHandle)(size_t); // 0x5c
    void (*freeHandle)(void *); // 0x60
    void *(*reallocHandle)(void *, size_t); // 0x64
    uint32_t (*lockHandle)(uint32_t); // 0x68
    void (*unlockHandle)(uint32_t); // 0x6c
} HostServices;

#endif // TYPES_H
