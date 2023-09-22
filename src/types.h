#ifndef TYPES_H
#define TYPES_H

// Ghidra: File -> Parse C Source -> Add types.h -> Parse to Program -> Use open archive

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "types_a3d.h"
#include "types_directx.h"
#include "types_enums.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct tagPOINT
    {
        long x;
        long y;
    } tagPOINT;

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
        float orthoLeft; // 0xc
        float orthoTop; // 0x10
        float orthoRight; // 0x14
        float orthoBottom; // 0x18
        float farTop; // 0x1c
        float bottom; // 0x20
        float farLeft; // 0x24
        float right; // 0x28
        float nearTop; // 0x2c
        float nearLeft; // 0x30 = 48
    } rdClipFrustum; // missing fields. sizeof 100

    typedef struct rdLight
    {
        uint32_t id;
        int32_t type;
        uint32_t active;
        rdVector3 direction;
        float intensity;
        float color;

        // #ifdef JKM_LIGHTING
        //         float angleX;
        //         float cosAngleX;
        //         float angleY;
        //         float cosAngleY;
        //         float lux;
        // #else
        float dword20;
        uint32_t dword24;
        // #endif
        float falloffMin;
        float falloffMax;
    } rdLight;

    typedef struct rdTexFormat
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
    } rdTexFormat; // sizeof(56)

    typedef struct stdVBufferTexFmt
    {
        int32_t width;
        int32_t height;
        uint32_t texture_size_in_bytes;
        uint32_t width_in_bytes;
        uint32_t width_in_pixels;
        rdTexFormat format;
    } stdVBufferTexFmt; // sizeof(76)

    typedef struct rdDDrawSurface
    {
        IDirectDrawSurface4Vtbl* lpVtbl; // 0x0
        uint32_t direct3d_tex; // 0x4
        DDSURFACEDESC2 surface_desc; // 0x8
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

    typedef struct stdFileSearch
    {
        int searchMode;
        int isNotFirst;
        char path[128];
        intptr_t filesearchHandle;
    } stdFileSearch; // sizeof 0x8c = 140

    typedef struct stdFileSearchResult
    {
        char fpath[256];
        int field_100;
        int is_subdirectory;
        int time_write;
    } stdFileSearchResult;

    typedef struct stdVBuffer // 0x00ec8da0
    {
        uint32_t bSurfaceLocked;
        uint32_t lock_cnt;
        stdVBufferTexFmt format;
        void* palette;
        char* surface_lock_alloc; // sizeof(width_in_pixels)
        uint32_t transparent_color;
        rdDDrawSurface* ddraw_surface; // 0x00ec8e00 = offset 96 = 0x60
        DDSURFACEDESC2 desc;
    } stdVBuffer; // sizeof (224), Allocated at FUN_004881c0

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
    } rdCanvas; // sizeof 0x20

    typedef struct rdCamera
    {
        rdCameraProjectType projectType; // 0x0
        rdCanvas* canvas; // 0x4
        rdMatrix34 view_matrix; // 0x8
        float fov; // 0x38
        float fov_y; // 0x3c
        float screenAspectRatio; // 0x40
        float orthoScale; // 0x44
        rdClipFrustum* pClipFrustum; // 0x48
        void (*fnProject)(rdVector3*, rdVector3*); // 0x4c
        void (*fnProjectLst)(rdVector3*, rdVector3*, unsigned int); // 0x50
        float ambientLight;
        uint32_t unk;
        rdVector4 unk2;
        int numLights; // 0x6c
        rdLight* lights[128];
        rdVector3 lightPositions[128];
        float attenuationMin;
        float attenuationMax;
    } rdCamera; // sizeof 0x878 ok

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

    typedef struct swrSpriteTexturePage
    {
        unsigned short width; // 0x0
        unsigned short height; // 0x2
        uint32_t offset; // 0x4
    } swrSpriteTexturePage; // sizeof(0x8)

    typedef struct swrSpriteTextureHeader
    {
        unsigned short width; // 0x0
        unsigned short height; // 0x2
        uint8_t format; // 0x4 actual format?
        uint8_t page_width_align; // 0x5 page width alignment: 0=0x10, 1=0x8, 2=0x4, 3=0x2, 7=0x2. all other values are undefined
        unsigned short unk3; // 0x6 always zero?
        uint32_t palette_offset; // 0x8 palette pointer
        unsigned short page_count; // 0xC page count
        unsigned short unk6; // 0xE always 32 [bits per pixel?]
        swrSpriteTexturePage* page_table; // 0x10 pagetable pointer
        // 0x14 bytes total, but will be followed by its page, palette and pixel data normally
    } swrSpriteTextureHeader;

    typedef struct swrSpriteTexture
    {
        swrSpriteTextureHeader header;
        swrSpriteTexturePage* pages; // Exists as a 0 sized array
        // char[] palette; // Exists as a 0 sized array under pages
    } swrSpriteTexture;

    typedef struct swrSprite
    {
        short x; // Position x
        short y; // Position y
        short unk0x4; // 0x4, written in sub_4286C0
        short unk0x6; // 0x6, written in sub_4286C0
        float width; // 0x8 Size X
        float height; // 0xC Size Y
        uint32_t unk0x10; // written in sub_428720
        uint32_t flags; // Flags:
                        // 0x10000 = position is again different + size is different
                        // 0x8000 = colors are weird? might be unrelated?!
                        // 0x4000 = can't find the image on screen?!
                        // 0x2000 = ???
                        // 0x1000 = offsets the image
                        // 0x800 = ???
                        // 0x400 = ???
                        // 0x200 = ???
                        // 0x100 = tiles differently
                        // 0x80 = tiles the image somewhat?
                        // 0x40 = ???
                        // 0x20 = stay in memory?
                        // 0x10 = ???
                        // 0x8 = mirror vertically
                        // 0x4 = mirror horizontally
                        // 0x2 = ???
                        // 0x1 = used/displayed?
        uint8_t r; // 0x18 R
        uint8_t g; // 0x19 G
        uint8_t b; // 0x1A B
        uint8_t a; // 0x1B A
        swrSpriteTexture* texture; // 0x1C, written in sub_4282F0
        // 32 bytes
    } swrSprite;

    typedef struct swrTranslationRotation
    {
        rdVector3 translation;
        // rotation
        float yaw;
        float roll;
        float pitch;
    } swrTranslationRotation;

    typedef struct swrRace
    {
        char unk0[6];
        short unk0_1; // 0x6 some kind of flag
        swrTranslationRotation translation_rotation; // 0x8. See fun_00454d40. This is a translation-rotation at the same time ?? FUN_00473f40
        rdMatrix44 transform; // 0x20
        uint32_t flags0;
        uint32_t flags1;
        char unk1_1[2];

        float antiskid; // 0x6c. Something is wrong here. void* ?
        float turnResponse; // 0x70. Something is also wrong here. Is it really turnResponse ?
        float maxTurnRate; // 0x74
        char unk2[4];
        float topSpeed; // 0x7c
        float airBrakeInterval; // 0x80
        float decelerationInterval; // 0x84
        float boostThrust; // 0x88
        float heatRate; // 0x8c
        float coolRate; // 0x90
        float hoverHeight; // 0x94
        float repairRate; // 0x98
        float scaleUnk; // 0x9c
        uint32_t damageImmunity; // 0xa0
        float intersectRadius; // 0xa4
        char unk4[4];
        rdMatrix34 unk4_mat; // 0xac
        int unk4_0002; // 0xdc
        int unk4_0003; // 0xe0
        char unk4_0004[4];
        int unk4_0005; // 0xe8
        void* unk4_001; // 0xec
        char unk4_01[8];
        float unk4_010; // 0xf8
        char unk4_0100[4];
        int unk4_0101; // 0x100
        char unk4_0102[8];
        short unk4_0103; // 0x10c
        short unk4_0104; // 0x10e
        int unk4_0105; // 0x110
        int unk4_0106; // 0x114
        rdVector4 unk4_0107; // 0x118
        char unk4_0108[20];
        void* unk4_011; // 0x13c
        char unk4_02[4];
        rdVector3 unk4_021; // 0x144
        int unk4_022; // 0x148
        rdVector3 unk4_03; // 0x154
        rdVector3 unk4_1; // 0x160
        rdVector3 currentPos; // 0x16c. Same as 0x2cc position ?
        char unk5[12];
        float groundToPodMeasure; // 0x184. Same as 0x94 hoverHeight ?
        float thrust; // 0x18c. default 0.1, 1.0 with thrust, 1.32 thrust nose down, 0.68 thrust nose up
        float gravityMultiplier; // 0x190
        float unk6; // float, 0x194, fall related
        rdVector3 unk6_1; // 0x198
        float speedValue; // 0x1a0
        float speedValue2; // 0x1a4 ??
        float boostValue; // 0x1a8
        float speedMultiplier; // 0x1ac
        float fallRate; // 0x1b0
        float fallValue; // 0x1b4
        rdVector3 speedDir; // 0x1b8
        rdVector3 unk7; // 0x1c4
        rdVector3 unk7_1; // 0x1d0
        rdVector3 unk7_11; // 0x1e4
        char unk7_2[4];
        float unk7_3; // 0x1ec
        float projTurnRate; // 0x1f0
        float unk8; // 0x1f4
        float unk8_1; // 0x1f8
        float unk8_11; // 0x1fc
        float unk8_12; // 0x200
        float unk8_13; // 0x204
        float tilt; // 0x208 -1 tilt left, 0 neutral, 1 tilt right
        int unk9; // 0x20c
        uint32_t boostIndicatorStatus; // 0x210 0 not ready, 1 charging, 2 ready
        float boostChargeProgress; // 0x214
        float engineTemp; // 0x218
        char unk10[4];
        float unk10_1; // 0x220
        float unk10_2; // 0x224
        int unk10_3; // 0x228
        uint32_t multiplayerStats; // 0x22c. This is weird. Should be float ?
        char unk11[16];
        float terrainSpeedOffset; // 0x240
        float terrainSpeedMultiplier; // 0x244
        float terrainSkidModifier; // 0x248
        float slide; // 0x24c
        int unk11_1; // 0x250
        char unk12[16];
        float unk12_1; // 0x264
        float unk12_2; // 0x268 an angle of some kind ?
        int unk12_3; // 0x. Some flag. See FUN_0047a930
        char unk12_4[24]; // engine health related
        float engineHealth[6]; // 0x288 left top-mid-bot, right top-mid-bot
        char unk13[28]; // engine flag ?
        float repairTimer; // 0x2bc
        char unk14[4];
        float totalDamage; // 0x2c4
        float oobTimer; // 0x2c8
        rdVector3 position; // 0x2cc
        char unk15[12];
        rdVector3 turnInput; // 0x2e4
        char unk16[12];
        float pitch; // 0x2fc .8 pitch down -.8 pitch up
        // Behold the great unknown
        char unk17__19[64 * 3];
        rdVector3 unk19_0; // 0x3c0
        char unk20[52];
        rdVector3 unk20_0; // 0x400
        char unk21[52];
        char unk22__125[64 * 126];
        char unk126[48];
        void* unk127; // 0x1e70
    } swrRace; // at 0x00e29c44 sizeof(?)

    typedef struct swrEventManager
    {
        int event; // 0x0 Trig, Test,...
        int unk1; // 0x4. Pointer to data ?
        int count; // 0x8
        int size; // 0xca
        void* head; // 0x10
        char unk[4];
        void (*f1)(swrRace* player); // 0x18
        void (*f2)(swrRace* player); // 0x1c
        void (*f3)(swrRace* player); // 0x20. Is this really a swrRace* ?
        void (*f4)(swrRace* player, void* unk); // 0x24
    } swrEventManager; // sizeof(0x28)

    typedef struct swrRace_unk
    {
        char unk[4]; // 0x0
        int unk1; // 0x4
        int unk2; // 0x8
        char unk3[8];
        rdMatrix44 unk4; // 0x14
        char unk5[24];
        rdVector4 unk6; // 0x6c
    } swrRace_unk; // sizeof(0x7c). At 0x04b91c4 ?

    typedef struct swr_unk1
    {
        char unk[120];
        swr_unk3* unk2_swrunk3;
        char unk3[20];
    } swr_unk1; // sizeof(0x90). 0x0050c6b0. See FUN_00408e40

    typedef struct swr_unk2
    {
        char unk[0xd8cc0];
    } swr_unk2; // sizeof(0xd8cc0). See FUN_00408e40

    typedef struct swr_unk3
    {
        char unk[0x1abbc0];
    } swr_unk3; // sizeof(0x1abbc0). See FUN_00408e40

    typedef struct swrSound
    {
        int unk0;
        int id;
        int unk;
        int unk1;
        int unk2;
        float pitch;
        int unk4;
        short unk5;
        short unk51;
        IA3dSource* source;
        char unk6[8];
        rdVector3 pos;
        int unk7;
        float maxDist;
        float minDist;
    } swrSound; // sizeof(0x44) in [8] ?. See DAT_00e68080

#ifdef __cplusplus
}
#endif
#endif // TYPES_H
