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

    typedef struct
    {
        union
        {
            struct
            {
                unsigned short size_short; // -8
                unsigned short pad;
            };
            uint32_t size; // -8
        };
        uint32_t unk1; // -4
        uint8_t data[]; // 0 Pointer which is actually returned
    } Allocation;

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
    } rdVector2; // sizeof(0x8)

    typedef struct rdVector3
    {
        float x;
        float y;
        float z;
    } rdVector3; // sizeof(0xc)

    typedef struct rdVector4
    {
        float x;
        float y;
        float z;
        float w;
    } rdVector4; // sizeof(0x10)

    typedef struct rdMatrix33
    {
        rdVector3 rvec;
        rdVector3 lvec;
        rdVector3 uvec;
    } rdMatrix33; // sizeof(0x30)

    typedef struct rdMatrix34
    {
        rdVector3 rvec;
        rdVector3 lvec;
        rdVector3 uvec;
        rdVector3 scale;
    } rdMatrix34; // sizeof(0x3c)

    typedef struct rdMatrix44
    {
        rdVector4 vA;
        rdVector4 vB;
        rdVector4 vC;
        rdVector4 vD;
    } rdMatrix44; // sizeof(0x40)

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
        char unk[46];
    } rdClipFrustum; // sizeof(0x64) == 100

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
    } rdTexFormat; // sizeof(0x38)

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

    typedef enum TGADataType
    {
        TGADataType_NOIMAGEDATA = 0,
        TGADataType_UNCOMPRESSEDCOLORMAPPED = 1,
        TGADataType_UNCOMPRESSEDRGB = 2,
        TGADataType_UNCOMPRESSEDBW = 3,
        TGADataType_RLECOLORMAPPED = 9,
        TGADataType_RLERGB = 10,
        TGADataType_COMPRESSEDBW = 11,
        TGADataType_COMPRESSEDCOLORMAPPED = 32,
        TGADataType_COMPRESSEDCOLORMAPPEDQUADTREE = 33,
    } TGADataType;

    typedef struct TGAHeader
    {
        char idlength;
        char colormaptype;
        TGADataType datatypecode;
        short int colormaporigin;
        short int colormaplength;
        char colormapdepth;
        short int x_origin;
        short int y_origin;
        short width;
        short height;
        char bitsperpixel;
        char imagedescriptor;
    } TGAHeader; // sizeof(18); PACK 1 !

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
    } swrSpriteTextureHeader; // sizeof(0x14)

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

    typedef struct swrSpriteTexItem
    {
        swrSpriteTexture* texture;
        int id; // 0x4
    } swrSpriteTexItem; // sizeof(0x8)

    typedef struct swrTranslationRotation
    {
        rdVector3 translation;
        rdVector3 yaw_roll_pitch;
    } swrTranslationRotation;

    // Used to do the C-style "Inheritance" for different game objects
    typedef struct swrObj
    {
        int event;
        short id; // 0x4
        short flags; // 0x6
    } swrObj; // sizeof(0x8)

    typedef struct swrRace
    {
        swrObj obj;
        swrTranslationRotation translation_rotation; // 0x8. See fun_00454d40. FUN_00473f40
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
        char unk4_0100[34];
        int unk4_0101; // 0x100
        char unk4_0102[8];
        short unk4_0103; // 0x10c
        short unk4_0104; // 0x10e
        int unk4_0105; // 0x110
        int unk4_0106; // 0x114
        rdVector4 unk4_0107; // 0x118
        char unk4_0108[20];
        swrModel_unk* model_unk; // 0x13c
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
        char unk440[6704];
        char unk1e70[184]; // 0x1e70
    } swrRace; // at 0x00e29c44 sizeof(?). From Objs: sizeof(0x1f28)

    typedef struct swrObjToss
    {
        swrObj obj;
        char unk8[24];
        rdMatrix44 mat;
        int unk60;
        int unk64;
        float unk68_ms;
        float unk6c;
        char unk70;
        char unk71;
        char unk72;
        char unk73;
        void* unk74;
        void* unk78;
    } swrObjToss; // sizeof(0x7c)

    typedef struct swrObjTrig
    {
        swrObj obj;
        int modelId; // 0x8 // supposed modelId
        int flag; // 0xc
        float unk10_ms;
        float unk14_ms;
        char unk18[12];
        rdVector3 unk24;
        rdVector3 unk30;
        int unk3c;
        int unk40;
        int unk44;
        void* unk48;
        void* unk4c;
        void* unk50;
        int unk54;
    } swrObjTrig; // sizeof(0x58)

    typedef struct swrObjHang
    {
        swrObj obj;
        int unk8;
        char unkc[4];
        int unk10;
        int flag;
        char unk18[8];
        swrModel_unk* unk20_model;
        swrModel_unk* unk24_model;
        char unk28[4];
        swrModel_unk* unk2c_model;
        char unk30[4];
        int unk34_index;
        int unk38;
        char unk3c[4];
        int unk40_index;
        char unk44[4];
        char unk48[24];
        char unk60;
        char unk61[11];
        char unk6c[64];
        char unkac[36];
    } swrObjHang; // sizeof(0xd0)

    typedef struct swrObjJdge
    {
        swrObj obj;
        int flag;
        float unkc_ms;
        swrModel_unk* unk10;
        void* unk14;
        void* unk18;
        void* unk1c;
        void* unk20;
        void* unk24;
        swrModel_unk* unk28_model;
        int unk2c_spline;
        int unk30;
        int unk34;
        float unk38;
        int unk3c;
        int unk40;
        char unk44[16];
        int unk54;
        int unk58;
        int unk5c;
        int unk60;
        rdMatrix44 unk64_mat;
        rdMatrix44 unk80_mat;
        rdMatrix44 unkbc_mat;
        int unk124;
        int event;
        char unk128[4];
        void* unk12c;
        rdMatrix44 unk134_mat;
        rdMatrix44 unk170_mat;
        int unk1a4;
        int unk1a8;
        int unk1ac_index;
        char unk1b0[4];
        int unk1b4_splineId;
        int unk1b8_splineId;
        int unk1bc_count;
        int unk1c0_type;
        char unk1c4[4];
        int unk1c8_index;
        float unk1cc_ms;
        float best_lap_time_ms;
        char unk1d4[4];
        int unk1d8;
        int unk1dc;
        int unk1e0;
        float unk1e4;
    } swrObjJdge; // sizeof(0x1e8)

    typedef struct swrObjScen
    {
        swrObj obj;
        int unk8;
        int unkc;
        char unk0_0[64];
        int unk50;
        char unk0_1[48];
        rdMatrix44 unk84_mat;
        int unkc4;
        char unkc8[72];
        char unk110[264];
        char unk218[264];
        char unk320[264];
        char unk428[264];
        char unk530[264];
        char unk0_2[264];
        char unk0_3[264];
        char unk0_4[264];
        char unk0_5[264];
        char unk0_6[208];
        rdMatrix44 unkb28_mat;
        char unk0_7[264];
        char unk0_8[264];
        char unk0_9[264];
        char unk0_10[264];
        char unk0_11[264];
        char unk0_12[264];
        char unk0_13[264];
        char unk0_14[264];
        char unk0_15[264];
        char unk0_16[264];
        char unk0_17[264];
        char unk0_18[264];
        char unk0_19[264];
        char unk0_20[264];
        char unk0_21[264];
        char unk0_22[108];
    } swrObjScen; // sizeof(0x1b4c)

    typedef struct swrObjElmo
    {
        swrObj obj;
        int unk8;
        int unkc;
        char unk10[4];
        void* unk14;
        float unk18_ms;
        float unk1c_ms;
        char unk1c[16];
        swrModel_unk** unk30;
        void* unk34;
        char unk38[16];
        float unk48_angle_degrees;
        char unk4c[4];
        rdVector3 unk50;
        char unk5c[12];
        float unk68;
        float unk6c_angle_degrees;
        int unk70;
        char unk74[8];
        char unk7c[12];
        int unk88;
        char unk8c[8];
        int unk94;
        char unk98[14];
        float unka8_ms;
        float unkac_ms;
        char unkb0[4];
        int unkb4;
        char unkb8[8];
    } swrObjElmo; // sizeof(0xc0)

    typedef struct swrObjSmok
    {
        swrObj obj;
        char unk8[32];
        char unk28[32];
        char unk48[24];
        int unk60;
        int unk64;
        float unk68_ms;
        char unk6c[4];
        int unk70;
        float unk74;
        float unk78;
        float unk7c;
        char unk80[4];
        float unk84;
        float unk88;
        float unk8c;
        float unk90;
        float unk94;
        float unk98;
        float unk9c;
        float unka0;
        float unka4;
        float unka8_ms;
        char unkac[28];
        char unkc8[12];
        float unkd4_ms;
        float unkd8_ms;
        char unkdc[12];
        char unke8[8];
        float unkf0;
        swrModel_unk* unkf4_model;
        float unkf8;
        float unkfc;
        float unk100;
        float unk104;
    } swrObjSmok; // sizeof(0x108)

    typedef struct swrObjcMan
    {
        swrObj obj;
        rdVector3 unk8;
        rdVector3 unk14;
        rdMatrix44 unk20_mat;
        int unk60;
        int unk64;
        int unk6c;
        int unk6c_count;
        float unk70_ms;
        int unk74_count;
        int unk78;
        int unk7c_type;
        int unk80;
        rdMatrix34 unk84_mat;
        rdMatrix44 unkb4_mat;
        swrRace* unkf4_objTest;
        int unkf8;
        rdVector3 unkfc;
        rdMatrix44 unk108_mat;
        float unk148;
        float unk14c;
        int unk150;
        int unk154;
        int unk158;
        float unk15c[12];
        char unk0_0[12];
        float unk198;
        float unk19c;
        float unk1a0;
        int unk1a4;
        int unk1a8;
        int unk1ac;
        int unk1b0;
        rdMatrix44 unk1b4_mat;
        rdMatrix44 unk1e4_mat;
        rdMatrix44 unk224_mat;
        rdMatrix44 unk264_mat;
        int unk2a4;
        int unk2a8_flag;
        unsigned int unk2ac_flag;
        float unk2b0;
        float unk2b4;
        float unk2b8;
        unsigned int unk2bc;
        unsigned int unk2c0;
        unsigned int unk2c4;
        unsigned int unk2c8;
        unsigned int unk2cc;
        unsigned int unk2d0;
        float unk2d4;
        float unk2d8;
        float unk2dc;
        float unk2e0;
        unsigned int unk2e4_flag;
        float unk2e8;
        float unk2ec;
        float unk2f0;
        rdVector3 unk2f4;
        rdVector3 unk300;
        rdVector3 unk30c;
        float unk310;
        float unk314;
        float unk318;
        float unk31c;
        float unk320;
        float unk324;
        float unk330;
        float unk334;
        float unk338;
        float unk33c;
        rdVector3 unk340;
        float unk34c;
        float unk350;
        float unk354;
        rdVector3 unk358;
        float unk35c;
        rdVector3 unk368;
        rdVector3 unk374;
        rdVector3 unk380;
        rdVector3 unk38c;
        float unk398_ms;
        float unk39c;
        float unk3a0;
        float unk3a4;
    } swrObjcMan; // sizeof(0x3a8)

    typedef struct swrEventManager
    {
        int event; // 0x0 Trig, Test,...
        int flags; // 0x4. Flag ?
        int count; // 0x8
        int size; // 0xca
        swrObj* head; // 0x10
        void (*f0)(swrObj* obj); // 0x14
        void (*f1)(swrObj* obj); // 0x18
        void (*f2)(swrObj* obj); // 0x1c
        void (*f3)(swrObj* obj); // 0x20
        void (*f4)(swrObj* obj, int* subEvent); // 0x24 int[2] subEvent
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

    typedef struct swrUI_unk
    {
        swrUI_unk* prev2;
        swrUI_unk* next2;
        swrUI_unk* prev;
        swrUI_unk* next;
        void* fun;
        void* fun2;
        int unk00_6;
        int id;
        int unk00_flag;
        int unk00_7;
        int unk00_8;
        int unk00_9;
        int unk00_10;
        char unk01[8];
        int size_unk1;
        int size_unk2;
        char* unk01_10;
        char unk01_11[20];
        int unk01_counter;
        swrUI_unk2 unk0_0[20];
        char unk0_0_99;
        char unk0_0_100;
        char unk0_0_101;
        char unk0_0_102;
        char unk0_0_103;
        char unk0_0_104;
        char unk0_0_105;
        char unk0_0_106;
        char unk0_0_107;
        char unk0_0_108;
        char unk0_0_109;
        char unk0_0_110;
        char unk0_0_111;
        char unk0_0_112;
        char unk0_0_113;
        char unk0_0_114;
        char unk0_0_115;
        char unk0_0_116;
        char unk0_0_117;
        char unk0_0_118;
        char* str_allocated;
        char unk0_0_119[4];
        int unk0_index;
        int unk0_100;
        int unk0_101;
        int unk0_102;
        int unk0_103;
        unsigned int unk0_flag;
        char unk1[64];
        int unk1_50;
        char unk2[4232];
    } swrUI_unk; // sizeof(0x15c0 + unk size)

    typedef struct swrUI_unk2
    {
        int flag;
        int unk0;
        int id;
        float unk2;
        float unk3;
        int unk31;
        int unk32;
        int unk33;
        int unk34;
        void* unk35;
        void* unk36;
        int unk37;
        int unk38;
        char unk4;
        char unk5;
        char unk6;
        char unk7;
    } swrUI_unk2; // sizeof(0x38) in a [20]

    typedef struct swrModel_unk
    {
        char unk[0x30]; // rdMatrix34 between 0x1c and 0x48
        rdMatrix44 unk_mat1; // 0x30
        rdMatrix44 unk_mat2; // 0x70
        rdMatrix44 unk_mat3; // 0xb0
        rdMatrix44 unk_mat4; // 0xb0
        char unk2[124];
    } swrModel_unk; // sizeof(0x16c)

    typedef struct swr3DTextureFormat
    {
        rdTexFormat texFormat;
        int unk60;
        int unk61;
        DDPIXELFORMAT pixelFormat;
    } swr3DTextureFormat; // sizeof(0x60)

    typedef struct swr3DDevice
    {
        unsigned int flags;
        unsigned int TriTexCapsUnk1;
        unsigned int hasZBuffer;
        int TriTexCapsUnk4;
        int TriTexCapsUnk2;
        int TriTexCapsUnk3;
        int hasTexBlendUnk;
        int TriTexCapsUnk5;
        int minTexWidth;
        int minTexHeight;
        int maxTexWidth;
        int maxTexHeight;
        int maxVertexCount;
        char name[128];
        char description[128];
        char unk1[8];
        D3DDEVICEDESC deviceDesc;
        GUID guid; // 0x238
        char unk[0x288];
    } swr3DDevice; // sizeof(0x368)

    typedef struct swrDrawDevice
    {
        char driver_desc[128];
        char driver_name[128];
        int isEmulationOrHardware;
        int supportUnk1;
        int useActiveDevice; // !isEmulationOrHardware
        int supportUnk2;
        int unk2;
        int unk3;
        char unk1[380];
        GUID guid; // 0x294
    } swrDrawDevice; // sizeof(0x2a4)

    typedef struct swrDrawDevice3D
    {
        swrDrawDevice drawDevice; // 0x0
        int nbDisplayModes; // 0x2a4
        swrDisplayMode* displayModes; // 0x2a8
        int nb3dDevices; // 0x2ac
        swr3DDevice* swr3dDevices; // 0x2b0
    } swrDrawDevice3D; // sizeof(0x2b4)

    typedef struct swrDrawDevices
    {
        unsigned int nbDevices;
        swrDrawDevice* devices;
    } swrDrawDevices;

    typedef struct swrDisplayMode
    {
        float aspectRatio; // 0x0
        int width; // 0x4
        int height; // 0x8
        int size; // 0xc
        int linearSize; // 0x10
        char unk2[4]; // 0x14
        int pixelFormatIsUnk;
        int bytePerPixel;
        int nbBitUnk2;
        int nbBitUnk5;
        int nbBitUnk6;
        int nbRBitMask;
        int nbGBitMask;
        int nbBBitMask;
        int nbBitUnk;
        int nbBitUnk3;
        int nbBitUnk4;
        char unk[12];
    } swrDisplayMode; // sizeof(0x50)

    typedef struct swrRenderUnk
    {
        char unk[64];
    } swrRenderUnk; // sizeof(0x40)

    typedef struct swrSoundUnk
    {
        int prime_nbUnks2;
        swrSoundUnk2* unks2; // sizeof(prime * 16)
        void* f;
    } swrSoundUnk; // sizeof(0xc)

    typedef struct swrSoundUnk2
    {
        char unk[0x10];
    } swrSoundUnk2; // sizeof(0x10)

    typedef struct swrUI_Unk3
    {
        int unk0;
        swr_unk1* unk1;
        int unk2;
        int unk3;
        int unk4_canvas;
        int unk5;
        int unk6;
        int unk7_alloc;
        int unk71_alloc;
        int unk8_alloc;
        int unk9;
        int unk10;
        int unk11;
        int unk12;
        char unk13[4];
        int unk14;
    } swrUI_Unk3; // sizeof(0x40)

    typedef struct MATHeader
    {
        char magic[4]; // "MAT "
        unsigned int version; // 0x32
        unsigned int type; // 0 colors, 1 unk, 2 texture
        int numTextures; // num textures OR colors
        int numTextures1; // 0 colors, numTextures in texture
        int zero; // 0
        int eight; // 8
        int unk[12];
    } MATHeader; // sizeof(0x4c) as defined in www.massassi.net/jkspecs/

    typedef struct MATTexHeader
    {
        int texType; // 0 color, 8 texture // UNSURE
        int colornum; // unk // UNSURE
        // float unk[4]; // REMOVED from massassi
        int unk2[2]; // UNSURE
        int magic; // 0xbff78482 // UNSURE
        int nbMipMap; // 0x14
    } MATTexHeader; // sizeof(0x18). DOESNT Checks out. Above was 0x28

    typedef struct swrMaterial
    {
        char filename[64];
        char unk40[4];
        int unk_mat[14]; // MAT unk header part
        int unk_mat_flag;
        char unk80[8];
        unsigned int nbTextures;
        int unk8c;
        void* textures_alloc;
    } swrMaterial; // sizeof(0x94)

#ifdef __cplusplus
}
#endif
#endif // TYPES_H
