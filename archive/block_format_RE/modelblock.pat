// Copy this file in ImHex
#pragma endian big

#include "std/mem.pat"

u32 modelCount @ 0x00;

enum MODEL_STR: u32 {
    MAlt // TODO
};

enum HEADER_STR: u32 {
        HEnd = 0x48456E64,
        AltN = 0x416C744E,
        Anim = 0x416E696D,
        Data = 0x44617461
};

struct AltNData {
    u32 d[while(std::mem::read_unsigned($, 4) != 0x0)];
    u32 dataEnd; // 0x0
};

struct Animation {
    u8 animUnk[4];
    s16 flag1; // always 4352
};

struct AnimationPointer {
    Animation *ptr: u32;
};

struct AnimData {
    AnimationPointer d[while(std::mem::read_unsigned($, 4) != 0x0)];
    u32 animEnd; // 0x0
};

struct DataData {
    u32 size;
    u32 d[size]; // TODO: LightStreak
};

struct HeaderData {
    HEADER_STR headerStr; // AltN, Anim or Data
    match (headerStr) {
        (HEADER_STR::AltN): AltNData d;
        (HEADER_STR::Anim): AnimData d;
        (HEADER_STR::Data): DataData d;

    }
};

fn validHeaderStr(u32 headerStr){
    if (headerStr == HEADER_STR::HEnd
        || headerStr == HEADER_STR::AltN
        || headerStr == HEADER_STR::Anim
        || headerStr == HEADER_STR::Data)
        return true;

    return false;
};

struct ModelHeader {
    char extension[4]; // Podd, Trak, MAlt, Pupp
    u32 headers[while(std::mem::read_unsigned($, 4) != 0xFFFFFFFF)];
    s32 headersEnd; // -1
    HeaderData hData[while(validHeaderStr(std::mem::read_unsigned($, 4, std::mem::Endian::Big)) && std::mem::read_unsigned($, 4, std::mem::Endian::Big) != HEADER_STR::HEnd)];
    u32 hEnd; // HEADER_STR::HEnd
};

struct ModelHeaderPtr {
    ModelHeader* ptr: u32;
    //u32* asset_end: u32;
};

ModelHeaderPtr modelAddresses[modelCount] @ 0x04;
