// Copy this file in ImHex
#pragma endian big

#include "std/mem.pat"

struct SpriteHeader {
    u16 width;
    u16 height;
    u16 format;
    u16 unk3; // always zero
    u32 palette_offset;
    u16 page_count;
    u16 unke; // always 32
    u32 unk10; // always 20. TODO: Check
};

struct PageMetaData {
    u16 pageWidth;
    u16 pageHeight;
    u32 dataStart;
};

struct Pages<auto pixel_size, auto width, auto height> {
    u8 pixelData[pixel_size * width * height];
};

fn patchWidth(u16 format, u16 pageWidth) {
    if (format == 513 || format == 1025) {
        return 1;
    } else if (format == 512 || format == 1024) {
        return 2;
    }
};

struct Sprite {
    SpriteHeader header;
    PageMetaData pagesMetadata[header.page_count];


    if (header.palette_offset != 0) {
        u32 palette_size = 16; // format 512
        if (header.format == 513) {
            palette_size = 256;
        }
        u16 palette[palette_size]; // @ addressof(header) + header.palette_offset;
    }
    u32 pixel_size = 1;
    if (header.format == 3) {
        pixel_size = 4;
    }

    // TODO: Patch width and page size for each page
    if (header.page_count > 0) {
        Pages<pixel_size, pagesMetadata[0].pageWidth, pagesMetadata[0].pageHeight> pagesData[1] @ addressof(header) + pagesMetadata[0].dataStart;
    }
};

struct Sprite_ptr {
    Sprite* p: u32 [[inline]];
};

struct SpriteBlock {
    u32 spriteCount;
    Sprite_ptr spriteBegins[spriteCount];
    u32 EOF;
};

SpriteBlock block @ 0;
