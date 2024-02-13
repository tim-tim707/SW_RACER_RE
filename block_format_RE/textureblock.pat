// Copy this file in ImHex
#pragma endian big

#include "std/mem.pat"

// How to know width, height and format from here ?

struct Texture {
    u32 pixelData;
};

struct Palette {
    u32 paletteData;
};

struct Texture_ptr {
    Texture* t: u32 [[inline]];
    Palette* p: u32 [[inline]];
};

struct TextureBlock {
    u32 textureCount;
    Texture_ptr texBegins[textureCount];
    u32 EOF;
};

TextureBlock block @ 0;
