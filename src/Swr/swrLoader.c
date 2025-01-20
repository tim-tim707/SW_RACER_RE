#include "swrLoader.h"

#include <stdio.h>

#include "types.h"
#include "globals.h"

#include <macros.h>

// 0x0042D520
void swrLoader_DecompressData(char* compressed, char* decompressed)
{
    HANG("TODO");
}

// 0x0042d600
FILE** swrLoader_TypeToFile(swrLoader_TYPE type)
{
    switch (type)
    {
    case swrLoader_TYPE_MODEL_BLOCK:
        return &swrLoader_model_file;
    case swrLoader_TYPE_SPRITE_BLOCK:
        return &swrLoader_sprite_file;
    case swrLoader_TYPE_SPLINE_BLOCK:
        return &swrLoader_spline_file;
    case swrLoader_TYPE_TEXTURE_BLOCK:
        return &swrLoader_texture_file;
    default:
        return NULL;
    }
}

// 0x0042d640 TODO: crashes on game start
size_t swrLoader_ReadAt(swrLoader_TYPE type, long _Offset, void* _DstBuf, size_t _ElementSize)
{
    FILE** f;
    f = swrLoader_TypeToFile(type);
    fseek(*f, _Offset, 0);
    return fread(_DstBuf, _ElementSize, 1, *f);
}

// 0x0042d680 TODO: crashes on game start
void swrLoader_OpenBlock(swrLoader_TYPE type)
{
    FILE** file;
    FILE* opened_file;
    char* filename;

    switch (type)
    {
    case swrLoader_TYPE_MODEL_BLOCK:
        filename = "data/lev01/out_modelblock.bin";
        break;
    case swrLoader_TYPE_SPRITE_BLOCK:
        filename = "data/lev01/out_spriteblock.bin";
        break;
    case swrLoader_TYPE_SPLINE_BLOCK:
        filename = "data/lev01/out_splineblock.bin";
        break;
    case swrLoader_TYPE_TEXTURE_BLOCK:
        filename = "data/lev01/out_textureblock.bin";
    }
    file = swrLoader_TypeToFile(type);
    if (*file == NULL)
    {
        opened_file = fopen(filename, "rb");
        *file = opened_file;
        if (opened_file == NULL)
        {
            do
            {
            } while (true);
        }
    }
    return;
}

// 0x0042d6f0 TODO: crashes on game start
void swrLoader_CloseBlock(swrLoader_TYPE type)
{
    FILE** f;
    f = swrLoader_TypeToFile(type);
    fclose(*f);
    *f = NULL;
}
