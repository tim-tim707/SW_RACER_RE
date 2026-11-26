#include "swrLoader.h"

#include <stdio.h>

#include "types.h"
#include "globals.h"

#include <macros.h>
#include <engine_config.h>
#include <Platform/cstdlib.h>

// 0x0042D520
void swrLoader_DecompressLZSS(char* compressed, char* decompressed)
{
    // the 4 KiB ring buffer is the caller's scratch space just before the input
    char* window = compressed - SWR_LZSS_WINDOW_SIZE;
    int windowPos = 1;
    int done = 0;
    int flags;
    int bit;
    int hi;
    int offset;
    int length;
    int i;
    char c;

    do {
        flags = (signed char)*compressed++;
        for (bit = 0; bit < 8; bit++) {
            if (flags & (1 << bit)) {
                c = *compressed++;
                *decompressed++ = c;
                window[windowPos] = c;
                windowPos = (windowPos + 1) & (SWR_LZSS_WINDOW_SIZE - 1);
                continue;
            }
            // both bytes are sign-extended in the original
            hi = (signed char)compressed[0];
            offset = (signed char)compressed[1] + ((hi & 0xf) << 8);
            compressed += 2;
            length = hi >> 4;
            if (offset == 0) {
                done = 1;
                break;
            }
            for (i = 0; i <= length + 1; i++) {
                c = window[(offset + i) & (SWR_LZSS_WINDOW_SIZE - 1)];
                *decompressed++ = c;
                window[windowPos] = c;
                windowPos = (windowPos + 1) & (SWR_LZSS_WINDOW_SIZE - 1);
            }
        }
    } while (!done);
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

// 0x0042d640
size_t swrLoader_ReadAt(swrLoader_TYPE type, long _Offset, void* _DstBuf, size_t _ElementSize)
{
    FILE** f;
    f = swrLoader_TypeToFile(type);
    fseek(*f, _Offset, 0);
    return fread(_DstBuf, _ElementSize, 1, *f);
}

// 0x0042d680
void swrLoader_OpenBlock(swrLoader_TYPE type)
{
    FILE** file;
    FILE* opened_file;
    char* filename;

    // the paths are read through pointer slots, not as literals
    switch (type)
    {
    case swrLoader_TYPE_MODEL_BLOCK:
        filename = swrLoader_model_path;
        break;
    case swrLoader_TYPE_SPRITE_BLOCK:
        filename = swrLoader_sprite_path;
        break;
    case swrLoader_TYPE_SPLINE_BLOCK:
        filename = swrLoader_spline_path;
        break;
    case swrLoader_TYPE_TEXTURE_BLOCK:
        filename = swrLoader_texture_path;
        break;
    default:
        // faithful: the original reuses the argument's register
        filename = (char*)type;
        break;
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

// 0x0042d6f0
void swrLoader_CloseBlock(swrLoader_TYPE type)
{
    FILE** f;
    f = swrLoader_TypeToFile(type);
    fclose(*f);
    *f = NULL;
}
