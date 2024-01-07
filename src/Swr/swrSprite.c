#include "swrSprite.h"

#include "macros.h"
#include "globals.h"

extern swrSpriteTexture* FUN_00445b40();

// 0x004081e0
void swrSprite_SetCursorVisibility2(int visibility)
{
    if (visibility != 0)
    {
        swrSprite_mouseVisible = swrSprite_mouseVisible + 1;
        return;
    }
    swrSprite_mouseVisible = swrSprite_mouseVisible + -1;
}

// 0x00408200
bool swrSprite_IsCursorVisible(void)
{
    return 0 < swrSprite_mouseVisible;
}

// 0x00408210
void swrSprite_SetCursorVisibility(int visible)
{
    swrSprite_mouseVisible = visible;
}

// 0x00408220
void swrSprite_DisplayCursor(void)
{
    HANG("TODO, easy");
}

// 0x004114d0
swrSpriteTexture* swrSprite_GetTextureFromTGA(char* filename_tga, int id)
{
    HANG("TODO");
    return NULL;
}

// 0x00416fd0
void swrSprite_AssignTextureToId(swrSpriteTexture* spriteTex, int id, int from_tga)
{
    HANG("TODO, easy");
}

// 0x00417010
swrSpriteTexture* swrSprite_GetTextureFromId(int id)
{
    HANG("TODO");
}

// 0x00417120
void swrSprite_GetTextureDimFromId(swrSprite_NAME spriteId, int* out_width, int* out_height)
{
    swrSpriteTexture* tmp;

    tmp = swrSprite_GetTextureFromId(spriteId);
    if (tmp != NULL)
    {
        if (out_width != NULL)
        {
            *out_width = (int)(short)(tmp->header).width;
        }
        if (out_height != NULL)
        {
            *out_height = (int)(short)(tmp->header).height;
        }
    }
}

// 0x00417150
void swrSprite_GetBBoxFromId(swrSprite_NAME spriteId, swrSprite_BBox* box)
{
    unsigned int* out_height;
    unsigned int* out_width;

    if (box != NULL)
    {
        out_height = &box->y2;
        out_width = &box->x2;
        box->y = 0;
        box->x = 0;
        *out_height = 0;
        *out_width = 0;
        swrSprite_GetTextureDimFromId(spriteId, out_width, out_height);
        *out_width = *out_width - 1;
        *out_height = *out_height - 1;
    }
}

// 0x00417900
void swrSprite_MoveBBoxTo(swrSprite_BBox* box, int newX, int newY)
{
    unsigned int tmpx;
    unsigned int tmpy;

    if (box != NULL)
    {
        tmpx = box->y;
        tmpy = box->x;
        box->x = newX;
        box->y = newY;
        box->x2 = (box->x2 - tmpy) + newX;
        box->y2 = (box->y2 - tmpx) + newY;
    }
}

// 0x004282f0
void swrSprite_NewSprite(short id, swrSpriteTexture* tex)
{
    int id_;

    if (id < 400)
    {
        id_ = (int)id;
        if (swrSprite_SpriteCount <= id_)
        {
            swrSprite_SpriteCount = id_ + 1;
        }
        (&swrSprite_array)[id_].x = 0;
        (&swrSprite_array)[id_].y = 0;
        (&swrSprite_array)[id_].width = 1.0;
        (&swrSprite_array)[id_].height = 1.0;
        (&swrSprite_array)[id_].unk0x10 = 0;
        (&swrSprite_array)[id_].flags = 1;
        (&swrSprite_array)[id_].r = 0xff;
        (&swrSprite_array)[id_].g = 0xff;
        (&swrSprite_array)[id_].b = 0xff;
        (&swrSprite_array)[id_].a = 0xff;
        (&swrSprite_array)[id_].texture = tex;
    }
}

// 0x004285d0
void swrSprite_SetVisible(short id, int visible) // Guess, but I believe accurate
{
    HANG("TODO, easy");
}

// 0x00428660
void swrSprite_SetPos(short id, short x, short y)
{
    if (id == -0xc9)
    {
        swrSprite_unk_x = (float)x;
        swrSprite_unk_y = (float)y;
        return;
    }
    if (-1 < id)
    {
        (&swrSprite_array)[id].x = x;
        (&swrSprite_array)[id].y = y;
    }
}

// 0x004286f0
void swrSprite_SetDim(short id, float width, float height)
{
    if (-1 < id)
    {
        (&swrSprite_array)[id].width = width;
        (&swrSprite_array)[id].height = height;
    }
}

// 0x00428740
void swrSprite_SetColor(short id, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (id == -0x67)
    {
        swrSprite_unk1_r = r;
        swrSprite_unk1_g = g;
        swrSprite_unk1_b = b;
        swrSprite_unk1_a = a;
        return;
    }
    if (id == -0x68)
    {
        swrSprite_unk2_r = r;
        swrSprite_unk2_g = g;
        swrSprite_unk2_b = b;
        swrSprite_unk2_a = a;
        return;
    }
    if (-1 < id)
    {
        (&swrSprite_array)[id].r = r;
        (&swrSprite_array)[id].g = g;
        (&swrSprite_array)[id].b = b;
        (&swrSprite_array)[id].a = a;
    }
}

// 0x004287e0
void swrSprite_SetFlag(short id, unsigned int flag)
{
    (&swrSprite_array)[id].flags = (&swrSprite_array)[id].flags | flag;
}

// 00428800
void swrSprite_UnsetFlag(short id, unsigned int flag)
{
    (&swrSprite_array)[id].flags = (&swrSprite_array)[id].flags & ~flag;
}

// 0x00445c90
int swrSprite_UpperPowerOfTwo(int x)
{
    int power_of_two = 0x40000000; // 2^30
    unsigned int uVar2;
    int res = 0x1f;
    do
    {
        if (res == 0)
            break;
        uVar2 = power_of_two & x;
        power_of_two = power_of_two >> 1;
        res = res + -1;
    } while (uVar2 == 0);
    res = power_of_two * 2;
    if (res < x)
    {
        res = power_of_two << 2;
    }
    if (res < 16)
    {
        res = 16;
    }
    return res;
}

// 0x00446a20
void FUN_00446a20(swrSpriteTexture* spriteTex)
{
    HANG("TODO");

    short w = swrSprite_UpperPowerOfTwo(spriteTex->header.width);
    short h = swrSprite_UpperPowerOfTwo(spriteTex->header.height);
    void* alloc = FUN_00408e60(spriteTex->header.page_table->offset, h * w * 2); // why * 2 ?

    int page_index = spriteTex->header.page_count;
    int unk;
    while (page_index = page_index - 1, unk = h, 0 <= h)
    {
        int unk2;
        switch (spriteTex->header.page_width_align)
        {
        case 0:
            unk2 = 15;
        case 1:
            unk2 = 7;
        case 2:
            unk2 = 3;
        case 3:
            unk2 = 1;
        }
        FUN_00445e50(spriteTex->header.page_table[page_index], spriteTex->header.page_table->height, w, spriteTex->header.page_table->offset, spriteTex->header.palette_offset, alloc);
        spriteTex->header.page_table->width = 0;
        spriteTex->header.page_table->height = 0;
        spriteTex->header.page_table->offset = 0;
    }

    int unk3;
    FUN_00445cd0(spriteTex->header.width, spriteTex->header.height, w, h, spriteTex->header.page_table->offset, &unk3, &alloc);
    spriteTex->header.page_table[0].width = spriteTex->header.width;
    spriteTex->header.page_table[0].height = spriteTex->header.height;
    spriteTex->header.page_table[0].offset = unk3;
    spriteTex->header.page_count = 1;
}

// 0x00446ca0
swrSpriteTexture* swrSprite_LoadTexture(int index)
{
    int nbSprites;
    swrSpriteTexture* spriteTex;
    swrSpriteTexturePage* _DstBuf;
    unsigned int indicesBound[2];

    swrLoader_OpenBlock(swrLoader_TYPE_SPRITE_BLOCK);
    spriteTex = (swrSpriteTexture*)FUN_00445b40();
    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, 0, &nbSprites, sizeof(int));
    nbSprites = SWAP32(nbSprites);

    if (index < 0 || index >= nbSprites)
    {
        return NULL;
    }

    // Get sprite header
    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, index * 4 + 4, indicesBound, sizeof(indicesBound));
    SWAP32(indicesBound[0]);
    SWAP32(indicesBound[1]);
    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0], spriteTex->header, sizeof(swrSpriteTextureHeader));
    spriteTex->header.width = SWAP16(spriteTex->header.width);
    spriteTex->header.height = SWAP16(spriteTex->header.height);
    spriteTex->header.unk3 = SWAP16(spriteTex->header.unk3);
    spriteTex->header.unk6 = SWAP16(spriteTex->header.unk6);
    spriteTex->header.page_count = SWAP16(spriteTex->header.page_count);
    spriteTex->header.palette_offset = SWAP32(spriteTex->header.palette_offset);

    if (spriteTex->header.format != 2 || (_DstBuf = spriteTex, spriteTex->header.palette_offset != 0))
    {
        // Get all pages infos
        swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0] + sizeof(swrSpriteTextureHeader), spriteTex->pages, spriteTex->header.page_count * sizeof(swrSpriteTexturePage));
        if (0 < spriteTex->header.page_count)
        {
            for (int i = 0; i < spriteTex->header.page_count; i++)
            {
                spriteTex->pages[i].width = SWAP16(spriteTex->pages[i].width);
                spriteTex->pages[i].height = SWAP16(spriteTex->pages[i].height);
                spriteTex->pages[i].offset = SWAP32(spriteTex->pages[i].offset);
            }
        }

        // Get palette ?
        if (spriteTex->header.palette_offset != 0)
        {
            // check if this is correct
            swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0] + spriteTex->header.palette_offset, (int)(spriteTex->pages[spriteTex->header.page_count].offset) + 1 & 0xfffffff0, spriteTex->pages->offset - spriteTex->header.palette_offset);
        }

        // Get pixels ?
        _DstBuf = (int)(&spriteTex->pages[spriteTex->header.page_count]) + 0xf & 0xfffffff0;
        if (0 < spriteTex->header.page_count)
        {
            for (int j = 0; j < spriteTex->header.page_count; j++)
            {
                int k = 0;
                if (j == spriteTex->header.page_count - 1)
                {
                    k = indicesBound[1] - indicesBound[0];
                }
                else
                {
                    k = spriteTex->pages[j + 1].offset;
                }

                swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0] + spriteTex->pages[j].offset, _DstBuf, k - spriteTex->pages[j].offset);
                spriteTex->pages[j].offset = _DstBuf;
                if (index != 99)
                {
                    FUN_00446b60(spriteTex, spriteTex->pages[j]);
                }
                _DstBuf = (int)(&_DstBuf[spriteTex->header.page_count]) + 0xf & 0xfffffff0;
            }
        }

        if (index == 99)
        {
            FUN_00446a20(spriteTex);
        }
    }
    swrLoader_CloseBlock(swrLoader_TYPE_SPRITE_BLOCK);
    FUN_00445b20(_DstBuf);
    return spriteTex;
}

// 0x00446fb0
swrSpriteTexture* swrSprite_LoadTexture_(swrSprite_NAME index)
{
    return swrSprite_LoadTexture(index);
}
