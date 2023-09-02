#include "swrSprite.h"

#include "macros.h"

extern swrSpriteTexture* FUN_00445b40();

// 0x00446ca0
swrSpriteTexture* swrSprite_LoadTexture(int index)
{
    int nbSprites;
    swrSpriteTexture* spriteTex;
    unsigned int indicesBound[2];

    swrLoader_OpenBlock(swrLoader_TYPE_SPRITE_BLOCK);
    spriteTex = (swrSpriteTexture*)FUN_00445b40();
    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, 0, &nbSprites, sizeof(int));
    nbSprites = SWAP32(nbSprites);

    if ((-1 < index) && (index < nbSprites))
    {
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

        if (spriteTex->header.format != 2 || spriteTex->header.palette_offset != 0)
        {
            swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0] + sizeof(swrSpriteTextureHeader), spriteTex->pages, spriteTex->header.page_count * sizeof(swrSpriteTexturePage));
            if (0 < spriteTex->header.page_count)
            {
                for (int i = 0; i < spriteTex->header.page_count; i++)
                {
                    spriteTex->pages[i * sizeof(swrSpriteTexturePage)].width = SWAP16(spriteTex->pages[i * sizeof(swrSpriteTexturePage)].width);
                    spriteTex->pages[i * sizeof(swrSpriteTexturePage)].height = SWAP16(spriteTex->pages[i * sizeof(swrSpriteTexturePage)].height);
                    spriteTex->pages[i * sizeof(swrSpriteTexturePage)].offset = SWAP32(spriteTex->pages[i * sizeof(swrSpriteTexturePage)].offset);
                }
            }

            if (spriteTex->header.palette_offset != 0)
            {
                // fix width of page ? + 0xf & 0xfffffff0
                swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, indicesBound[0] + spriteTex->header.palette_offset, spriteTex->pages->??, spriteTex->pages->offset - spriteTex->header.palette_offset);
            }
        }
    }

    hang("TODO");
}

// 0x00446fb0
swrSpriteTexture* swrSprite_LoadTexture_(int index)
{
    return swrSprite_LoadTexture(index);
}
