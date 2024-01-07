#ifndef SWRSPRITE_H
#define SWRSPRITE_H

#include "types.h"

#define swrSprite_SetCursorVisibility2_ADDR (0x004081e0)

#define swrSprite_IsCursorVisible_ADDR (0x00408200)

#define swrSprite_SetCursorVisibility_ADDR (0x00408210)

#define swrSprite_DisplayCursor_ADDR (0x00408220)

#define swrSprite_GetTextureFromTGA_ADDR (0x004114d0)

#define swrSprite_AssignTextureToId_ADDR (0x00416fd0)

#define swrSprite_GetTextureFromId_ADDR (0x00417010)

#define swrSprite_GetTextureDimFromId_ADDR (0x00417120)

#define swrSprite_GetBBoxFromId_ADDR (0x00417150)

#define swrSprite_MoveBBoxTo_ADDR (0x00417900)

#define swrSprite_NewSprite_ADDR (0x004282f0)

#define swrSprite_SetVisible_ADDR (0x004285d0)

#define swrSprite_SetPos_ADDR (0x00428660)

#define swrSprite_SetDim_ADDR (0x004286f0)

#define swrSprite_SetColor_ADDR (0x00428740)

#define swrSprite_SetFlag_ADDR (0x004287e0)

#define swrSprite_UnsetFlag_ADDR (0x00428800)

#define swrSprite_UpperPowerOfTwo_ADDR (0x00445c90)
#define swrSprite_LoadTexture_ADDR (0x00446ca0)
#define swrSprite_LoadTexture__ADDR (0x00446fb0)

void swrSprite_SetCursorVisibility2(int visibility);

bool swrSprite_IsCursorVisible(void);

void swrSprite_SetCursorVisibility(int visible);

void swrSprite_DisplayCursor(void);

swrSpriteTexture* swrSprite_GetTextureFromTGA(char* filename_tga, int id);

void swrSprite_AssignTextureToId(swrSpriteTexture* spriteTex, int id, int from_tga);

swrSpriteTexture* swrSprite_GetTextureFromId(int id);

void swrSprite_GetTextureDimFromId(swrSprite_NAME spriteId, int* out_width, int* out_height);

void swrSprite_GetBBoxFromId(swrSprite_NAME spriteId, swrSprite_BBox* box);

void swrSprite_MoveBBoxTo(swrSprite_BBox* box, int newX, int newY);

void swrSprite_NewSprite(short id, swrSpriteTexture* tex);

void swrSprite_SetVisible(short id, int visible);

void swrSprite_SetPos(short id, short x, short y);

void swrSprite_SetDim(short id, float width, float height);

void swrSprite_SetColor(short id, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrSprite_SetFlag(short id, unsigned int flag);

void swrSprite_UnsetFlag(short id, unsigned int flag);

int swrSprite_UpperPowerOfTwo(int x);

swrSpriteTexture* swrSprite_LoadTexture(int index);
swrSpriteTexture* swrSprite_LoadTexture_(swrSprite_NAME index);

#endif // SWRSPRITE_H
