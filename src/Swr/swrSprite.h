#ifndef SWRSPRITE_H
#define SWRSPRITE_H

#include "types.h"

#define swrSprite_SetCursorVisibility2_ADDR (0x004081e0)

#define swrSprite_IsCursorVisible_ADDR (0x00408200)

#define swrSprite_SetCursorVisibility_ADDR (0x00408210)

#define swrSprite_DisplayCursor_ADDR (0x00408220)

#define swrSprite_GetTextureFromTGA_ADDR (0x004114d0)

#define swrSprite_LoadAllSprites_ADDR (0x00412650)

#define swrSprite_UnloadAllSprites_ADDR (0x00412e20)

#define swrSprite_LoadFromId_ADDR (0x00412e90)

#define swrSprite_ClearSprites_ADDR (0x00412f60)

#define swrSprite_AssignTextureToId_ADDR (0x00416fd0)

#define swrSprite_GetTextureFromId_ADDR (0x00417010)

#define swrSprite_GetTextureDimFromId_ADDR (0x00417120)

#define swrSprite_FreeSpritesMaterials_ADDR (0x00417090)

#define swrSprite_FreeSprites_ADDR (0x00417090)

#define swrSprite_GetBBoxFromId_ADDR (0x00417150)

#define swrSprite_IsInsideBBox_ADDR (0x004172c0)

#define swrSprite_MoveBBoxTo_ADDR (0x00417900)

#define swrSprite_BBoxFit_ADDR (0x00417f00)

#define swrSprite_MoveBBox_ADDR (0x0041a9a0)

#define swrSprite_TranslateBBox_ADDR (0x0041aa10)

#define swrSprite_Draw2_ADDR (0x00428030)
#define swrSprite_DrawSomeSprites_ADDR (0x00428270)
#define swrSprite_NewSprite_ADDR (0x004282f0)
#define swrSprite_ResetAllSprites_ADDR (0x00428370)
#define swrSprite_DrawSprites_ADDR (0x004283B0)
#define swrSprite_SetVisible_ADDR (0x004285d0)
#define swrSprite_SetPos_ADDR (0x00428660)

#define swrSprite_SetDim_ADDR (0x004286f0)

#define swrSprite_SetColor_ADDR (0x00428740)
#define swrSprite_SetFlag_ADDR (0x004287e0)
#define swrSprite_UnsetFlag_ADDR (0x00428800)

#define swrSprite_setCurrentTextPos_ADDR (0x0042D910)
#define swrSprite_getCurrentTextPos_ADDR (0x0042D930)
#define swrSprite_setCurrentSpriteColor_ADDR (0x0042D950)
#define rdProcEntry_Add2DQuad2_ADDR (0x0042D990)

#define rdProcEntry_Add2DPolygon_ADDR (0x004321B0)
#define rdProcEntry_Add2DQuad3_ADDR (0x004325B0)
#define rdProcEntry_Add2DQuad4_ADDR (0x004327E0)
#define rdProcEntry_Add2DQuad_ADDR (0x004329C0)

#define swrSprite_UpperPowerOfTwo_ADDR (0x00445c90)

#define swrModel_ConvertTextureDataToRdMaterial_ADDR (0x00445EE0)

#define swrModel_DoConvertTextureDataToRdMaterial_ADDR (0x00446C20)
#define swrSprite_LoadTexture_ADDR (0x00446ca0)
#define swrSprite_LoadTexture__ADDR (0x00446fb0)

#define swrSprite_SetViewport_ADDR (0x0044EF70)
#define rdProcEntry_Add2DQuad5_ADDR (0x0044EFA0)
#define swrSprite_Draw_ADDR (0x0044F160)
#define swrSprite_ResetCurrentMaterial_ADDR (0x0044F5F0)
#define swrSprite_InitDrawing_ADDR (0x0044F600)

#define swrSprite_Draw1_ADDR (0x0044F670)

void swrSprite_SetCursorVisibility2(int visibility);

bool swrSprite_IsCursorVisible(void);

void swrSprite_SetCursorVisibility(int visible);

void swrSprite_DisplayCursor(void);

swrSpriteTexture* swrSprite_GetTextureFromTGA(char* filename_tga, int id);

void swrSprite_LoadAllSprites(void);

void swrSprite_UnloadAllSprites(void);

int swrSprite_LoadFromId(swrSprite_NAME id, char* tga_file_optional);

void swrSprite_ClearSprites(swrUI_unk* swrui_unk);

void swrSprite_AssignTextureToId(swrSpriteTexture* spriteTex, int id, int from_tga);

swrSpriteTexture* swrSprite_GetTextureFromId(int id);

void swrSprite_GetTextureDimFromId(swrSprite_NAME spriteId, int* out_width, int* out_height);

void swrSprite_FreeSpritesMaterials(void);

void swrSprite_FreeSprites(void);

void swrSprite_GetBBoxFromId(swrSprite_NAME spriteId, swrSprite_BBox* box);

int swrSprite_IsInsideBBox(swrSprite_BBox* bbox, int x, int y);

void swrSprite_MoveBBoxTo(swrSprite_BBox* box, int newX, int newY);

void swrSprite_BBoxFit(swrSprite_BBox* bboxSmaller, swrSprite_BBox* bboxLarger);

void swrSprite_MoveBBox(swrSprite_BBox* bbox_dest, swrSprite_BBox* bbox_src, int bMoveX, int bMoveY);

void swrSprite_TranslateBBox(swrSprite_BBox* bbox, int x, int y);

void swrSprite_Draw2(swrSprite* a1, int a2, float a3, float a4);
int swrSprite_DrawSomeSprites(int);
void swrSprite_NewSprite(short id, swrSpriteTexture* tex);
void swrSprite_ResetAllSprites(void);
void swrSprite_DrawSprites(int);
void swrSprite_SetVisible(short id, int visible);
void swrSprite_SetPos(short id, short x, short y);

void swrSprite_SetDim(short id, float width, float height);

void swrSprite_SetColor(short id, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrSprite_SetFlag(short id, unsigned int flag);
void swrSprite_UnsetFlag(short id, unsigned int flag);

int16_t swrSprite_setCurrentTextPos(int16_t, int16_t);
short swrSprite_getCurrentTextPos(int16_t*, int16_t*);
uint8_t swrSprite_setCurrentSpriteColor(uint8_t, uint8_t, uint8_t, uint8_t);
void rdProcEntry_Add2DQuad2(short, short, short, short, short, short, short, short);

void rdProcEntry_Add2DPolygon(short, short, float, float, float, float, int, int, int);
void rdProcEntry_Add2DQuad3(short x0, short y0, short x1, short y1, float tex_width, float tex_height, BOOL textured, BOOL add_z_offset);
void rdProcEntry_Add2DQuad4(short, short, short, short, short, short, short, short);
void rdProcEntry_Add2DQuad(short x0, short y0, short x1, short y1, float tex_u0, float tex_v0, float tex_u1, float tex_v1);

int swrSprite_UpperPowerOfTwo(int x);

void swrModel_ConvertTextureDataToRdMaterial(int texture_type_a, int texture_type_b, int orig_width, int orig_height, int width, int height, swrMaterial** texture_data_ptr, uint8_t** palette_ptr, char a9, char a10);
void swrModel_DoConvertTextureDataToRdMaterial(swrMaterial** texture_data_ptr, uint8_t** palette_data_ptr);

swrSpriteTexture* swrSprite_LoadTexture(int index);
swrSpriteTexture* swrSprite_LoadTexture_(swrSprite_NAME index);

void swrSprite_SetViewport(int, int, int, int);
void rdProcEntry_Add2DQuad5(int, int, int, int, int, int, int, int, int, float, float);
void swrSprite_Draw(int* arg0, swrSpriteTexture*, RdMaterial**, float, float, float, float, int, int, int, int, int, int, int, short, float, float, int);
void swrSprite_ResetCurrentMaterial();
void swrSprite_InitDrawing();

void swrSprite_Draw1(swrSpriteTexture*, short, int, float, float, float angle, short, short, int, float, unsigned __int8, float, unsigned __int8);

#endif // SWRSPRITE_H
