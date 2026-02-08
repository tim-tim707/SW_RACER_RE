#pragma once

#include "types.h"

void swrModel_LoadFonts_delta(void);

swrModel_Header *swrModel_LoadFromId_delta(MODELID id);

void swrModel_InitializeTextureBuffer_delta();

void swrModel_LoadModelTexture_delta(TEXID texture_index, swrMaterial** material_ptr, uint8_t** palette_data_ptr);
