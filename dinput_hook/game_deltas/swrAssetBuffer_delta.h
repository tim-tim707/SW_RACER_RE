#pragma once

// Resizes the asset buffer swrScene_InitWorld allocates to what settings.ini asks for
// ([settings] asset_buffer_mb). Verified byte patch, and it must run before swrScene_Startup:
// the buffer is allocated once and kept for the process.
void swrAssetBuffer_PatchSize();
