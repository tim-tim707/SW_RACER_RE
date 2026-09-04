#pragma once

// Raises the asset buffer swrScene_InitWorld allocates above the retail 8 MiB, to the size
// settings.ini asks for ([settings] asset_buffer_mb, default SWR_ASSET_BUFFER_MB_DEFAULT).
// Applied as a verified in-place byte patch at startup, before swrScene_Startup runs -- the
// buffer is malloc'd once and kept for the process, so the two immediates have to be right before
// the allocation happens. See swrAssetBuffer_delta.cpp.
void swrAssetBuffer_PatchSize();
