#pragma once

#include <filesystem>
#include <map>

#include "types.h"

// Raw-chunk per-model replacement.
//
// Drop a file at ./assets/replacement_models/<model_id>.bin with this layout:
//   [0]  char     magic[4]   = "RAWM"
//   [4]  uint32_t mask_size   (little-endian)
//   [8]  uint32_t model_size  (little-endian)
//   [12] mask payload   (mask_size  bytes, big-endian, verbatim from out_modelblock.bin)
//   [..] model payload  (model_size bytes, big-endian, verbatim from out_modelblock.bin)
//
// The mask/model payloads are the exact byte ranges [mask_offset, model_offset) and
// [model_offset, next_model_offset) for that model in the stock modelblock. They are
// stored unchanged (big-endian); the game's loader byte-swaps them on load.
// See scripts/extract_raw_asset.py for a producer.

extern bool enable_model_replacement;

// (Re)scan ./assets/replacement_models/ into the replacement map.
void refresh_replacement_models();

// If a replacement exists for *model_id (a stock id < CUSTOM_TRACK_MODELID_BEGIN),
// assemble a single-entry modelblock in a temp file, point the modelblock path at it,
// and remap *model_id to 0. Returns true if a replacement was prepared.
bool try_prepare_loose_model(MODELID *model_id);

// Revert the modelblock path swap performed by try_prepare_loose_model.
void finalize_loose_model();
