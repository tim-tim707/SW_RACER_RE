#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

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

// The game's model block and the stock copy kept when replacements are written into it.
#define MODELBLOCK_PATH "./data/lev01/out_modelblock.bin"
#define MODELBLOCK_ORIGINAL_PATH "./data/lev01/out_modelblock.original.bin"

// Write every replacement model (the <id>.bin files the loader would use) into the game's model
// block as that model's entry, so the game itself loads them (no loose-model swap needed, and the
// file can be shared). Always built from the stock block: the first call keeps it as
// out_modelblock.original.bin. `msg` says what happened. Returns false on failure (block unchanged).
bool write_replacements_into_modelblock(std::string &msg);

// Put the stock block back (from out_modelblock.original.bin) and drop the backup.
bool restore_original_modelblock(std::string &msg);

// The replacement models found (model id -> file), rescanned when their folders change.
const std::map<int, std::filesystem::path> &current_replacement_models();

// Stock model `id` as the pod editor's Build reads it: the kept stock block
// (out_modelblock.original.bin) if there is one, else the game's block. False if unreadable.
bool read_base_model(int id, std::vector<uint8_t> &mask, std::vector<uint8_t> &data);

// A short fingerprint of a model's mask + data ("<mask bytes>.<data bytes>-<FNV-1a>", hex). Build
// stamps each model it bakes with its base model's, in <id>.base next to <id>.bin; the pod editor's
// JavaScript (bake.js, fingerprint) computes the same.
std::string model_fingerprint(const std::vector<uint8_t> &mask, const std::vector<uint8_t> &data);

// Replacement models left out because their <id>.base stamp doesn't match this game's base model
// for that id (built on other game data, e.g. sent over by another player): id -> why.
const std::map<int, std::string> &skipped_replacement_models();
