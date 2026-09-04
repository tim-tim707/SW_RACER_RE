#include "custom_tracks.h"

#include <algorithm>
#include <filesystem>
#include <vector>
#include <optional>

#include "globals.h"
#include "types.h"
#include "n64_shader.h"
#include "macros.h"
#include "crash_logger.h"
#include "imgui_internal.h"

extern "C" {
#include "./game_deltas/tracks_delta.h"
}

// Two cyclic includes with the following headers:
// Need swrModel_InitializeTextureBuffer_delta
#include "./game_deltas/swrModel_delta.h"
// need isTrackModel
#include "./replacements.h"

extern FILE *hook_log;

// Generate a cyclic include with swrModel_delta.cpp, that uses prepare_loading and finalize_loading, that require swrModel_InitializeTextureBuffer_delta
// swrModel_delta shouldn't depend on prepare_loading and finalize_loading
static std::vector<CustomTrack> custom_tracks;

int currentCustomID = -1;
std::optional<CustomTrack> currentCustomTrack = std::nullopt;

// Slurp a whole block file. Returns an empty buffer if it cannot be read at all -- a missing or
// unreadable data/lev01 block used to fault here (fseek on a null FILE*) before hook_log even
// existed, which is the worst possible place for a mod to die silently.
static std::vector<char> read_block_file(const std::filesystem::path &file) {
    FILE *f = fopen(file.generic_string().c_str(), "rb");
    if (!f) {
        fprintf(hook_log, "[custom_tracks] cannot open block file %s\n",
                file.generic_string().c_str());
        fflush(hook_log);
        return {};
    }

    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> data(size > 0 ? size : 0);
    if (!data.empty())
        fread(data.data(), 1, data.size(), f);
    fclose(f);
    return data;
}

std::vector<TrackSplineInfo> compute_spline_hashes(const std::filesystem::path &file) {
    const std::vector<char> data = read_block_file(file);
    if (data.size() < sizeof(uint32_t))
        return {};

    const uint32_t num_entries = __builtin_bswap32(*(const uint32_t *) &data[0]);
    std::vector<TrackSplineInfo> hashes(num_entries);
    for (int i = 0; i < num_entries; i++) {
        const uint32_t entry_begin = __builtin_bswap32(*(const uint32_t *) &data[4 * (i + 1)]);
        const uint32_t entry_end = __builtin_bswap32(*(const uint32_t *) &data[4 * (i + 2)]);
        hashes[i] = {
            .spline_id = i,
            .hash = ImHashData(&data[entry_begin], entry_end - entry_begin),
            .num_control_points = 0,
            .bUsable = false,
        };

        // A spline entry is a swrSpline header (big-endian on disk) immediately followed by its
        // control points, so its size is fully determined by the control point count -- an
        // invariant that holds exactly for all 91 stock entries. Record whether it holds, so a
        // track is never paired with an entry that would hand swrSpline_Interpolate a garbage
        // control_points array.
        if (entry_end <= entry_begin || entry_end > data.size() ||
            entry_end - entry_begin < sizeof(swrSpline))
            continue;

        const uint32_t num_control_points = __builtin_bswap32(
            *(const uint32_t *) &data[entry_begin + offsetof(swrSpline, num_control_points)]);
        hashes[i].num_control_points = num_control_points;
        hashes[i].bUsable =
            num_control_points > 0 &&
            entry_end - entry_begin ==
                sizeof(swrSpline) + num_control_points * sizeof(swrSplineControlPoint);
    }

    return hashes;
}

std::vector<TrackModelInfo> compute_track_model_infos(const std::filesystem::path &file) {
    const std::vector<char> data = read_block_file(file);
    if (data.size() < sizeof(uint32_t))
        return {};

    const uint32_t num_entries = __builtin_bswap32(*(const uint32_t *) &data[0]);

    std::vector<TrackModelInfo> track_infos;
    for (int i = 0; i < num_entries; i++) {
        const uint32_t entry_begin = __builtin_bswap32(*(const uint32_t *) &data[4 * (2 * i + 2)]);
        const uint32_t entry_end = __builtin_bswap32(*(const uint32_t *) &data[4 * (2 * i + 3)]);
        if (std::string_view(&data[entry_begin], 4) == "Trak") {
            track_infos.emplace_back() = {
                .model_id = i,
                .hash = ImHashData(&data[entry_begin], entry_end - entry_begin),
            };
        }
    }

    return track_infos;
}

// The on-disk spline entry layout the size check in compute_spline_hashes relies on.
static_assert(sizeof(swrSpline) == 0x10);
static_assert(sizeof(swrSplineControlPoint) == 0x54);

// Reference hashes of the stock blocks: whatever in a custom folder does NOT match these is taken
// to be the custom track. Built on first use rather than at static-init time so a failure to read
// them lands in hook.log instead of before it is open.
static const std::vector<TrackModelInfo> &default_track_model_infos() {
    static const std::vector<TrackModelInfo> infos =
        compute_track_model_infos("./data/lev01/out_modelblock.bin");
    return infos;
}
static const std::vector<TrackSplineInfo> &default_spline_hashes() {
    static const std::vector<TrackSplineInfo> hashes =
        compute_spline_hashes("./data/lev01/out_splineblock.bin");
    return hashes;
}

// this function tries to find the changed modelid/splineid in the block files by computing their
// hashes.
bool try_load_custom_track_folder(const std::filesystem::path &folder) {
    if (!is_directory(folder) || (!is_regular_file(folder / "out_modelblock.bin") &&
                                  !is_regular_file(folder / "out_splineblock.bin")))
        return false;

    int trackCounterInThisFolder = 0;

    // A track model is only usable with a spline the game can actually evaluate: swrSpline_Interpolate
    // walks swrSpline::control_points unconditionally, so a malformed entry faults on the first frame
    // of the race instead of failing the load. Reject the pairing here and say why.
    auto spline_is_usable = [&](const TrackSplineInfo &spline_info, int model_id) {
        if (spline_info.bUsable)
            return true;

        fprintf(hook_log,
                "[try_load_custom_track_folder] skipping track model %d in %s: spline %d is "
                "malformed (%u control points, entry size does not match) -- racing it would "
                "crash.\n",
                model_id, folder.filename().generic_string().c_str(), spline_info.spline_id,
                spline_info.num_control_points);
        fflush(hook_log);
        return false;
    };

    auto add_track = [&](CustomTrack info) {
        if (trackCount >= MAX_NB_TRACKS) {
            fprintf(hook_log,
                    "[try_load_custom_track_folder] dropping track from %s: the %d track slots are "
                    "full.\n",
                    folder.filename().generic_string().c_str(), MAX_NB_TRACKS);
            fflush(hook_log);
            return;
        }

        const int trackIndex = trackCount++;
        const int customID = custom_tracks.size();
        custom_tracks.emplace_back(std::move(info));

        g_aNewTrackInfos[trackIndex] = (TrackInfo) {
            .trackID = (INGAME_MODELID) (CUSTOM_TRACK_MODELID_BEGIN + customID),
            .splineID = (SPLINEID) (CUSTOM_SPLINE_MODELID_BEGIN + customID),
            .planetTrackNumber = 0,
            .PlanetIdx = 1,
            .FavoritePilot = 2,
            .unused = 0,
        };
        trackCounterInThisFolder++;

        if (trackCounterInThisFolder >= 2) {
            if (trackCounterInThisFolder == 2) {
                // fix track counter for the first track since we have multiple tracks in a single modelBlock.
                snprintf(g_aCustomTrackNames[customID - 1],
                         sizeof(g_aCustomTrackNames[customID - 1]), "%s %d",
                         folder.filename().generic_string().c_str(), trackCounterInThisFolder - 1);
            }
            snprintf(g_aCustomTrackNames[customID], sizeof(g_aCustomTrackNames[customID]), "%s %d",
                     folder.filename().generic_string().c_str(), trackCounterInThisFolder);
        } else {
            snprintf(g_aCustomTrackNames[customID], sizeof(g_aCustomTrackNames[customID]), "%s",
                     folder.filename().generic_string().c_str());
        }
    };

    fprintf(hook_log, "[try_load_custom_track_folder] checking folder %s\n",
            folder.generic_string().c_str());
    fflush(hook_log);

    std::vector<TrackModelInfo> model_infos;
    if (exists(folder / "out_modelblock.bin")) {
        model_infos = compute_track_model_infos(folder / "out_modelblock.bin");
        std::erase_if(model_infos, [](const TrackModelInfo &info) {
            const bool is_default_track =
                std::find_if(default_track_model_infos().begin(), default_track_model_infos().end(),
                             [&](const TrackModelInfo &default_info) {
                                 return info.hash == default_info.hash;
                             }) != default_track_model_infos().end();
            return is_default_track;
        });
    }
    if (model_infos.empty()) {
        fprintf(hook_log,
                "[try_load_custom_track_folder] skipping custom track folder %s: "
                "out_modelblock.bin does not contain any modified tracks.\n",
                folder.filename().generic_string().c_str());
        fflush(hook_log);
        return false;
    }

    std::vector<TrackSplineInfo> spline_hashes;
    if (exists(folder / "out_splineblock.bin")) {
        spline_hashes = compute_spline_hashes(folder / "out_splineblock.bin");
        std::erase_if(spline_hashes, [](const TrackSplineInfo &info) {
            const bool is_default_track =
                std::find_if(default_spline_hashes().begin(), default_spline_hashes().end(),
                             [&](const TrackSplineInfo &default_info) {
                                 return info.hash == default_info.hash;
                             }) != default_spline_hashes().end();
            return is_default_track;
        });
    }
    if (spline_hashes.empty()) {
        fprintf(hook_log,
                "[try_load_custom_track_folder] skipping custom track folder %s: "
                "out_splineblock.bin does not contain any modified splines.\n",
                folder.filename().generic_string().c_str());
        fflush(hook_log);
        return false;
    }

    // default case: there is one custom track model and spline in the file.
    if (model_infos.size() == 1 && spline_hashes.size() == 1) {
        fprintf(hook_log, "[try_load_custom_track_folder] found track %d with spline %d.\n",
                model_infos.front().model_id, spline_hashes.front().spline_id);
        fflush(hook_log);

        if (!spline_is_usable(spline_hashes.front(), model_infos.front().model_id))
            return false;

        add_track(CustomTrack{
            .folder = folder,
            .model_id = model_infos.front().model_id,
            .spline_id = spline_hashes.front().spline_id,
        });
    } else {
        fprintf(hook_log,
                "[try_load_custom_track_folder] %d custom models / %d custom splines in %s:\n    "
                "searching for a fitting spline for each model.\n",
                (int) model_infos.size(), (int) spline_hashes.size(),
                folder.filename().generic_string().c_str());
        fflush(hook_log);

        // search for a spline for each custom model.
        for (const TrackModelInfo &model_info: model_infos) {
            for (int k = 0; k < std::size(g_aTrackInfos); k++) {
                const TrackInfo &track_info = g_aTrackInfos[k];
                if (track_info.trackID == model_info.model_id) {
                    // search for spline
                    auto it = std::find_if(spline_hashes.begin(), spline_hashes.end(),
                                           [&](const TrackSplineInfo &info) {
                                               return info.spline_id == track_info.splineID;
                                           });
                    if (it == spline_hashes.end()) {
                        fprintf(hook_log,
                                "[try_load_custom_track_folder] did not find a fitting spline for "
                                "track model %d (expected spline %d).\n",
                                model_info.model_id, track_info.splineID);
                        fflush(hook_log);
                    } else if (spline_is_usable(*it, model_info.model_id)) {
                        fprintf(hook_log,
                                "[try_load_custom_track_folder] found fitting spline %d for model "
                                "%d.\n",
                                it->spline_id, model_info.model_id);
                        fflush(hook_log);
                        add_track({
                            .folder = folder,
                            .model_id = model_info.model_id,
                            .spline_id = it->spline_id,
                        });
                    }
                }
            }
        }
    }
    return true;
}

int patch_occurrence(uint32_t value, uint32_t replacement) {
    int num_occurrences = 0;
    // search for all occurrences of pointers to the track infos array and replace them.
    std::string_view code_section((const char *) 0x401000, (const char *) 0x04AB800);

    DWORD old_protect = 0;
    VirtualProtect((void *) code_section.data(), code_section.size(), PAGE_EXECUTE_READWRITE,
                   &old_protect);

    std::size_t offset = 0;
    while (true) {
        const std::size_t pos =
            code_section.find(std::string_view((const char *) &value, sizeof(value)), offset);
        if (pos == std::string::npos)
            break;

        memcpy((char *) code_section.data() + pos, &replacement, sizeof(replacement));
        num_occurrences++;
        offset = pos + 1;
    }

    VirtualProtect((void *) code_section.data(), code_section.size(), old_protect, &old_protect);

    return num_occurrences;
}

void patch_trackInfos_Usages() {
    int num_occurrences = 0;
    num_occurrences += patch_occurrence((uintptr_t) &g_aTrackInfos[0].trackID,
                                        (uintptr_t) &g_aNewTrackInfos[0].trackID);
    num_occurrences += patch_occurrence((uintptr_t) &g_aTrackInfos[0].splineID,
                                        (uintptr_t) &g_aNewTrackInfos[0].splineID);
    num_occurrences += patch_occurrence((uintptr_t) &g_aTrackInfos[0].planetTrackNumber,
                                        (uintptr_t) &g_aNewTrackInfos[0].planetTrackNumber);
    num_occurrences += patch_occurrence((uintptr_t) &g_aTrackInfos[0].PlanetIdx,
                                        (uintptr_t) &g_aNewTrackInfos[0].PlanetIdx);
    num_occurrences += patch_occurrence((uintptr_t) &g_aTrackInfos[0].FavoritePilot,
                                        (uintptr_t) &g_aNewTrackInfos[0].FavoritePilot);
    fprintf(hook_log, "[init_customTracks]: patched %d occurrences of g_aTrackInfos.\n",
            num_occurrences);
    fflush(hook_log);
}

void init_customTracks() {
    fprintf(hook_log, "[init_customTracks]\n");
    fflush(hook_log);

    patch_trackInfos_Usages();

    // Copy stock Infos
    for (uint8_t i = 0; i < 25; i++)
        g_aNewTrackInfos[i] = g_aTrackInfos[i];

    // Detection is a hash diff against the stock blocks, so a modified data/lev01 silently
    // mis-pairs every custom track. Stamp the reference counts -- a stock install reads
    // 25 track models / 91 splines.
    fprintf(hook_log,
            "[init_customTracks] reference blocks (data/lev01): %d track models, %d splines\n",
            (int) default_track_model_infos().size(), (int) default_spline_hashes().size());
    fflush(hook_log);

    const char *custom_tracks_path = "./assets/custom_tracks";
    if (std::filesystem::exists(custom_tracks_path) &&
        std::filesystem::is_directory(custom_tracks_path)) {
        for (auto const &entry: std::filesystem::recursive_directory_iterator(custom_tracks_path)) {
            try_load_custom_track_folder(entry.path());
        }
    } else {
        fprintf(hook_log, "[init_customTracks] No custom tracks directory found at '%s'\n",
                custom_tracks_path);
        fflush(hook_log);
    }

    for (int i = 0; i < (int) custom_tracks.size(); i++) {
        fprintf(hook_log, "[init_customTracks] track %d \"%s\": model %d, spline %d from %s\n",
                DEFAULT_NB_TRACKS + i, g_aCustomTrackNames[i], custom_tracks[i].model_id,
                custom_tracks[i].spline_id, custom_tracks[i].folder.generic_string().c_str());
    }

    fprintf(hook_log, "[init_customTracks] Done: %d custom tracks\n", (int) custom_tracks.size());
    fflush(hook_log);
}

void replace_block_filepaths(const std::filesystem::path &folder) {
    // use static variables as string storage
    static std::string modelblock_path, splineblock_path, textureblock_path;

    if (exists(folder / "out_modelblock.bin")) {
        modelblock_path = (folder / "out_modelblock.bin").generic_string();
        *(const char **) 0x4B9598 = modelblock_path.c_str();
    }

    if (exists(folder / "out_splineblock.bin")) {
        splineblock_path = (folder / "out_splineblock.bin").generic_string();
        *(const char **) 0x4B9590 = splineblock_path.c_str();
    }

    if (exists(folder / "out_textureblock.bin")) {
        textureblock_path = (folder / "out_textureblock.bin").generic_string();
        *(const char **) 0x4B9594 = textureblock_path.c_str();
    }
}

void revert_block_filepaths() {
    *(const char **) 0x4B9598 = "data/lev01/out_modelblock.bin";
    *(const char **) 0x4B9590 = "data/lev01/out_splineblock.bin";
    *(const char **) 0x4B9594 = "data/lev01/out_textureblock.bin";
}

// fixup functions: the n64 material flags and display list in custom tracks built with blender-swe1r
// are not totally compatible with the renderer replacement. they are just set to values that the
// original game accepts.
// see: https://github.com/louriccia/blender-swe1r/blob/355c57d0d110de7fc8c9e37da923aa7c97984b61/swe1r/modelblock.py#L1109
void fixup_n64_material(swrModel_Material *material) {
    // TODO: fix alpha blending and some special modes...
    if (material->color_combine_mode_cycle1 == 0)
        material->color_combine_mode_cycle1 =
            CombineMode(G_CCMUX_TEXEL0, G_CCMUX_0, G_CCMUX_SHADE, G_CCMUX_0, false)
                .to_big_endian_u32();

    if (material->alpha_combine_mode_cycle1 == 0)
        material->alpha_combine_mode_cycle1 =
            CombineMode(G_ACMUX_TEXEL0, G_ACMUX_0, G_ACMUX_SHADE, G_ACMUX_0, true)
                .to_big_endian_u32();

    if (material->render_mode_1 == 0x00000000 || material->render_mode_2 == 0x00000000) {
        const bool enable_zwrite = material->render_mode_1 != 0x00000818;
        // TODO alpha blending
        RenderMode default_render_mode{
            .alpha_compare = AC_DITHER,
            .z_source_select = ZS_PIXEL,
            .z_compare = true,
            .z_update = enable_zwrite,
            .z_mode = ZMODE_OPA,
            .mode2_b_mux = ONE,
            .mode2_m_mux = CLR_IN,
            .mode2_a_mux = ZEROA,
            .mode2_p_mux = CLR_IN,
        };

        material->render_mode_1 =
            ((const uint32_t &) default_render_mode) & 0b1100'1100'1100'1100'1111'1111'1111'1111;
        material->render_mode_2 =
            ((const uint32_t &) default_render_mode) & 0b0011'0011'0011'0011'0000'0000'0000'0000;
    }
}

// the gSPVertex layout is wrong in the tracks from blender-swe1r. the max number of vertices is
// also too high (higher than 32), but this is fixed in renderer_hook.cpp.
void fixup_n64_display_list(swrModel_Mesh *mesh) {
    if (!mesh->vertex_display_list)
        return;

    Gfx *command = mesh->vertex_display_list;

    while (command->type != 0xdf) {
        switch (command->type) {
            case 0x1: {
                uint8_t n = (SWAP16(command->gSPVertex.n_packed) >> 4) & 0xFF;
                uint8_t v0 = command->gSPVertex.v0_plus_n - n;
                if (n == 0 && v0 != mesh->vertex_base_offset) {
                    n = v0;
                    v0 = mesh->vertex_base_offset;

                    command->gSPVertex.n_packed = SWAP16((n << 4));
                    command->gSPVertex.v0_plus_n = v0 + n;
                }
                break;
            }
            case 0x3:
                break;
            case 0x5:
                break;
            case 0x6:
                break;
            default:
                std::abort();
        }
        command++;
    }
}

void fixup_custom_model_node(swrModel_Node *node) {
    if (!node)
        return;

    if (node->type == NODE_MESH_GROUP) {
        for (int i = 0; i < node->num_children; i++) {
            swrModel_Mesh *mesh = node->children.meshes[i];
            if (!mesh)
                continue;

            fixup_n64_display_list(mesh);

            if (mesh->mesh_material && mesh->mesh_material->material)
                fixup_n64_material(mesh->mesh_material->material);
        }
    } else {
        for (int i = 0; i < node->num_children; i++)
            fixup_custom_model_node(node->children.nodes[i]);
    }
}

void fixup_custom_model(swrModel_Header *header) {
    // swrModel_LoadFromId returns NULL for a model it cannot load; walking the entry list from
    // there reads address 0x4 (entries[0] sits at offset 0, and the walk pre-increments). The
    // caller still has to revert the block file paths afterwards, so bail out here rather than at
    // the call site.
    if (!header)
        return;

    swrModel_HeaderEntry *curr = header->entries;
    curr++;

    while (curr->value != 0xFFFFFFFF) {
        if (curr->node)
            fixup_custom_model_node(curr->node);

        curr++;
    }
}

bool prepare_loading_custom_track_model(MODELID *model_id) {
    if (*model_id < CUSTOM_TRACK_MODELID_BEGIN) {
        if (isTrackModel(*model_id)) {
            currentCustomID = -1;
            currentCustomTrack = std::nullopt;
            crash_logger_stagef("loading stock track model %d", *model_id);
        }

        return false;
    }

    currentCustomID = *model_id - CUSTOM_TRACK_MODELID_BEGIN;
    currentCustomTrack = custom_tracks.at(currentCustomID);
    crash_logger_stagef("loading custom track \"%s\" (model %d) from %s",
                        g_aCustomTrackNames[currentCustomID], currentCustomTrack.value().model_id,
                        currentCustomTrack.value().folder.generic_string().c_str());
    replace_block_filepaths(currentCustomTrack.value().folder);
    *model_id = (MODELID) currentCustomTrack.value().model_id;

    // resize texture buffer if needed:
    swrModel_InitializeTextureBuffer_delta();

    return true;
}

void finalize_loading_custom_track_model(swrModel_Header *header) {
    fixup_custom_model(header);
    revert_block_filepaths();
}

bool prepare_loading_custom_track_spline(SPLINEID *spline_id) {
    if (*spline_id < CUSTOM_TRACK_MODELID_BEGIN)
        return false;

    const int customID = *spline_id - CUSTOM_TRACK_MODELID_BEGIN;
    const CustomTrack &track = custom_tracks.at(customID);
    crash_logger_stagef("loading custom track \"%s\" spline %d from %s",
                        g_aCustomTrackNames[customID], track.spline_id,
                        track.folder.generic_string().c_str());
    replace_block_filepaths(track.folder);
    *spline_id = (SPLINEID) track.spline_id;

    return true;
}

void finalize_loading_custom_track_spline(swrSpline *spline) {
    revert_block_filepaths();
}
