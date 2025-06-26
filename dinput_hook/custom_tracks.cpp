#include "custom_tracks.h"

#include <algorithm>
#include <filesystem>
#include <vector>
#include <optional>

#include "globals.h"
#include "types.h"
#include "n64_shader.h"
#include "macros.h"
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

std::vector<TrackSplineInfo> compute_spline_hashes(const std::filesystem::path &file) {
    FILE *f = fopen(file.generic_string().c_str(), "rb");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> data(size);
    fread(data.data(), 1, data.size(), f);
    fclose(f);

    const uint32_t num_entries = __builtin_bswap32(*(const uint32_t *) &data[0]);
    std::vector<TrackSplineInfo> hashes(num_entries);
    for (int i = 0; i < num_entries; i++) {
        const uint32_t entry_begin = __builtin_bswap32(*(const uint32_t *) &data[4 * (i + 1)]);
        const uint32_t entry_end = __builtin_bswap32(*(const uint32_t *) &data[4 * (i + 2)]);
        hashes[i] = {
            .spline_id = i,
            .hash = ImHashData(&data[entry_begin], entry_end - entry_begin),
        };
    }

    return hashes;
}

std::vector<TrackModelInfo> compute_track_model_infos(const std::filesystem::path &file) {
    FILE *f = fopen(file.generic_string().c_str(), "rb");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> data(size);
    fread(data.data(), 1, data.size(), f);
    fclose(f);

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

const static std::vector<TrackModelInfo> default_track_model_infos =
    compute_track_model_infos("./data/lev01/out_modelblock.bin");
const static std::vector<TrackSplineInfo> default_spline_hashes =
    compute_spline_hashes("./data/lev01/out_splineblock.bin");

// this function tries to find the changed modelid/splineid in the block files by computing their
// hashes.
bool try_load_custom_track_folder(const std::filesystem::path &folder) {
    if (!is_directory(folder) || (!is_regular_file(folder / "out_modelblock.bin") &&
                                  !is_regular_file(folder / "out_splineblock.bin")))
        return false;

    int trackCounterInThisFolder = 0;

    auto add_track = [&](CustomTrack info) {
        if (trackCount >= MAX_NB_TRACKS)
            return;

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
                std::find_if(default_track_model_infos.begin(), default_track_model_infos.end(),
                             [&](const TrackModelInfo &default_info) {
                                 return info.hash == default_info.hash;
                             }) != default_track_model_infos.end();
            return is_default_track;
        });
        /*for (int i = 0; i < infos.size(); i++) {
            fprintf(hook_log, "model %d\n", infos[i].model_id);
            fflush(hook_log);
        }*/
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
                std::find_if(default_spline_hashes.begin(), default_spline_hashes.end(),
                             [&](const TrackSplineInfo &default_info) {
                                 return info.hash == default_info.hash;
                             }) != default_spline_hashes.end();
            return is_default_track;
        });

        /*for (int i = 0; i < spline_hashes.size(); i++) {
            fprintf(hook_log, "spline %d\n", spline_hashes[i].spline_id);
            fflush(hook_log);
        }*/
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
        // fprintf(hook_log, "[try_load_custom_track_folder] found track %d with spline %d.\n",
        //         model_infos.front().model_id, spline_hashes.front().spline_id);
        // fflush(hook_log);

        add_track(CustomTrack{
            .folder = folder,
            .model_id = model_infos.front().model_id,
            .spline_id = spline_hashes.front().spline_id,
        });
    } else {
        // fprintf(hook_log,
        //         "[try_load_custom_track_folder] more than one custom model/spline in %s:\n    "
        //         "searching for fitting spline for each model.\n",
        //         folder.filename().generic_string().c_str());

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
                        // fprintf(hook_log,
                        //         "[try_load_custom_track_folder] did not find a fitting spline for "
                        //         "track model %d (expected spline %d).\n",
                        //         model_info.model_id, track_info.splineID);
                    } else {
                        // fprintf(hook_log,
                        //         "[try_load_custom_track_folder] found fitting spline %d for model "
                        //         "%d.\n",
                        //         it->spline_id, model_info.model_id);
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

    fprintf(hook_log, "[init_customTracks] Done\n");
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
        }

        return false;
    }

    currentCustomID = *model_id - CUSTOM_TRACK_MODELID_BEGIN;
    currentCustomTrack = custom_tracks.at(currentCustomID);
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
    replace_block_filepaths(track.folder);
    *spline_id = (SPLINEID) track.spline_id;

    return true;
}

void finalize_loading_custom_track_spline(swrSpline *spline) {
    revert_block_filepaths();
}
