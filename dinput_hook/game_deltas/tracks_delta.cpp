extern "C" {
#include "tracks_delta.h"
extern FILE *hook_log;
}
#include "globals.h"
#include "types.h"
#include "../n64_shader.h"
#include "macros.h"
#include "swrModel_delta.h"

#include <filesystem>
#include <vector>

static std::vector<std::filesystem::path> custom_track_folders;

bool try_load_custom_track_folder(const std::filesystem::path &folder) {
    if (!is_directory(folder) || (!is_regular_file(folder / "out_modelblock.bin") &&
                                  !is_regular_file(folder / "out_splineblock.bin")))
        return false;

    if (trackCount >= MAX_NB_TRACKS)
        return false;

    const int trackIndex = trackCount++;
    const int customID = trackIndex - DEFAULT_NB_TRACKS;
    g_aNewTrackInfos[trackIndex] = (TrackInfo){
        // .trackID = MODELID_planete1_track,
        // .splineID = SPLINEID_planete1_track,
        .trackID = (INGAME_MODELID) (CUSTOM_TRACK_MODELID_BEGIN + customID),
        .splineID = (SPLINEID) (CUSTOM_SPLINE_MODELID_BEGIN + customID),
        .planetTrackNumber = 0,
        .PlanetIdx = 1,
        .FavoritePilot = 2,
        .unused = 0,
    };

    snprintf(g_aCustomTrackNames[customID], sizeof(g_aCustomTrackNames[customID]), "%s",
             folder.filename().generic_string().c_str());

    custom_track_folders.emplace_back(folder);
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
        auto pos =
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

    for (const auto &entry: std::filesystem::recursive_directory_iterator("./custom_tracks"))
        try_load_custom_track_folder(entry.path());
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
    if (*model_id < CUSTOM_TRACK_MODELID_BEGIN)
        return false;

    const int customID = *model_id - CUSTOM_TRACK_MODELID_BEGIN;
    replace_block_filepaths(custom_track_folders.at(customID));
    *model_id = MODELID_tatooine_mini_track;

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
    replace_block_filepaths(custom_track_folders.at(customID));
    *spline_id = SPLINEID_tatooine_mini_track;

    return true;
}

void finalize_loading_custom_track_spline(swrSpline *spline) {
    revert_block_filepaths();
}
