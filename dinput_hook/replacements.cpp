#include "replacements.h"
#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"
#include "imgui_utils.h"

#include <map>
#include <string>
#include <filesystem>

extern "C" FILE *hook_log;

extern std::vector<gltfModel> g_models;

extern bool imgui_initialized;
extern ImGuiState imgui_state;

extern "C" {
#include <Swr/swrModel.h>
}

// Stringified MODELID at correct index
const char *modelid_cstr[] = {
    "alt_anakin_pod",
    "tatooine_track",
    "anakin_pod",
    "alt_teemto_pod",
    "teemto_pod",
    "alt_sebulba_pod",
    "sebulba_pod",
    "alt_ratts_pod",
    "ratts_pod",
    "aldar_beedo_pod",
    "alt_aldar_beedo_pod",
    "alt_mawhonic_pod",
    "mawhonic_pod",
    "alt_bumpy_roose_pod",
    "bumpy_roose_pod",
    "alt_wan_sandage_pod",
    "mars_guo_pod",
    "wan_sandage_pod",
    "alt_mars_guo_pod",
    "alt_ebe_endicott_pod",
    "ebe_endicott_pod",
    "alt_dud_bolt_pod",
    "dud_bolt_pod",
    "alt_gasgano_pod",
    "gasgano_pod",
    "alt_clegg_holdfast_pod",
    "clegg_holdfast_pod",
    "alt_elan_mak_pod",
    "elan_mak_pod",
    "alt_neva_kee_pod",
    "neva_kee_pod",
    "alt_bozzie_barada_pod",
    "bozzie_barada_pod",
    "alt_boles_roor_pod",
    "boles_roor_pod",
    "alt_ody_mandrell_pod",
    "ody_mandrell_pod",
    "alt_fud_sang_pod",
    "fud_sang_pod",
    "alt_ben_quadinaros_pod",
    "ben_quadinaros_pod",
    "alt_slide_paramita_pod",
    "slide_paramita_pod",
    "alt_toy_dampner_pod",
    "toy_dampner_pod",
    "alt_bullseye_pod",
    "bullseye_pod",
    "f_sentry_part",
    "flag2_part",
    "sparky_part",
    "part_control01_part",
    "part_control02_part",
    "part_control03_part",
    "part_control04_part",
    "part_control05_part",
    "replsr_part1_part",
    "replsr_part2_part",
    "replsr_part3_part",
    "replsr_part4_part",
    "replsr_part5_part",
    "moneybox1_part",
    "replsr_part6_part",
    "thrust_part1_part",
    "thrust_part2_part",
    "thrust_part3_part",
    "thrust_part4_part",
    "thrust_part5_part",
    "thrust_part6_part",
    "moneybox2_part",
    "moneybox3_part",
    "hovcart_part",
    "white_arrow_part",
    "hud_knob_part",
    "hud_knob1_part",
    "hud_knob2_part",
    "hud_knob3_part",
    "pln_coruscant_part",
    "pln_coruscant_cld_part",
    "pln_hoth_part",
    "pln_tatooine_part",
    "pln_terra_part",
    "pln_moon_part",
    "pln_asteroid_part",
    "hangar18_part",
    "loc_watto_part",
    "loc_junkyard_part",
    "char_teemto_puppet",
    "char_anakin_puppet",
    "char_gasgano_puppet",
    "char_mawhonic_puppet",
    "char_ody_puppet",
    "char_sebulba_puppet",
    "char_mars_puppet",
    "char_ratts_puppet",
    "char_ben_puppet",
    "char_ebe_puppet",
    "char_bumpy_puppet",
    "char_clegg_puppet",
    "char_dud_puppet",
    "char_wan_puppet",
    "char_elan_puppet",
    "char_toy_puppet",
    "char_fud_puppet",
    "char_neva_puppet",
    "char_slide_puppet",
    "char_aldar_puppet",
    "char_bozzie_puppet",
    "char_boles_puppet",
    "char_bullseye_puppet",
    "char_pitdroid_puppet",
    "char_watto_puppet",
    "char_dewback_puppet",
    "char_ronto_puppet",
    "char_jabba_puppet",
    "lightset_vlec",
    "tatooine_mini_track",
    "pln_spice_part",
    "pln_andoprime_part",
    "pln_water_part",
    "pln_jungle_part",
    "coin_part",
    "pln_malastare_part",
    "map_h_part",
    "award_first_part",
    "award_platform_part",
    "award_second_part",
    "award_third_part",
    "loc_awards_part",
    "planeth_track",
    "planeti_track",
    "planeta1_track",
    "planeta2_track",
    "planeta3_track",
    "planetb1_track",
    "planetb2_track",
    "planetb3_track",
    "planetc1_track",
    "planetc2_track",
    "planetc3_track",
    "planetd1_track",
    "planetd2_track",
    "planetd3_track",
    "planete1_track",
    "planete2_track",
    "planete3_track",
    "planetf1_track",
    "beamanim_vlec",
    "fireball_1_part",
    "planetf2_track",
    "cutscene_hostjabba_scene",
    "cutscene22_scene",
    "lightring_vlec",
    "cutscene08_scene",
    "cutscene27_scene",
    "loc_cantina_part",
    "char_big_fish_puppet",
    "cutscene27b_scene",
    "part_airbrake1_part",
    "part_airbrake2_part",
    "part_airbrake3_part",
    "part_airbrake4_part",
    "part_airbrake5_part",
    "part_airbrake6_part",
    "part_cooling1_part",
    "part_cooling2_part",
    "part_cooling3_part",
    "part_cooling4_part",
    "part_cooling5_part",
    "part_cooling6_part",
    "part_thrust1_part",
    "part_thrust2_part",
    "part_thrust3_part",
    "part_thrust4_part",
    "part_thrust5_part",
    "part_thrust6_part",
    "holo_proj02_puppet",
    "icebreak_vlec",
    "map_a1_part",
    "map_a2_part",
    "map_a3_part",
    "map_b1_part",
    "map_b2_part",
    "map_j1_part",
    "map_j2_part",
    "map_j3_part",
    "map_b3_part",
    "map_c1_part",
    "map_c2_part",
    "map_c3_part",
    "map_e1_part",
    "map_e2_part",
    "map_i_part",
    "map_e3_part",
    "map_f1_part",
    "map_f2_part",
    "map_f3_part",
    "flag_tip_part",
    "flag_wave_vlec",
    "part_accel01_part",
    "part_accel02_part",
    "part_accel03_part",
    "part_accel04_part",
    "part_accel05_part",
    "part_accel06_part",
    "part_grip01_part",
    "part_grip02_part",
    "part_grip03_part",
    "far_aldar_beedo_part",
    "far_anakin_part",
    "far_ben_quadinaros_part",
    "far_boles_roor_part",
    "far_bozzie_barada_part",
    "far_bullseye_part",
    "far_bumpy_roose_part",
    "far_clegg_holdfast_part",
    "far_dud_bolt_part",
    "far_ebe_endicott_part",
    "far_elan_mak_part",
    "far_fud_sang_part",
    "far_gasgano_part",
    "far_ratts_part",
    "far_mars_guo_part",
    "far_mawhonic_part",
    "far_neva_kee_part",
    "far_ody_mandrell_part",
    "far_sebulba_part",
    "far_slide_paramita_part",
    "far_teemto_part",
    "far_toy_dampner_part",
    "far_wan_sandage_part",
    "part_grip04_part",
    "planetf3_track",
    "planetj1_track",
    "planetj2_track",
    "part_powercell01_part",
    "part_powercell02_part",
    "map_d1_part",
    "part_powercell03_part",
    "part_powercell04_part",
    "part_powercell05_part",
    "part_control06_part",
    "part_grip05_part",
    "part_grip06_part",
    "part_powercell06_part",
    "char_npc_bartender_puppet",
    "char_npc_c3po_puppet",
    "char_npc_jarjar_puppet",
    "char_npc_jawa_puppet",
    "char_npc_r2d2_puppet",
    "map_d2_part",
    "map_d3_part",
    "fx_rockbig_part",
    "fx_rocksmall_part",
    "pln_cloud_part",
    "fx_shards_part",
    "mid_sebulba_part",
    "mid_anakin_part",
    "mid_teemto_part",
    "mid_ratts_part",
    "mid_aldar_beedo_part",
    "mid_mawhonic_part",
    "mid_bumpy_roose_part",
    "mid_wan_sandage_part",
    "mid_mars_guo_part",
    "mid_ebe_endicott_part",
    "mid_dud_bolt_part",
    "mid_gasgano_part",
    "mid_clegg_holdfast_part",
    "mid_elan_mak_part",
    "mid_neva_kee_part",
    "mid_bozzie_barada_part",
    "mid_boles_roor_part",
    "mid_ody_mandrell_part",
    "mid_fud_sang_part",
    "mid_ben_quadinaros_part",
    "mid_slide_paramita_part",
    "mid_toy_dampner_part",
    "mid_bullseye_part",
    "startgate_part",
    "map_tat1_part",
    "map_tat2_part",
    "cutscene_hostb_scene",
    "cutscene_hostc_scene",
    "cutscene_hostd_scene",
    "cutscene_hoste_scene",
    "cutscene_hostf_scene",
    "cutscene_hostt_scene",
    "cutscene_intro01_scene",
    "cutscene_intro02_scene",
    "cutscene_intro06_scene",
    "cutscene_intro17_scene",
    "cutscene_intro19_scene",
    "cutscene_intro25_scene",
    "cutscene_intro30_scene",
    "lavaanim_vlec",
    "fx_rockash_part",
    "fx_treesmash_part",
    "beachanim_vlec",
    "alt_jinn_reeso_pod",
    "jinn_reeso_pod",
    "alt_cy_yunga_pod",
    "cy_yunga_pod",
    "mid_jinn_reeso_part",
    "mid_cy_yunga_part",
    "char_jinn_reeso_puppet",
    "char_cy_yunga_puppet",
    "fx_rockgiant_part",
    "fx_rockzero_part",
    "balloon01_part",
    "fx_methanefoof_part",
    "gate01_part",
    "fx_lavafoof_part",
    "dozer_part",
    "dustkick1_part",
    "dustkick1_vlec",
    "planetj3_track",
    "explo1_vlec",
    "fx_flameanim_part",
    "fx_podasx_part",
    "char_npc_quigon_puppet",
    "shadow_circle_part",
    "shadow_square_part",
    "xpans_pak_part",
};

struct ReplacementModel {
    bool fileExist;
    gltfModel model;
};

// MODELID, ReplacementModel
std::map<int, ReplacementModel> replacement_map{};

/*
    Load models from gltf files and store them in replacement_map MODELID slot
*/

static void addImguiReplacementString(int modelId, std::string s) {
    if (imgui_initialized && imgui_state.show_replacementTries) {
        if (imgui_state.replacedTries[modelId] == 0) {
            imgui_state.replacementTries += s;
            imgui_state.replacedTries[modelId] += 1;
        }
    }
}

bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos) {
    // Env textures
    static bool environment_setuped = false;

    // Try to load file or mark as not existing
    if (!replacement_map.contains(model_id)) {
        tinygltf::Model model;

        std::string filename = std::string(modelid_cstr[model_id]) + std::string(".gltf");
        std::string path = "./assets/gltf/" + filename;

        bool fileExist = true;
        if (std::filesystem::exists(path)) {
            tinygltf::TinyGLTF loader;
            std::string err;
            std::string warn;

            if (!loader.LoadASCIIFromFile(&model, &err, &warn, path)) {
                fprintf(hook_log, "Failed to parse %s glTF\n", filename.c_str());
            }

            if (!warn.empty()) {
                fprintf(hook_log, "Warn: %s\n", warn.c_str());
            }

            if (!err.empty()) {
                fprintf(hook_log, "Err: %s\n", err.c_str());
            }

            fprintf(hook_log, "[Replacements] Loaded %s\n", filename.c_str());
            fflush(hook_log);
        } else {
            fileExist = false;
            // fprintf(hook_log, "Failed to find replacement for %s\n", filename.c_str());
            // fflush(hook_log);
        }

        ReplacementModel replacement{
            .fileExist = fileExist,
            .model = {.filename = filename,
                      .setuped = false,
                      .gltf = model,
                      .material_infos = {},
                      .mesh_infos = {}},
        };
        replacement_map[model_id] = replacement;
    }

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);

        renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, replacement.model, envInfos);

        addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
                                                std::string(" Replaced \n"));
        // glPopDebugGroup();

        return true;
    }

    if ((model_id >= MODELID_part_control01_part && model_id <= MODELID_part_control05_part) ||
        (model_id >= MODELID_part_airbrake1_part && model_id <= MODELID_part_thrust6_part) ||
        (model_id >= MODELID_part_accel01_part && model_id <= MODELID_part_grip03_part) ||
        (model_id >= MODELID_part_powercell01_part && model_id <= MODELID_part_powercell06_part)) {
        // renderer_drawTetrahedron(proj_matrix, view_matrix, model_matrix);
        renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[1], envInfos);
        addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
                                                std::string(" Hardcoded\n"));
        return true;
    }

    if (model_id == MODELID_part_grip04_part) {
        // renderer_drawCube(proj_matrix, view_matrix, model_matrix);
        renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[0], envInfos);
        addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
                                                std::string(" Hardcoded\n"));
        return true;
    }

    addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) + std::string("\n"));

    return false;
}
