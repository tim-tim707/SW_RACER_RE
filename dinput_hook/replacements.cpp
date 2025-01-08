#include "replacements.h"

#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include <globals.h>

#include <map>
#include <string>
#include <filesystem>
#include <format>

extern "C" FILE *hook_log;

extern std::vector<gltfModel> g_models;

extern bool imgui_initialized;
extern ImGuiState imgui_state;

extern "C" {
#include <Swr/swrModel.h>
#include <Primitives/rdMatrix.h>
}

enum replacementFlag {
    None = 0,
    Normal = 1 << 1,
    Mirrored = 1 << 2,
};

uint8_t replacedTries[323] = {0};// 323 MODELIDs

// Stringified MODELID at correct index
const char *modelid_cstr[] = {
    "AnakinSkywalker_alt",
    "TheBoontaClassic_track",
    "AnakinSkywalker_pod",
    "TeemtoPagalies_alt",
    "TeemtoPagalies_pod",
    "Sebulba_alt",
    "Sebulba_pod",
    "RattsTyerell_alt",
    "RattsTyerell_pod",
    "AldarBeedo_pod",
    "AldarBeedo_alt",
    "Mawhonic_alt",
    "Mawhonic_pod",
    "Ark_Bumpy_Roose_pod",
    "Ark_Bumpy_Roose_alt",
    "WanSandage_pod",
    "MarsGuo_pod",
    "WanSandage_pod",
    "MarsGuo_alt",
    "EbeEndocott_alt",
    "EbeEndocott_pod",
    "DudBolt_alt",
    "DudBolt_pod",
    "Gasgano_alt",
    "Gasgano_pod",
    "CleggHoldfast_alt",
    "CleggHoldfast_pod",
    "ElanMak_alt",
    "ElanMak_pod",
    "NevaKee_alt",
    "NevaKee_pod",
    "BozzieBaranta_alt",
    "BozzieBaranta_pod",
    "BolesRoor_alt",
    "BolesRoor_pod",
    "OdyMandrell_alt",
    "OdyMandrell_pod",
    "FudSang_alt",
    "FudSang_pod",
    "BenQuadinaros_alt",
    "BenQuadinaros_pod",
    "SlideParamita_alt",
    "SlideParamita_pod",
    "ToyDampner_alt",
    "ToyDampner_pod",
    "BullseyeNavior_alt",
    "BullseyeNavior_pod",
    "Sentry_part",
    "VehicleSelectFlag_part",
    "Spark_part",
    "ControlLinkage_part",
    "ControlShiftPlate_part",
    "ControlVectro-Jet_part",
    "ControlCoupling_part",
    "ControlNozzle_part",
    "UnusedRepulsorUpgrade1_part",
    "UnusedRepulsorUpgrade2_part",
    "UnusedRepulsorUpgrade3_part",
    "UnusedRepulsorUpgrade4_part",
    "UnusedRepulsorUpgrade5_part",
    "Coffer_part",
    "UnusedRepulsorUpgrade6_part",
    "UnusedThrustUpgrade1_part",
    "UnusedThrustUpgrade2_part",
    "UnusedThrustUpgrade3_part",
    "UnusedThrustUpgrade4_part",
    "UnusedThrustUpgrade5_part",
    "UnusedThrustUpgrade6_part",
    "DoubleCoffer_part",
    "QuadCoffer_part",
    "Hovercart_part",
    "GuideArrow_part",
    "plane_part",
    "plane_part",
    "plane_part",
    "plane_part",
    "PlanetA_part",
    "PlanetB_part",
    "PlanetC_part",
    "Tatooine_part",
    "Baroonda_part",
    "Moon_part",
    "OvooIV_part",
    "Hangar_part",
    "Watto_sShop_part",
    "Watto_sJunkyard_part",
    "TeemtoPagalies_puppet",
    "AnakinSkywalker_puppet",
    "Gasgano_puppet",
    "Mawhonic_puppet",
    "OdyMandrell_puppet",
    "Sebulba_puppet",
    "MarsGuo_puppet",
    "RattsTyerell_puppet",
    "BenQuadinaros_puppet",
    "EbeEndocott_puppet",
    "Ark_Bumpy_Roose_puppet",
    "CleggHoldfast_puppet",
    "DudBolt_puppet",
    "WanSandage_puppet",
    "ElanMak_puppet",
    "ToyDampner_puppet",
    "FudSang_puppet",
    "NevaKee_puppet",
    "SlideParamita_puppet",
    "AldarBeedo_puppet",
    "BozzieBaranta_puppet",
    "BolesRoor_puppet",
    "BullseyeNavior_puppet",
    "PitDroid_puppet",
    "Watto_puppet",
    "Dewback_puppet",
    "Ronto_puppet",
    "Jabba_puppet",
    "LightSet",
    "BoontaTrainingCourse_track",
    "MonGazza_part",
    "AndoPrime_part",
    "Aquilaris_part",
    "Baroonda_part",
    "Trugut_part",
    "Malastare_part",
    "AndoPrimeCentrum_part",
    "FirstPlaceFlag_part",
    "Winner_sPlatform_part",
    "SecondPlaceFlag_part",
    "ThirdPlaceFlag_part",
    "_podiumScene_part",
    "AndoPrimeCentrum_track",
    "Inferno_track",
    "Beedo_sWildRide_track",
    "HowlerGorge_track",
    "AndobiMountainRun_track",
    "AquilarisClassic_track",
    "SunkenCity_track",
    "Bumpy_sBreakers_track",
    "Scrapper_sRun_track",
    "Dethro_sRevenge_track",
    "Abyss_track",
    "BarooCoast_track",
    "GrabvineGateway_track",
    "FireMountainRally_track",
    "MonGazzaSpeedway_track",
    "SpiceMineRun_track",
    "ZuggaChallenge_track",
    "Vengeance_track",
    "EnergyBinder",
    "Fireball_part",
    "Executioner_track",
    "Jabba_sSpectatorBoothScen",
    "CutsceneScen",
    "LightRing",
    "CutsceneScen",
    "CutsceneScen",
    "Cantina_part",
    "OpeeSeaKiller_puppet",
    "CutsceneScen",
    "MarkIIAirBrake_part",
    "MarkIIIAirBrake_part",
    "MarkIVAirBrake_part",
    "MarkVAirBrake_part",
    "Tri-JetAirBrake_part",
    "QuadrijetAirBrake_part",
    "CoolantRadiator_part",
    "Stack-3Radiator_part",
    "Stack-6Radiator_part",
    "RodCoolantPump_part",
    "DualCoolantPump_part",
    "TurboCoolantPump_part",
    "Plug2ThrustCoil_part",
    "Plug3ThrustCoil_part",
    "Plug5ThrustCoil_part",
    "Plug8ThrustCoil_part",
    "Block5ThrustCoil_part",
    "Block6ThrustCoil_part",
    "HoloTable_puppet",
    "IceStub",
    "Beedo_sWildRide_part",
    "HowlerGorge_part",
    "AndobiMountainRun_part",
    "AquilarisClassic_part",
    "SunkenCity_part",
    "Malastare100_part",
    "DugDerby_part",
    "Sebulba_sLegacy_part",
    "Bumpy_sBreakers_part",
    "Scrapper_sRun_part",
    "Dethro_sRevenge_part",
    "Abyss_part",
    "MonGazzaSpeedway_part",
    "SpiceMineRun_part",
    "Inferno_part",
    "ZuggaChallenge_part",
    "Vengeance_part",
    "Executioner_part",
    "TheGauntlet_part",
    "Flag_part",
    "Flag",
    "Dual20PCXInjector_part",
    "44PCXInjector_part",
    "Dual32PCXInjector_part",
    "Quad32PCXInjector_part",
    "Quad44Injector_part",
    "Mag6Injector_part",
    "R-20Repulsorgrip_part",
    "R-60Repulsorgrip_part",
    "R-80Repulsorgrip_part",
    "AldarBeedo_part",
    "AnakinSkywalker_part",
    "BenQuadinaros_part",
    "BolesRoor_part",
    "BozzieBaranta_part",
    "BullseyeNavior_part",
    "Ark_Bumpy_Roose_part",
    "CleggHoldfast_part",
    "DudBolt_part",
    "EbeEndocott_part",
    "ElanMak_part",
    "FudSang_part",
    "Gasgano_part",
    "RattsTyerell_part",
    "MarsGuo_part",
    "Mawhonic_part",
    "NevaKee_part",
    "OdyMandrell_part",
    "Sebulba_part",
    "SlideParamita_part",
    "TeemtoPagalies_part",
    "ToyDampner_part",
    "WanSandage_part",
    "R-100Repulsorgrip_part",
    "TheGauntlet_track",
    "Malastare100_track",
    "DugDerby_track",
    "SinglePowerCell_part",
    "DualPowerCell_part",
    "BarooCoast_part",
    "QuadPowerCell_part",
    "ClusterPowerPlug_part",
    "RotaryPowerPlug_part",
    "ControlStabilizer_part",
    "R-300Repulsorgrip_part",
    "R-600Repulsorgrip_part",
    "Cluster2PowerPlug_part",
    "Hammerhead(Bartender)_puppet",
    "C3PO_puppet",
    "JarJarBinks_puppet",
    "Jawa_puppet",
    "R2D2_puppet",
    "GrabvineGateway_part",
    "FireMountainRally_part",
    "BigRockExplosion_part",
    "SmallRockExplosion_part",
    "OrdIbanna_part",
    "IceExplosion_part",
    "Sebulba_part",
    "AnakinSkywalker_part",
    "TeemtoPagalies_part",
    "RattsTyerell_part",
    "AldarBeedo_part",
    "Mawhonic_part",
    "Ark_Bumpy_Roose_part",
    "WanSandage_part",
    "MarsGuo_part",
    "EbeEndocott_part",
    "DudBolt_part",
    "Gasgano_part",
    "CleggHoldfast_part",
    "ElanMak_part",
    "NevaKee_part",
    "BozzieBaranta_part",
    "BolesRoor_part",
    "OdyMandrell_part",
    "FudSang_part",
    "BenQuadinaros_part",
    "SlideParamita_part",
    "ToyDampner_part",
    "BullseyeNavior_part",
    "TatooineStartingGate_part",
    "BoontaTrainingCourse_part",
    "BoontaClassic_part",
    "AquilarisScen",
    "OrdIbannaScen",
    "BarondaScen",
    "MonGazzaScen",
    "OovoIVScen",
    "TatooineScen",
    "LogoLucasArtScen",
    "CutsceneScen",
    "CutsceneScen",
    "CutsceneScen",
    "CutsceneScen",
    "CutsceneScen",
    "CutsceneScen",
    "Lava",
    "RockExplosion_part",
    "TreeExplosion_part",
    "BaroondaBeach",
    "JinnReeso_alt",
    "JinnReeso_pod",
    "CyYunga_alt",
    "CyYunga_pod",
    "JinnReeso_part",
    "CyYunga_part",
    "JinnReeso_puppet",
    "CyYunga_puppet",
    "GiantRockExplosion_part",
    "Explosion_part",
    "Ballooncraft_part",
    "MethaneExplosion_part",
    "StartingGate_part",
    "LavaExplosion_part",
    "MonGazzaDozer_part",
    "DustEffect_part",
    "DustEffect",
    "Sebulba_sLegacy_track",
    "Explosion",
    "Flames_part",
    "_podExplosion_part",
    "QuiGonJinn_puppet",
    "CircleShadow_part",
    "SquareShadow_part",
    "N64ExpansionPak_part",
    "Unknown",
};

// MODELID, ReplacementModel
std::map<int, ReplacementModel> replacement_map{};

static void addImguiReplacementString(std::string s) {
    if (imgui_initialized && imgui_state.show_replacementTries) {
        imgui_state.replacementTries += s;
    }
}

void load_replacement_if_missing(MODELID model_id) {
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
}

/*
    Load models from gltf files and store them in replacement_map MODELID slot
*/
bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored, uint8_t type) {

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);


        uint8_t mirrorFlag = mirrored ? replacementFlag::Mirrored : replacementFlag::Normal;
        if ((replacedTries[model_id] & mirrorFlag) == 0) {
            renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, replacement.model, envInfos,
                              mirrored, type);

            addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                      std::string(" Replaced \n"));
            replacedTries[model_id] |= mirrorFlag;
            // glPopDebugGroup();
        }

        return true;
    }

    if (replacedTries[model_id] == 0) {
        addImguiReplacementString(std::string(modelid_cstr[model_id]) + std::string("\n"));
        replacedTries[model_id] += 1;
    }

    return false;
}

// TODO: bag of Ai pod _part
bool try_replace_pod(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                     const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored,
                     uint8_t type) {
    // Inspection hangar only. Find the id of the current selected pod by looking at a sub-node (engineR here)
    if (model_id == MODELID_pln_tatooine_part) {
        // We have to find the id of the current selected pod
        assert(root_node != nullptr && "try_replace_pod root should not be null");
        swrModel_Node *engineR_node =
            root_node->children.nodes[15]->children.nodes[0]->children.nodes[2];
        auto opt_id = find_model_id_for_node(engineR_node);
        assert(opt_id.has_value() && "try_replace_pod engineR should have an id");

        model_id = opt_id.value();
    }

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist && replacedTries[model_id] == 0) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);

        // In a race
        if (currentPlayer_Test != nullptr) {
            renderer_drawGLTFPod(proj_matrix, view_matrix, currentPlayer_Test->engineXfR,
                                 currentPlayer_Test->engineXfL, currentPlayer_Test->cockpitXf,
                                 replacement.model, envInfos, mirrored, 0);
        } else {
            // Selecting and Inspecting
            if (root_node != nullptr) {
                // Slot 15 selected _pod
                swrModel_Node *pod_slot = root_node->children.nodes[15];
                if (pod_slot != nullptr) {
                    swrModel_Node *node_to_replace = pod_slot->children.nodes[0];

                    // resolve matrices transform
                    rdMatrix44 engineR_mat = model_matrix;
                    rdMatrix44 engineL_mat = model_matrix;
                    rdMatrix44 cockpit_mat = model_matrix;
                    {
                        swrModel_Node *engineR_node = node_to_replace->children.nodes[2];
                        apply_node_transform(engineR_mat, engineR_node, nullptr);
                        swrModel_Node *engineL_node = node_to_replace->children.nodes[3];
                        apply_node_transform(engineL_mat, engineL_node, nullptr);
                        swrModel_Node *cockpit_node = node_to_replace->children.nodes[13];
                        apply_node_transform(cockpit_mat, cockpit_node, nullptr);
                    }
                    renderer_drawGLTFPod(proj_matrix, view_matrix, engineR_mat, engineL_mat,
                                         cockpit_mat, replacement.model, envInfos, mirrored, 0);
                }
            }
        }
        // glPopDebugGroup();

        addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                  std::string(" Pod Replaced \n"));
        replacedTries[model_id] |= replacementFlag::Mirrored | replacementFlag::Normal;

        return true;
    }

    return false;
}
