#include "replacements.h"
#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"
#include "imgui_utils.h"

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
    "TeemtoPagaliesPupp",
    "AnakinSkywalkerPupp",
    "GasganoPupp",
    "MawhonicPupp",
    "OdyMandrellPupp",
    "SebulbaPupp",
    "MarsGuoPupp",
    "RattsTyerellPupp",
    "BenQuadinarosPupp",
    "EbeEndocottPupp",
    "Ark_Bumpy_RoosePupp",
    "CleggHoldfastPupp",
    "DudBoltPupp",
    "WanSandagePupp",
    "ElanMakPupp",
    "ToyDampnerPupp",
    "FudSangPupp",
    "NevaKeePupp",
    "SlideParamitaPupp",
    "AldarBeedoPupp",
    "BozzieBarantaPupp",
    "BolesRoorPupp",
    "BullseyeNaviorPupp",
    "PitDroidPupp",
    "WattoPupp",
    "DewbackPupp",
    "RontoPupp",
    "JabbaPupp",
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
    "OpeeSeaKillerPupp",
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
    "HoloTablePupp",
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
    "Hammerhead(Bartender)Pupp",
    "C3POPupp",
    "JarJarBinksPupp",
    "JawaPupp",
    "R2D2Pupp",
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
    "JinnReesoPupp",
    "CyYungaPupp",
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
    "QuiGonJinnPupp",
    "CircleShadow_part",
    "SquareShadow_part",
    "N64ExpansionPak_part",
};

struct ReplacementModel {
    bool fileExist;
    gltfModel model;
};

// MODELID, ReplacementModel
std::map<int, ReplacementModel> replacement_map{};


static void addImguiReplacementString(int modelId, std::string s) {
    if (imgui_initialized && imgui_state.show_replacementTries) {
        imgui_state.replacementTries += s;
    }
}

/*
    Load models from gltf files and store them in replacement_map MODELID slot
*/
bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored, uint8_t type) {

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

        if (replacedTries[model_id] == 0) {
            renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, replacement.model, envInfos,
                              mirrored, type);

            addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
                                                    std::string(" Replaced \n"));
            replacedTries[model_id] += 1;
            // glPopDebugGroup();
        }

        return true;
    }

    // if ((model_id >= MODELID_part_control01_part && model_id <= MODELID_replsr_part5_part) ||
    //     (model_id >= MODELID_replsr_part6_part && model_id <= MODELID_thrust_part6_part) ||
    //     (model_id >= MODELID_part_airbrake1_part && model_id <= MODELID_part_thrust6_part) ||
    //     (model_id >= MODELID_part_accel01_part && model_id <= MODELID_part_grip03_part) ||
    //     (model_id >= MODELID_part_powercell01_part && model_id <= MODELID_part_powercell06_part &&
    //      model_id != MODELID_map_d1_part)) {
    //     // renderer_drawTetrahedron(proj_matrix, view_matrix, model_matrix);
    //     renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[1], envInfos, mirrored,
    //                       type);
    //     // addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
    //     //                                         std::string(" Hardcoded\n"));
    //     return true;
    // }

    // if (model_id == MODELID_part_grip04_part) {
    //     // renderer_drawCube(proj_matrix, view_matrix, model_matrix);
    //     renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[0], envInfos, mirrored,
    //                       type);
    //     // addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) +
    //     //                                         std::string(" Hardcoded\n"));
    //     return true;
    // }

    // if (model_id == MODELID_alt_neva_kee_pod) {
    //     // renderer_drawCube(proj_matrix, view_matrix, model_matrix);
    //     if (replacedTries[model_id] == 0) {
    //         rdMatrix44 model_matrix_corrected = model_matrix;
    //         swrTranslationRotation tr_rot = {0};
    //         rdMatrix_ExtractTransform(&model_matrix_corrected, &tr_rot);
    //         renderer_drawGLTF(proj_matrix, view_matrix, model_matrix_corrected, g_models[5],
    //                           envInfos, mirrored, type);
    //         addImguiReplacementString(
    //             model_id, std::string(modelid_cstr[model_id]) +
    //                           std::format("\n{:.2f} {:.2f} {:.2f}\n", tr_rot.yaw_roll_pitch.x,
    //                                       tr_rot.yaw_roll_pitch.y, tr_rot.yaw_roll_pitch.z) +
    //                           std::string(" Hardcoded pod\n"));
    //         imgui_state.modelMatScale[0] = model_matrix_corrected.vA.x;
    //         imgui_state.modelMatScale[1] = model_matrix_corrected.vB.y;
    //         imgui_state.modelMatScale[2] = model_matrix_corrected.vC.z;
    //     }
    //     return true;
    // }

    // addImguiReplacementString(model_id, std::string(modelid_cstr[model_id]) + std::string("\n"));

    return false;
}
