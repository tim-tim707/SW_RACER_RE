#include "replacements.h"

#include "renderer_utils.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include <globals.h>

#include <map>
#include <string>
#include <filesystem>
#include <format>

extern "C" FILE *hook_log;

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
    "Ark_Bumpy_Roose_alt",
    "Ark_Bumpy_Roose_pod",
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
    "AldarBeedo_far_part",
    "AnakinSkywalker_far_part",
    "BenQuadinaros_far_part",
    "BolesRoor_far_part",
    "BozzieBaranta_far_part",
    "BullseyeNavior_far_part",
    "Ark_Bumpy_Roose_far_part",
    "CleggHoldfast_far_part",
    "DudBolt_far_part",
    "EbeEndocott_far_part",
    "ElanMak_far_part",
    "FudSang_far_part",
    "Gasgano_far_part",
    "RattsTyerell_far_part",
    "MarsGuo_far_part",
    "Mawhonic_far_part",
    "NevaKee_far_part",
    "OdyMandrell_far_part",
    "Sebulba_far_part",
    "SlideParamita_far_part",
    "TeemtoPagalies_far_part",
    "ToyDampner_far_part",
    "WanSandage_far_part",
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
    "Sebulba_mid_part",
    "AnakinSkywalker_mid_part",
    "TeemtoPagalies_mid_part",
    "RattsTyerell_mid_part",
    "AldarBeedo_mid_part",
    "Mawhonic_mid_part",
    "Ark_Bumpy_Roose_mid_part",
    "WanSandage_mid_part",
    "MarsGuo_mid_part",
    "EbeEndocott_mid_part",
    "DudBolt_mid_part",
    "Gasgano_mid_part",
    "CleggHoldfast_mid_part",
    "ElanMak_mid_part",
    "NevaKee_mid_part",
    "BozzieBaranta_mid_part",
    "BolesRoor_mid_part",
    "OdyMandrell_mid_part",
    "FudSang_mid_part",
    "BenQuadinaros_mid_part",
    "SlideParamita_mid_part",
    "ToyDampner_mid_part",
    "BullseyeNavior_mid_part",
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
    "JinnReeso_mid_part",
    "CyYunga_mid_part",
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

const int ignoredModels[] = {
    MODELID_dustkick1_vlec,      MODELID_shadow_square_part, MODELID_shadow_circle_part,
    MODELID_fireball_1_part,     MODELID_fx_flameanim_part,  MODELID_fx_lavafoof_part,
    MODELID_fx_methanefoof_part, MODELID_fx_rocksmall_part,  MODELID_fx_rockbig_part,
    MODELID_fx_rockgiant_part,   MODELID_fx_shards_part,     MODELID_fx_treesmash_part,
};

bool isEnvModel(MODELID modelId) {
    // Places and tracks
    if (modelId == MODELID_hangar18_part || modelId == MODELID_loc_watto_part ||
        modelId == MODELID_loc_junkyard_part || modelId == MODELID_loc_awards_part ||
        modelId == MODELID_loc_cantina_part || modelId == MODELID_tatooine_track ||
        modelId == MODELID_tatooine_mini_track ||
        (modelId >= MODELID_planeth_track && modelId <= MODELID_planetf1_track) ||
        modelId == MODELID_planetf2_track ||
        (modelId >= MODELID_planetf3_track && modelId <= MODELID_planetj2_track) ||
        modelId == MODELID_planetj3_track)
        return true;

    // Various elements
    if (modelId == MODELID_holo_proj02_puppet || modelId == MODELID_balloon01_part ||
        modelId == MODELID_gate01_part)
        return true;

    for (size_t i = 0; i < std::size(ignoredModels); i++) {
        if (modelId == ignoredModels[i])
            return true;
    }

    return false;
}

bool isPodModel(MODELID modelId) {
    if (modelId == MODELID_alt_anakin_pod || modelId == MODELID_anakin_pod ||
        modelId == MODELID_alt_teemto_pod || modelId == MODELID_teemto_pod ||
        modelId == MODELID_alt_sebulba_pod || modelId == MODELID_sebulba_pod ||
        modelId == MODELID_alt_ratts_pod || modelId == MODELID_ratts_pod ||
        modelId == MODELID_aldar_beedo_pod || modelId == MODELID_alt_aldar_beedo_pod ||
        modelId == MODELID_alt_mawhonic_pod || modelId == MODELID_mawhonic_pod ||
        modelId == MODELID_alt_bumpy_roose_pod || modelId == MODELID_bumpy_roose_pod ||
        modelId == MODELID_alt_wan_sandage_pod || modelId == MODELID_wan_sandage_pod ||
        modelId == MODELID_alt_mars_guo_pod || modelId == MODELID_mars_guo_pod ||
        modelId == MODELID_alt_ebe_endicott_pod || modelId == MODELID_ebe_endicott_pod ||
        modelId == MODELID_alt_dud_bolt_pod || modelId == MODELID_dud_bolt_pod ||
        modelId == MODELID_alt_gasgano_pod || modelId == MODELID_gasgano_pod ||
        modelId == MODELID_alt_clegg_holdfast_pod || modelId == MODELID_clegg_holdfast_pod ||
        modelId == MODELID_alt_elan_mak_pod || modelId == MODELID_elan_mak_pod ||
        modelId == MODELID_alt_neva_kee_pod || modelId == MODELID_neva_kee_pod ||
        modelId == MODELID_alt_bozzie_barada_pod || modelId == MODELID_bozzie_barada_pod ||
        modelId == MODELID_alt_boles_roor_pod || modelId == MODELID_boles_roor_pod ||
        modelId == MODELID_alt_ody_mandrell_pod || modelId == MODELID_ody_mandrell_pod ||
        modelId == MODELID_alt_fud_sang_pod || modelId == MODELID_fud_sang_pod ||
        modelId == MODELID_alt_ben_quadinaros_pod || modelId == MODELID_ben_quadinaros_pod ||
        modelId == MODELID_alt_slide_paramita_pod || modelId == MODELID_slide_paramita_pod ||
        modelId == MODELID_alt_toy_dampner_pod || modelId == MODELID_toy_dampner_pod ||
        modelId == MODELID_alt_bullseye_pod || modelId == MODELID_bullseye_pod ||
        modelId == MODELID_alt_jinn_reeso_pod || modelId == MODELID_jinn_reeso_pod ||
        modelId == MODELID_alt_cy_yunga_pod || modelId == MODELID_cy_yunga_pod) {
        return true;
    }

    return false;
}

bool isAIPodModel(MODELID modelId) {
    // AIs in a race have a _part suffix + LOD
    // mid_ and _far modelIds here
    if (modelId == MODELID_mid_sebulba_part || modelId == MODELID_mid_anakin_part ||
        modelId == MODELID_mid_teemto_part || modelId == MODELID_mid_ratts_part ||
        modelId == MODELID_mid_aldar_beedo_part || modelId == MODELID_mid_mawhonic_part ||
        modelId == MODELID_mid_bumpy_roose_part || modelId == MODELID_mid_wan_sandage_part ||
        modelId == MODELID_mid_mars_guo_part || modelId == MODELID_mid_ebe_endicott_part ||
        modelId == MODELID_mid_dud_bolt_part || modelId == MODELID_mid_gasgano_part ||
        modelId == MODELID_mid_clegg_holdfast_part || modelId == MODELID_mid_elan_mak_part ||
        modelId == MODELID_mid_neva_kee_part || modelId == MODELID_mid_bozzie_barada_part ||
        modelId == MODELID_mid_boles_roor_part || modelId == MODELID_mid_ody_mandrell_part ||
        modelId == MODELID_mid_fud_sang_part || modelId == MODELID_mid_ben_quadinaros_part ||
        modelId == MODELID_mid_slide_paramita_part || modelId == MODELID_mid_toy_dampner_part ||
        modelId == MODELID_mid_bullseye_part || modelId == MODELID_mid_jinn_reeso_part ||
        modelId == MODELID_mid_cy_yunga_part || modelId == MODELID_far_aldar_beedo_part ||
        modelId == MODELID_far_anakin_part || modelId == MODELID_far_ben_quadinaros_part ||
        modelId == MODELID_far_boles_roor_part || modelId == MODELID_far_bozzie_barada_part ||
        modelId == MODELID_far_bullseye_part || modelId == MODELID_far_bumpy_roose_part ||
        modelId == MODELID_far_clegg_holdfast_part || modelId == MODELID_far_dud_bolt_part ||
        modelId == MODELID_far_ebe_endicott_part || modelId == MODELID_far_elan_mak_part ||
        modelId == MODELID_far_fud_sang_part || modelId == MODELID_far_gasgano_part ||
        modelId == MODELID_far_ratts_part || modelId == MODELID_far_mars_guo_part ||
        modelId == MODELID_far_mawhonic_part || modelId == MODELID_far_neva_kee_part ||
        modelId == MODELID_far_ody_mandrell_part || modelId == MODELID_far_sebulba_part ||
        modelId == MODELID_far_slide_paramita_part || modelId == MODELID_far_teemto_part ||
        modelId == MODELID_far_toy_dampner_part || modelId == MODELID_far_wan_sandage_part) {
        return true;
    }

    return false;
}

bool isTrackModel(MODELID modelId) {
    if (modelId == MODELID_tatooine_track || modelId == MODELID_tatooine_mini_track ||
        modelId == MODELID_planeth_track || modelId == MODELID_planeti_track ||
        modelId == MODELID_planeta1_track || modelId == MODELID_planeta2_track ||
        modelId == MODELID_planeta3_track || modelId == MODELID_planetb1_track ||
        modelId == MODELID_planetb2_track || modelId == MODELID_planetb3_track ||
        modelId == MODELID_planetc1_track || modelId == MODELID_planetc2_track ||
        modelId == MODELID_planetc3_track || modelId == MODELID_planetd1_track ||
        modelId == MODELID_planetd2_track || modelId == MODELID_planetd3_track ||
        modelId == MODELID_planete1_track || modelId == MODELID_planete2_track ||
        modelId == MODELID_planete3_track || modelId == MODELID_planetf1_track ||
        modelId == MODELID_planetf2_track || modelId == MODELID_planetf3_track ||
        modelId == MODELID_planetj1_track || modelId == MODELID_planetj2_track ||
        modelId == MODELID_planetj3_track) {
        return true;
    }
    return false;
}

// Prevent loading the same gltf model for the different ids such as
// MODELID_alt_anakin_pod, MODELID_anakin_pod, MODELID_mid_anakin_part, MODELID_far_anakin_part
MODELID AnyPodModelToPodModel(MODELID modelId) {
    if (modelId == MODELID_anakin_pod || modelId == MODELID_alt_anakin_pod ||
        modelId == MODELID_mid_anakin_part || modelId == MODELID_far_anakin_part) {
        return MODELID_anakin_pod;
    }
    if (modelId == MODELID_teemto_pod || modelId == MODELID_alt_teemto_pod ||
        modelId == MODELID_mid_teemto_part || modelId == MODELID_far_teemto_part) {
        return MODELID_teemto_pod;
    }
    if (modelId == MODELID_sebulba_pod || modelId == MODELID_alt_sebulba_pod ||
        modelId == MODELID_mid_sebulba_part || modelId == MODELID_far_sebulba_part) {
        return MODELID_sebulba_pod;
    }
    if (modelId == MODELID_ratts_pod || modelId == MODELID_alt_ratts_pod ||
        modelId == MODELID_mid_ratts_part || modelId == MODELID_far_ratts_part) {
        return MODELID_ratts_pod;
    }
    if (modelId == MODELID_aldar_beedo_pod || modelId == MODELID_alt_aldar_beedo_pod ||
        modelId == MODELID_mid_aldar_beedo_part || modelId == MODELID_far_aldar_beedo_part) {
        return MODELID_aldar_beedo_pod;
    }
    if (modelId == MODELID_mawhonic_pod || modelId == MODELID_alt_mawhonic_pod ||
        modelId == MODELID_mid_mawhonic_part || modelId == MODELID_far_mawhonic_part) {
        return MODELID_mawhonic_pod;
    }
    if (modelId == MODELID_bumpy_roose_pod || modelId == MODELID_alt_bumpy_roose_pod ||
        modelId == MODELID_mid_bumpy_roose_part || modelId == MODELID_far_bumpy_roose_part) {
        return MODELID_bumpy_roose_pod;
    }
    if (modelId == MODELID_wan_sandage_pod || modelId == MODELID_alt_wan_sandage_pod ||
        modelId == MODELID_mid_wan_sandage_part || modelId == MODELID_far_wan_sandage_part) {
        return MODELID_wan_sandage_pod;
    }
    if (modelId == MODELID_mars_guo_pod || modelId == MODELID_alt_mars_guo_pod ||
        modelId == MODELID_mid_mars_guo_part || modelId == MODELID_far_mars_guo_part) {
        return MODELID_mars_guo_pod;
    }
    if (modelId == MODELID_ebe_endicott_pod || modelId == MODELID_alt_ebe_endicott_pod ||
        modelId == MODELID_mid_ebe_endicott_part || modelId == MODELID_far_ebe_endicott_part) {
        return MODELID_ebe_endicott_pod;
    }
    if (modelId == MODELID_dud_bolt_pod || modelId == MODELID_alt_dud_bolt_pod ||
        modelId == MODELID_mid_dud_bolt_part || modelId == MODELID_far_dud_bolt_part) {
        return MODELID_dud_bolt_pod;
    }
    if (modelId == MODELID_gasgano_pod || modelId == MODELID_alt_gasgano_pod ||
        modelId == MODELID_mid_gasgano_part || modelId == MODELID_far_gasgano_part) {
        return MODELID_gasgano_pod;
    }
    if (modelId == MODELID_clegg_holdfast_pod || modelId == MODELID_alt_clegg_holdfast_pod ||
        modelId == MODELID_mid_clegg_holdfast_part || modelId == MODELID_far_clegg_holdfast_part) {
        return MODELID_clegg_holdfast_pod;
    }
    if (modelId == MODELID_elan_mak_pod || modelId == MODELID_alt_elan_mak_pod ||
        modelId == MODELID_mid_elan_mak_part || modelId == MODELID_far_elan_mak_part) {
        return MODELID_elan_mak_pod;
    }
    if (modelId == MODELID_neva_kee_pod || modelId == MODELID_alt_neva_kee_pod ||
        modelId == MODELID_mid_neva_kee_part || modelId == MODELID_far_neva_kee_part) {
        return MODELID_neva_kee_pod;
    }
    if (modelId == MODELID_bozzie_barada_pod || modelId == MODELID_alt_bozzie_barada_pod ||
        modelId == MODELID_mid_bozzie_barada_part || modelId == MODELID_far_bozzie_barada_part) {
        return MODELID_bozzie_barada_pod;
    }
    if (modelId == MODELID_boles_roor_pod || modelId == MODELID_alt_boles_roor_pod ||
        modelId == MODELID_mid_boles_roor_part || modelId == MODELID_far_boles_roor_part) {
        return MODELID_boles_roor_pod;
    }
    if (modelId == MODELID_ody_mandrell_pod || modelId == MODELID_alt_ody_mandrell_pod ||
        modelId == MODELID_mid_ody_mandrell_part || modelId == MODELID_far_ody_mandrell_part) {
        return MODELID_ody_mandrell_pod;
    }
    if (modelId == MODELID_fud_sang_pod || modelId == MODELID_alt_fud_sang_pod ||
        modelId == MODELID_mid_fud_sang_part || modelId == MODELID_far_fud_sang_part) {
        return MODELID_fud_sang_pod;
    }
    if (modelId == MODELID_ben_quadinaros_pod || modelId == MODELID_alt_ben_quadinaros_pod ||
        modelId == MODELID_mid_ben_quadinaros_part || modelId == MODELID_far_ben_quadinaros_part) {
        return MODELID_ben_quadinaros_pod;
    }
    if (modelId == MODELID_slide_paramita_pod || modelId == MODELID_alt_slide_paramita_pod ||
        modelId == MODELID_mid_slide_paramita_part || modelId == MODELID_far_slide_paramita_part) {
        return MODELID_slide_paramita_pod;
    }
    if (modelId == MODELID_toy_dampner_pod || modelId == MODELID_alt_toy_dampner_pod ||
        modelId == MODELID_mid_toy_dampner_part || modelId == MODELID_far_toy_dampner_part) {
        return MODELID_toy_dampner_pod;
    }
    if (modelId == MODELID_bullseye_pod || modelId == MODELID_alt_bullseye_pod ||
        modelId == MODELID_mid_bullseye_part || modelId == MODELID_far_bullseye_part) {
        return MODELID_bullseye_pod;
    }
    if (modelId == MODELID_jinn_reeso_pod || modelId == MODELID_alt_jinn_reeso_pod ||
        modelId == MODELID_mid_jinn_reeso_part) {
        return MODELID_jinn_reeso_pod;
    }
    if (modelId == MODELID_cy_yunga_pod || modelId == MODELID_alt_cy_yunga_pod ||
        modelId == MODELID_mid_cy_yunga_part) {
        return MODELID_cy_yunga_pod;
    }

    assert(false && "PodModelId is not a correct pod id");
    return MODELID_anakin_pod;
}

void load_replacement_if_missing(MODELID model_id) {
    // Try to load file or mark as not existing
    if (!replacement_map.contains(model_id)) {
        constexpr auto supportedExtensions = fastgltf::Extensions::None;
        fastgltf::Parser parser(supportedExtensions);

        constexpr auto gltfOptions =
            fastgltf::Options::DontRequireValidAssetMember |
            fastgltf::Options::LoadExternalBuffers | fastgltf::Options::LoadExternalImages |
            fastgltf::Options::GenerateMeshIndices | fastgltf::Options::DecomposeNodeMatrices;

        fastgltf::Asset asset;

        std::string filename = std::string(modelid_cstr[model_id]);

        std::string filename_gltf = filename + std::string(".gltf");
        std::string path_gltf = "./assets/gltf/" + filename_gltf;
        std::string filename_glb = filename + std::string(".glb");
        std::string path_glb = "./assets/gltf/" + filename_glb;
        std::string used_path;

        bool fileExist_gltf = true;
        bool fileExist_glb = true;
        if (std::filesystem::exists(path_glb)) {
            used_path = path_glb;
            fileExist_gltf = false;
        } else if (std::filesystem::exists(path_gltf)) {
            used_path = path_gltf;
            fileExist_glb = false;
        } else {
            fileExist_gltf = false;
            fileExist_glb = false;
        }
        bool fileExist = fileExist_glb || fileExist_gltf;

        if (fileExist) {
            auto gltfFile = fastgltf::MappedGltfFile::FromPath(used_path);
            if (!bool(gltfFile)) {
                fprintf(hook_log, "Failed to open glTF file: %s\n",
                        std::string(fastgltf::getErrorMessage(gltfFile.error())).c_str());
            }

            auto asset_gltf = parser.loadGltf(
                gltfFile.get(), std::filesystem::path(used_path).parent_path(), gltfOptions);
            if (asset_gltf.error() != fastgltf::Error::None) {
                fprintf(hook_log, "Failed to load glTF file: %s\n",
                        std::string(fastgltf::getErrorMessage(asset_gltf.error())).c_str());
            }
            asset = std::move(asset_gltf.get());

            fprintf(hook_log, "[Replacements] Loaded %s\n",
                    fileExist_gltf ? filename_gltf.c_str() : filename_glb.c_str());
            fflush(hook_log);
        }

        ReplacementModel replacement{
            .fileExist = fileExist_gltf || fileExist_glb,
            .model = {.filename = fileExist_gltf ? filename_gltf : filename_glb,
                      .setuped = false,
                      .gltf2 = std::move(asset),
                      .material_infos = {},
                      .mesh_infos = {}},
        };
        replacement_map[model_id] = std::move(replacement);
    }
}

/*
    Load models from gltf files and store them in replacement_map MODELID slot
*/
bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored, uint8_t type) {
    if (isPodModel(model_id) || isAIPodModel(model_id) || isTrackModel(model_id))
        return false;

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);


        uint8_t mirrorFlag = mirrored ? replacementFlag::Mirrored : replacementFlag::Normal;
        if ((replacedTries[model_id] & mirrorFlag) == 0) {
            rdMatrix44 adjusted_model_matrix;
            rdMatrix_ScaleBasis44(&adjusted_model_matrix, 100, 100, 100, &model_matrix);
            renderer_drawGLTF(proj_matrix, view_matrix, adjusted_model_matrix, replacement.model,
                              envInfos, mirrored, type);

            addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                      std::string(" REPLACED\n"));
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

bool try_replace_pod(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                     const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored) {
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

    // Ark bumpy uses his alt pod as main one
    if (model_id == MODELID_alt_bumpy_roose_pod) {
        model_id == MODELID_bumpy_roose_pod;
    }

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist && replacedTries[model_id] == 0) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);

        // Ben has 4 engines, and cockpit is at index 18 instead of 13
        size_t engineL_node_index = 3;
        size_t cockpit_node_index = 13;
        if (model_id == MODELID_ben_quadinaros_pod) {
            engineL_node_index = 4;
            cockpit_node_index = 18;
        }

        // In a race. Static pointer
        if ((uint32_t) root_node == 0x00E28980) {
            renderer_drawGLTFPod(proj_matrix, view_matrix, currentPlayer_Test->engineXfR,
                                 currentPlayer_Test->engineXfL, currentPlayer_Test->cockpitXf,
                                 replacement.model, envInfos, mirrored, 0);

            // Always clear this visibility flag, to prevent visual issues with the mirrored pod
            // unset visibility flag for node 1 will remove mirror reflexion
            root_node->children.nodes[1]->flags_1 &= ~0x2;
            // Check if on a mirrored face by looking at flags for node 1 0.
            // If we are, also render the pod upside down somehow
            if (root_node->children.nodes[1]->children.nodes[0]->flags_1 & 0x2) {
                // Check if both engines are alive to draw the mirror (spinning causes error)
                swrModel_Node *engineR_node = root_node->children.nodes[1]
                                                  ->children.nodes[0]
                                                  ->children.nodes[0]
                                                  ->children.nodes[2];
                swrModel_Node *engineL_node = root_node->children.nodes[1]
                                                  ->children.nodes[0]
                                                  ->children.nodes[0]
                                                  ->children.nodes[3];
                if (!(!(engineR_node->flags_1 & 0x2) || !(engineL_node->flags_1 & 0x2))) {
                    // Rotate along Z axis by 180 degrees, and scale all axes by -1 to mirror (prevent non-uniform scale)
                    // This upper 3x3 matrix is the same as the one in the node 1-0
                    rdMatrix44 mirrorMatrix = rdMatrix44{
                        .vA = {1, 0, 0, 0},
                        .vB = {0, 1, 0, 0},
                        .vC = {0, 0, -1, 0},
                        .vD = {0, 0, 0, 1},
                    };

                    // offset along Z-axis, translate before rotation
                    const rdVector3 v = rdVector3{0.0, 0.0, -5.0};
                    const rdVector3 v_transformed = {
                        mirrorMatrix.vA.x * v.x + mirrorMatrix.vB.x * v.y + mirrorMatrix.vC.x * v.z,
                        mirrorMatrix.vA.y * v.x + mirrorMatrix.vB.y * v.y + mirrorMatrix.vC.y * v.z,
                        mirrorMatrix.vA.z * v.x + mirrorMatrix.vB.z * v.y + mirrorMatrix.vC.z * v.z,
                    };
                    mirrorMatrix.vD.x += v.x - v_transformed.x;
                    mirrorMatrix.vD.y += v.y - v_transformed.y;
                    mirrorMatrix.vD.z += v.z - v_transformed.z;

                    rdMatrix44 engineRMirror = currentPlayer_Test->engineXfR;
                    rdMatrix_Multiply44(&engineRMirror, &mirrorMatrix, &engineRMirror);

                    rdMatrix44 engineLMirror = currentPlayer_Test->engineXfL;
                    rdMatrix_Multiply44(&engineLMirror, &mirrorMatrix, &engineLMirror);

                    rdMatrix44 cockpitMirror = currentPlayer_Test->cockpitXf;
                    rdMatrix_Multiply44(&cockpitMirror, &mirrorMatrix, &cockpitMirror);

                    renderer_drawGLTFPod(proj_matrix, view_matrix, engineRMirror, engineLMirror,
                                         cockpitMirror, replacement.model, envInfos, mirrored, 0);
                }
            }
        } else {// root_node should be 0x00E2A660
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
                        swrModel_Node *engineL_node =
                            node_to_replace->children.nodes[engineL_node_index];
                        apply_node_transform(engineL_mat, engineL_node, nullptr);
                        swrModel_Node *cockpit_node =
                            node_to_replace->children.nodes[cockpit_node_index];
                        apply_node_transform(cockpit_mat, cockpit_node, nullptr);
                    }
                    renderer_drawGLTFPod(proj_matrix, view_matrix, engineR_mat, engineL_mat,
                                         cockpit_mat, replacement.model, envInfos, mirrored, 0);
                }
            }
        }
        // glPopDebugGroup();

        addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                  std::string(" player pod REPLACED \n"));
        replacedTries[model_id] |= replacementFlag::Mirrored | replacementFlag::Normal;

        return true;
    }

    if (replacedTries[model_id] == 0) {
        addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                  std::string(" player pod\n"));
        replacedTries[model_id] += 1;
    }

    return false;
}

bool try_replace_AIPod(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, const rdMatrix44 &model_matrix,
                       EnvInfos envInfos, bool mirrored) {
    // dedup pod id
    model_id = AnyPodModelToPodModel(model_id);

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist && replacedTries[model_id] == 0) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);

        // In a race
        if (currentPlayer_Test != nullptr) {
            rdMatrix44 scaled_model_mat;
            rdMatrix_ScaleBasis44(
                &scaled_model_mat, 1.2 / rdVector_Len3((rdVector3 *) &model_matrix.vA),
                1.2 / rdVector_Len3((rdVector3 *) &model_matrix.vB),
                1.2 / rdVector_Len3((rdVector3 *) &model_matrix.vC), &model_matrix);
            rdVector3 forward = {
                6.0f * scaled_model_mat.vB.x,
                6.0f * scaled_model_mat.vB.y,
                6.0f * scaled_model_mat.vB.z,
            };
            rdVector3 right = {
                2.5f * scaled_model_mat.vA.x,
                2.5f * scaled_model_mat.vA.y,
                2.5f * scaled_model_mat.vA.z,
            };
            rdVector3 left = {-right.x, -right.y, -right.z};

            rdMatrix44 engineR = scaled_model_mat;
            rdVector_Add3((rdVector3 *) &(engineR.vD), (rdVector3 *) &(engineR.vD), &forward);
            rdVector_Add3((rdVector3 *) &(engineR.vD), (rdVector3 *) &(engineR.vD), &right);

            rdMatrix44 engineL = scaled_model_mat;
            rdVector_Add3((rdVector3 *) &(engineL.vD), (rdVector3 *) &(engineL.vD), &forward);
            rdVector_Add3((rdVector3 *) &(engineL.vD), (rdVector3 *) &(engineL.vD), &left);

            renderer_drawGLTFPod(proj_matrix, view_matrix, engineR, engineL, scaled_model_mat,
                                 replacement.model, envInfos, mirrored, 0);
        }
        // glPopDebugGroup();

        addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                  std::string(" AI Pod REPLACED \n"));
        replacedTries[model_id] |= replacementFlag::Mirrored | replacementFlag::Normal;

        return true;
    }

    if (replacedTries[model_id] == 0) {
        addImguiReplacementString(std::string(modelid_cstr[model_id]) + std::string(" ai pod\n"));
        replacedTries[model_id] += 1;
    }

    return false;
}

bool try_replace_track(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, EnvInfos envInfos, bool mirrored) {

    load_replacement_if_missing(model_id);

    ReplacementModel &replacement = replacement_map[model_id];
    if (replacement.fileExist && replacedTries[model_id] == 0) {
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(modelid_cstr[model_id]),
        //                  modelid_cstr[model_id]);

        // In a race
        if (currentPlayer_Test != nullptr) {
            rdMatrix44 adjusted_model_matrix = {
                {100.0, 0.0, 0.0, 0.0},
                {0.0, 100.0, 0.0, 0.0},
                {0.0, 0.0, 100.0, 0.0},
                {0.0, 0.0, 0.0, 1.0},
            };
            renderer_drawGLTF(proj_matrix, view_matrix, adjusted_model_matrix, replacement.model,
                              envInfos, mirrored, 0);
        }
        // glPopDebugGroup();

        addImguiReplacementString(std::string(modelid_cstr[model_id]) +
                                  std::string(" Track REPLACED \n"));
        replacedTries[model_id] |= replacementFlag::Mirrored | replacementFlag::Normal;

        return true;
    }

    if (replacedTries[model_id] == 0) {
        addImguiReplacementString(std::string(modelid_cstr[model_id]) + std::string(" Track\n"));
        replacedTries[model_id] += 1;
    }

    return false;
}
