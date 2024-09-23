#include "replacements.h"
#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"

extern std::vector<tinygltf::Model> g_models;

extern "C" {
#include <Swr/swrModel.h>
}

bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix) {
    if ((model_id >= MODELID_part_control01_part && model_id <= MODELID_part_control05_part) ||
        (model_id >= MODELID_part_airbrake1_part && model_id <= MODELID_part_thrust6_part) ||
        (model_id >= MODELID_part_accel01_part && model_id <= MODELID_part_grip03_part) ||
        (model_id >= MODELID_part_powercell01_part && model_id <= MODELID_part_powercell06_part)) {
        // renderer_drawTetrahedron(proj_matrix, view_matrix, model_matrix);
        renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[1]);
        return true;
    }

    if (model_id == MODELID_part_grip04_part) {
        renderer_drawCube(proj_matrix, view_matrix, model_matrix);
        // renderer_drawGLTF(proj_matrix, view_matrix, model_matrix, g_models[0]);
        return true;
    }

    return false;
}
