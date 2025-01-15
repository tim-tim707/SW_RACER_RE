#pragma once

#include "../tinygltf/gltf_utils.h"

extern EnvInfos envInfos;
extern int frameCount;
extern bool environment_models_drawn;

void swrViewport_Render_delta(int x);
