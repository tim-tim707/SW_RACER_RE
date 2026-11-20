#pragma once

#include <filesystem>
#include <vector>

#include "types.h"

// Pod editor support (tools/pod_editor/pod_editor.html):
//   - Export: Mods > Pod Editor > "Export my pod" writes the local pod, as drawn in the next race
//     frame, to <workspace>/export/<Pod>.json (and assets/pod_edits/export/): every mesh's
//     triangles in the pod's frame with a stable "<model>:<file offset>" key, its textures, and the
//     pod layout (pilot, cockpit / engine frames, the pilot's swrRacer_PodVisualData row).
//   - Write: the editor's "Build & install" bakes the edited models into the workspace's
//     replacement_models; the panel's "Write into out_modelblock.bin" builds them into the game's
//     data (the stock file kept as out_modelblock.original.bin), "Restore original" puts it back.

// The workspace folder the editor builds into: Desktop\SWEP1R Pod Editor (created on first use,
// with replacement_models, pod_edits, export and a copy of the game's stock out_modelblock.bin).
// Empty if it can't be made.
const std::filesystem::path& pod_workspace();

// Export, called by the renderer: whether an export is waiting for a frame; every mesh drawn
// under one of the local pod's part nodes (part = partNodes index) with its world-space triangles
// and final texture coordinates; and the end of the scene walk (writes the file).
bool pod_edits_export_armed();
void pod_edits_export_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model_matrix,
                           const std::vector<float>& world_pos, const std::vector<float>& uv, unsigned texture,
                           bool textured);
void pod_edits_export_end_frame(bool in_race);

void pod_edits_register_panel();
