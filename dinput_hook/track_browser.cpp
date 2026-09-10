//
// The in-game track browser: the panel over track_catalog.h.
//
// Downloading and installing happen on the catalog's worker thread; this only reads its state and
// enqueues work, so a slow or dead catalog cannot stall a frame. A track installed while the game
// is running is picked up by a registry rescan, which appends to the track table -- safe at any
// time, because existing indices never move.
//
#include <cstdio>
#include <string>

#include "imgui.h"

#include "debug_ui.h"
#include "track_catalog.h"
#include "track_registry.h"

namespace {
    std::string human_bytes(uint64_t bytes) {
        char text[32];
        if (bytes >= 1024 * 1024)
            snprintf(text, sizeof(text), "%.1f MB", (double) bytes / (1024 * 1024));
        else if (bytes >= 1024)
            snprintf(text, sizeof(text), "%.0f KB", (double) bytes / 1024);
        else
            snprintf(text, sizeof(text), "%llu B", (unsigned long long) bytes);
        return text;
    }

    void panel_track_browser() {
        const CatalogStatus status = track_catalog_Status();

        ImGui::TextUnformatted(track_catalog_Url().c_str());
        if (ImGui::Button("Refresh"))
            track_catalog_Refresh();

        const bool busy = status.state == CatalogState::Fetching ||
            status.state == CatalogState::Downloading;
        if (busy) {
            ImGui::SameLine();
            ImGui::TextUnformatted(status.message.c_str());
            if (status.bytes_total != 0) {
                const float fraction = (float) ((double) status.bytes_done / status.bytes_total);
                ImGui::ProgressBar(fraction, ImVec2(-1, 0),
                                   (human_bytes(status.bytes_done) + " / " +
                                    human_bytes(status.bytes_total))
                                       .c_str());
            }
        } else if (status.state == CatalogState::Failed) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", status.message.c_str());
        } else if (!status.message.empty()) {
            ImGui::SameLine();
            ImGui::TextUnformatted(status.message.c_str());
        }

        // A track installed mid-session only reaches the menus once the registry has it. Doing it
        // here keeps it on the game thread, and out of a race.
        if (track_catalog_TakePendingRescan())
            track_registry_Rescan();

        const std::vector<CatalogTrack> tracks = track_catalog_Tracks();
        if (tracks.empty()) {
            ImGui::TextDisabled("No catalog loaded yet.");
            return;
        }

        if (ImGui::BeginTable("tracks", 4,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Track");
            ImGui::TableSetupColumn("Author");
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableHeadersRow();

            for (const CatalogTrack &track: tracks) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(track.name.empty() ? track.slug.c_str()
                                                          : track.name.c_str());
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s\nversion %s", track.slug.c_str(), track.version.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(track.author.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(human_bytes(track.download_bytes).c_str());

                ImGui::TableNextColumn();
                if (track.installed) {
                    ImGui::TextDisabled("installed");
                } else {
                    ImGui::BeginDisabled(busy);
                    ImGui::PushID(track.slug.c_str());
                    if (ImGui::Button("Download"))
                        track_catalog_Install(track.slug);
                    ImGui::PopID();
                    ImGui::EndDisabled();
                }
            }
            ImGui::EndTable();
        }

        ImGui::TextDisabled("Only assets this install is missing are downloaded.");
    }

    DebugPanel g_panel_track_browser = {.category = "Tracks",
                                        .name = "Track browser",
                                        .draw = panel_track_browser,
                                        .dev_only = false};
}

void track_browser_RegisterPanel() {
    debug_ui_register(&g_panel_track_browser);
}
