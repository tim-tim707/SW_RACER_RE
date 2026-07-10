//
// The contextual "Randomizer" dialog. Unlike the F5 debug panels, this is a
// standalone window drawn every frame from imgui_Update and gated on game state:
// it appears ONLY while the player is on the new-profile name-entry screen, so the
// player opts into randomization exactly when creating the profile it locks to.
// See randomizer.h / RANDOMIZER_ROADMAP.md.
//
// UI only -- the seed/RNG/config logic and the game-side appliers live elsewhere.
//

#include "randomizer.h"

#include <imgui.h>

extern "C" {
#include <globals.h>
#include <Swr/swrUI.h>
}

// The swrUI page id of the profile select/create screen (the top-of-stack page's
// `id` field equals this only on that screen). Confirmed at runtime; all pages are
// pre-built into one tree, so searching by widget id can't distinguish screens --
// the current-page id can.
static const int SWRUI_PAGE_PROFILE_SELECT = 0x2736;

// The name text-entry widget on that page. It is hidden while browsing existing
// profiles and shown (RunCallbacks2(entry,1) = widget msg 0xe) once the "New" button
// (0x2737) is pressed -- so its visibility is our "creating a new profile" signal.
static const int SWRUI_WIDGET_NAME_ENTRY = 0x2731;

// swrUI element "visible" flag (0x40). Not yet in the swrUI_FLAG enum (only noted in
// the swrUI_unk comment); kept local until confirmed, then can be promoted.
static const int SWRUI_FLAG_VISIBLE = 0x40;

// swrUI_GetById is address-only for the delta; call it via its address.
typedef swrUI_unk *(swrUI_GetById_t)(swrUI_unk *, int);

// Category rows, in display order. The enum is the source of truth; this is labels.
// `implemented` gates whether the applier actually exists yet -- unimplemented ones
// are shown disabled so the dialog never promises an effect it can't deliver.
struct RandomizerCategoryRow {
    RandomizerCategory cat;
    const char *label;
    const char *help;
    bool implemented;
};

static const RandomizerCategoryRow CATEGORY_ROWS[] = {
    {RANDOMIZER_CAT_TRACK_ORDER, "Tracks (Shuffle)",
     "Shuffle the track order within each circuit.", true},
    {RANDOMIZER_CAT_POD_HANDLING, "Pod Handling (Shuffle)",
     "Swap the pods' handling profiles between pods.", true},
    {RANDOMIZER_CAT_STARTING_MONEY, "Starting Truguts", "Randomize the starting truguts.", true},
    {RANDOMIZER_CAT_SHOP_PRICES, "Shop Prices", "Shuffle the pod-part upgrade prices.", true},
    {RANDOMIZER_CAT_WINNINGS, "Race Winnings",
     "Shuffle the prize truguts paid per finishing place.", true},
    {RANDOMIZER_CAT_STARTING_UNLOCKS, "Starting Pods",
     "Randomize which pods start unlocked.", true},
    {RANDOMIZER_CAT_TRACK_FAVORITE, "Track Favorites",
     "Randomize which pod each track unlocks on a win.", true},
    {RANDOMIZER_CAT_MIRROR, "Mirror Mode", "Randomize which tracks are mirrored.", true},
    {RANDOMIZER_CAT_LAPS, "Lap Count", "Randomize each track's lap count (1-5).", true},
    {RANDOMIZER_CAT_AI_DIFFICULTY, "AI Difficulty/Spread",
     "Randomize each track's opponent skill and spread.", true},
};

void randomizer_render_overlay() {
    static bool was_shown = false;

    // Draw only while the player is on the profile select/create screen AND actually creating a
    // NEW profile (the name text-entry is shown), not while browsing existing profiles.
    swrUI_unk *page = swrUI_GetCurrentPage();
    swrUI_unk *nameEntry =
        (page && page->id == SWRUI_PAGE_PROFILE_SELECT)
            ? ((swrUI_GetById_t *) swrUI_GetById_ADDR)(page, SWRUI_WIDGET_NAME_ENTRY)
            : nullptr;
    bool on_screen = nameEntry && (nameEntry->flags & SWRUI_FLAG_VISIBLE);
    if (!on_screen) {
        was_shown = false;
        return;
    }

    // Each time the create dialog appears, default "Randomize this profile" to OFF (don't carry
    // the master toggle over between profile creations). Category selections are preserved.
    if (!was_shown) {
        RandomizerConfig c = randomizer_pending_config();
        if (c.master) {
            c.master = false;
            randomizer_set_pending_config(&c);
        }
        was_shown = true;
    }

    ImGuiIO &io = ImGui::GetIO();
    // Anchored to the right edge, vertically centered.
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x - 20.0f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_Appearing, ImVec2(1.0f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(360, 0), ImGuiCond_Appearing);

    if (ImGui::Begin("Randomizer", nullptr,
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("The profile name you enter becomes the randomization seed, and "
                           "these choices lock to this profile for its lifetime.");
        ImGui::Separator();

        // Edit the config staged for the profile about to be created. The creation
        // hook freezes this into the new profile's sidecar.
        RandomizerConfig pending = randomizer_pending_config();
        bool changed = false;

        changed |= ImGui::Checkbox("Randomize this profile", &pending.master);
        if (pending.master) {
            ImGui::Indent();

            if (ImGui::SmallButton("Randomize all")) {
                for (const RandomizerCategoryRow &row: CATEGORY_ROWS)
                    if (row.implemented)
                        pending.categories[row.cat] = true;
                changed = true;
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Clear all")) {
                for (const RandomizerCategoryRow &row: CATEGORY_ROWS)
                    pending.categories[row.cat] = false;
                changed = true;
            }

            for (const RandomizerCategoryRow &row: CATEGORY_ROWS) {
                if (!row.implemented) {
                    // Not wired up yet: show disabled + forced off so it can't be selected.
                    if (pending.categories[row.cat]) {
                        pending.categories[row.cat] = false;
                        changed = true;
                    }
                    ImGui::BeginDisabled();
                    bool off = false;
                    ImGui::Checkbox(row.label, &off);
                    ImGui::SameLine();
                    ImGui::TextDisabled("(coming soon)");
                    ImGui::EndDisabled();
                    continue;
                }
                changed |= ImGui::Checkbox(row.label, &pending.categories[row.cat]);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", row.help);

                // Starting Pods: how many pods begin unlocked.
                if (row.cat == RANDOMIZER_CAT_STARTING_UNLOCKS && pending.categories[row.cat]) {
                    ImGui::Indent();
                    if (pending.starting_pod_count < 1)
                        pending.starting_pod_count = 1;
                    if (ImGui::SliderInt("# starting pods", &pending.starting_pod_count, 1, 23))
                        changed = true;
                    ImGui::Unindent();
                }
            }
            ImGui::Unindent();
        } else {
            ImGui::TextDisabled("(off = a normal, vanilla profile)");
        }

        if (changed)
            randomizer_set_pending_config(&pending);

        // Live seed preview from the name being typed, and publish the creation intent
        // so arming can freeze this config into the profile once it is committed.
        const char *typedName = nameEntry->str_allocated;
        ImGui::Separator();
        if (typedName && typedName[0]) {
            ImGui::Text("Seed: 0x%08X", randomizer_seed_from_name(typedName));
            randomizer_set_creation_intent(typedName, &pending);
        } else {
            ImGui::TextDisabled("Seed: (enter a name)");
        }
    }
    ImGui::End();
}
