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
    {RANDOMIZER_CAT_AI_DIFFICULTY, "AI difficulty", "Randomize each track's opponent skill.", true},
    {RANDOMIZER_CAT_STARTING_MONEY, "Starting money", "Randomize the starting truguts.", true},
    {RANDOMIZER_CAT_STARTING_UNLOCKS, "Starting pod unlocks",
     "Randomize which extra pods start unlocked.", true},
    {RANDOMIZER_CAT_TRACK_ORDER, "Track order", "Shuffle the order tracks are raced in.", true},
    {RANDOMIZER_CAT_POD_HANDLING, "Pod handling stats", "Shuffle the pods' handling stats.", true},
    {RANDOMIZER_CAT_TRACK_FAVORITE, "Track pod rewards",
     "Randomize which pod you unlock by winning each track.", true},
};

void randomizer_render_overlay() {
    // Draw only while the player is on the profile select/create screen...
    swrUI_unk *page = swrUI_GetCurrentPage();
    if (!page || page->id != SWRUI_PAGE_PROFILE_SELECT)
        return;

    // ...and only while actually creating a NEW profile (the name text-entry is shown),
    // not while browsing existing profiles.
    swrUI_unk *nameEntry = ((swrUI_GetById_t *) swrUI_GetById_ADDR)(page, SWRUI_WIDGET_NAME_ENTRY);
    if (!nameEntry || !(nameEntry->flags & SWRUI_FLAG_VISIBLE))
        return;

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
            for (const RandomizerCategoryRow &row: CATEGORY_ROWS) {
                if (!row.implemented) {
                    // Not wired up yet: show disabled + forced off so it can't be selected
                    // (and clear any stale stored value so it isn't frozen into a profile).
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
