// Tracks > Account: the panel over junkyard_account.h.
#include "imgui.h"

#include "debug_ui.h"
#include "junkyard_account.h"

namespace {
    void panel_account() {
        const AccountStatus account = junkyard_account_Status();

        switch (account.state) {
            case AccountState::SignedOut:
                ImGui::TextUnformatted("Not signed in.");
                if (ImGui::Button("Sign in with Discord"))
                    junkyard_account_SignIn();
                break;

            case AccountState::Linking:
                ImGui::TextUnformatted("Approve this game in your browser. The page asks for:");
                ImGui::SetWindowFontScale(1.6f);
                ImGui::TextUnformatted(account.code.c_str());
                ImGui::SetWindowFontScale(1.0f);
                ImGui::TextDisabled("%s", account.verify_url.c_str());
                if (ImGui::Button("Open the page again"))
                    junkyard_account_OpenVerifyPage();
                ImGui::SameLine();
                if (ImGui::Button("Cancel"))
                    junkyard_account_CancelSignIn();
                break;

            case AccountState::SignedIn:
                ImGui::Text("Signed in as %s",
                            account.username.empty() ? "(unknown)" : account.username.c_str());
                if (ImGui::Button("Sign out"))
                    junkyard_account_SignOut();
                break;
        }

        if (!account.message.empty())
            ImGui::TextDisabled("%s", account.message.c_str());

        ImGui::Separator();

        bool auto_submit = junkyard_account_AutoSubmit();
        if (ImGui::Checkbox("Submit new records automatically", &auto_submit))
            junkyard_account_SetAutoSubmit(auto_submit);

        ImGui::Text("%d record(s) waiting to be submitted", account.pending_submissions);
        ImGui::BeginDisabled(account.state != AccountState::SignedIn ||
                             account.pending_submissions == 0);
        if (ImGui::Button("Submit now"))
            junkyard_account_SubmitPending();
        ImGui::EndDisabled();

        ImGui::TextDisabled("Nothing leaves this machine unless you are signed in. Signing out\n"
                            "revokes the token and deletes assets/junkyard_token.json.");
    }

    DebugPanel g_panel_account = {.category = "Tracks",
                                  .name = "Account",
                                  .draw = panel_account,
                                  .dev_only = false};
}

void account_panel_RegisterPanel() {
    debug_ui_register(&g_panel_account);
}
