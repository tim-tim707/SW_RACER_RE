#pragma once

// Mod identity + community links, surfaced in the debug-overlay header and used
// by the update check. Keep this the single source of truth: bump MOD_VERSION
// when cutting a build/tag so the GitHub release check (update_check.cpp) can
// tell players when a newer release is out.

// Short display name shown in the overlay header.
#define MOD_NAME "SWE1R-RE"

// Current build version. Matches the git tag / GitHub release tag_name so the
// update check can compare directly (e.g. "v0.15"). Bump on every release.
#define MOD_VERSION "v0.15"

// Canonical repository the links and the release check point at. Owner/repo are
// kept separate so update_check.cpp can build the api.github.com path from them.
#define MOD_GITHUB_OWNER "tim-tim707"
#define MOD_GITHUB_REPO "SW_RACER_RE"

#define MOD_GITHUB_URL "https://github.com/" MOD_GITHUB_OWNER "/" MOD_GITHUB_REPO
#define MOD_ISSUES_URL MOD_GITHUB_URL "/issues/new"
#define MOD_RELEASES_URL MOD_GITHUB_URL "/releases"
#define MOD_DISCORD_URL "https://discord.gg/qYBKSGuKHJ"
