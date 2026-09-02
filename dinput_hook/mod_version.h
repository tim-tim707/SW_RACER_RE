#pragma once

// Mod identity + community links. Single source of truth: bump MOD_VERSION when cutting a
// build/tag, so the GitHub release check in update_check.cpp can compare against it.

#define MOD_NAME "SWE1R-RE"

// Must match the git tag / GitHub release tag_name (e.g. "v0.15") for the update check.
#define MOD_VERSION "v0.15"

// Owner/repo kept separate so update_check.cpp can build the api.github.com path.
#define MOD_GITHUB_OWNER "tim-tim707"
#define MOD_GITHUB_REPO "SW_RACER_RE"

#define MOD_GITHUB_URL "https://github.com/" MOD_GITHUB_OWNER "/" MOD_GITHUB_REPO
#define MOD_ISSUES_URL MOD_GITHUB_URL "/issues/new"
#define MOD_RELEASES_URL MOD_GITHUB_URL "/releases"
#define MOD_DISCORD_URL "https://discord.gg/qYBKSGuKHJ"

#define MOD_SPEEDRUN_URL "https://www.speedrun.com/swe1r"
