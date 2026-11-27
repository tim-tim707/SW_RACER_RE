#pragma once

// Asks GitHub for the latest SW_RACER_RE release on a background thread and
// compares its tag with the version this build was stamped with (build_id.h).

enum UpdateCheckState {
    UPDATE_CHECK_IDLE,       // not started (disabled, or no version stamp to compare)
    UPDATE_CHECK_RUNNING,
    UPDATE_CHECK_UP_TO_DATE,
    UPDATE_CHECK_AVAILABLE,  // update_check_latest_tag() is newer than this build
    UPDATE_CHECK_FAILED,
};

// Starts a check unless one is running. Safe to call every frame.
void update_check_start();

UpdateCheckState update_check_state();

// Valid once the state is UP_TO_DATE or AVAILABLE.
const char *update_check_latest_tag();
const char *update_check_release_url();
// Plain-text notes for the latest release (may be empty); '#' lines are headings.
const char *update_check_release_notes();

// Whether this build has a release version to compare against.
bool update_check_supported();
