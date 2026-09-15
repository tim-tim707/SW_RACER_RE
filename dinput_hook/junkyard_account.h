// The game's own junkyard identity, and the outbox that rides on it.
//
// Discord has no device grant and the game cannot host an OAuth redirect, so the website's login
// is the approval surface: the game asks botto-api for a short code, opens the approval page in
// the player's browser, and polls until the signed-in user approves. What comes back is a
// long-lived token scoped to what the game may do (submit records today), stored in
// assets/junkyard_token.json -- deliberately not the ini, which players paste into Discord -- and
// never written to hook.log. Signing out revokes it server-side and deletes the file.
//
// Signing in is the consent: once linked, a record that beats the local best is submitted, and
// the times file itself is the outbox (track_times.h: each record's `submission` state), so a
// run made offline goes up on the next boot with nothing extra to persist.
//
// Network work happens on one worker thread; the game thread reads the status snapshot.
#pragma once

#include <string>

enum class AccountState {
    SignedOut,
    Linking,// a code is shown and the worker is polling for approval
    SignedIn,
};

struct AccountStatus {
    AccountState state;
    std::string username;
    std::string code;      // while linking: what the approval page asks for
    std::string verify_url;// while linking: where to approve
    std::string message;   // last outcome or error, for the panel
    int pending_submissions;
};

// Loads a stored token, if any, and checks it against the server in the background.
void junkyard_account_Init();
// Stop the worker before the process exits; safe to call from either quit path.
extern "C" void junkyard_account_Shutdown();

void junkyard_account_SignIn();
void junkyard_account_CancelSignIn();
void junkyard_account_OpenVerifyPage();// the browser hop again, if the first one was missed
void junkyard_account_SignOut();

// Push whatever the outbox holds now, regardless of the auto-submit setting.
void junkyard_account_SubmitPending();

// Whether new records leave the machine on their own ([tracks] auto_submit). Only while signed in.
bool junkyard_account_AutoSubmit();
void junkyard_account_SetAutoSubmit(bool enabled);

AccountStatus junkyard_account_Status();

// Called by track_times when a record improved. Queues a submission if signed in and allowed.
void junkyard_account_OnRecordStored();
