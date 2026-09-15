#include "junkyard_account.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include <windows.h>
#include <shellapi.h>

#include <simdjson.h>

#include "build_id.h"
#include "config.h"
#include "http_client.h"
#include "track_times.h"

extern "C" FILE *hook_log;

namespace {
    const char *TOKEN_PATH = "./assets/junkyard_token.json";
    constexpr int DEFAULT_POLL_INTERVAL_S = 3;
    constexpr int DEFAULT_LINK_TTL_S = 600;
    constexpr int CANCEL_CHECK_MS = 100;// how long a cancel or shutdown can wait on a sleeping worker
    constexpr size_t MAX_LOGGED_BODY = 2048;

    enum class Job { CheckToken, Link, Flush, Revoke };

    std::mutex state_mutex;
    AccountStatus status = {AccountState::SignedOut, "", "", "", "", 0};
    std::string token;// read under state_mutex; never logged

    std::mutex queue_mutex;
    std::condition_variable queue_signal;
    std::deque<Job> jobs;
    std::thread worker;
    std::atomic<bool> stopping{false};
    std::atomic<bool> cancel_link{false};

    const std::string &api_url() {
        static const std::string url =
            config::get_string("tracks", "api_url", "https://bottosjunkyard.com/api/v1");
        return url;
    }

    std::wstring widen(const std::string &text) {
        if (text.empty())
            return std::wstring();
        const int size =
            MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), nullptr, 0);
        std::wstring wide(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), wide.data(), size);
        return wide;
    }

    std::string escaped(const std::string &text) {
        std::string out;
        for (char c: text) {
            if (c == '"' || c == '\\') {
                out.push_back('\\');
                out.push_back(c);
            } else if ((unsigned char) c >= 0x20) {
                out.push_back(c);
            }
        }
        return out;
    }

    std::string get_string(simdjson::dom::element parent, const char *key) {
        std::string_view value;
        if (parent[key].get(value) != simdjson::SUCCESS)
            return std::string();
        return std::string(value);
    }

    void set_state(AccountState state, const std::string &message) {
        std::lock_guard<std::mutex> lock(state_mutex);
        status.state = state;
        status.message = message;
        if (state != AccountState::Linking) {
            status.code.clear();
            status.verify_url.clear();
        }
        if (state == AccountState::SignedOut)
            status.username.clear();
    }

    void log(const char *text) {
        fprintf(hook_log, "[junkyard] %s\n", text);
        fflush(hook_log);
    }

    void log(const std::string &text) {
        log(text.c_str());
    }

    // What the server sent back, trimmed so a stack trace cannot flood the log.
    std::string body_excerpt(const HttpResponse &response) {
        std::string text(response.body.begin(), response.body.end());
        if (text.size() > MAX_LOGGED_BODY)
            text.resize(MAX_LOGGED_BODY);
        return text;
    }

    bool load_token_file() {
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.load(TOKEN_PATH).get(root) != simdjson::SUCCESS)
            return false;
        const std::string stored = get_string(root, "token");
        if (stored.empty())
            return false;
        std::lock_guard<std::mutex> lock(state_mutex);
        token = stored;
        status.username = get_string(root, "username");
        status.state = AccountState::SignedIn;
        return true;
    }

    void save_token_file(const std::string &new_token, const std::string &user_id,
                         const std::string &username) {
        FILE *f = fopen(TOKEN_PATH, "wb");
        if (!f) {
            log(std::string("cannot write ") + TOKEN_PATH);
            return;
        }
        fprintf(f, "{\"token\": \"%s\", \"user_id\": \"%s\", \"username\": \"%s\"}\n",
                escaped(new_token).c_str(), escaped(user_id).c_str(), escaped(username).c_str());
        fclose(f);
    }

    void forget_token() {
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            token.clear();
        }
        remove(TOKEN_PATH);
    }

    std::string bearer() {
        std::lock_guard<std::mutex> lock(state_mutex);
        return token.empty() ? std::string() : "Bearer " + token;
    }

    bool signed_in() {
        std::lock_guard<std::mutex> lock(state_mutex);
        return status.state == AccountState::SignedIn && !token.empty();
    }

    void run_job(Job job);

    void enqueue(Job job) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!worker.joinable())
                worker = std::thread([] {
                    while (!stopping) {
                        Job job;
                        {
                            std::unique_lock<std::mutex> lock(queue_mutex);
                            queue_signal.wait(lock, [] { return stopping || !jobs.empty(); });
                            if (stopping)
                                return;
                            job = jobs.front();
                            jobs.pop_front();
                        }
                        run_job(job);
                    }
                });
            jobs.push_back(job);
        }
        queue_signal.notify_one();
    }

    bool wait_seconds(double seconds) {
        const auto until =
            std::chrono::steady_clock::now() + std::chrono::milliseconds((int) (seconds * 1000));
        while (std::chrono::steady_clock::now() < until) {
            if (stopping || cancel_link)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(CANCEL_CHECK_MS));
        }
        return true;
    }

    void open_in_browser(const std::string &url) {
        // The URL came from the server; only ever hand the shell an https page, never a scheme
        // that could run something.
        if (url.rfind("https://", 0) != 0)
            return;
        ShellExecuteW(nullptr, L"open", widen(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }

    void do_check_token() {
        const std::string auth = bearer();
        if (auth.empty())
            return;

        HttpResponse response;
        std::string error;
        if (!http_Request({"GET", api_url() + "/auth/game/me", {{"Authorization", auth}}, ""},
                          &response, &error)) {
            // Offline: keep the token and say so; the next boot tries again.
            set_state(AccountState::SignedIn, "could not reach the server: " + error);
            return;
        }
        if (response.status == 401) {
            forget_token();
            set_state(AccountState::SignedOut, "Your sign-in expired or was revoked. Sign in again.");
            log("stored token rejected; signed out");
            return;
        }
        if (response.status == 200) {
            simdjson::dom::parser parser;
            simdjson::dom::element root;
            simdjson::dom::element user;
            if (parser.parse(response.body.data(), response.body.size()).get(root) ==
                    simdjson::SUCCESS &&
                root["user"].get(user) == simdjson::SUCCESS) {
                std::lock_guard<std::mutex> lock(state_mutex);
                status.username = get_string(user, "username");
            }
            set_state(AccountState::SignedIn, "");
            enqueue(Job::Flush);
            return;
        }
        set_state(AccountState::SignedIn,
                  "server answered HTTP " + std::to_string(response.status) + " to a token check");
    }

    void do_link() {
        cancel_link = false;
        char host[64] = {};
        DWORD host_size = sizeof(host);
        GetComputerNameA(host, &host_size);

        const std::string body = std::string("{\"client\": \"SW_RACER_RE\", \"build\": \"") +
            escaped(std::string(SWR_BUILD_BRANCH) + "@" + SWR_BUILD_COMMIT) +
            "\", \"host\": \"" + escaped(host) + "\"}";

        HttpResponse response;
        std::string error;
        if (!http_Request({"POST", api_url() + "/auth/game/start",
                           {{"Content-Type", "application/json"}}, body},
                          &response, &error) ||
            response.status != 200) {
            set_state(AccountState::SignedOut,
                      response.status != 0 ? "sign-in could not start (HTTP " +
                                                 std::to_string(response.status) + ")"
                                           : "sign-in could not start: " + error);
            return;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.parse(response.body.data(), response.body.size()).get(root) !=
            simdjson::SUCCESS) {
            set_state(AccountState::SignedOut, "sign-in could not start: unreadable reply");
            return;
        }
        const std::string code = get_string(root, "code");
        const std::string poll_token = get_string(root, "poll_token");
        const std::string verify_url = get_string(root, "verify_url");
        int64_t expires_in = DEFAULT_LINK_TTL_S;
        root["expires_in"].get(expires_in);
        int64_t interval = DEFAULT_POLL_INTERVAL_S;
        root["interval"].get(interval);
        if (code.empty() || poll_token.empty() || verify_url.empty()) {
            set_state(AccountState::SignedOut, "sign-in could not start: incomplete reply");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(state_mutex);
            status.state = AccountState::Linking;
            status.code = code;
            status.verify_url = verify_url;
            status.message = "Approve this game in your browser.";
        }
        log("link code " + code + " shown for host " + host);
        open_in_browser(verify_url);

        const std::string poll_body = "{\"poll_token\": \"" + escaped(poll_token) + "\"}";
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds((int) expires_in);
        double wait = (double) (interval > 0 ? interval : DEFAULT_POLL_INTERVAL_S);

        while (std::chrono::steady_clock::now() < deadline) {
            if (!wait_seconds(wait)) {
                set_state(AccountState::SignedOut, cancel_link ? "Sign-in cancelled." : "");
                return;
            }

            HttpResponse poll;
            if (!http_Request({"POST", api_url() + "/auth/game/poll",
                               {{"Content-Type", "application/json"}}, poll_body},
                              &poll, &error)) {
                continue;// a blip; the deadline bounds how long this can go on
            }
            if (poll.status == 428)
                continue;
            if (poll.status == 429) {
                wait *= 2;
                continue;
            }
            if (poll.status == 200) {
                simdjson::dom::element reply;
                simdjson::dom::element user;
                if (parser.parse(poll.body.data(), poll.body.size()).get(reply) !=
                        simdjson::SUCCESS ||
                    get_string(reply, "token").empty()) {
                    set_state(AccountState::SignedOut, "sign-in failed: unreadable token reply");
                    return;
                }
                const std::string new_token = get_string(reply, "token");
                std::string user_id;
                std::string username;
                if (reply["user"].get(user) == simdjson::SUCCESS) {
                    user_id = get_string(user, "id");
                    username = get_string(user, "username");
                }
                save_token_file(new_token, user_id, username);
                {
                    std::lock_guard<std::mutex> lock(state_mutex);
                    token = new_token;
                    status.username = username;
                }
                set_state(AccountState::SignedIn, "");
                log("signed in as " + username);
                enqueue(Job::Flush);
                return;
            }
            if (poll.status == 410) {
                simdjson::dom::element reply;
                std::string why = "expired";
                if (parser.parse(poll.body.data(), poll.body.size()).get(reply) ==
                    simdjson::SUCCESS)
                    why = get_string(reply, "status");
                set_state(AccountState::SignedOut,
                          why == "denied" ? "Sign-in was denied on the website."
                                          : "The sign-in code expired. Try again.");
                return;
            }
            set_state(AccountState::SignedOut,
                      "sign-in failed (HTTP " + std::to_string(poll.status) + ")");
            return;
        }
        set_state(AccountState::SignedOut, "The sign-in code expired. Try again.");
    }

    void do_flush() {
        const std::string auth = bearer();
        if (auth.empty())
            return;

        std::vector<TrackTimeKey> keys;
        const std::string body = track_times_PendingSubmissionBody(&keys);
        if (keys.empty())
            return;

        HttpResponse response;
        std::string error;
        if (!http_Request({"POST", api_url() + "/customtracks/times",
                           {{"Authorization", auth}, {"Content-Type", "application/json"}}, body},
                          &response, &error)) {
            set_state(AccountState::SignedIn, "records not sent: " + error);
            return;
        }
        if (response.status == 200) {
            track_times_MarkSubmission(keys, "done");
            log(std::to_string(keys.size()) + " record(s) submitted");
            set_state(AccountState::SignedIn,
                      std::to_string(keys.size()) + " record(s) submitted");
            return;
        }
        if (response.status == 401) {
            forget_token();
            set_state(AccountState::SignedOut, "Your sign-in expired or was revoked. Sign in again.");
            log("submission rejected 401; signed out");
            return;
        }
        if (response.status == 422) {
            // The data itself is wrong; retrying the same bytes would fail the same way.
            track_times_MarkSubmission(keys, "rejected");
            log("submission rejected 422: " + body_excerpt(response));
            set_state(AccountState::SignedIn, "the server rejected " +
                                                  std::to_string(keys.size()) +
                                                  " record(s); see hook.log");
            return;
        }
        // Anything else is the server's problem, and the records stay pending for next time.
        log("submission got HTTP " + std::to_string(response.status) + ": " +
            body_excerpt(response));
        set_state(AccountState::SignedIn,
                  "records not sent (HTTP " + std::to_string(response.status) + "); will retry");
    }

    void do_revoke() {
        const std::string auth = bearer();
        if (!auth.empty()) {
            HttpResponse response;
            std::string error;
            http_Request({"POST", api_url() + "/auth/game/revoke", {{"Authorization", auth}}, ""},
                         &response, &error);
        }
        forget_token();
        set_state(AccountState::SignedOut, "Signed out.");
        log("signed out");
    }

    void run_job(Job job) {
        switch (job) {
            case Job::CheckToken:
                do_check_token();
                break;
            case Job::Link:
                do_link();
                break;
            case Job::Flush:
                do_flush();
                break;
            case Job::Revoke:
                do_revoke();
                break;
        }
    }
}

void junkyard_account_Init() {
    if (load_token_file()) {
        log("stored sign-in found; checking it");
        enqueue(Job::CheckToken);
    }
}

void junkyard_account_Shutdown() {
    stopping = true;
    cancel_link = true;
    queue_signal.notify_all();
    if (worker.joinable())
        worker.join();
}

void junkyard_account_SignIn() {
    if (signed_in())
        return;
    enqueue(Job::Link);
}

void junkyard_account_CancelSignIn() {
    cancel_link = true;
}

void junkyard_account_OpenVerifyPage() {
    std::string url;
    {
        std::lock_guard<std::mutex> lock(state_mutex);
        url = status.verify_url;
    }
    open_in_browser(url);
}

void junkyard_account_SignOut() {
    cancel_link = true;
    enqueue(Job::Revoke);
}

void junkyard_account_SubmitPending() {
    if (signed_in())
        enqueue(Job::Flush);
}

bool junkyard_account_AutoSubmit() {
    return config::get_int("tracks", "auto_submit", 1) != 0;
}

void junkyard_account_SetAutoSubmit(bool enabled) {
    config::set_int("tracks", "auto_submit", enabled ? 1 : 0);
    config::save();
}

AccountStatus junkyard_account_Status() {
    AccountStatus snapshot;
    {
        std::lock_guard<std::mutex> lock(state_mutex);
        snapshot = status;
    }
    snapshot.pending_submissions = track_times_PendingCount();
    return snapshot;
}

void junkyard_account_OnRecordStored() {
    if (signed_in() && junkyard_account_AutoSubmit())
        enqueue(Job::Flush);
}
