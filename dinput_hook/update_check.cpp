#include "config.h"
#include "update_check.h"
#include "mod_version.h"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>
#include <winhttp.h>

// Forward-declared rather than included: those headers pull heavy transitive includes.
extern "C" FILE *hook_log;

namespace {

std::thread g_worker;
std::atomic<bool> g_started{false};
std::atomic<bool> g_update_available{false};
std::mutex g_result_mutex;
std::string g_latest_tag;
std::string g_latest_url;

// ASCII -> wide for WinHTTP; the host/path fed to it are ASCII literals.
std::wstring widen(const char *s) {
    std::wstring w;
    for (; *s; s++)
        w.push_back((wchar_t) (unsigned char) *s);
    return w;
}

// Value of a flat JSON string field. NOT a general JSON parser -- only two top-level string
// fields (tag_name, html_url) are needed out of the releases/latest body.
std::string json_string_field(const std::string &body, const char *key) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t k = body.find(needle);
    if (k == std::string::npos)
        return {};
    size_t colon = body.find(':', k + needle.size());
    if (colon == std::string::npos)
        return {};
    size_t open = body.find('"', colon + 1);
    if (open == std::string::npos)
        return {};

    std::string out;
    for (size_t i = open + 1; i < body.size(); i++) {
        char c = body[i];
        if (c == '\\' && i + 1 < body.size()) {
            out.push_back(body[++i]);// copy the escaped char verbatim (good enough for URLs/tags)
            continue;
        }
        if (c == '"')
            break;
        out.push_back(c);
    }
    return out;
}

// Numeric components of a version tag, ignoring a leading 'v' ("v0.2.15" -> {0,2,15}).
std::vector<int> parse_version(const std::string &s) {
    std::vector<int> parts;
    int cur = 0;
    bool in_num = false;
    for (char c: s) {
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            in_num = true;
        } else if (in_num) {
            parts.push_back(cur);
            cur = 0;
            in_num = false;
        }
    }
    if (in_num)
        parts.push_back(cur);
    return parts;
}

// Component-wise, so no lexicographic "v0.9 > v0.10" trap. Missing components count as 0.
bool version_greater(const std::string &a, const std::string &b) {
    const std::vector<int> va = parse_version(a);
    const std::vector<int> vb = parse_version(b);
    const size_t n = va.size() > vb.size() ? va.size() : vb.size();
    for (size_t i = 0; i < n; i++) {
        const int x = i < va.size() ? va[i] : 0;
        const int y = i < vb.size() ? vb[i] : 0;
        if (x != y)
            return x > y;
    }
    return false;
}

// Blocking HTTPS GET; worker thread only. Empty on any failure -- a failed check is silent.
std::string http_get_latest_release() {
    std::string body;

    HINTERNET session = WinHttpOpen(L"SWE1R-RE-UpdateCheck", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return body;
    // Bound every phase (resolve, connect, send, receive in ms) so a filtered network cannot wedge
    // the worker.
    WinHttpSetTimeouts(session, 5000, 5000, 5000, 7000);

    HINTERNET connect = WinHttpConnect(session, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connect) {
        const std::wstring path =
            widen("/repos/" MOD_GITHUB_OWNER "/" MOD_GITHUB_REPO "/releases/latest");
        HINTERNET request =
            WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                               WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request) {
            // GitHub requires a User-Agent (set via WinHttpOpen above).
            const wchar_t *accept = L"Accept: application/vnd.github+json\r\n";
            if (WinHttpSendRequest(request, accept, (DWORD) -1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(request, nullptr)) {
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(request, &avail) || avail == 0)
                        break;
                    std::string chunk(avail, '\0');
                    DWORD read = 0;
                    if (!WinHttpReadData(request, &chunk[0], avail, &read) || read == 0)
                        break;
                    chunk.resize(read);
                    body += chunk;
                }
            }
            WinHttpCloseHandle(request);
        }
        WinHttpCloseHandle(connect);
    }
    WinHttpCloseHandle(session);
    return body;
}

void worker_main() {
    const std::string body = http_get_latest_release();
    const std::string tag = json_string_field(body, "tag_name");
    const std::string url = json_string_field(body, "html_url");

    if (!tag.empty()) {
        const bool newer = version_greater(tag, MOD_VERSION);
        {
            std::lock_guard<std::mutex> lock(g_result_mutex);
            g_latest_tag = tag;
            g_latest_url = url.empty() ? std::string(MOD_RELEASES_URL) : url;
        }
        g_update_available.store(newer);
        if (hook_log) {
            fprintf(hook_log, "[update_check] current=%s latest=%s -> %s\n", MOD_VERSION,
                    tag.c_str(), newer ? "update available" : "up to date");
            fflush(hook_log);
        }
    } else if (hook_log) {
        fprintf(hook_log, "[update_check] no release info (offline or request failed)\n");
        fflush(hook_log);
    }
}

}// namespace

extern "C" void update_check_start(void) {
    if (g_started.exchange(true))
        return;// already kicked off
    if (!config::get_int("settings", "check_updates", 1))
        return;// player opted out
    g_worker = std::thread(worker_main);
}

extern "C" void update_check_join(void) {
    if (g_worker.joinable())
        g_worker.join();
}

bool update_check_get_result(std::string *out_latest, std::string *out_url) {
    if (!g_update_available.load())
        return false;
    std::lock_guard<std::mutex> lock(g_result_mutex);
    if (out_latest)
        *out_latest = g_latest_tag;
    if (out_url)
        *out_url = g_latest_url;
    return true;
}
