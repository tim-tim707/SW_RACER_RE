#include "update_check.h"

#include <algorithm>
#include <atomic>
#include <string>
#include <vector>
#include <cstdlib>

#include <windows.h>
#include <winhttp.h>
#include <simdjson.h>

#include "build_id.h"

static const wchar_t *const k_api_host = L"api.github.com";
static const wchar_t *const k_api_path = L"/repos/tim-tim707/SW_RACER_RE/releases/latest";

static std::atomic<int> g_state{UPDATE_CHECK_IDLE};
// Written by the worker before it publishes the final state, read only after.
static std::string g_latest_tag;
static std::string g_release_url;

// "v0.18.1" -> {0, 18, 1}. Anything after the numeric part (e.g. "-rc1") is ignored.
static std::vector<int> parse_version(const std::string &tag) {
    std::vector<int> parts;
    const char *s = tag.c_str();
    if (*s == 'v' || *s == 'V')
        s++;
    while (*s >= '0' && *s <= '9') {
        char *end = nullptr;
        parts.push_back((int) std::strtol(s, &end, 10));
        s = end;
        if (*s != '.')
            break;
        s++;
    }
    return parts;
}

static bool version_newer(const std::string &candidate, const std::string &current) {
    std::vector<int> a = parse_version(candidate);
    std::vector<int> b = parse_version(current);
    if (a.empty() || b.empty())
        return false;
    const size_t n = std::max(a.size(), b.size());
    a.resize(n, 0);
    b.resize(n, 0);
    return a > b;
}

static bool http_get(std::string *body) {
    bool ok = false;
    HINTERNET session = WinHttpOpen(L"SW_RACER_RE-update-check", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    if (session) {
        WinHttpSetTimeouts(session, 5000, 5000, 5000, 10000);
        connect = WinHttpConnect(session, k_api_host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    }
    if (connect)
        request = WinHttpOpenRequest(connect, L"GET", k_api_path, nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (request &&
        WinHttpSendRequest(request, L"Accept: application/vnd.github+json\r\n", (DWORD) -1L,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr)) {
        DWORD status = 0;
        DWORD size = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
        if (status == 200) {
            DWORD avail = 0;
            while (WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
                const size_t old = body->size();
                body->resize(old + avail);
                DWORD read = 0;
                if (!WinHttpReadData(request, &(*body)[old], avail, &read))
                    break;
                body->resize(old + read);
            }
            ok = !body->empty();
        }
    }
    if (request)
        WinHttpCloseHandle(request);
    if (connect)
        WinHttpCloseHandle(connect);
    if (session)
        WinHttpCloseHandle(session);
    return ok;
}

static DWORD WINAPI check_thread(LPVOID) {
    std::string body;
    int result = UPDATE_CHECK_FAILED;
    if (http_get(&body)) {
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        std::string_view tag;
        std::string_view url;
        if (parser.parse(body).get(root) == simdjson::SUCCESS &&
            root["tag_name"].get(tag) == simdjson::SUCCESS) {
            g_latest_tag = std::string(tag);
            g_release_url = root["html_url"].get(url) == simdjson::SUCCESS
                                ? std::string(url)
                                : "https://github.com/tim-tim707/SW_RACER_RE/releases/latest";
            result = version_newer(g_latest_tag, SWR_BUILD_VERSION) ? UPDATE_CHECK_AVAILABLE
                                                                    : UPDATE_CHECK_UP_TO_DATE;
        }
    }
    g_state.store(result, std::memory_order_release);
    return 0;
}

bool update_check_supported() {
    return SWR_BUILD_VERSION[0] != '\0';
}

void update_check_start() {
    if (!update_check_supported())
        return;
    int expected = g_state.load(std::memory_order_acquire);
    if (expected == UPDATE_CHECK_RUNNING)
        return;
    if (!g_state.compare_exchange_strong(expected, UPDATE_CHECK_RUNNING))
        return;
    HANDLE thread = CreateThread(nullptr, 0, check_thread, nullptr, 0, nullptr);
    if (thread)
        CloseHandle(thread);
    else
        g_state.store(UPDATE_CHECK_FAILED, std::memory_order_release);
}

UpdateCheckState update_check_state() {
    return (UpdateCheckState) g_state.load(std::memory_order_acquire);
}

const char *update_check_latest_tag() {
    return g_latest_tag.c_str();
}

const char *update_check_release_url() {
    return g_release_url.c_str();
}
