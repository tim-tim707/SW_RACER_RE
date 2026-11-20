#include "http_client.h"

#include <windows.h>
#include <winhttp.h>

namespace {
    // Requests are small (a catalog, a record) or a few MB (one asset), and the game must never
    // wait on the network, so a modest timeout is enough.
    constexpr int TIMEOUT_MS = 15000;
    constexpr uint64_t MAX_RESPONSE_BYTES = 64ull * 1024 * 1024;

    std::wstring widen(const std::string &text) {
        if (text.empty())
            return std::wstring();
        const int size =
            MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), nullptr, 0);
        std::wstring wide(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), wide.data(), size);
        return wide;
    }

    bool read_body(HINTERNET request, std::vector<uint8_t> *out, std::string *error,
                   const std::string &url) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available) {
            if (out->size() + available > MAX_RESPONSE_BYTES) {
                *error = "response larger than the " + std::to_string(MAX_RESPONSE_BYTES) +
                    " byte limit";
                return false;
            }
            const size_t offset = out->size();
            out->resize(offset + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, out->data() + offset, available, &read)) {
                *error = "read failed partway through " + url;
                return false;
            }
            out->resize(offset + read);
        }
        return true;
    }
}

bool http_Request(const HttpRequest &req, HttpResponse *response, std::string *error) {
    response->status = 0;
    response->body.clear();

    const std::wstring wide_url = widen(req.url);
    URL_COMPONENTS parts = {};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    parts.lpszHostName = host;
    parts.dwHostNameLength = (DWORD) std::size(host);
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = (DWORD) std::size(path);
    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &parts)) {
        *error = "not a usable URL: " + req.url;
        return false;
    }

    HINTERNET session = WinHttpOpen(L"SW_RACER_RE", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        *error = "could not open an HTTP session";
        return false;
    }
    WinHttpSetTimeouts(session, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS);

    std::wstring headers;
    for (const auto &[name, value]: req.headers)
        headers += widen(name) + L": " + widen(value) + L"\r\n";

    bool ok = false;
    HINTERNET connection = WinHttpConnect(session, host, parts.nPort, 0);
    if (connection) {
        const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET request =
            WinHttpOpenRequest(connection, widen(req.method).c_str(), path, nullptr,
                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (request) {
            // WinHttpSendRequest wants a mutable body pointer; it does not write through it.
            void *body = req.body.empty() ? WINHTTP_NO_REQUEST_DATA
                                          : (void *) const_cast<char *>(req.body.data());
            const DWORD body_size = (DWORD) req.body.size();
            if (WinHttpSendRequest(request,
                                   headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
                                                   : headers.c_str(),
                                   headers.empty() ? 0 : (DWORD) -1, body, body_size, body_size,
                                   0) &&
                WinHttpReceiveResponse(request, nullptr)) {
                DWORD code = 0;
                DWORD code_size = sizeof(code);
                WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &code, &code_size,
                                    WINHTTP_NO_HEADER_INDEX);
                response->status = (int) code;
                ok = read_body(request, &response->body, error, req.url);
            } else {
                *error = "request failed (" + std::to_string(GetLastError()) + ") for " + req.url;
            }
            WinHttpCloseHandle(request);
        } else {
            *error = "could not build a request for " + req.url;
        }
        WinHttpCloseHandle(connection);
    } else {
        *error = "could not reach the host of " + req.url;
    }
    WinHttpCloseHandle(session);
    return ok;
}

bool http_Get(const std::string &url, std::vector<uint8_t> *out, std::string *error) {
    HttpResponse response;
    if (!http_Request({"GET", url, {}, ""}, &response, error))
        return false;
    if (response.status != 200) {
        *error = "HTTP " + std::to_string(response.status) + " for " + url;
        return false;
    }
    *out = std::move(response.body);
    return true;
}
