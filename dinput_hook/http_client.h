// One HTTP request, whole response in memory, on the caller's thread -- which must never be the
// game thread. WinHTTP follows redirects itself (a blob GET is a 302 to storage), so callers see
// the final status.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct HttpRequest {
    std::string method;// "GET" / "POST"
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

struct HttpResponse {
    int status;// 0 when no response came back
    std::vector<uint8_t> body;
};

// False only when no response came back (bad URL, unreachable host, timeout, oversize). An HTTP
// error status is a true return with response->status set: the body then says why.
bool http_Request(const HttpRequest &request, HttpResponse *response, std::string *error);

// The two-endpoint download protocol's shape: anything but a 200 is an error with a message.
bool http_Get(const std::string &url, std::vector<uint8_t> *out, std::string *error);
