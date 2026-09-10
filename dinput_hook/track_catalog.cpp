#include "track_catalog.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <thread>

#include <windows.h>
#include <winhttp.h>

#include <simdjson.h>

#include "config.h"
#include "track_manifest.h"

extern "C" FILE *hook_log;

namespace fs = std::filesystem;

namespace {
    // Requests are small (a catalog) or a few MB (one asset), and the game must never wait on the
    // network, so a modest timeout is enough and the worker owns all of it.
    constexpr int TIMEOUT_MS = 15000;
    constexpr uint64_t MAX_RESPONSE_BYTES = 64ull * 1024 * 1024;

    std::mutex state_mutex;
    CatalogStatus status = {CatalogState::Idle, "", "", 0, 0, 0};
    std::vector<CatalogTrack> tracks;
    std::atomic<bool> pending_rescan{false};

    std::mutex queue_mutex;
    std::condition_variable queue_signal;
    std::deque<std::string> install_queue;// slugs; "" means "refresh the catalog"
    std::thread worker;
    std::atomic<bool> stopping{false};

    void set_status(CatalogState state, const std::string &message,
                    const std::string &slug = std::string(), uint64_t done = 0,
                    uint64_t total = 0) {
        std::lock_guard<std::mutex> lock(state_mutex);
        status.state = state;
        status.message = message;
        status.active_slug = slug;
        status.bytes_done = done;
        status.bytes_total = total;
    }

    std::wstring widen(const std::string &text) {
        if (text.empty())
            return std::wstring();
        const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), nullptr, 0);
        std::wstring wide(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int) text.size(), wide.data(), size);
        return wide;
    }

    // One GET, whole response in memory. Fails loudly rather than half-succeeding: a partial body
    // would only be caught later by the hash check, and the message would be less useful.
    bool http_get(const std::string &url, std::vector<uint8_t> *out, std::string *error) {
        const std::wstring wide_url = widen(url);
        URL_COMPONENTS parts = {};
        parts.dwStructSize = sizeof(parts);
        wchar_t host[256] = {};
        wchar_t path[2048] = {};
        parts.lpszHostName = host;
        parts.dwHostNameLength = (DWORD) std::size(host);
        parts.lpszUrlPath = path;
        parts.dwUrlPathLength = (DWORD) std::size(path);
        if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &parts)) {
            *error = "not a usable URL: " + url;
            return false;
        }

        HINTERNET session = WinHttpOpen(L"SW_RACER_RE", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) {
            *error = "could not open an HTTP session";
            return false;
        }
        WinHttpSetTimeouts(session, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS);

        bool ok = false;
        HINTERNET connection = WinHttpConnect(session, host, parts.nPort, 0);
        if (connection) {
            const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
            HINTERNET request = WinHttpOpenRequest(connection, L"GET", path, nullptr,
                                                   WINHTTP_NO_REFERER,
                                                   WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
            if (request) {
                if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                    WinHttpReceiveResponse(request, nullptr)) {
                    DWORD code = 0;
                    DWORD code_size = sizeof(code);
                    WinHttpQueryHeaders(request,
                                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &code_size,
                                        WINHTTP_NO_HEADER_INDEX);
                    if (code != 200) {
                        *error = "HTTP " + std::to_string(code) + " for " + url;
                    } else {
                        ok = true;
                        DWORD available = 0;
                        while (ok && WinHttpQueryDataAvailable(request, &available) && available) {
                            if (out->size() + available > MAX_RESPONSE_BYTES) {
                                *error = "response larger than the " +
                                    std::to_string(MAX_RESPONSE_BYTES) + " byte limit";
                                ok = false;
                                break;
                            }
                            const size_t offset = out->size();
                            out->resize(offset + available);
                            DWORD read = 0;
                            if (!WinHttpReadData(request, out->data() + offset, available, &read)) {
                                *error = "read failed partway through " + url;
                                ok = false;
                                break;
                            }
                            out->resize(offset + read);
                        }
                    }
                } else {
                    *error = "request failed (" + std::to_string(GetLastError()) + ") for " + url;
                }
                WinHttpCloseHandle(request);
            } else {
                *error = "could not build a request for " + url;
            }
            WinHttpCloseHandle(connection);
        } else {
            *error = "could not reach the host of " + url;
        }
        WinHttpCloseHandle(session);
        return ok;
    }

    fs::path blob_path(const std::string &sha256) {
        return fs::path("./assets/content") / sha256.substr(0, 2) / sha256;
    }

    bool write_file(const fs::path &path, const void *data, size_t size) {
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        FILE *f = fopen(path.generic_string().c_str(), "wb");
        if (!f)
            return false;
        const bool ok = size == 0 || fwrite(data, 1, size, f) == size;
        fclose(f);
        if (!ok)
            fs::remove(path, ec);
        return ok;
    }

    // The hashes a manifest names, with the size each declares.
    struct WantedAsset {
        std::string sha256;
        uint64_t size;
    };

    std::vector<WantedAsset> wanted_assets(const std::string &manifest_json) {
        std::vector<WantedAsset> wanted;
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.parse(manifest_json).get(root) != simdjson::SUCCESS)
            return wanted;

        const auto add = [&](simdjson::dom::element asset) {
            std::string_view sha;
            if (asset["sha256"].get(sha) != simdjson::SUCCESS)
                return;
            int64_t size = 0;
            asset["size"].get(size);
            wanted.push_back({std::string(sha), (uint64_t) size});
        };

        for (const char *key: {"model", "spline", "preview_model"}) {
            simdjson::dom::element asset;
            if (root[key].get(asset) == simdjson::SUCCESS)
                add(asset);
        }
        simdjson::dom::array textures;
        if (root["textures"].get(textures) == simdjson::SUCCESS) {
            for (simdjson::dom::element texture: textures)
                add(texture);
        }
        return wanted;
    }

    std::string slug_of(const std::string &manifest_json) {
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        std::string_view slug;
        if (parser.parse(manifest_json).get(root) == simdjson::SUCCESS &&
            root["slug"].get(slug) == simdjson::SUCCESS)
            return std::string(slug);
        return std::string();
    }

    void do_refresh() {
        set_status(CatalogState::Fetching, "fetching the catalog");
        std::vector<uint8_t> body;
        std::string error;
        if (!http_get(track_catalog_Url() + "/index.json", &body, &error)) {
            fprintf(hook_log, "[track_catalog] %s\n", error.c_str());
            fflush(hook_log);
            set_status(CatalogState::Failed, error);
            return;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.parse(body.data(), body.size()).get(root) != simdjson::SUCCESS) {
            set_status(CatalogState::Failed, "the catalog is not readable JSON");
            return;
        }

        std::vector<CatalogTrack> fetched;
        simdjson::dom::array entries;
        if (root["tracks"].get(entries) == simdjson::SUCCESS) {
            for (simdjson::dom::element entry: entries) {
                CatalogTrack track = {};
                std::string_view text;
                if (entry["slug"].get(text) == simdjson::SUCCESS)
                    track.slug = std::string(text);
                if (entry["name"].get(text) == simdjson::SUCCESS)
                    track.name = std::string(text);
                if (entry["author"].get(text) == simdjson::SUCCESS)
                    track.author = std::string(text);
                if (entry["version"].get(text) == simdjson::SUCCESS)
                    track.version = std::string(text);
                if (entry["content_hash"].get(text) == simdjson::SUCCESS)
                    track.content_hash = std::string(text);
                int64_t bytes = 0;
                entry["download_bytes"].get(bytes);
                track.download_bytes = (uint64_t) bytes;

                simdjson::dom::element manifest;
                if (entry["manifest"].get(manifest) != simdjson::SUCCESS)
                    continue;
                track.manifest_json = simdjson::to_string(manifest);
                if (track.slug.empty())
                    track.slug = slug_of(track.manifest_json);

                std::error_code ec;
                track.installed =
                    fs::is_regular_file(fs::path("./assets/tracks") / track.slug / "track.json", ec);
                fetched.push_back(std::move(track));
            }
        }

        {
            std::lock_guard<std::mutex> lock(state_mutex);
            tracks = std::move(fetched);
            status.tracks_installed_since_refresh = 0;
        }
        fprintf(hook_log, "[track_catalog] catalog lists %d track(s)\n", (int) tracks.size());
        fflush(hook_log);
        set_status(CatalogState::Idle, "");
    }

    void do_install(const std::string &slug) {
        CatalogTrack track;
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            const auto it = std::find_if(tracks.begin(), tracks.end(),
                                         [&](const CatalogTrack &t) { return t.slug == slug; });
            if (it == tracks.end()) {
                set_status(CatalogState::Failed, "no catalog entry for " + slug);
                return;
            }
            track = *it;
        }

        // Only what the store is missing: a track sharing art with an installed one is nearly free.
        std::vector<WantedAsset> missing;
        uint64_t total = 0;
        for (const WantedAsset &asset: wanted_assets(track.manifest_json)) {
            std::error_code ec;
            if (fs::is_regular_file(blob_path(asset.sha256), ec))
                continue;
            missing.push_back(asset);
            total += asset.size;
        }

        fprintf(hook_log, "[track_catalog] installing %s: %d of %d asset(s) missing, %llu bytes\n",
                slug.c_str(), (int) missing.size(),
                (int) wanted_assets(track.manifest_json).size(), (unsigned long long) total);
        fflush(hook_log);

        uint64_t done = 0;
        for (const WantedAsset &asset: missing) {
            if (stopping)
                return;

            set_status(CatalogState::Downloading, "downloading " + track.name, slug, done, total);
            std::vector<uint8_t> body;
            std::string error;
            if (!http_get(track_catalog_Url() + "/blobs/" + asset.sha256, &body, &error)) {
                fprintf(hook_log, "[track_catalog] %s\n", error.c_str());
                fflush(hook_log);
                set_status(CatalogState::Failed, error);
                return;
            }

            // Verified before it is written, so a bad response never enters the store. The manifest
            // reader checks again on load, which covers a blob that rots on disk afterwards.
            const TrackAsset expected = {asset.sha256, 0, (uint32_t) body.size()};
            std::vector<uint8_t> verified;
            if (!write_file(blob_path(asset.sha256), body.data(), body.size()) ||
                !track_manifest_ReadAsset(expected, &verified)) {
                std::error_code ec;
                fs::remove(blob_path(asset.sha256), ec);
                set_status(CatalogState::Failed, "the download of " + asset.sha256.substr(0, 12) +
                               " did not match its hash");
                return;
            }

            done += asset.size;
        }

        // The manifest lands last: a track directory only exists once its assets are all present.
        const fs::path manifest_path = fs::path("./assets/tracks") / slug / "track.json";
        if (!write_file(manifest_path, track.manifest_json.data(), track.manifest_json.size())) {
            set_status(CatalogState::Failed, "could not write " + manifest_path.generic_string());
            return;
        }

        {
            std::lock_guard<std::mutex> lock(state_mutex);
            for (CatalogTrack &entry: tracks) {
                if (entry.slug == slug)
                    entry.installed = true;
            }
            status.tracks_installed_since_refresh++;
        }
        pending_rescan = true;
        fprintf(hook_log, "[track_catalog] installed %s\n", slug.c_str());
        fflush(hook_log);
        set_status(CatalogState::Idle, track.name + " installed");
    }

    void worker_main() {
        while (!stopping) {
            std::string job;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                queue_signal.wait(lock, [] { return stopping || !install_queue.empty(); });
                if (stopping)
                    return;
                job = install_queue.front();
                install_queue.pop_front();
            }

            if (job.empty())
                do_refresh();
            else
                do_install(job);
        }
    }

    void enqueue(const std::string &job) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!worker.joinable())
                worker = std::thread(worker_main);
            install_queue.push_back(job);
        }
        queue_signal.notify_one();
    }
}

const std::string &track_catalog_Url() {
    // Defaults to the local mock (scripts/serve_catalog.py) so the browser is usable before the
    // public catalog exists; point it at that host when it does.
    static const std::string url =
        config::get_string("tracks", "catalog_url", "http://127.0.0.1:8099");
    return url;
}

void track_catalog_Refresh() {
    enqueue("");
}

void track_catalog_Install(const std::string &slug) {
    enqueue(slug);
}

std::vector<CatalogTrack> track_catalog_Tracks() {
    std::lock_guard<std::mutex> lock(state_mutex);
    return tracks;
}

CatalogStatus track_catalog_Status() {
    std::lock_guard<std::mutex> lock(state_mutex);
    return status;
}

bool track_catalog_TakePendingRescan() {
    return pending_rescan.exchange(false);
}

void track_catalog_Shutdown() {
    stopping = true;
    queue_signal.notify_all();
    if (worker.joinable())
        worker.join();
}
