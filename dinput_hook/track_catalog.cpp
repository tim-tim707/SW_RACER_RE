#include "track_catalog.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <thread>

#include <simdjson.h>

#include "config.h"
#include "http_client.h"
#include "track_manifest.h"

extern "C" FILE *hook_log;

namespace fs = std::filesystem;

namespace {
    // The sync primitives live for the whole process and are never destroyed: a static
    // std::mutex / condition_variable / thread is torn down during DLL detach, after Windows has
    // already killed the worker, and winpthreads can wait forever on the thread that no longer
    // exists -- which froze the game's own Quit. Leaking them is the correct lifetime.
    std::mutex &state_mutex = *new std::mutex;
    CatalogStatus status = {CatalogState::Idle, "", "", 0, 0, 0};
    std::vector<CatalogTrack> tracks;
    std::atomic<bool> pending_rescan{false};

    std::mutex &queue_mutex = *new std::mutex;
    std::condition_variable &queue_signal = *new std::condition_variable;
    std::deque<std::string> install_queue;// slugs; "" means "refresh the catalog"
    std::thread &worker = *new std::thread;
    std::atomic<bool> stopping{false};
    std::atomic<bool> worker_finished{false};
    // How long shutdown waits for a request in flight before abandoning the thread to the OS.
    constexpr int SHUTDOWN_WAIT_MS = 500;

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
        if (!http_Get(track_catalog_Url() + "/index.json", &body, &error)) {
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
            if (!http_Get(track_catalog_Url() + "/blobs/" + asset.sha256, &body, &error)) {
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

    void worker_loop() {
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

    void worker_main() {
        worker_loop();
        worker_finished = true;
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
    // scripts/serve_catalog.py speaks the same protocol for developing against a local folder.
    static const std::string url =
        config::get_string("tracks", "catalog_url",
                           "https://bottosjunkyard.com/api/v1/customtracks");
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

// A joinable std::thread whose destructor runs at process teardown calls std::terminate, which
// is what turned quitting into a stall once the worker started at boot. Give a request in flight
// a moment to notice, then let the OS have the thread rather than wait on the network.
extern "C" bool hook_process_terminating;// main.cpp

extern "C" void track_catalog_Shutdown() {
    stopping = true;
    queue_signal.notify_all();
    if (!worker.joinable())
        return;
    if (hook_process_terminating) {
        worker.detach();// the thread is already gone; there is nothing to wait for
        return;
    }
    for (int waited = 0; waited < SHUTDOWN_WAIT_MS && !worker_finished; waited += 10)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (worker_finished)
        worker.join();
    else
        worker.detach();
}
