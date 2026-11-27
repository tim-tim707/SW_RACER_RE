#include "custom_engine_sound.h"

#include <windows.h>
#include <mmsystem.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {
    constexpr int kRate = 44100;
    constexpr int kFramesPerBuffer = 1024;// ~23 ms
    constexpr int kBuffers = 4;           // ~93 ms queued
    constexpr uint64_t kFilmKey = 1;

    struct Sound {
        std::vector<float> l, r;
        double rate_scale = 1.0;// file rate / output rate
    };
    struct Voice {
        int sound = -1;
        double pos = 0.0;
        float gain = 0.0f, rate = 1.0f, pan = 0.0f;   // current (mixer thread)
        float tgain = 0.0f, trate = 1.0f, tpan = 0.0f;// targets (game thread)
        int64_t last_ms = 0;
        bool fresh = true;
    };

    std::mutex g_mutex;// guards g_sounds (append-only) and g_voices
    std::vector<std::unique_ptr<Sound>> g_sounds;
    std::unordered_map<std::string, int> g_sound_ids;
    std::unordered_map<uint64_t, Voice> g_voices;
    std::atomic<bool> g_started{false};
    std::atomic<bool> g_available{false};
    std::atomic<const char*> g_status{""};
    int g_film_sound = -2;// -2 = not tried yet

    int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    std::wstring exe_dir() {
        wchar_t buf[MAX_PATH];
        const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
        std::wstring p(buf, n);
        const size_t slash = p.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            p.resize(slash + 1);
        return p;
    }

    // Minimal RIFF/WAVE reader: 16-bit PCM, mono or stereo.
    std::unique_ptr<Sound> read_wav(const std::wstring& path) {
        FILE* f = _wfopen(path.c_str(), L"rb");
        if (!f)
            return nullptr;
        std::vector<uint8_t> data;
        fseek(f, 0, SEEK_END);
        const long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        data.resize(size > 0 ? (size_t) size : 0);
        const size_t got = fread(data.data(), 1, data.size(), f);
        fclose(f);
        if (got < 44 || memcmp(data.data(), "RIFF", 4) != 0 || memcmp(data.data() + 8, "WAVE", 4) != 0)
            return nullptr;
        int channels = 0, bits = 0, file_rate = 0;
        size_t pos = 12;
        while (pos + 8 <= got) {
            const uint32_t len = *(const uint32_t*) (data.data() + pos + 4);
            const uint8_t* body = data.data() + pos + 8;
            if (memcmp(data.data() + pos, "fmt ", 4) == 0 && len >= 16) {
                channels = *(const uint16_t*) (body + 2);
                file_rate = (int) *(const uint32_t*) (body + 4);
                bits = *(const uint16_t*) (body + 14);
            } else if (memcmp(data.data() + pos, "data", 4) == 0) {
                if (bits != 16 || (channels != 1 && channels != 2) || file_rate <= 0)
                    return nullptr;
                const size_t frames = std::min<size_t>(len, got - (pos + 8)) / (size_t) (2 * channels);
                if (frames < 64)
                    return nullptr;
                auto s = std::make_unique<Sound>();
                const int16_t* p = (const int16_t*) body;
                s->l.resize(frames);
                s->r.resize(frames);
                for (size_t i = 0; i < frames; i++) {
                    s->l[i] = p[i * channels] / 32768.0f;
                    s->r[i] = p[i * channels + (channels - 1)] / 32768.0f;
                }
                s->rate_scale = (double) file_rate / (double) kRate;
                return s;
            }
            pos += 8 + len + (len & 1);
        }
        return nullptr;
    }

    void mixer_thread() {
        HANDLE ev = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        WAVEFORMATEX fmt{};
        fmt.wFormatTag = WAVE_FORMAT_PCM;
        fmt.nChannels = 2;
        fmt.nSamplesPerSec = kRate;
        fmt.wBitsPerSample = 16;
        fmt.nBlockAlign = 4;
        fmt.nAvgBytesPerSec = kRate * 4;
        HWAVEOUT out = nullptr;
        if (waveOutOpen(&out, WAVE_MAPPER, &fmt, (DWORD_PTR) ev, 0, CALLBACK_EVENT) != MMSYSERR_NOERROR) {
            g_status = "could not open the audio output";
            return;
        }
        g_available = true;

        static int16_t pcm[kBuffers][kFramesPerBuffer * 2];
        static float mix[kFramesPerBuffer * 2];
        WAVEHDR hdr[kBuffers]{};
        for (int b = 0; b < kBuffers; b++) {
            hdr[b].lpData = (LPSTR) pcm[b];
            hdr[b].dwBufferLength = sizeof(pcm[b]);
            waveOutPrepareHeader(out, &hdr[b], sizeof(WAVEHDR));
            hdr[b].dwFlags |= WHDR_DONE;// mark free
        }
        for (;;) {
            bool wrote = false;
            for (int b = 0; b < kBuffers; b++) {
                if (!(hdr[b].dwFlags & WHDR_DONE))
                    continue;
                std::fill(std::begin(mix), std::end(mix), 0.0f);
                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    const int64_t now = now_ms();
                    for (auto it = g_voices.begin(); it != g_voices.end();) {
                        Voice& v = it->second;
                        // Not asserted for a moment (paused / menus / pod gone): fade to silence.
                        const bool stale = now - v.last_ms > 150;
                        const float tg = stale ? 0.0f : v.tgain;
                        if (stale && v.gain < 1e-4f) {
                            it = g_voices.erase(it);
                            continue;
                        }
                        if (v.sound < 0 || v.sound >= (int) g_sounds.size()) {
                            ++it;
                            continue;
                        }
                        const Sound& s = *g_sounds[v.sound];
                        const size_t n = s.l.size();
                        if (v.fresh) {// start a new voice at a random point so stacked loops don't phase
                            v.pos = (double) (((uint64_t) it->first * 2654435761u) % n);
                            v.rate = v.trate;
                            v.pan = v.tpan;
                            v.fresh = false;
                        }
                        for (int i = 0; i < kFramesPerBuffer; i++) {
                            // Per-sample smoothing (~15 ms) so changes never click.
                            v.gain += (tg - v.gain) * 0.0015f;
                            v.rate += (v.trate - v.rate) * 0.0015f;
                            v.pan += (v.tpan - v.pan) * 0.0015f;
                            const size_t i0 = (size_t) v.pos, i1 = (i0 + 1) % n;
                            const float fr = (float) (v.pos - (double) i0);
                            const float l = s.l[i0] + (s.l[i1] - s.l[i0]) * fr;
                            const float r = s.r[i0] + (s.r[i1] - s.r[i0]) * fr;
                            const float pl = std::sqrt(0.5f * (1.0f - v.pan)) * 1.414f;
                            const float pr = std::sqrt(0.5f * (1.0f + v.pan)) * 1.414f;
                            mix[i * 2] += l * v.gain * pl;
                            mix[i * 2 + 1] += r * v.gain * pr;
                            v.pos += v.rate * s.rate_scale;
                            while (v.pos >= (double) n)
                                v.pos -= (double) n;// loops wrap seamlessly
                        }
                        ++it;
                    }
                }
                int16_t* o = pcm[b];
                for (int i = 0; i < kFramesPerBuffer * 2; i++) {
                    // Gentle soft clip so several engines summed never hard-clip.
                    const float x = mix[i];
                    const float y = x / (1.0f + std::fabs(x) * 0.25f);
                    o[i] = (int16_t) std::lround(std::fmax(-1.0f, std::fmin(1.0f, y)) * 32767.0f);
                }
                hdr[b].dwFlags &= ~WHDR_DONE;
                waveOutWrite(out, &hdr[b], sizeof(WAVEHDR));
                wrote = true;
            }
            if (!wrote)
                WaitForSingleObject(ev, 30);
        }
    }

    void ensure_started() {
        bool expected = false;
        if (g_started.compare_exchange_strong(expected, true))
            std::thread(mixer_thread).detach();
    }

    float clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }
}// namespace

int custom_sound_load(const char* rel_path) {
    const std::string key(rel_path);
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_sound_ids.find(key);
        if (it != g_sound_ids.end())
            return it->second;
    }
    std::wstring w;
    for (const char* c = rel_path; *c; c++)
        w.push_back((wchar_t) (unsigned char) *c);
    auto s = read_wav(exe_dir() + w);// file read outside the lock
    std::lock_guard<std::mutex> lock(g_mutex);
    int id = -1;
    if (s) {
        g_sounds.push_back(std::move(s));
        id = (int) g_sounds.size() - 1;
    }
    g_sound_ids[key] = id;// cache failures too, so a missing file is only tried once
    return id;
}

void custom_sound_voice(uint64_t key, int sound, float gain, float rate, float pan) {
    if (sound < 0)
        return;
    ensure_started();
    std::lock_guard<std::mutex> lock(g_mutex);
    Voice& v = g_voices[key];
    if (v.sound != sound) {// new voice, or this key switched sound: restart it
        const bool was_new = v.sound < 0;
        v.sound = sound;
        v.fresh = true;
        if (!was_new)
            v.gain = 0.0f;
    }
    v.tgain = clampf(gain, 0.0f, 1.5f);
    v.trate = clampf(rate, 0.25f, 3.0f);
    v.tpan = clampf(pan, -1.0f, 1.0f);
    v.last_ms = now_ms();
}

void custom_engine_sound_set(float gain, float rate, float pan) {
    if (g_film_sound == -2) {
        g_film_sound = custom_sound_load("sounds\\sebulba_engine_loop.wav");
        if (g_film_sound < 0)
            g_status = "sounds\\sebulba_engine_loop.wav not found / not a 16-bit WAV";
    }
    custom_sound_voice(kFilmKey, g_film_sound, clampf(gain, 0.0f, 1.0f), rate, pan);
}

bool custom_engine_sound_available() {
    return g_available;
}

const char* custom_engine_sound_status() {
    return g_status.load();
}
