#include "frame_trace.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <sstream>

namespace gr {
namespace ieee802_11 {
namespace frame_trace {
namespace {

struct frame_row_t {
    std::string sync_short = "-";
    std::string sync_long = "-";
    std::string equalizer = "-";
    std::string decode = "-";
    std::string outcome = "-";
};

std::mutex g_mutex;
std::map<uint64_t, frame_row_t> g_rows;
bool g_registered = false;

void ensure_registered()
{
    if (!g_registered) {
        std::atexit([]() {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_rows.empty()) {
                return;
            }

            auto cell = [](const std::string& s, size_t width) -> std::string {
                if (s.size() >= width) {
                    if (width <= 1) {
                        return s.substr(0, width);
                    }
                    return s.substr(0, width - 1) + ".";
                }
                return s + std::string(width - s.size(), ' ');
            };

            const size_t w_id = 8;
            const size_t w_short = 14;
            const size_t w_long = 20;
            const size_t w_eq = 14;
            const size_t w_dec = 28;
            const size_t w_out = 10;

            const std::string sep =
                "+" + std::string(w_id + 2, '-') +
                "+" + std::string(w_short + 2, '-') +
                "+" + std::string(w_long + 2, '-') +
                "+" + std::string(w_eq + 2, '-') +
                "+" + std::string(w_dec + 2, '-') +
                "+" + std::string(w_out + 2, '-') + "+";

            std::cout << "\n[frame_trace] Per-Frame Stage Table" << std::endl;
            std::cout << "[frame_trace] " << sep << std::endl;
            std::cout << "[frame_trace] | " << cell("frame_id", w_id)
                      << " | " << cell("sync_short", w_short)
                      << " | " << cell("sync_long", w_long)
                      << " | " << cell("equalizer", w_eq)
                      << " | " << cell("decode_mac", w_dec)
                      << " | " << cell("outcome", w_out)
                      << " |" << std::endl;
            std::cout << "[frame_trace] " << sep << std::endl;

            for (const auto& kv : g_rows) {
                const auto& r = kv.second;
                std::ostringstream id_ss;
                id_ss << kv.first;
                std::cout << "[frame_trace] | " << cell(id_ss.str(), w_id)
                          << " | " << cell(r.sync_short, w_short)
                          << " | " << cell(r.sync_long, w_long)
                          << " | " << cell(r.equalizer, w_eq)
                          << " | " << cell(r.decode, w_dec)
                          << " | " << cell(r.outcome, w_out)
                          << " |" << std::endl;
            }
            std::cout << "[frame_trace] " << sep << std::endl;
        });
        g_registered = true;
    }
}

frame_row_t& row(uint64_t frame_id)
{
    ensure_registered();
    return g_rows[frame_id];
}

} // namespace

void note_sync_short(uint64_t frame_id, const char* status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).sync_short = status;
}

void note_sync_long(uint64_t frame_id, const char* status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).sync_long = status;
}

void note_sync_long(uint64_t frame_id, const std::string& status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).sync_long = status;
}

void note_equalizer(uint64_t frame_id, const char* status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).equalizer = status;
}

void note_decode(uint64_t frame_id, const char* status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).decode = status;
}

void note_decode(uint64_t frame_id, const std::string& status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).decode = status;
}

void note_outcome(uint64_t frame_id, const char* status)
{
    if (!frame_id) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    row(frame_id).outcome = status;
}

} // namespace frame_trace
} // namespace ieee802_11
} // namespace gr
