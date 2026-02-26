#include "timing_stats.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <algorithm>

namespace gr {
namespace ieee802_11 {
namespace timing_stats {
namespace {

struct stats_t {
    uint64_t calls = 0;
    uint64_t items_in = 0;
    uint64_t items_out = 0;
    uint64_t time_ns = 0;
};

std::mutex g_mutex;
std::map<std::string, stats_t> g_stats;
bool g_registered = false;

void print_total_summary()
{
    std::lock_guard<std::mutex> lock(g_mutex);

    uint64_t total_calls = 0;
    uint64_t total_in = 0;
    uint64_t total_out = 0;
    uint64_t total_ns = 0;

    for (const auto& kv : g_stats) {
        total_calls += kv.second.calls;
        total_in += kv.second.items_in;
        total_out += kv.second.items_out;
        total_ns += kv.second.time_ns;
    }

    if (!total_calls) {
        return;
    }

    const double total_ms = static_cast<double>(total_ns) / 1e6;
    const double avg_us = static_cast<double>(total_ns) / total_calls / 1e3;
    auto fmt3 = [](double v) -> std::string {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(3) << v;
        return ss.str();
    };
    auto cell = [](const std::string& s, size_t width) -> std::string {
        if (s.size() >= width) {
            if (width <= 1) {
                return s.substr(0, width);
            }
            return s.substr(0, width - 1) + ".";
        }
        return s + std::string(width - s.size(), ' ');
    };

    const size_t w_block = 20;
    const size_t w_ms = 11;
    const size_t w_pct = 8;
    const size_t w_calls = 10;
    const size_t w_avg = 11;
    const size_t w_in = 10;
    const size_t w_out = 10;
    const std::string sep =
        "+" + std::string(w_block + 2, '-') +
        "+" + std::string(w_ms + 2, '-') +
        "+" + std::string(w_pct + 2, '-') +
        "+" + std::string(w_calls + 2, '-') +
        "+" + std::string(w_avg + 2, '-') +
        "+" + std::string(w_in + 2, '-') +
        "+" + std::string(w_out + 2, '-') + "+";

    std::cout << "\n[timing] ================= C++ Timing Summary ================="
              << std::endl;
    std::cout << "[timing] cpp_total_ms=" << fmt3(total_ms)
              << "  calls=" << total_calls
              << "  avg_call_us=" << fmt3(avg_us)
              << "  in=" << total_in
              << "  out=" << total_out << std::endl;

    std::vector<std::pair<std::string, stats_t>> rows(g_stats.begin(), g_stats.end());
    std::sort(rows.begin(),
              rows.end(),
              [](const auto& a, const auto& b) { return a.second.time_ns > b.second.time_ns; });

    std::cout << "[timing] " << sep << std::endl;
    std::cout << "[timing] | " << cell("block", w_block)
              << " | " << cell("total_ms", w_ms)
              << " | " << cell("pct", w_pct)
              << " | " << cell("calls", w_calls)
              << " | " << cell("avg_us", w_avg)
              << " | " << cell("in", w_in)
              << " | " << cell("out", w_out) << " |" << std::endl;
    std::cout << "[timing] " << sep << std::endl;

    for (const auto& row : rows) {
        const std::string& name = row.first;
        const stats_t& s = row.second;
        const double ms = static_cast<double>(s.time_ns) / 1e6;
        const double avg_call_us = s.calls ? static_cast<double>(s.time_ns) / s.calls / 1e3 : 0.0;
        const double pct = total_ns ? (100.0 * s.time_ns) / total_ns : 0.0;
        std::cout << "[timing] | " << cell(name, w_block)
                  << " | " << cell(fmt3(ms), w_ms)
                  << " | " << cell(fmt3(pct) + "%", w_pct)
                  << " | " << cell(std::to_string(s.calls), w_calls)
                  << " | " << cell(fmt3(avg_call_us), w_avg)
                  << " | " << cell(std::to_string(s.items_in), w_in)
                  << " | " << cell(std::to_string(s.items_out), w_out)
                  << " |" << std::endl;
    }
    std::cout << "[timing] " << sep << std::endl;
}

} // namespace

void add_block_timing(const char* block_name,
                      uint64_t calls,
                      uint64_t items_in,
                      uint64_t items_out,
                      uint64_t time_ns)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_registered) {
        std::atexit(print_total_summary);
        g_registered = true;
    }

    stats_t& s = g_stats[std::string(block_name)];
    s.calls += calls;
    s.items_in += items_in;
    s.items_out += items_out;
    s.time_ns += time_ns;
}

} // namespace timing_stats
} // namespace ieee802_11
} // namespace gr
