#include "timing_stats.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
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

enum class stage_t {
    SYNC_SHORT = 0,
    SYNC_LONG = 1,
    FRAME_EQUALIZER = 2,
    DECODE_MAC = 3,
    SUPPORT = 4,
    COUNT = 5
};

const char* stage_name(stage_t s)
{
    switch (s) {
    case stage_t::SYNC_SHORT:
        return "sync_short";
    case stage_t::SYNC_LONG:
        return "sync_long";
    case stage_t::FRAME_EQUALIZER:
        return "frame_equalizer";
    case stage_t::DECODE_MAC:
        return "decode_mac";
    default:
        return "support";
    }
}

double env_weight(const char* key)
{
    const char* v = std::getenv(key);
    if (!(v && *v)) {
        return 0.0;
    }
    return std::strtod(v, nullptr);
}

stage_t stage_for_block(const std::string& block_name)
{
    if (block_name == "sync_short") {
        return stage_t::SYNC_SHORT;
    }
    if (block_name == "sync_long") {
        return stage_t::SYNC_LONG;
    }
    if (block_name == "frame_equalizer") {
        return stage_t::FRAME_EQUALIZER;
    }
    if (block_name == "decode_mac") {
        return stage_t::DECODE_MAC;
    }
    return stage_t::SUPPORT;
}

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
    const char* file_total_env = std::getenv("WIFI_FILE_TOTAL_NS");
    const uint64_t file_total_ns =
        (file_total_env && *file_total_env)
            ? static_cast<uint64_t>(std::strtoull(file_total_env, nullptr, 10))
            : 0ULL;
    const char* run_non_handler_env = std::getenv("WIFI_RUN_NON_HANDLER_NS");
    const uint64_t run_non_handler_ns =
        (run_non_handler_env && *run_non_handler_env)
            ? static_cast<uint64_t>(std::strtoull(run_non_handler_env, nullptr, 10))
            : 0ULL;
    const double total_pct_file = file_total_ns ? (100.0 * total_ns / file_total_ns) : 0.0;
    const double total_pct_run =
        run_non_handler_ns ? (100.0 * total_ns / run_non_handler_ns) : 0.0;
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
    const size_t w_run = 9;
    const size_t w_file = 8;
    const size_t w_calls = 10;
    const size_t w_avg = 11;
    const size_t w_in = 10;
    const size_t w_out = 10;
    const std::string sep_top =
        "+" + std::string(w_block + 2, '-') +
        "+" + std::string(w_ms + 2, '-') +
        "+" + std::string(w_run + 2, '-') +
        "+" + std::string(w_file + 2, '-') +
        "+" + std::string(w_calls + 2, '-') +
        "+" + std::string(w_avg + 2, '-') +
        "+" + std::string(w_in + 2, '-') +
        "+" + std::string(w_out + 2, '-') + "+";

    std::cout << "\n[timing] ================= C++ Timing Summary ================="
              << std::endl;
    std::cout << "[timing] cpp_total_ms=" << fmt3(total_ms)
              << "  cpp_pct_of_run_non_handler="
              << (run_non_handler_ns ? (fmt3(total_pct_run) + "%") : "n/a")
              << "  cpp_pct_of_file=" << (file_total_ns ? (fmt3(total_pct_file) + "%") : "n/a")
              << "  calls=" << total_calls
              << "  avg_call_us=" << fmt3(avg_us)
              << "  in=" << total_in
              << "  out=" << total_out << std::endl;

    std::vector<std::pair<std::string, stats_t>> rows(g_stats.begin(), g_stats.end());
    std::sort(rows.begin(),
              rows.end(),
              [](const auto& a, const auto& b) { return a.second.time_ns > b.second.time_ns; });

    // Expand run_non_handler unattributed time per failure-map stage.
    if (run_non_handler_ns > 0) {
        double stage_measured_ns[static_cast<int>(stage_t::COUNT)] = { 0.0, 0.0, 0.0, 0.0, 0.0 };
        uint64_t stage_calls[static_cast<int>(stage_t::COUNT)] = { 0, 0, 0, 0, 0 };
        uint64_t stage_in[static_cast<int>(stage_t::COUNT)] = { 0, 0, 0, 0, 0 };
        uint64_t stage_out[static_cast<int>(stage_t::COUNT)] = { 0, 0, 0, 0, 0 };
        for (const auto& row : rows) {
            const stage_t st = stage_for_block(row.first);
            stage_measured_ns[static_cast<int>(st)] += static_cast<double>(row.second.time_ns);
            stage_calls[static_cast<int>(st)] += row.second.calls;
            stage_in[static_cast<int>(st)] += row.second.items_in;
            stage_out[static_cast<int>(st)] += row.second.items_out;
        }

        const double measured_sum_ns = static_cast<double>(total_ns);
        const double run_non_handler_d = static_cast<double>(run_non_handler_ns);
        const double unattributed_ns =
            (run_non_handler_d > measured_sum_ns) ? (run_non_handler_d - measured_sum_ns) : 0.0;

        const double alloc_base_ns =
            stage_measured_ns[static_cast<int>(stage_t::SYNC_SHORT)] +
            stage_measured_ns[static_cast<int>(stage_t::SYNC_LONG)] +
            stage_measured_ns[static_cast<int>(stage_t::FRAME_EQUALIZER)] +
            stage_measured_ns[static_cast<int>(stage_t::DECODE_MAC)];

        double stage_alloc_ns[static_cast<int>(stage_t::COUNT)] = { 0.0, 0.0, 0.0, 0.0, 0.0 };
        if (unattributed_ns > 0.0) {
            const double w_sync_short = env_weight("WIFI_STAGE_WEIGHT_SYNC_SHORT");
            const double w_sync_long = env_weight("WIFI_STAGE_WEIGHT_SYNC_LONG");
            const double w_frame_equalizer = env_weight("WIFI_STAGE_WEIGHT_FRAME_EQUALIZER");
            const double w_decode_mac = env_weight("WIFI_STAGE_WEIGHT_DECODE_MAC");
            const double w_support = env_weight("WIFI_STAGE_WEIGHT_SUPPORT");
            const double w_sum =
                w_sync_short + w_sync_long + w_frame_equalizer + w_decode_mac + w_support;

            if (w_sum > 0.0) {
                stage_alloc_ns[static_cast<int>(stage_t::SYNC_SHORT)] =
                    unattributed_ns * (w_sync_short / w_sum);
                stage_alloc_ns[static_cast<int>(stage_t::SYNC_LONG)] =
                    unattributed_ns * (w_sync_long / w_sum);
                stage_alloc_ns[static_cast<int>(stage_t::FRAME_EQUALIZER)] =
                    unattributed_ns * (w_frame_equalizer / w_sum);
                stage_alloc_ns[static_cast<int>(stage_t::DECODE_MAC)] =
                    unattributed_ns * (w_decode_mac / w_sum);
                stage_alloc_ns[static_cast<int>(stage_t::SUPPORT)] =
                    unattributed_ns * (w_support / w_sum);
            } else if (alloc_base_ns > 0.0) {
                for (int i = 0; i < static_cast<int>(stage_t::COUNT); i++) {
                    const stage_t st = static_cast<stage_t>(i);
                    if (st == stage_t::SUPPORT) {
                        continue;
                    }
                    stage_alloc_ns[i] = unattributed_ns * (stage_measured_ns[i] / alloc_base_ns);
                }
            } else {
                stage_alloc_ns[static_cast<int>(stage_t::SUPPORT)] = unattributed_ns;
            }
        }

        const size_t w_stage = 16;
        const size_t w_meas = 11;
        const size_t w_unat = 11;
        const size_t w_est = 11;
        const size_t w_rn = 9;
        const size_t w_pf = 8;
        const size_t w_scalls = 10;
        const size_t w_sin = 10;
        const size_t w_sout = 10;
        const std::string sep_stage =
            "+" + std::string(w_stage + 2, '-') +
            "+" + std::string(w_meas + 2, '-') +
            "+" + std::string(w_unat + 2, '-') +
            "+" + std::string(w_est + 2, '-') +
            "+" + std::string(w_rn + 2, '-') +
            "+" + std::string(w_pf + 2, '-') +
            "+" + std::string(w_scalls + 2, '-') +
            "+" + std::string(w_sin + 2, '-') +
            "+" + std::string(w_sout + 2, '-') + "+";

        std::cout << "\n[timing] Failure-Map Stage Expansion (C++ run_non_handler)" << std::endl;
        std::cout << "[timing] " << sep_stage << std::endl;
        std::cout << "[timing] | " << cell("stage", w_stage)
                  << " | " << cell("measured_ms", w_meas)
                  << " | " << cell("unattr_ms", w_unat)
                  << " | " << cell("est_total_ms", w_est)
                  << " | " << cell("%run_non", w_rn)
                  << " | " << cell("%file", w_pf)
                  << " | " << cell("calls", w_scalls)
                  << " | " << cell("in", w_sin)
                  << " | " << cell("out", w_sout) << " |" << std::endl;
        std::cout << "[timing] " << sep_stage << std::endl;

        double est_sum_ns = 0.0;
        for (int i = 0; i < static_cast<int>(stage_t::COUNT); i++) {
            const stage_t st = static_cast<stage_t>(i);
            const double measured_ns = stage_measured_ns[i];
            const double unattr_alloc_ns = stage_alloc_ns[i];
            const double est_ns = measured_ns + unattr_alloc_ns;
            est_sum_ns += est_ns;
            const double pct_run = run_non_handler_d > 0.0 ? (100.0 * est_ns / run_non_handler_d) : 0.0;
            const double pct_file = file_total_ns ? (100.0 * est_ns / file_total_ns) : 0.0;
            std::cout << "[timing] | " << cell(stage_name(st), w_stage)
                      << " | " << cell(fmt3(measured_ns / 1e6), w_meas)
                      << " | " << cell(fmt3(unattr_alloc_ns / 1e6), w_unat)
                      << " | " << cell(fmt3(est_ns / 1e6), w_est)
                      << " | " << cell(fmt3(pct_run) + "%", w_rn)
                      << " | " << cell(file_total_ns ? (fmt3(pct_file) + "%") : "n/a", w_pf)
                      << " | " << cell(std::to_string(stage_calls[i]), w_scalls)
                      << " | " << cell(std::to_string(stage_in[i]), w_sin)
                      << " | " << cell(std::to_string(stage_out[i]), w_sout)
                      << " |" << std::endl;
        }
        const double sum_pct_file = file_total_ns ? (100.0 * est_sum_ns / file_total_ns) : 0.0;
        std::cout << "[timing] " << sep_stage << std::endl;
        std::cout << "[timing] | " << cell("run_non_handler", w_stage)
                  << " | " << cell(fmt3(measured_sum_ns / 1e6), w_meas)
                  << " | " << cell(fmt3(unattributed_ns / 1e6), w_unat)
                  << " | " << cell(fmt3(est_sum_ns / 1e6), w_est)
                  << " | " << cell("100.000%", w_rn)
                  << " | " << cell(file_total_ns ? (fmt3(sum_pct_file) + "%") : "n/a", w_pf)
                  << " | " << cell(std::to_string(total_calls), w_scalls)
                  << " | " << cell(std::to_string(total_in), w_sin)
                  << " | " << cell(std::to_string(total_out), w_sout)
                  << " |" << std::endl;
        std::cout << "[timing] " << sep_stage << std::endl;
        const bool used_env_weights =
            (env_weight("WIFI_STAGE_WEIGHT_SYNC_SHORT") +
             env_weight("WIFI_STAGE_WEIGHT_SYNC_LONG") +
             env_weight("WIFI_STAGE_WEIGHT_FRAME_EQUALIZER") +
             env_weight("WIFI_STAGE_WEIGHT_DECODE_MAC") +
             env_weight("WIFI_STAGE_WEIGHT_SUPPORT")) > 0.0;
        if (used_env_weights) {
            std::cout << "[timing] note: unattr_ms allocated using GNU Radio stage weights "
                         "(includes FFT/builtin/helper block time)."
                      << std::endl;
        } else {
            std::cout << "[timing] note: unattr_ms allocated from measured custom-block proportions."
                      << std::endl;
        }
    }
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
