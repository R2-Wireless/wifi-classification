/*
 * Copyright (C) 2013, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// =============================================================================
//  sync_combined.cc
//
//  Merges sync_short_impl and sync_long_impl into one translation unit.
//
//  ── COMPILE-TIME FLAG ────────────────────────────────────────────────────────
//  This file is only active when the build system defines:
//
//      -DUSE_SYNC_COMBINED=1
//
//  When USE_SYNC_COMBINED is not set (or is 0), nothing in this file is
//  compiled, and the original sync_short.cc / sync_long.cc translation units
//  supply the factory functions as before.  The Python layer reads the same
//  flag (exported as an env-var or passed via CMake-generated config) to decide
//  which make() overload to call.
//
//  ── SYNC-SHORT ENHANCEMENT: COHERENT STS AVERAGING ──────────────────────────
//  New constructor / factory parameter  sts_periods  (unsigned int, default 1).
//
//    sts_periods = 1   →   identical to the original sync_short, no behaviour
//                          change whatsoever.
//
//    sts_periods = M   →   before comparing against the threshold the block
//                          coherently averages the complex autocorrelation over
//                          M consecutive 16-sample STS windows:
//
//                              acc = (1/M) Σ_{m=0}^{M-1} in_abs[i + m·16]
//
//                          and forms the normalised metric as |acc|² / energy,
//                          where energy is recovered from the last window.
//                          This gives ~10·log10(M) dB of SNR gain on the
//                          detection metric at the cost of (M-1)·16 samples of
//                          extra look-ahead latency.
//
//  New factory signature (added sts_periods as last defaulted parameter):
//      sync_short::make(threshold, min_plateau, log, debug, sts_periods = 1)
//
//  ── PIPELINE LATENCY NOTE ────────────────────────────────────────────────────
//  With M > 1 the block needs to look (M-1)*16 samples ahead before it can
//  commit a detection decision.  This is handled inside general_work() by
//  reducing ninput_usable = ninput - (M-1)*16.  The upstream moving-average
//  window_size (48 samples, set in main_script_14.py) already spans 3 STS
//  periods; M ≤ 3 therefore adds no additional latency pressure.  For M > 3
//  you may want to widen window_size accordingly, although in practice the
//  metric quality improvement from M > 3 is modest (< 2 dB more than M = 3).
// =============================================================================

#if defined(USE_SYNC_COMBINED) && USE_SYNC_COMBINED

// ── shared headers ────────────────────────────────────────────────────────────
#include "utils.h"
#include "timing_stats.h"
#include "frame_trace.h"
#include <gnuradio/io_signature.h>

// ── sync_long-only headers ────────────────────────────────────────────────────
#include <gnuradio/fft/fft.h>
#include <gnuradio/filter/fir_filter.h>
#include <volk/volk.h>

// ── public block headers ──────────────────────────────────────────────────────
#include <ieee802_11/sync_short.h>
#include <ieee802_11/sync_long.h>

// ── stdlib ────────────────────────────────────────────────────────────────────
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using namespace gr::ieee802_11;


// =============================================================================
//  S Y N C _ S H O R T
// =============================================================================

static const int MIN_GAP     = 480 * 1;
static const int MAX_SAMPLES = 540 * 80;
static const int STS_PERIOD  = 16;   ///< one STS repetition = 16 samples

enum SyncShortStateId : uint8_t { STATE_SEARCH = 0, STATE_COPY = 1 };

// ── one-time SO mapping printer ───────────────────────────────────────────────
static void print_loaded_ieee80211_so_once()
{
    static bool printed = false;
    if (printed) return;
    printed = true;

    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("libgnuradio-ieee802_11.so") != std::string::npos) {
            const std::string msg =
                "[sync_combined.cc] loaded SO mapping: " + line;
            std::cout << msg << std::endl;
            std::cerr << msg << std::endl;
            return;
        }
    }
    const std::string msg =
        "[sync_combined.cc] loaded SO mapping: not found in /proc/self/maps";
    std::cout << msg << std::endl;
    std::cerr << msg << std::endl;
}

// ── coherent STS metric ───────────────────────────────────────────────────────
//
//  Computes the M-period averaged normalised autocorrelation at position i.
//
//  in_abs[j]  — complex moving-average output at sample j (sync_short port 1)
//  in_cor[j]  — single-window normalised metric at sample j (sync_short port 2)
//  i          — current sample index within the work buffer
//  M          — number of STS periods to average (1 = original behaviour)
//
//  For M = 1: returns in_cor[i] exactly, no extra computation.
//  For M > 1: coherently averages M complex autocorrelation estimates spaced
//             16 samples apart, then normalises by the average recovered
//             energy across the same M windows.
//
//  The caller guarantees that [i .. i + (M-1)*STS_PERIOD] is within bounds.
//
static float sts_averaged_metric(const gr_complex* in_abs,
                                  const float*      in_cor,
                                  int               i,
                                  int               M)
{
    if (M <= 1) {
        return in_cor[i];
    }

    // Step 1 — coherently accumulate complex autocorrelation over M windows.
    gr_complex acc(0.0f, 0.0f);
    for (int m = 0; m < M; m++) {
        acc += in_abs[i + m * STS_PERIOD];
    }
    acc /= static_cast<float>(M);

    // Step 2 — recover/average energy denominator over the same M windows:
    //   in_cor[k] = |in_abs[k]|² / energy_k  =>  energy_k = |in_abs[k]|² / in_cor[k]
    constexpr float kEps = 1e-9f;
    float energy_sum = 0.0f;
    int energy_cnt = 0;
    for (int m = 0; m < M; m++) {
        const int k = i + m * STS_PERIOD;
        const float cor_k = in_cor[k];
        if (cor_k > kEps) {
            const float abs_k_sq = std::norm(in_abs[k]);
            energy_sum += abs_k_sq / cor_k;
            energy_cnt++;
        }
    }
    if (energy_cnt == 0) return 0.0f;
    const float energy = energy_sum / static_cast<float>(energy_cnt);
    if (energy <= kEps) return 0.0f;

    // Step 3 — normalised metric: |avg_complex|² / avg_energy
    return std::norm(acc) / energy;
}


// ── sync_short_impl ───────────────────────────────────────────────────────────

class sync_short_impl : public sync_short
{
public:
    sync_short_impl(double       threshold,
                    unsigned int min_plateau,
                    bool         log,
                    bool         debug,
                    unsigned int sts_periods)
        : block("sync_short",
                gr::io_signature::make3(
                    3, 3, sizeof(gr_complex), sizeof(gr_complex), sizeof(float)),
                gr::io_signature::make(1, 1, sizeof(gr_complex))),
          d_log(log),
          d_debug(debug),
          d_state(SEARCH),
          d_plateau(0),
          d_freq_offset(0),
          d_copied(0),
          d_copy_region_open(false),
          d_copy_region_start_input(0),
          d_next_frame_id(1),
          d_work_calls(0),
          d_items_in(0),
          d_items_out(0),
          d_work_time_ns(0),
          d_seen_usable_input(false),
          d_no_progress_calls(0),
          d_last_no_progress_nread(0),
          d_last_no_progress_ninput(-1),
          MIN_PLATEAU(min_plateau),
          d_threshold(threshold),
          // Clamp to [1, 10].  Beyond 10 the extra look-ahead (144 samples)
          // offers little additional gain and may stress small work buffers.
          M(std::max(1u, std::min(sts_periods, 10u)))
    {
        set_tag_propagation_policy(block::TPP_DONT);
        print_loaded_ieee80211_so_once();

        if (M > 1) {
            std::cout << "[sync_short] coherent STS averaging enabled: M=" << M
                      << "  gain ≈ " << std::fixed << std::setprecision(1)
                      << (10.0 * std::log10(static_cast<double>(M)))
                      << " dB  look-ahead=" << (M - 1) * STS_PERIOD
                      << " samples"
                      << std::endl;
        }
    }

    ~sync_short_impl()
    {
        if (!d_work_calls) return;
        timing_stats::add_block_timing(
            "sync_short", d_work_calls, d_items_in, d_items_out, d_work_time_ns);
    }

    int general_work(int noutput_items,
                     gr_vector_int&             ninput_items,
                     gr_vector_const_void_star& input_items,
                     gr_vector_void_star&       output_items)
    {
        const auto t_start = std::chrono::steady_clock::now();
        auto finish = [&](int consumed, int produced) -> int {
            d_work_calls++;
            d_items_in  += consumed;
            d_items_out += produced;
            d_work_time_ns +=
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t_start).count();
            return produced;
        };

        const gr_complex* in     = (const gr_complex*)input_items[0];
        const gr_complex* in_abs = (const gr_complex*)input_items[1];
        const float*      in_cor = (const float*)     input_items[2];
        gr_complex*       out    = (gr_complex*)output_items[0];

        const int noutput   = noutput_items;
        const int lookahead = (M - 1) * STS_PERIOD;   // extra samples needed ahead
        const uint64_t nread0 = nitems_read(0);

        int ninput = std::min(std::min(ninput_items[0], ninput_items[1]),
                              ninput_items[2]);

        // Optional correlation dump.  Enable with WIFI_DUMP_CORR=1.
        static bool  dump_init    = false;
        static bool  dump_enabled = false;
        static FILE* fp_short     = nullptr;
        static FILE* fp_abs_file  = nullptr;
        if (!dump_init) {
            dump_init    = true;
            dump_enabled = (std::getenv("WIFI_DUMP_CORR") != nullptr);
            if (dump_enabled) {
                const char* sp = std::getenv("WIFI_DUMP_SHORT_COR_PATH");
                const char* ap = std::getenv("WIFI_DUMP_SHORT_ABS_PATH");
                fp_short    = std::fopen(sp ? sp : "/tmp/sync_short_cor.bin", "wb");
                fp_abs_file = std::fopen(ap ? ap : "/tmp/sync_short_abs.bin", "wb");
            }
        }

        // Positions we can safely evaluate: we must have lookahead samples
        // available beyond position i to form the M-window average.
        const int ninput_usable = ninput - lookahead;
        if (ninput_usable > 0) {
            d_seen_usable_input = true;
            d_no_progress_calls = 0;
        }
        // End-of-stream: terminate cleanly to avoid consume=0 livelock.
        if (ninput == 0) {
            return WORK_DONE;
        }
        if (ninput_usable <= 0) {
            // Not enough look-ahead yet.
            // Before we've ever had usable input, never consume.
            if (!d_seen_usable_input) {
                return finish(0, 0);
            }
            // In SEARCH, avoid startup jitter by waiting first; if scheduler
            // keeps calling us with the same unread tail, drain deterministically.
            if (d_state == SEARCH) {
                if (d_last_no_progress_nread == nread0 &&
                    d_last_no_progress_ninput == ninput) {
                    d_no_progress_calls++;
                } else {
                    d_no_progress_calls = 1;
                    d_last_no_progress_nread = nread0;
                    d_last_no_progress_ninput = ninput;
                }
                if (d_no_progress_calls < 8) {
                    return finish(0, 0);
                }
            }
            // COPY-state tail drain: keep progress to avoid EOF livelock.
            // Keep dump streams sample-aligned with consumed input.
            if (dump_enabled && ninput > 0) {
                if (fp_short) {
                    const float v = in_cor[0];
                    std::fwrite(&v, sizeof(float), 1, fp_short);
                    std::fflush(fp_short);
                }
                if (fp_abs_file) {
                    const gr_complex a = in_abs[0];
                    std::fwrite(&a, sizeof(gr_complex), 1, fp_abs_file);
                    std::fflush(fp_abs_file);
                }
            }
            d_no_progress_calls = 0;
            consume_each(1);
            return finish(1, 0);
        }

        switch (d_state) {

        // ── SEARCH ────────────────────────────────────────────────────────────
        case SEARCH: {
            int i;
            for (i = 0; i < ninput_usable; i++) {
                const float metric = sts_averaged_metric(in_abs, in_cor, i, M);

                if (metric > d_threshold) {
                    if (d_plateau < MIN_PLATEAU) {
                        d_plateau++;
                    } else {
                        // Keep detection/tag coordinate at the averaged-metric
                        // peak index i so plotted detections align with the
                        // dumped sync_short metric for all M.
                        const int trigger_i = i;

                        d_state   = COPY;
                        d_copied  = 0;
                        d_copy_region_open        = true;
                        d_copy_region_start_input = nitems_read(0) + trigger_i;
                        // For M>1, estimate CFO from the freshest window used
                        // in the average (last STS period).
                        d_freq_offset = arg(in_abs[i + lookahead]) / 16;
                        d_plateau = 0;
                        insert_tag(nitems_written(0),
                                   d_freq_offset,
                                   nitems_read(0) + trigger_i,
                                   metric,
                                   STATE_SEARCH,
                                   d_copied);
                        dout << "SHORT Frame!" << std::endl;
                        i = trigger_i; // consume up to aligned trigger point
                        break;
                    }
                } else {
                    d_plateau = 0;
                }
            }

            if (dump_enabled && i > 0) {
                if (fp_short)    { std::fwrite(in_cor, sizeof(float),      i, fp_short);    std::fflush(fp_short);    }
                if (fp_abs_file) { std::fwrite(in_abs, sizeof(gr_complex), i, fp_abs_file); std::fflush(fp_abs_file); }
            }
            if (dump_enabled && i > 0 && fp_short && M > 1) {
                // For M>1 the detector runs on sts_averaged_metric, not raw in_cor.
                // Dump the effective metric so MATLAB overlays match detection markers.
                std::vector<float> det_metric(i);
                for (int k = 0; k < i; k++) {
                    det_metric[k] = sts_averaged_metric(in_abs, in_cor, k, M);
                }
                std::fseek(fp_short, -(long)(i * (int)sizeof(float)), SEEK_CUR);
                std::fwrite(det_metric.data(), sizeof(float), i, fp_short);
                std::fflush(fp_short);
            }

            consume_each(i);
            return finish(i, 0);
        }

        // ── COPY ──────────────────────────────────────────────────────────────
        case COPY: {
            int o = 0;
            while (o < ninput_usable && o < noutput && d_copied < MAX_SAMPLES) {
                const float metric = sts_averaged_metric(in_abs, in_cor, o, M);

                if (metric > d_threshold) {
                    if (d_plateau < MIN_PLATEAU) {
                        d_plateau++;
                    } else if (d_copied > MIN_GAP) {
                        std::fprintf(
                            stderr,
                            "[sync_short][retrigger] in_idx=%llu copied=%d "
                            "metric=%.6f thr=%.6f plateau=%d start=%llu\n",
                            (unsigned long long)(nitems_read(0) + o),
                            d_copied,
                            (double)metric,
                            d_threshold,
                            d_plateau,
                            (unsigned long long)d_copy_region_start_input);
                        if (d_copy_region_open) {
                            dump_copy_region(d_copy_region_start_input,
                                             nitems_read(0) + o);
                            d_copy_region_open = false;
                        }
                        d_copy_region_open        = true;
                        d_copy_region_start_input = nitems_read(0) + o;

                        const uint32_t copied_before = (uint32_t)d_copied;
                        d_copied      = 0;
                        d_plateau     = 0;
                        d_freq_offset = arg(in_abs[o]) / 16;
                        insert_tag(nitems_written(0) + o,
                                   d_freq_offset,
                                   nitems_read(0) + o,
                                   metric,
                                   STATE_COPY,
                                   copied_before);
                        dout << "SHORT Frame!" << std::endl;
                        break;
                    }
                } else {
                    d_plateau = 0;
                }

                out[o] = in[o] * exp(gr_complex(0, -d_freq_offset * d_copied));
                o++;
                d_copied++;
            }

            if (d_copied == MAX_SAMPLES) {
                if (d_copy_region_open) {
                    dump_copy_region(d_copy_region_start_input,
                                     nitems_read(0) + o);
                    d_copy_region_open = false;
                }
                d_state = SEARCH;
            }

            dout << "SHORT copied " << o << std::endl;

            if (dump_enabled && o > 0) {
                if (fp_short)    { std::fwrite(in_cor, sizeof(float),      o, fp_short);    std::fflush(fp_short);    }
                if (fp_abs_file) { std::fwrite(in_abs, sizeof(gr_complex), o, fp_abs_file); std::fflush(fp_abs_file); }
            }
            if (dump_enabled && o > 0 && fp_short && M > 1) {
                // Keep dump aligned with the actual M-window detector metric.
                std::vector<float> det_metric(o);
                for (int k = 0; k < o; k++) {
                    det_metric[k] = sts_averaged_metric(in_abs, in_cor, k, M);
                }
                std::fseek(fp_short, -(long)(o * (int)sizeof(float)), SEEK_CUR);
                std::fwrite(det_metric.data(), sizeof(float), o, fp_short);
                std::fflush(fp_short);
            }

            consume_each(o);
            return finish(o, o);
        }
        }

        throw std::runtime_error("sync_short: unknown state");
        return 0;
    }

    void insert_tag(uint64_t item,
                    double   freq_offset,
                    uint64_t input_item,
                    float    cor_metric,
                    uint8_t  state_id,
                    uint32_t copied_in_state)
    {
        mylog("frame start at in: {} out: {}", item, input_item);
        const uint64_t frame_id = d_next_frame_id++;
        frame_trace::note_sync_short(frame_id, "detected");

        static bool  dump_init    = false;
        static bool  dump_enabled = false;
        static FILE* fp_det       = nullptr;
        if (!dump_init) {
            dump_init    = true;
            dump_enabled = (std::getenv("WIFI_DUMP_CORR") != nullptr);
            if (dump_enabled) {
                const char* p = std::getenv("WIFI_DUMP_SHORT_DET_PATH");
                fp_det = std::fopen(p ? p : "/tmp/sync_short_det.bin", "wb");
            }
        }
        if (dump_enabled && fp_det) {
            std::fwrite(&input_item, sizeof(uint64_t), 1, fp_det);
            std::fflush(fp_det);
        }

        static bool  det_meta_init    = false;
        static bool  det_meta_enabled = false;
        static FILE* fp_det_meta      = nullptr;
        if (!det_meta_init) {
            det_meta_init    = true;
            det_meta_enabled = (std::getenv("WIFI_DUMP_CORR") != nullptr);
            if (det_meta_enabled) {
                const char* p = std::getenv("WIFI_DUMP_SHORT_DET_META_PATH");
                fp_det_meta = std::fopen(p ? p : "/tmp/sync_short_det_meta.bin", "wb");
            }
        }
        if (det_meta_enabled && fp_det_meta) {
            const float threshold = (float)d_threshold;
            std::fwrite(&input_item,      sizeof(uint64_t), 1, fp_det_meta);
            std::fwrite(&cor_metric,      sizeof(float),    1, fp_det_meta);
            std::fwrite(&threshold,       sizeof(float),    1, fp_det_meta);
            std::fwrite(&state_id,        sizeof(uint8_t),  1, fp_det_meta);
            std::fwrite(&copied_in_state, sizeof(uint32_t), 1, fp_det_meta);
            std::fwrite(&frame_id,        sizeof(uint64_t), 1, fp_det_meta);
            std::fwrite(&item,            sizeof(uint64_t), 1, fp_det_meta);
            std::fflush(fp_det_meta);
        }

        const pmt::pmt_t key   = pmt::string_to_symbol("wifi_start");
        const pmt::pmt_t value = pmt::from_double(freq_offset);
        const pmt::pmt_t srcid = pmt::string_to_symbol(name());
        add_item_tag(0, item, key, value, srcid);
        add_item_tag(0, item,
                     pmt::string_to_symbol("frame_id"),
                     pmt::from_uint64(frame_id),
                     srcid);
    }

private:
    void dump_copy_region(uint64_t start_input, uint64_t end_input_exclusive)
    {
        static bool  copy_dump_init    = false;
        static bool  copy_dump_enabled = false;
        static FILE* fp_copy_regions   = nullptr;
        if (!copy_dump_init) {
            copy_dump_init    = true;
            copy_dump_enabled = (std::getenv("WIFI_DUMP_CORR") != nullptr);
            if (copy_dump_enabled) {
                const char* p = std::getenv("WIFI_DUMP_SHORT_COPY_REGIONS_PATH");
                fp_copy_regions = std::fopen(
                    p ? p : "/tmp/sync_short_copy_regions.bin", "wb");
            }
        }
        if (copy_dump_enabled && fp_copy_regions
                && end_input_exclusive > start_input) {
            std::fwrite(&start_input,         sizeof(uint64_t), 1, fp_copy_regions);
            std::fwrite(&end_input_exclusive, sizeof(uint64_t), 1, fp_copy_regions);
            std::fflush(fp_copy_regions);
        }
    }

    enum { SEARCH, COPY } d_state;
    int      d_copied;
    int      d_plateau;
    float    d_freq_offset;
    bool     d_copy_region_open;
    uint64_t d_copy_region_start_input;
    uint64_t d_next_frame_id;
    uint64_t d_work_calls;
    uint64_t d_items_in;
    uint64_t d_items_out;
    uint64_t d_work_time_ns;
    bool     d_seen_usable_input;
    int      d_no_progress_calls;
    uint64_t d_last_no_progress_nread;
    int      d_last_no_progress_ninput;
    const double       d_threshold;
    const bool         d_log;
    const bool         d_debug;
    const unsigned int MIN_PLATEAU;
    const unsigned int M;   ///< STS periods to coherently average (1 = original)
};

// Factory function — sts_periods defaults to 1 (original behaviour).
sync_short::sptr
sync_short::make(double       threshold,
                 unsigned int min_plateau,
                 bool         log,
                 bool         debug)
{
    return sync_short::make(threshold, min_plateau, log, debug, 1);
}

sync_short::sptr
sync_short::make(double       threshold,
                 unsigned int min_plateau,
                 bool         log,
                 bool         debug,
                 unsigned int sts_periods /* = 1 */)
{
    return gnuradio::get_initial_sptr(
        new sync_short_impl(threshold, min_plateau, log, debug, sts_periods));
}


// =============================================================================
//  S Y N C _ L O N G   (unchanged from original)
// =============================================================================

using namespace std;

static bool compare_abs(const std::pair<gr_complex, int>& first,
                        const std::pair<gr_complex, int>& second)
{
    return abs(get<0>(first)) > abs(get<0>(second));
}

class sync_long_impl : public sync_long
{
public:
    sync_long_impl(unsigned int sync_length, bool log, bool debug)
        : block("sync_long",
                gr::io_signature::make2(2, 2, sizeof(gr_complex), sizeof(gr_complex)),
                gr::io_signature::make(1, 1, sizeof(gr_complex))),
          d_fir(gr::filter::kernel::fir_filter_ccc(LONG)),
          d_log(log),
          d_debug(debug),
          d_offset(0),
          d_state(SYNC),
          d_current_frame_id(0),
          d_work_calls(0),
          d_items_in(0),
          d_items_out(0),
          d_work_time_ns(0),
          SYNC_LENGTH(sync_length)
    {
        set_tag_propagation_policy(block::TPP_DONT);
        d_correlation = (gr_complex*)volk_malloc(
            sizeof(gr_complex) * 8192, volk_get_alignment());
    }

    ~sync_long_impl()
    {
        if (d_work_calls) {
            timing_stats::add_block_timing(
                "sync_long", d_work_calls, d_items_in, d_items_out, d_work_time_ns);
        }
        volk_free(d_correlation);
    }

    int general_work(int noutput,
                     gr_vector_int&             ninput_items,
                     gr_vector_const_void_star& input_items,
                     gr_vector_void_star&       output_items)
    {
        const auto t_start = std::chrono::steady_clock::now();

        const gr_complex* in         = (const gr_complex*)input_items[0];
        const gr_complex* in_delayed = (const gr_complex*)input_items[1];
        gr_complex*       out        = (gr_complex*)output_items[0];

        dout << "LONG ninput[0] " << ninput_items[0]
             << "   ninput[1] "   << ninput_items[1]
             << "  noutput "      << noutput
             << "   state "       << d_state << std::endl;

        int ninput = std::min(std::min(ninput_items[0], ninput_items[1]), 8192);

        // Optional correlation / detection dumps.  Enable with WIFI_DUMP_CORR=1.
        static bool     dump_init          = false;
        static bool     dump_enabled       = false;
        static FILE*    fp_long_mag        = nullptr;
        static FILE*    fp_long_mag_abs    = nullptr;
        static FILE*    fp_long_cplx       = nullptr;
        static FILE*    fp_long_det        = nullptr;
        static FILE*    fp_long_det_meta   = nullptr;
        static uint64_t long_corr_counter  = 0;
        if (!dump_init) {
            dump_init    = true;
            dump_enabled = (std::getenv("WIFI_DUMP_CORR") != nullptr);
            if (dump_enabled) {
                const char* mag_p      = std::getenv("WIFI_DUMP_LONG_MAG_PATH");
                const char* mag_abs_p  = std::getenv("WIFI_DUMP_LONG_MAG_ABS_PATH");
                const char* cplx_p     = std::getenv("WIFI_DUMP_LONG_CPLX_PATH");
                const char* det_p      = std::getenv("WIFI_DUMP_LONG_DET_PATH");
                const char* det_meta_p = std::getenv("WIFI_DUMP_LONG_DET_META_PATH");
                fp_long_mag      = std::fopen(mag_p      ? mag_p      : "/tmp/sync_long_cor_mag.bin",     "wb");
                fp_long_mag_abs  = std::fopen(mag_abs_p  ? mag_abs_p  : "/tmp/sync_long_cor_mag_abs.bin", "wb");
                fp_long_cplx     = std::fopen(cplx_p     ? cplx_p     : "/tmp/sync_long_cor_cplx.bin",    "wb");
                fp_long_det      = std::fopen(det_p      ? det_p      : "/tmp/sync_long_det.bin",         "wb");
                fp_long_det_meta = std::fopen(det_meta_p ? det_meta_p : "/tmp/sync_long_det_meta.bin",    "wb");
            }
        }

        const uint64_t nread = nitems_read(0);
        get_tags_in_range(
            d_tags, 0, nread, nread + ninput, pmt::string_to_symbol("wifi_start"));
        if (d_tags.size()) {
            std::sort(d_tags.begin(), d_tags.end(), gr::tag_t::offset_compare);

            const uint64_t offset = d_tags.front().offset;
            if (offset > nread) {
                ninput = offset - nread;
            } else {
                uint64_t new_frame_id = 0;
                std::vector<gr::tag_t> frame_id_tags;
                get_tags_in_range(frame_id_tags, 0, offset, offset + 1,
                                  pmt::string_to_symbol("frame_id"));
                if (frame_id_tags.size()) {
                    new_frame_id = pmt::to_uint64(frame_id_tags.front().value);
                }
                if (d_offset && (d_state == SYNC)) {
                    throw std::runtime_error("wtf");
                }
                if (d_state == COPY) {
                    if (d_current_frame_id) {
                        const int rel    = d_offset - d_frame_start;
                        const int copied = (rel > 0) ? rel : 0;
                        std::ostringstream ss;
                        ss << "interrupted copied=" << copied;
                        frame_trace::note_sync_long(d_current_frame_id, ss.str());
                        std::fprintf(stderr,
                                     "[sync_long][interrupt] frame_id=%llu "
                                     "interrupted copied=%d\n",
                                     (unsigned long long)d_current_frame_id,
                                     copied);
                    }
                    d_state = RESET;
                }
                d_freq_offset_short = pmt::to_double(d_tags.front().value);
                d_current_frame_id  = new_frame_id;
                if (d_current_frame_id) {
                    frame_trace::note_sync_long(d_current_frame_id, "tag_received");
                }
            }
        }

        int i = 0;
        int o = 0;

        switch (d_state) {

        case SYNC: {
            const int n_computed = std::min(SYNC_LENGTH, std::max(ninput - 63, 0));
            d_fir.filterN(d_correlation, in, n_computed);

            while (i + 63 < ninput) {
                d_cor.push_back(pair<gr_complex, int>(d_correlation[i], d_offset));
                if (dump_enabled) {
                    if (fp_long_mag) {
                        const float mag = std::abs(d_correlation[i]);
                        std::fwrite(&mag, sizeof(float), 1, fp_long_mag);
                    }
                    if (fp_long_mag_abs) {
                        const uint64_t sl_idx = nread + i;
                        const float    mag    = std::abs(d_correlation[i]);
                        std::fwrite(&sl_idx, sizeof(uint64_t), 1, fp_long_mag_abs);
                        std::fwrite(&mag,    sizeof(float),    1, fp_long_mag_abs);
                    }
                    if (fp_long_cplx) {
                        std::fwrite(&d_correlation[i], sizeof(gr_complex), 1, fp_long_cplx);
                    }
                }
                long_corr_counter++;

                i++;
                d_offset++;

                if (d_offset == SYNC_LENGTH) {
                    search_frame_start();
                    if (d_current_frame_id) {
                        if (d_frame_start == SYNC_LENGTH) {
                            frame_trace::note_sync_long(
                                d_current_frame_id, "fallback_no_peak");
                        } else {
                            frame_trace::note_sync_long(
                                d_current_frame_id, "aligned_copy");
                        }
                    }
                    if (dump_enabled && fp_long_det && d_frame_start != SYNC_LENGTH) {
                        const uint64_t peak1 =
                            (long_corr_counter >= (uint64_t)SYNC_LENGTH)
                                ? (long_corr_counter - SYNC_LENGTH + d_frame_start)
                                : d_frame_start;
                        const uint64_t peak2 = peak1 + 64;
                        std::fwrite(&peak1, sizeof(uint64_t), 1, fp_long_det);
                        std::fwrite(&peak2, sizeof(uint64_t), 1, fp_long_det);
                        std::fflush(fp_long_det);
                        if (fp_long_det_meta) {
                            const uint64_t fid = d_current_frame_id;
                            std::fwrite(&fid,   sizeof(uint64_t), 1, fp_long_det_meta);
                            std::fwrite(&peak1, sizeof(uint64_t), 1, fp_long_det_meta);
                            std::fwrite(&peak2, sizeof(uint64_t), 1, fp_long_det_meta);
                            std::fflush(fp_long_det_meta);
                        }
                    }
                    mylog("LONG: frame start at {}", d_frame_start);
                    d_offset = 0;
                    d_count  = 0;
                    d_state  = COPY;
                    break;
                }
            }

            if (dump_enabled) {
                if (fp_long_mag)     std::fflush(fp_long_mag);
                if (fp_long_cplx)    std::fflush(fp_long_cplx);
                if (fp_long_mag_abs) std::fflush(fp_long_mag_abs);
            }
            break;
        }

        case COPY:
            while (i < ninput && o < noutput) {
                const int rel = d_offset - d_frame_start;

                if (!rel) {
                    add_item_tag(0, nitems_written(0),
                                 pmt::string_to_symbol("wifi_start"),
                                 pmt::from_double(d_freq_offset_short - d_freq_offset),
                                 pmt::string_to_symbol(name()));
                    if (d_current_frame_id) {
                        add_item_tag(0, nitems_written(0),
                                     pmt::string_to_symbol("frame_id"),
                                     pmt::from_uint64(d_current_frame_id),
                                     pmt::string_to_symbol(name()));
                    }
                    add_item_tag(0, nitems_written(0),
                                 pmt::string_to_symbol("cfo_short_rad_per_samp"),
                                 pmt::from_double(d_freq_offset_short),
                                 pmt::string_to_symbol(name()));
                    add_item_tag(0, nitems_written(0),
                                 pmt::string_to_symbol("cfo_long_rad_per_samp"),
                                 pmt::from_double(d_freq_offset),
                                 pmt::string_to_symbol(name()));
                }

                if (rel >= 0 && (rel < 128 || ((rel - 128) % 80) > 15)) {
                    out[o] = in_delayed[i]
                             * exp(gr_complex(0, d_offset * d_freq_offset));
                    o++;
                }

                i++;
                d_offset++;
            }
            break;

        case RESET:
            while (o < noutput) {
                if (((d_count + o) % 64) == 0) {
                    d_offset = 0;
                    d_state  = SYNC;
                    break;
                } else {
                    out[o] = 0;
                    o++;
                }
            }
            break;
        }

        dout << "produced : " << o << " consumed: " << i << std::endl;

        d_count += o;
        d_work_calls++;
        d_items_in  += i;
        d_items_out += o;
        d_work_time_ns +=
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - t_start).count();
        consume(0, i);
        consume(1, i);
        return o;
    }

    void forecast(int noutput_items, gr_vector_int& ninput_items_required)
    {
        if (d_state == SYNC) {
            ninput_items_required[0] = 64;
            ninput_items_required[1] = 64;
        } else {
            ninput_items_required[0] = noutput_items;
            ninput_items_required[1] = noutput_items;
        }
    }

    void search_frame_start()
    {
        assert(d_cor.size() == (size_t)SYNC_LENGTH);
        d_cor.sort(compare_abs);

        vector<pair<gr_complex, int>> vec(d_cor.begin(), d_cor.end());
        d_cor.clear();

        d_frame_start = SYNC_LENGTH;
        d_freq_offset = 0.0f;

        for (int i = 0; i < 3; i++) {
            for (int k = i + 1; k < 4; k++) {
                gr_complex first, second;
                if (get<1>(vec[i]) > get<1>(vec[k])) {
                    first  = get<0>(vec[k]);
                    second = get<0>(vec[i]);
                } else {
                    first  = get<0>(vec[i]);
                    second = get<0>(vec[k]);
                }
                const int diff = abs(get<1>(vec[i]) - get<1>(vec[k]));
                if (diff == 64) {
                    d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
                    d_freq_offset = arg(first * conj(second)) / 64;
                    return;   // exact match — stop immediately
                } else if (diff == 63) {
                    d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
                    d_freq_offset = arg(first * conj(second)) / 63;
                } else if (diff == 65) {
                    d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
                    d_freq_offset = arg(first * conj(second)) / 65;
                }
            }
        }
    }

private:
    enum { SYNC, COPY, RESET } d_state;
    int      d_count;
    int      d_offset;
    int      d_frame_start;
    uint64_t d_current_frame_id;
    float    d_freq_offset;
    double   d_freq_offset_short;

    gr_complex* d_correlation;
    list<pair<gr_complex, int>> d_cor;
    std::vector<gr::tag_t>      d_tags;
    gr::filter::kernel::fir_filter_ccc d_fir;

    const bool d_log;
    const bool d_debug;
    uint64_t d_work_calls;
    uint64_t d_items_in;
    uint64_t d_items_out;
    uint64_t d_work_time_ns;
    const int SYNC_LENGTH;

    static const std::vector<gr_complex> LONG;
};

sync_long::sptr
sync_long::make(unsigned int sync_length, bool log, bool debug)
{
    return gnuradio::get_initial_sptr(new sync_long_impl(sync_length, log, debug));
}

const std::vector<gr_complex> sync_long_impl::LONG = {
    gr_complex(-0.0455, -1.0679), gr_complex(0.3528, -0.9865),
    gr_complex(0.8594,  0.7348),  gr_complex(0.1874,  0.2475),
    gr_complex(0.5309, -0.7784),  gr_complex(-1.0218, -0.4897),
    gr_complex(-0.3401, -0.9423), gr_complex(0.8657, -0.2298),
    gr_complex(0.4734,  0.0362),  gr_complex(0.0088, -1.0207),
    gr_complex(-1.2142, -0.4205), gr_complex(0.2172, -0.5195),
    gr_complex(0.5207, -0.1326),  gr_complex(-0.1995,  1.4259),
    gr_complex(1.0583, -0.0363),  gr_complex(0.5547, -0.5547),
    gr_complex(0.3277,  0.8728),  gr_complex(-0.5077,  0.3488),
    gr_complex(-1.1650,  0.5789), gr_complex(0.7297,  0.8197),
    gr_complex(0.6173,  0.1253),  gr_complex(-0.5353,  0.7214),
    gr_complex(-0.5011, -0.1935), gr_complex(-0.3110, -1.3392),
    gr_complex(-1.0818, -0.1470), gr_complex(-1.1300, -0.1820),
    gr_complex(0.6663, -0.6571),  gr_complex(-0.0249,  0.4773),
    gr_complex(-0.8155,  1.0218), gr_complex(0.8140,  0.9396),
    gr_complex(0.1090,  0.8662),  gr_complex(-1.3868, -0.0000),
    gr_complex(0.1090, -0.8662),  gr_complex(0.8140, -0.9396),
    gr_complex(-0.8155, -1.0218), gr_complex(-0.0249, -0.4773),
    gr_complex(0.6663,  0.6571),  gr_complex(-1.1300,  0.1820),
    gr_complex(-1.0818,  0.1470), gr_complex(-0.3110,  1.3392),
    gr_complex(-0.5011,  0.1935), gr_complex(-0.5353, -0.7214),
    gr_complex(0.6173, -0.1253),  gr_complex(0.7297, -0.8197),
    gr_complex(-1.1650, -0.5789), gr_complex(-0.5077, -0.3488),
    gr_complex(0.3277, -0.8728),  gr_complex(0.5547,  0.5547),
    gr_complex(1.0583,  0.0363),  gr_complex(-0.1995, -1.4259),
    gr_complex(0.5207,  0.1326),  gr_complex(0.2172,  0.5195),
    gr_complex(-1.2142,  0.4205), gr_complex(0.0088,  1.0207),
    gr_complex(0.4734, -0.0362),  gr_complex(0.8657,  0.2298),
    gr_complex(-0.3401,  0.9423), gr_complex(-1.0218,  0.4897),
    gr_complex(0.5309,  0.7784),  gr_complex(0.1874, -0.2475),
    gr_complex(0.8594, -0.7348),  gr_complex(0.3528,  0.9865),
    gr_complex(-0.0455,  1.0679), gr_complex(1.3868, -0.0000),
};

#endif  // USE_SYNC_COMBINED
