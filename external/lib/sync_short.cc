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
#include "utils.h"
#include "timing_stats.h"
#include "frame_trace.h"
#include <gnuradio/io_signature.h>
#include <ieee802_11/sync_short.h>

#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <cstdint>

using namespace gr::ieee802_11;

static const int MIN_GAP = 480;
static const int MAX_SAMPLES = 540 * 80;

static void print_loaded_ieee80211_so_once()
{
    static bool printed = false;
    if (printed) {
        return;
    }
    printed = true;

    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("libgnuradio-ieee802_11.so") != std::string::npos) {
            const std::string msg =
                std::string("[sync_short.cc] loaded SO mapping: ") + line;
            std::cout << msg << std::endl;
            std::cerr << msg << std::endl;
            return;
        }
    }

    const std::string msg =
        "[sync_short.cc] loaded SO mapping: not found in /proc/self/maps";
    std::cout << msg << std::endl;
    std::cerr << msg << std::endl;
}

class sync_short_impl : public sync_short
{

public:
    sync_short_impl(double threshold, unsigned int min_plateau, bool log, bool debug)
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
          d_next_frame_id(1),
          d_work_calls(0),
          d_items_in(0),
          d_items_out(0),
          d_work_time_ns(0),
          MIN_PLATEAU(min_plateau),
          d_threshold(threshold)
    {

        set_tag_propagation_policy(block::TPP_DONT);
        print_loaded_ieee80211_so_once();
    }

    ~sync_short_impl()
    {
        if (!d_work_calls) {
            return;
        }
        timing_stats::add_block_timing(
            "sync_short", d_work_calls, d_items_in, d_items_out, d_work_time_ns);
        const double total_ms = static_cast<double>(d_work_time_ns) / 1e6;
        const double avg_us = static_cast<double>(d_work_time_ns) / d_work_calls / 1e3;
        std::cout << "[timing] sync_short calls=" << d_work_calls
                  << " in=" << d_items_in
                  << " out=" << d_items_out
                  << " total_ms=" << total_ms
                  << " avg_us=" << avg_us << std::endl;
    }

    int general_work(int noutput_items,
                     gr_vector_int& ninput_items,
                     gr_vector_const_void_star& input_items,
                     gr_vector_void_star& output_items)
    {
        const auto t_start = std::chrono::steady_clock::now();
        auto finish = [&](int consumed, int produced) {
            d_work_calls++;
            d_items_in += consumed;
            d_items_out += produced;
            d_work_time_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  std::chrono::steady_clock::now() - t_start)
                                  .count();
            return produced;
        };

        const gr_complex* in = (const gr_complex*)input_items[0];
        const gr_complex* in_abs = (const gr_complex*)input_items[1];
        const float* in_cor = (const float*)input_items[2];
        gr_complex* out = (gr_complex*)output_items[0];

        int noutput = noutput_items;
        int ninput =
            std::min(std::min(ninput_items[0], ninput_items[1]), ninput_items[2]);

        // dout << "SHORT noutput : " << noutput << " ninput: " << ninput_items[0] <<
        // std::endl;

        switch (d_state) {

        case SEARCH: {
            int i;

            for (i = 0; i < ninput; i++) {
                if (in_cor[i] > d_threshold) {
                    if (d_plateau < MIN_PLATEAU) {
                        d_plateau++;

                    } else {
                        d_state = COPY;
                        d_copied = 0;
                        d_freq_offset = arg(in_abs[i]) / 16;
                        d_plateau = 0;
                        insert_tag(nitems_written(0), d_freq_offset, nitems_read(0) + i);
                        dout << "SHORT Frame!" << std::endl;
                        break;
                    }
                } else {
                    d_plateau = 0;
                }
            }

            consume_each(i);
            return finish(i, 0);
        }

        case COPY: {

            int o = 0;
            while (o < ninput && o < noutput && d_copied < MAX_SAMPLES) {
                if (in_cor[o] > d_threshold) {
                    if (d_plateau < MIN_PLATEAU) {
                        d_plateau++;

                        // there's another frame
                    } else if (d_copied > MIN_GAP) {
                        d_copied = 0;
                        d_plateau = 0;
                        d_freq_offset = arg(in_abs[o]) / 16;
                        insert_tag(
                            nitems_written(0) + o, d_freq_offset, nitems_read(0) + o);
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
                d_state = SEARCH;
            }

            dout << "SHORT copied " << o << std::endl;

            consume_each(o);
            return finish(o, o);
        }
        }

        throw std::runtime_error("sync short: unknown state");
        return 0;
    }

    void insert_tag(uint64_t item, double freq_offset, uint64_t input_item)
    {
        mylog("frame start at in: {} out: {}", item, input_item);
        const uint64_t frame_id = d_next_frame_id++;
        frame_trace::note_sync_short(frame_id, "detected");

        const pmt::pmt_t key = pmt::string_to_symbol("wifi_start");
        const pmt::pmt_t value = pmt::from_double(freq_offset);
        const pmt::pmt_t srcid = pmt::string_to_symbol(name());
        add_item_tag(0, item, key, value, srcid);
        add_item_tag(0,
                     item,
                     pmt::string_to_symbol("frame_id"),
                     pmt::from_uint64(frame_id),
                     srcid);
    }

private:
    enum { SEARCH, COPY } d_state;
    int d_copied;
    int d_plateau;
    float d_freq_offset;
    uint64_t d_next_frame_id;
    uint64_t d_work_calls;
    uint64_t d_items_in;
    uint64_t d_items_out;
    uint64_t d_work_time_ns;
    const double d_threshold;
    const bool d_log;
    const bool d_debug;
    const unsigned int MIN_PLATEAU;
};

sync_short::sptr
sync_short::make(double threshold, unsigned int min_plateau, bool log, bool debug)
{
    return gnuradio::get_initial_sptr(
        new sync_short_impl(threshold, min_plateau, log, debug));
}
