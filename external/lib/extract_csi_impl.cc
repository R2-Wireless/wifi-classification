/* -*- c++ -*- */
/*
 * Copyright 2021 Anton Ottosson.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extract_csi_impl.h"
#include "timing_stats.h"
#include <gnuradio/io_signature.h>
#include <chrono>
#include <iostream>

namespace gr {
namespace ieee802_11 {

extract_csi::sptr extract_csi::make()
{
    return gnuradio::get_initial_sptr(new extract_csi_impl());
}


extract_csi_impl::extract_csi_impl()
    : gr::sync_block("extract_csi",
                     gr::io_signature::make(0, 0, 0),
                     gr::io_signature::make(1, 1, 52 * sizeof(gr_complex))),
      d_work_calls(0),
      d_items_in(0),
      d_items_out(0),
      d_work_time_ns(0)
{
    message_port_register_in(pmt::mp("pdu in"));
}

extract_csi_impl::~extract_csi_impl()
{
    if (!d_work_calls) {
        return;
    }
    timing_stats::add_block_timing(
        "extract_csi", d_work_calls, d_items_in, d_items_out, d_work_time_ns);
    const double total_ms = static_cast<double>(d_work_time_ns) / 1e6;
    const double avg_us = static_cast<double>(d_work_time_ns) / d_work_calls / 1e3;
    std::cout << "[timing] extract_csi calls=" << d_work_calls
              << " in=" << d_items_in
              << " out=" << d_items_out
              << " total_ms=" << total_ms
              << " avg_us=" << avg_us << std::endl;
}

int extract_csi_impl::work(int noutput_items,
                           gr_vector_const_void_star& input_items,
                           gr_vector_void_star& output_items)
{
    const auto t_start = std::chrono::steady_clock::now();
    auto finish = [&](int produced) {
        d_work_calls++;
        d_items_out += produced;
        d_work_time_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::steady_clock::now() - t_start)
                              .count();
        return produced;
    };

    pmt::pmt_t pdu(delete_head_nowait(pmt::mp("pdu in")));

    if (pdu.get() == NULL)
        return finish(0);

    if (!pmt::is_pair(pdu) || !pmt::is_dict(pmt::car(pdu)))
        throw std::runtime_error("received a malformed pdu message");

    d_meta = pmt::car(pdu);

    if (!pmt::dict_has_key(d_meta, pmt::mp("csi")))
        return finish(0);

    d_csi = pmt::c32vector_elements(pmt::dict_ref(d_meta, pmt::mp("csi"), pmt::PMT_NIL));

    gr_complex* out = (gr_complex*)output_items[0];

    std::copy(d_csi.begin(), d_csi.end(), out);

    pmt::pmt_t keys(pmt::dict_keys(d_meta));
    for (int i = 0; i < pmt::length(keys); i++) {
        pmt::pmt_t k(pmt::nth(i, keys));
        pmt::pmt_t v(pmt::dict_ref(d_meta, k, pmt::PMT_NIL));
        add_item_tag(0, nitems_written(0), k, v, alias_pmt());
    }

    d_items_in += 52;
    return finish(1);
}

} /* namespace ieee802_11 */
} /* namespace gr */
