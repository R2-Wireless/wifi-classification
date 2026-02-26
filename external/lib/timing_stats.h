#ifndef INCLUDED_IEEE802_11_TIMING_STATS_H
#define INCLUDED_IEEE802_11_TIMING_STATS_H

#include <cstdint>

namespace gr {
namespace ieee802_11 {
namespace timing_stats {

void add_block_timing(const char* block_name,
                      uint64_t calls,
                      uint64_t items_in,
                      uint64_t items_out,
                      uint64_t time_ns);

} // namespace timing_stats
} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_TIMING_STATS_H */
