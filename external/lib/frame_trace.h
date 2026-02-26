#ifndef INCLUDED_IEEE802_11_FRAME_TRACE_H
#define INCLUDED_IEEE802_11_FRAME_TRACE_H

#include <cstdint>
#include <string>

namespace gr {
namespace ieee802_11 {
namespace frame_trace {

void note_sync_short(uint64_t frame_id, const char* status);
void note_sync_long(uint64_t frame_id, const char* status);
void note_sync_long(uint64_t frame_id, const std::string& status);
void note_equalizer(uint64_t frame_id, const char* status);
void note_decode(uint64_t frame_id, const char* status);
void note_decode(uint64_t frame_id, const std::string& status);
void note_outcome(uint64_t frame_id, const char* status);

} // namespace frame_trace
} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_FRAME_TRACE_H */
