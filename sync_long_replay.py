#!/usr/bin/env python3
"""
sync_long_replay.py
===================
Loads a .npz capture produced by SyncLongCaptureProbe and replays it
through the downstream pipeline:

    file_source (captured .bin) → stream_to_vector(64) → fft_vcc(64)
        → frame_equalizer → decode_mac → message_handler

This is a DROP-IN replacement for the full wifi_rx_file flowgraph that
completely bypasses sync_short and sync_long.

The captured samples are written to a temporary raw binary file first,
because GNURadio's file_source reads raw bytes.  Tags cannot travel
through file_source, so a custom TagInjectBlock re-injects the four
sync_long tags at the correct item positions before stream_to_vector.

Usage:
    python3 sync_long_replay.py /tmp/sync_long_capture.npz [output.pcap]

    # or import and call directly:
    from sync_long_replay import run_replay
    run_replay("/tmp/sync_long_capture.npz", "/tmp/replay_output.pcap")
"""

import sys
import os
import tempfile
import numpy as np
import pmt

from gnuradio import gr, blocks, fft as gr_fft
from gnuradio.fft import window
import ieee802_11

# Reuse the loader from the capture module
sys.path.insert(0, os.path.dirname(__file__))
from sync_long_capture_probe import load_sync_long_capture

# Reuse the message handler and PCAPWriter from the main script
# Adjust the import path if main_script_14.py is in a different location.
try:
    from main_script_14 import message_handler, PCAPWriter
except ImportError:
    # Minimal stub if the main script is not importable
    class PCAPWriter:
        def __init__(self, path):
            print(f"[replay] PCAPWriter stub — output to {path}")
            self.packet_count = 0
        def write_packet(self, *a, **kw): pass
        def close(self): pass

    class message_handler(gr.sync_block):
        def __init__(self, pcap, center_freq_hz=5.18e9, samp_rate_hz=20e6, verbose=True):
            gr.sync_block.__init__(self, "message_handler", in_sig=None, out_sig=None)
            self.pcap = pcap
            self.packet_count = 0
            self.total_msg_time_ns = 0
            self.stats = type("S", (), {"print_summary": lambda s: None,
                                        "total_frames": 0})()
            self.message_port_register_in(pmt.intern("in"))
            self.set_msg_handler(pmt.intern("in"), self._handle)
        def _handle(self, msg):
            self.packet_count += 1
            meta = pmt.car(msg)
            fcs_ok = pmt.to_bool(pmt.dict_ref(meta, pmt.intern("fcs_ok"),
                                              pmt.from_bool(False)))
            print(f"[replay] PDU #{self.packet_count}  fcs_ok={fcs_ok}")


# =============================================================================
# Tag injection block
# =============================================================================

class TagInjectBlock(gr.sync_block):
    """
    Passes samples through unchanged and injects GNURadio tags at specified
    absolute item offsets.  Used to re-insert the sync_long tags that were
    lost when samples were saved to a raw binary file.

    tags: list of dicts, each with:
        offset  : int    — absolute item index (matches nitems_written(0))
        key     : str
        value_f64 : float | None
        value_u64 : int   | None
        value_type: "f64" | "u64"
    """

    def __init__(self, tags: list):
        gr.sync_block.__init__(
            self,
            name="tag_inject",
            in_sig=[np.complex64],
            out_sig=[np.complex64],
        )
        # Sort by offset so we can pop from the front efficiently
        self._pending = sorted(tags, key=lambda t: t["offset"])
        self._pending_idx = 0          # next tag to emit
        self.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

    def work(self, input_items, output_items):
        in0  = input_items[0]
        out  = output_items[0]
        n    = len(in0)

        out[:n] = in0[:n]

        write_base = self.nitems_written(0)   # absolute output index of out[0]
        write_end  = write_base + n

        # Emit any tags whose offset falls within this output window
        while self._pending_idx < len(self._pending):
            tag = self._pending[self._pending_idx]
            abs_off = tag["offset"]
            if abs_off >= write_end:
                break                         # not yet in this window
            if abs_off < write_base:
                # Missed window (shouldn't happen with monotone flow) — emit now
                abs_off = write_base

            key_pmt = pmt.string_to_symbol(tag["key"])
            if tag["value_type"] == "u64":
                val_pmt = pmt.from_uint64(int(tag["value_u64"]))
            else:
                val_pmt = pmt.from_double(float(tag["value_f64"]))

            self.add_item_tag(0, abs_off, key_pmt, val_pmt,
                              pmt.string_to_symbol("tag_inject"))
            self._pending_idx += 1

        return n


# =============================================================================
# Replay flowgraph
# =============================================================================

class wifi_rx_replay(gr.top_block):
    """
    Replays a sync_long capture (.npz) through the downstream pipeline.

    Pipeline:
        file_source(.bin)  →  TagInjectBlock  →  stream_to_vector(64)
            →  fft_vcc(64)  →  frame_equalizer  →  decode_mac
            →  message_handler
    """

    def __init__(self, npz_path: str, output_pcap: str,
                 freq: float = 5.180e9, samp_rate: float = 20e6,
                 chan_est=None, verbose: bool = True):
        gr.top_block.__init__(self, "WiFi RX Replay")

        # ----------------------------------------------------------------
        # 1. Load the capture
        # ----------------------------------------------------------------
        if 0:
            print(f"[replay] Loading capture: {npz_path}")
            cap = load_sync_long_capture(npz_path)
            samples  = cap["samples"]    # np.complex64[N]
            tags_raw = cap["tags_raw"]   # list[dict]

            n_frames = len(cap["frames"])
            print(f"[replay] {len(samples):,} samples, {len(tags_raw)} tags, "
                f"{n_frames} detected frames")

        #-----------------------------------------------------------------
         # ----------------------------------------------------------------
        # 1. Load the capture
        # ----------------------------------------------------------------
        print(f"[replay] Loading capture: {npz_path}")

        npz_path_full = npz_path if npz_path.endswith('.npz') else npz_path + '.npz'
        d = np.load(npz_path_full, allow_pickle=True)

        samples         = d['samples']                    # np.complex64[N]
        tag_offsets     = d['tag_offsets']                # np.uint64[T]
        tag_keys        = d['tag_keys']                   # np.object_[T] (strings)
        tag_values_f64  = d['tag_values_f64']             # np.float64[T]
        tag_values_u64  = d['tag_values_u64']             # np.uint64[T]
        tag_value_types = d['tag_value_types']            # np.object_[T] (strings)

        # Build tags_raw as list of dicts (same structure the rest of the code expects)
        tags_raw = []
        for i in range(len(tag_keys)):
            vtype = str(tag_value_types[i])
            value = float(tag_values_f64[i]) if vtype == 'f64' else int(tag_values_u64[i])
            tags_raw.append({
                "offset": int(tag_offsets[i]),
                "key":    str(tag_keys[i]),
                "value":  value,
                "type":   vtype,
            })

        # Count frames from wifi_start tags
        frame_offsets = sorted(set(
            t["offset"] for t in tags_raw if t["key"] == "wifi_start"
        ))
        n_frames = len(frame_offsets)

        print(f"[replay] {len(samples):,} samples, {len(tags_raw)} tags, "
            f"{n_frames} detected frames") 

        # ----------------------------------------------------------------
        # 2. Write samples to a temp binary file for file_source
        # ----------------------------------------------------------------
        self._tmpfile = tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False, prefix="sync_long_replay_"
        )
        samples.tofile(self._tmpfile)
        self._tmpfile.flush()
        self._tmpfile.close()
        print(f"[replay] Temp binary: {self._tmpfile.name}  "
              f"({os.path.getsize(self._tmpfile.name):,} bytes)")

        # ----------------------------------------------------------------
        # 3. Build tag list for TagInjectBlock
        # ----------------------------------------------------------------
        inject_tags = []
        for t in tags_raw:
            entry = {
                "offset":     t["offset"],
                "key":        t["key"],
                "value_type": t["type"],
                "value_f64":  t["value"] if t["type"] == "f64" else 0.0,
                "value_u64":  t["value"] if t["type"] == "u64" else 0,
            }
            inject_tags.append(entry)

        # ----------------------------------------------------------------
        # 4. Instantiate blocks
        # ----------------------------------------------------------------
        self.pcap        = PCAPWriter(output_pcap)
        self.msg_handler = message_handler(
            self.pcap,
            center_freq_hz=freq,
            samp_rate_hz=samp_rate,
            verbose=verbose,
        )

        # file_source: reads the raw complex64 binary, no repeat
        self.file_source = blocks.file_source(
            gr.sizeof_gr_complex,
            self._tmpfile.name,
            False,   # repeat=False
            0, 0,
        )
        self.file_source.set_begin_tag(pmt.PMT_NIL)

        # Tag injector — re-inserts sync_long tags at correct sample positions
        self.tag_inject = TagInjectBlock(inject_tags)

        # Throttle is optional in replay (no real-time constraint), but keeps
        # the scheduler from spinning at 100% CPU.  Remove if you want max speed.
        self.throttle = blocks.throttle(gr.sizeof_gr_complex, samp_rate, True)

        # stream_to_vector: pack 64 scalar complex samples → one 64-vector item
        # Tag propagation ALL_TO_ALL: tags land on the vector item that contains
        # the tagged scalar sample.  Because the wifi_start tag is at the FIRST
        # sample of LTS1, and LTS1 starts at a 64-sample boundary (sync_long
        # ensures this), the tag will land on item 0 of the frame's vector
        # sequence — exactly where frame_equalizer expects it.
        self.stream_to_vector = blocks.stream_to_vector(gr.sizeof_gr_complex, 64)
        self.stream_to_vector.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

        # FFT: 64-point forward FFT, rectangular window, shift=True
        self.fft_block = gr_fft.fft_vcc(64, True, window.rectangular(64), True, 1)
        self.fft_block.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

        if chan_est is None:
            chan_est = ieee802_11.LS
        self.frame_equalizer = ieee802_11.frame_equalizer(
            ieee802_11.Equalizer(chan_est), freq, samp_rate, True, True
        )

        self.decode_mac = ieee802_11.decode_mac(True, True)

        # ----------------------------------------------------------------
        # 5. Wire connections
        # ----------------------------------------------------------------
        #
        #  file_source → throttle → tag_inject → stream_to_vector
        #      → fft_block → frame_equalizer → decode_mac → msg_handler
        #
        self.connect((self.file_source,      0), (self.throttle,        0))
        self.connect((self.throttle,         0), (self.tag_inject,      0))
        self.connect((self.tag_inject,       0), (self.stream_to_vector, 0))
        self.connect((self.stream_to_vector, 0), (self.fft_block,        0))
        self.connect((self.fft_block,        0), (self.frame_equalizer,  0))
        self.connect((self.frame_equalizer,  0), (self.decode_mac,       0))

        self.msg_connect((self.decode_mac, "out"),      (self.msg_handler, "in"))
        self.msg_connect((self.decode_mac, "out_fail"), (self.msg_handler, "in"))

    def __del__(self):
        # Clean up temp file
        try:
            if hasattr(self, "_tmpfile") and os.path.exists(self._tmpfile.name):
                os.unlink(self._tmpfile.name)
        except Exception:
            pass


# =============================================================================
# Entry point
# =============================================================================

def run_replay(npz_path: str, output_pcap: str = "/tmp/replay_output.pcap",
               freq: float = 5.180e9, samp_rate: float = 20e6,
               verbose: bool = True):
    tb = wifi_rx_replay(
        npz_path, output_pcap,
        freq=freq, samp_rate=samp_rate,
        verbose=verbose,
    )
    print("[replay] Starting flowgraph …")
    tb.run()
    print(f"[replay] Done.  PDUs received: {tb.msg_handler.packet_count}")
    tb.pcap.close()
    try:
        tb.msg_handler.stats.print_summary()
    except Exception:
        pass


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Replay sync_long capture through downstream pipeline")
    p.add_argument("npz_path",     help="Path to .npz capture (with or without .npz suffix)")
    p.add_argument("output_pcap",  nargs="?", default="/tmp/replay_output.pcap")
    p.add_argument("--freq",       type=float, default=5.180e9,
                   help="Center frequency in Hz (default: 5.180e9)")
    p.add_argument("--samp-rate",  type=float, default=20e6,
                   help="Sample rate in Hz (default: 20e6)")
    p.add_argument("--compact",    action="store_true")
    args = p.parse_args()

    run_replay(
        args.npz_path,
        args.output_pcap,
        freq=args.freq,
        samp_rate=args.samp_rate,
        verbose=not args.compact,
    )
