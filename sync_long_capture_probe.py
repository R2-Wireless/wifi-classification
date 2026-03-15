#!/usr/bin/env python3
"""
sync_long_capture_probe.py
==========================
A GNU Radio sync_block that sits between sync_long and blocks_stream_to_vector_0
and captures everything sync_long produces into a single .npz file:

  - samples:          np.complex64 array  — the raw time-domain IQ stream
  - tag_offsets:      np.uint64 array     — item index of each tag
  - tag_keys:         list[str]           — tag key strings
  - tag_values_f64:   np.float64 array    — value for double-typed tags
  - tag_values_u64:   np.uint64 array     — value for uint64-typed tags
  - tag_value_types:  list[str]           — "f64" or "u64" per tag

Usage — in main_script_14.py, inside wifi_rx_file.__init__():

    # 1. Import at the top of the file:
    from sync_long_capture_probe import SyncLongCaptureProbe

    # 2. Instantiate after sync_long:
    self.capture_probe = SyncLongCaptureProbe("/tmp/sync_long_capture.npz")

    # 3. Wire it between sync_long and stream_to_vector (fan-out):
    #    Replace the original single connection:
    #      self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
    #    With these two:
    self.connect((self.ieee802_11_sync_long_0,  0), (self.capture_probe,            0))
    self.connect((self.capture_probe,           0), (self.blocks_stream_to_vector_0, 0))

    # The probe is transparent — it passes every sample and every tag through
    # unchanged, so the rest of the pipeline (FFT, frame_equalizer, decode_mac)
    # continues to work exactly as before.

After tb.run() completes, the file at the path you specified will exist and can
be loaded with load_sync_long_capture() from this same module.
"""

import numpy as np
import pmt
from gnuradio import gr


# Keys that sync_long places on its output stream (from sync_long.cc COPY state).
# We record all tags we see, but these are the four expected ones.
EXPECTED_TAG_KEYS = {"wifi_start", "frame_id", "cfo_short_rad_per_samp", "cfo_long_rad_per_samp"}


class SyncLongCaptureProbe(gr.sync_block):
    """
    Transparent passthrough that captures every sample and tag from sync_long.

    Item size: sizeof(gr_complex) = 8 bytes  (real32 + imag32)
    This matches sync_long's output declaration and stream_to_vector's input.
    """

    def __init__(self, output_path: str):
        gr.sync_block.__init__(
            self,
            name="sync_long_capture_probe",
            in_sig=[np.complex64],   # 1 complex sample per item — matches sync_long output
            out_sig=[np.complex64],  # pass-through, same item size
        )
        self._output_path = output_path

        # Accumulation buffers
        self._samples = []          # list of np.complex64 chunks
        self._tag_offsets = []      # absolute item offset of each tag
        self._tag_keys = []         # str
        self._tag_values_f64 = []   # float64 (used for double-typed tags)
        self._tag_values_u64 = []   # uint64  (used for uint64-typed tags)
        self._tag_value_types = []  # "f64" or "u64"

        # Tell GNURadio to propagate ALL tags from input to output automatically.
        # This means frame_equalizer will see the exact same tags as before.
        self.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

        print(f"[SyncLongCaptureProbe] will save to: {output_path}")

    # ------------------------------------------------------------------
    # GNURadio work() — called repeatedly by the scheduler
    # ------------------------------------------------------------------

    def work(self, input_items, output_items):
        in0 = input_items[0]    # np.complex64 view of current buffer chunk
        out = output_items[0]

        n = len(in0)
        if n == 0:
            return 0

        # --- 1. Copy samples to output (passthrough) ---
        out[:n] = in0[:n]

        # --- 2. Collect samples for saving ---
        self._samples.append(in0[:n].copy())

        # --- 3. Collect tags in this window ---
        abs_start = self.nitems_read(0)     # absolute item index of in0[0]
        abs_end   = abs_start + n

        tags = self.get_tags_in_range(0, abs_start, abs_end)
        for tag in tags:
            key_str = pmt.symbol_to_string(tag.key)
            abs_offset = tag.offset        # absolute item index

            self._tag_offsets.append(abs_offset)
            self._tag_keys.append(key_str)

            # Decode value — sync_long uses from_double or from_uint64
            val = tag.value
            if pmt.is_real(val) or pmt.is_number(val):
                try:
                    self._tag_values_f64.append(float(pmt.to_double(val)))
                    self._tag_values_u64.append(0)
                    self._tag_value_types.append("f64")
                    continue
                except Exception:
                    pass
            if pmt.is_uint64(val):
                try:
                    self._tag_values_u64.append(int(pmt.to_uint64(val)))
                    self._tag_values_f64.append(0.0)
                    self._tag_value_types.append("u64")
                    continue
                except Exception:
                    pass
            # Fallback: try double first, then uint64
            try:
                self._tag_values_f64.append(float(pmt.to_double(val)))
                self._tag_values_u64.append(0)
                self._tag_value_types.append("f64")
            except Exception:
                try:
                    self._tag_values_u64.append(int(pmt.to_uint64(val)))
                    self._tag_values_f64.append(0.0)
                    self._tag_value_types.append("u64")
                except Exception:
                    # Unknown type — skip
                    self._tag_offsets.pop()
                    self._tag_keys.pop()

        return n

    # ------------------------------------------------------------------
    # Called by GNURadio when the flowgraph stops — save the file
    # ------------------------------------------------------------------

    def stop(self):
        self._save()
        return True

    def _save(self):
        if not self._samples:
            print("[SyncLongCaptureProbe] No samples collected — nothing saved.")
            return

        samples = np.concatenate(self._samples).astype(np.complex64)

        tag_offsets    = np.array(self._tag_offsets,    dtype=np.uint64)
        tag_values_f64 = np.array(self._tag_values_f64, dtype=np.float64)
        tag_values_u64 = np.array(self._tag_values_u64, dtype=np.uint64)

        np.savez(
            self._output_path,
            samples         = samples,
            tag_offsets     = tag_offsets,
            tag_keys        = np.array(self._tag_keys,        dtype=object),
            tag_values_f64  = tag_values_f64,
            tag_values_u64  = tag_values_u64,
            tag_value_types = np.array(self._tag_value_types, dtype=object),
        )

        # Count detected frames (wifi_start tags = one per frame)
        n_frames = sum(1 for k in self._tag_keys if k == "wifi_start")
        print(f"[SyncLongCaptureProbe] Saved {len(samples):,} samples, "
              f"{len(self._tag_keys)} tags, {n_frames} frames "
              f"→ {self._output_path}.npz")


# =============================================================================
# Loader utility — use this to inspect / replay the capture
# =============================================================================

#===================

def load_sync_long_capture(path: str) -> dict:
    """
    Load a .npz file produced by SyncLongCaptureProbe.

    Returns a dict with:
        samples         : np.complex64[N]   — full time-domain IQ stream
        frames          : list[dict]        — one dict per detected frame, with:
            start_offset        : int       — absolute sample index in `samples`
            wifi_start          : float     — CFO residual rad/sample (= cfo_short - cfo_long)
            cfo_short_rad_per_samp : float
            cfo_long_rad_per_samp  : float
            frame_id            : int
            lts1                : np.complex64[64]   — first long training symbol
            lts2                : np.complex64[64]   — second long training symbol
            data_symbols        : np.complex64[K,64] — CP-stripped OFDM symbols after LTS
                                   row 0 = SIGNAL field, rows 1..N = data symbols
        tags_raw        : list[dict]        — every tag as {"offset","key","value","type"}
    """
    # Accept path with or without .npz suffix
    npz_path = path if path.endswith(".npz") else path + ".npz"
    data = np.load(npz_path, allow_pickle=True)

    samples         = data["samples"]              # complex64[N]
    tag_offsets     = data["tag_offsets"]          # uint64[T]
    tag_keys        = data["tag_keys"].tolist()    # list[str]
    tag_values_f64  = data["tag_values_f64"]       # float64[T]
    tag_values_u64  = data["tag_values_u64"]       # uint64[T]
    tag_value_types = data["tag_value_types"].tolist()  # list[str]

    # Build raw tag list
    tags_raw = []
    for i in range(len(tag_keys)):
        vtype = tag_value_types[i]
        value = float(tag_values_f64[i]) if vtype == "f64" else int(tag_values_u64[i])
        tags_raw.append({
            "offset": int(tag_offsets[i]),
            "key":    tag_keys[i],
            "value":  value,
            "type":   vtype,
        })

    # Group tags by frame — a new frame starts at each "wifi_start" tag offset.
    # All four tags for one frame share the same absolute offset.
    frame_offsets = sorted(
        set(t["offset"] for t in tags_raw if t["key"] == "wifi_start")
    )

    frames = []
    for idx, frame_start in enumerate(frame_offsets):
        frame_tags = {t["key"]: t["value"] for t in tags_raw if t["offset"] == frame_start}

        # ── FIX: cap slice at the next frame's start, not end-of-file ──
        if idx + 1 < len(frame_offsets):
            frame_end = frame_offsets[idx + 1]   # exclusive: first sample of next frame
        else:
            frame_end = len(samples)              # last frame: go to end of buffer

        rel = samples[frame_start : frame_end]   # only this frame's samples

        lts1 = rel[0:64].copy()   if len(rel) >= 64  else np.array([], dtype=np.complex64)
        lts2 = rel[64:128].copy() if len(rel) >= 128 else np.array([], dtype=np.complex64)

        remaining = rel[128:]
        n_syms = len(remaining) // 64
        data_symbols = remaining[:n_syms * 64].reshape(n_syms, 64).copy() if n_syms > 0 \
                       else np.zeros((0, 64), dtype=np.complex64)

        frames.append({
            "start_offset":            frame_start,
            "end_offset":              frame_end,       # ← also useful to store
            "raw_sample_count":        frame_end - frame_start,
            "wifi_start":              frame_tags.get("wifi_start", 0.0),
            "cfo_short_rad_per_samp":  frame_tags.get("cfo_short_rad_per_samp", 0.0),
            "cfo_long_rad_per_samp":   frame_tags.get("cfo_long_rad_per_samp",  0.0),
            "frame_id":                int(frame_tags.get("frame_id", 0)),
            "lts1":                    lts1,
            "lts2":                    lts2,
            "data_symbols":            data_symbols,
        })

    return {
        "samples":  samples,
        "frames":   frames,
        "tags_raw": tags_raw,
    }

#===========================


def load_sync_long_capture_(path: str) -> dict:
    """
    Load a .npz file produced by SyncLongCaptureProbe.

    Returns a dict with:
        samples         : np.complex64[N]   — full time-domain IQ stream
        frames          : list[dict]        — one dict per detected frame, with:
            start_offset        : int       — absolute sample index in `samples`
            wifi_start          : float     — CFO residual rad/sample (= cfo_short - cfo_long)
            cfo_short_rad_per_samp : float
            cfo_long_rad_per_samp  : float
            frame_id            : int
            lts1                : np.complex64[64]   — first long training symbol
            lts2                : np.complex64[64]   — second long training symbol
            data_symbols        : np.complex64[K,64] — CP-stripped OFDM symbols after LTS
                                   row 0 = SIGNAL field, rows 1..N = data symbols
        tags_raw        : list[dict]        — every tag as {"offset","key","value","type"}
    """
    # Accept path with or without .npz suffix
    npz_path = path if path.endswith(".npz") else path + ".npz"
    data = np.load(npz_path, allow_pickle=True)

    samples         = data["samples"]              # complex64[N]
    tag_offsets     = data["tag_offsets"]          # uint64[T]
    tag_keys        = data["tag_keys"].tolist()    # list[str]
    tag_values_f64  = data["tag_values_f64"]       # float64[T]
    tag_values_u64  = data["tag_values_u64"]       # uint64[T]
    tag_value_types = data["tag_value_types"].tolist()  # list[str]

    # Build raw tag list
    tags_raw = []
    for i in range(len(tag_keys)):
        vtype = tag_value_types[i]
        value = float(tag_values_f64[i]) if vtype == "f64" else int(tag_values_u64[i])
        tags_raw.append({
            "offset": int(tag_offsets[i]),
            "key":    tag_keys[i],
            "value":  value,
            "type":   vtype,
        })

    # Group tags by frame — a new frame starts at each "wifi_start" tag offset.
    # All four tags for one frame share the same absolute offset.
    frame_offsets = sorted(
        set(t["offset"] for t in tags_raw if t["key"] == "wifi_start")
    )

    frames = []
    for frame_start in frame_offsets:
        # Collect all tags at this offset
        frame_tags = {t["key"]: t["value"] for t in tags_raw if t["offset"] == frame_start}

        # Slice the sample array from frame_start
        # Layout from sync_long: 128 samples of LTS (rel 0..127), then 64/symbol thereafter
        rel = samples[frame_start:]  # view from this frame's first sample

        lts1 = rel[0:64].copy()   if len(rel) >= 64  else np.array([], dtype=np.complex64)
        lts2 = rel[64:128].copy() if len(rel) >= 128 else np.array([], dtype=np.complex64)

        # Everything after sample 128 are OFDM symbols with CP stripped:
        # row 0 = SIGNAL field, rows 1..N = data symbols
        remaining = rel[128:]
        n_syms = len(remaining) // 64
        if n_syms > 0:
            data_symbols = remaining[:n_syms * 64].reshape(n_syms, 64).copy()
        else:
            data_symbols = np.zeros((0, 64), dtype=np.complex64)

        frames.append({
            "start_offset":            frame_start,
            "wifi_start":              frame_tags.get("wifi_start", 0.0),
            "cfo_short_rad_per_samp":  frame_tags.get("cfo_short_rad_per_samp", 0.0),
            "cfo_long_rad_per_samp":   frame_tags.get("cfo_long_rad_per_samp",  0.0),
            "frame_id":                int(frame_tags.get("frame_id", 0)),
            "lts1":                    lts1,
            "lts2":                    lts2,
            "data_symbols":            data_symbols,  # shape (K, 64)
        })

    return {
        "samples":  samples,
        "frames":   frames,
        "tags_raw": tags_raw,
    }
