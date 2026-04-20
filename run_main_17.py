# -*- coding: utf-8 -*-
"""
Created on Mon Mar 30 13:41:29 2026

@author: Owner
"""

#!/usr/bin/env python3
from __future__ import annotations
"""
run_main_17.py  (stand-alone detect/capture with optional direct replay)
=======================================================================
Stand-alone pipeline: load IQ file → resample → sync_long detect → capture

This file depends ONLY on the Python standard library plus NumPy / SciPy.
It does NOT import from sync_long_python.py, main_script_14.py,
sync_long_capture_probe.py, or any other project module.

Supported input formats
-----------------------
  .mat   — MATLAB file, one complex variable
  .iq    — raw interleaved int16 IQ
  .bin   — raw interleaved int16 IQ
  .cfile — raw interleaved float32 IQ, GNURadio format

Pipeline stages
---------------
  1. init()         — pre-compute CFO filter bank for the long training sequence
  2. load_file()    — read raw IQ samples from disk
  3. resample()     — rational-rate resample to TARGET_SAMP_RATE (skipped if already there)
  4. detect()       — sync_long peak detection (uses pre-built filter bank)
  5. capture()      — build per-frame sample + tag arrays
  6. replay()       — optional direct handoff into GNU Radio (no .npz needed)

Target sample rate
------------------
  This standalone tool supports native target rates of 5/10/20 MHz. Input
  files are loaded at their true source rates and resampled to the selected
  target rate before detection. The detector geometry remains fixed to the
  existing 64-sample / 80-sample pipeline constants.

Usage (CLI)
-----------
  python run_main_1.py capture.iq
  python run_main_1.py capture.mat --output /tmp/out.npz
  python run_main_1.py capture.cfile --no-cfo-search
  python run_main_1.py capture.iq --output /tmp/out.npz
  python run_main_1.py capture.iq  --channel-bw 5
  python run_main_1.py capture.bin --channel-bw 10
  python run_main_1.py capture.mat --channel-bw 20

Usage (import)
--------------
  from run_main_1 import init, load_file, resample, detect, capture, SyncLongConfig

  cfg    = SyncLongConfig()
  bank   = init(cfg)                         # pre-build filter bank (call once)
  raw, _ = load_file("capture.iq")           # load raw samples
  iq     = resample(raw, ".iq")
  det    = detect(iq, bank, cfg)             # sync_long detection
  cap    = capture(iq, det, cfg)             # build frame capture
  # cap["samples"], cap["tag_offsets"], ... etc.
"""

import argparse
import math
import os
import sys
import time
from dataclasses import dataclass, field
from math import gcd
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy.fft import fft as _scipy_fft, ifft as _scipy_ifft
from scipy.signal import firwin, resample_poly

# ---------------------------------------------------------------------------
# Global tunables (override via environment variables)
# ---------------------------------------------------------------------------
_FFT_WORKERS    = int(os.environ.get("SYNC_LONG_FFT_WORKERS", "-1"))
_CFO_TILE_SIZE  = max(1, int(os.environ.get("SYNC_LONG_CFO_TILE", "4")))

# Default target sample rate — can be overridden per-call via target_rate arguments
# or via the --target-rate CLI flag (e.g. 10e6 for 10 MHz).
TARGET_SAMP_RATE: float = 20e6

# Source sample rates by file extension (used when --samp-rate-in is not given).
SAMP_RATE_BY_EXT: Dict[str, float] = {
    ".mat":   30.72e6,
    ".iq":    40e6,
    ".bin":   30.72e6,
    ".cfile": 20e6,
}

# All input-rate hypotheses to try when the extension is .iq.
IQ_RATE_HYPOTHESES: List[float] = [40e6]

# All input-rate hypotheses to try when the extension is .bin.
BIN_RATE_HYPOTHESES: List[float] = [30.72e6]

# ---------------------------------------------------------------------------
# Channel-bandwidth → target-rate mapping
# ---------------------------------------------------------------------------
CHANNEL_BW_TO_TARGET_RATE: Dict[int, float] = {5: 5e6, 10: 10e6, 20: 20e6}


def _resolve_target_rate(target_rate: Optional[float], channel_bw: Optional[int]) -> float:
    if target_rate is None and channel_bw is None:
        return TARGET_SAMP_RATE
    if target_rate is None:
        return CHANNEL_BW_TO_TARGET_RATE[int(channel_bw)]
    target_rate = float(target_rate)
    if channel_bw is not None:
        expected = CHANNEL_BW_TO_TARGET_RATE[int(channel_bw)]
        if abs(target_rate - expected) > 1.0:
            raise ValueError(
                f"--target-rate ({target_rate}) does not match --channel-bw {channel_bw} MHz ({expected})"
            )
    return target_rate


def _rates_for_channel_bw(
    channel_bw: Optional[int],
    ext: str,
) -> Optional[List[float]]:
    """Return fixed true source-rate hypotheses by file type."""
    _ = channel_bw
    if ext == ".iq":
        return [40e6]
    if ext in (".bin", ".mat"):
        return [30.72e6]
    if ext == ".cfile":
        return [20e6]
    return None


def _resolve_chan_est(name: str):
    name = str(name).strip().lower()
    import ieee802_11

    mapping = {
        "ls": ieee802_11.LS,
        "lms": ieee802_11.LMS,
        "sta": ieee802_11.STA,
        "comb": ieee802_11.COMB,
    }
    try:
        return mapping[name]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported --chan-est {name!r}; expected one of: ls, lms, sta, comb"
        ) from exc


def _scale_timing(cfg: "SyncLongConfig", target_rate: float) -> "SyncLongConfig":
    """
    Keep the detector geometry fixed for the existing 64-sample / 80-sample
    pipeline, but update cfg.samp_rate so the CFO search and reported best_freq_hz
    use the true target-rate units.
    """
    if abs(target_rate - cfg.samp_rate) < 1.0:
        return cfg

    from dataclasses import replace
    return replace(cfg, samp_rate=target_rate)


def _dump_sync_long_debug(detection: Dict[str, object]) -> None:
    """Optionally dump sync-long correlation / detections for offline MATLAB plots.

    Mirrors the file naming used by sync_long.cc when WIFI_DUMP_CORR=1.
    """
    if os.getenv("WIFI_DUMP_CORR") is None:
        return

    corr_long = np.asarray(detection.get("corr_long", []), dtype=np.float32).reshape(-1)
    corr_long_phase = np.asarray(detection.get("corr_long_phase", []), dtype=np.complex64).reshape(-1)
    sorted_peaks = np.asarray(detection.get("sorted_peaks", []), dtype=np.int64).reshape(-1)

    mag_path = os.getenv("WIFI_DUMP_LONG_MAG_PATH", "/tmp/sync_long_cor_mag.bin")
    mag_abs_path = os.getenv("WIFI_DUMP_LONG_MAG_ABS_PATH", "/tmp/sync_long_cor_mag_abs.bin")
    cplx_path = os.getenv("WIFI_DUMP_LONG_CPLX_PATH", "/tmp/sync_long_cor_cplx.bin")
    det_path = os.getenv("WIFI_DUMP_LONG_DET_PATH", "/tmp/sync_long_det.bin")
    det_meta_path = os.getenv("WIFI_DUMP_LONG_DET_META_PATH", "/tmp/sync_long_det_meta.bin")

    corr_long.astype(np.float32, copy=False).tofile(mag_path)
    corr_long_phase.astype(np.complex64, copy=False).tofile(cplx_path)

    abs_dtype = np.dtype([("idx", np.uint64), ("mag", np.float32)])
    if len(corr_long):
        abs_dump = np.empty(len(corr_long), dtype=abs_dtype)
        abs_dump["idx"] = np.arange(len(corr_long), dtype=np.uint64)
        abs_dump["mag"] = corr_long
        abs_dump.tofile(mag_abs_path)
    else:
        np.zeros(0, dtype=abs_dtype).tofile(mag_abs_path)

    pair_count = len(sorted_peaks) // 2
    peak_pairs = sorted_peaks[: pair_count * 2].reshape(pair_count, 2) if pair_count else np.zeros((0, 2), dtype=np.int64)
    peak_pairs.astype(np.uint64, copy=False).tofile(det_path)

    if pair_count:
        frame_ids = np.arange(1, pair_count + 1, dtype=np.uint64).reshape(-1, 1)
        det_meta = np.concatenate((frame_ids, peak_pairs.astype(np.uint64)), axis=1)
        det_meta.tofile(det_meta_path)
    else:
        np.zeros((0, 3), dtype=np.uint64).tofile(det_meta_path)

    print(
        f"[dump] sync_long correlation written: mag={mag_path} det={det_path}"
    )

# ===========================================================================
# Low-level FFT helpers
# ===========================================================================

def _fft(x: np.ndarray, n: Optional[int] = None, axis: int = -1) -> np.ndarray:
    return _scipy_fft(x, n=n, axis=axis, workers=_FFT_WORKERS)


def _ifft(x: np.ndarray, n: Optional[int] = None, axis: int = -1) -> np.ndarray:
    return _scipy_ifft(x, n=n, axis=axis, workers=_FFT_WORKERS)


def _as_c64(x: np.ndarray) -> np.ndarray:
    return np.asarray(x, dtype=np.complex64)


# ===========================================================================
# 802.11 Long Training Sequence  (64 samples, time domain)
# ===========================================================================

LONG_TRAINING = np.array([
    complex(-0.0455, -1.0679), complex( 0.3528, -0.9865),
    complex( 0.8594,  0.7348), complex( 0.1874,  0.2475),
    complex( 0.5309, -0.7784), complex(-1.0218, -0.4897),
    complex(-0.3401, -0.9423), complex( 0.8657, -0.2298),
    complex( 0.4734,  0.0362), complex( 0.0088, -1.0207),
    complex(-1.2142, -0.4205), complex( 0.2172, -0.5195),
    complex( 0.5207, -0.1326), complex(-0.1995,  1.4259),
    complex( 1.0583, -0.0363), complex( 0.5547, -0.5547),
    complex( 0.3277,  0.8728), complex(-0.5077,  0.3488),
    complex(-1.1650,  0.5789), complex( 0.7297,  0.8197),
    complex( 0.6173,  0.1253), complex(-0.5353,  0.7214),
    complex(-0.5011, -0.1935), complex(-0.3110, -1.3392),
    complex(-1.0818, -0.1470), complex(-1.1300, -0.1820),
    complex( 0.6663, -0.6571), complex(-0.0249,  0.4773),
    complex(-0.8155,  1.0218), complex( 0.8140,  0.9396),
    complex( 0.1090,  0.8662), complex(-1.3868, -0.0000),
    complex( 0.1090, -0.8662), complex( 0.8140, -0.9396),
    complex(-0.8155, -1.0218), complex(-0.0249, -0.4773),
    complex( 0.6663,  0.6571), complex(-1.1300,  0.1820),
    complex(-1.0818,  0.1470), complex(-0.3110,  1.3392),
    complex(-0.5011,  0.1935), complex(-0.5353, -0.7214),
    complex( 0.6173, -0.1253), complex( 0.7297, -0.8197),
    complex(-1.1650, -0.5789), complex(-0.5077, -0.3488),
    complex( 0.3277, -0.8728), complex( 0.5547,  0.5547),
    complex( 1.0583,  0.0363), complex(-0.1995, -1.4259),
    complex( 0.5207,  0.1326), complex( 0.2172,  0.5195),
    complex(-1.2142,  0.4205), complex( 0.0088,  1.0207),
    complex( 0.4734, -0.0362), complex( 0.8657,  0.2298),
    complex(-0.3401,  0.9423), complex(-1.0218,  0.4897),
    complex( 0.5309,  0.7784), complex( 0.1874, -0.2475),
    complex( 0.8594, -0.7348), complex( 0.3528,  0.9865),
    complex(-0.0455,  1.0679), complex( 1.3868, -0.0000),
], dtype=np.complex64)


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class SyncLongConfig:
    # Target output sample rate in Hz.
    samp_rate:               float = TARGET_SAMP_RATE
    expected_gap:            int   = 64
    with_freqoffset_search:  bool  = True
    # CFO search range and number of steps directly define the CFO grid in Hz:
    #     step_hz = (2 * cfo_range_hz) / (num_cfo_steps - 1)
    # and the detector searches linearly from -cfo_range_hz to +cfo_range_hz.
    # This keeps the circular-shift FFT optimization intact while making the
    # CFO search spacing explicit and easy to tune.
    num_cfo_steps:          int   = 401
    # Hard cap on the CFO search range in Hz.  Any bins whose |freq_hz| exceeds
    # this value are dropped after the step-based axis is built.  This prevents
    # the ±200-step default from expanding to ±31 MHz on large buffers (where
    # each step is thousands of bins wide), keeping detect() fast.
    # 802.11 spec: ±20 ppm @ 2.4 GHz ≈ ±48 kHz; ±500 kHz is generous and
    # ensures the true CFO is never right at the edge of the search window.
    cfo_range_hz:            float = 500e3
    threshold_scale:         float = 0.7
    rms_stride:              int   = 30
    max_copy:                int   = 540 * 80
    min_symbols:             int   = 3
    peak_search_safe_len:    int   = 700
    peak_search_max_len:     int   = 300
    peak_tol:                int   = 2
    peak_distance_from_peak: int   = 4
    long_training:           Optional[np.ndarray] = field(default=None, repr=False)


# ===========================================================================
# CFO Filter Bank
# ===========================================================================

@dataclass
class CFOFilterBank:
    """
    Memory-efficient CFO filter bank.

    Instead of pre-storing all (n_freqs x fft_len) shifted templates (~800 MB
    for 401 hypotheses at 250 k samples), only the single FFT of the training
    sequence is kept (~2 MB).  Each hypothesis's shifted template is computed
    on-the-fly during correlation using a 1-D circular-index gather into
    fft_seq — one vector per hypothesis, allocated and freed immediately.

    Peak memory during correlate() is O(fft_len) regardless of n_freqs.
    """
    fft_len:     int
    freq_search: Dict[str, np.ndarray]
    fft_seq:     np.ndarray            # shape (fft_len,) complex64  — single FFT
    tile_size:   int = _CFO_TILE_SIZE  # kept for API compatibility (unused internally)

    def correlate(self, iq_data: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Scan every CFO hypothesis and return the best correlation result.

        Memory cost: O(fft_len) — no large temporaries.
        """
        fft_iq       = _as_c64(_fft(iq_data.astype(np.complex64), n=self.fft_len))
        sampled_bins = self.freq_search["sampled_freq_bins"]
        n            = self.fft_len

        if len(sampled_bins) == 0:
            z = np.zeros(n, dtype=np.float32)
            return {"best_corr": z,
                    "best_corr_phase": z.astype(np.complex64),
                    "best_freq_index": 0}

        # Pre-build a base index array once; each hypothesis shifts it by bin.
        base_idx = np.arange(n, dtype=np.int64)

        best_mag        = -np.inf
        best_freq_index = 0
        best_corr       = None
        best_corr_phase = None

        for hyp_idx, bin_shift in enumerate(sampled_bins):
            # Circular-shift fft_seq by -bin_shift bins (one 1-D gather, ~2 MB)
            shifted_template = self.fft_seq[(base_idx - int(bin_shift)) % n]

            # Multiply + IFFT -> correlation for this single hypothesis
            cp      = _as_c64(_ifft(fft_iq * shifted_template))
            mag     = np.abs(cp).astype(np.float32, copy=False)
            hyp_max = float(mag.max())

            if hyp_max > best_mag:
                best_mag        = hyp_max
                best_freq_index = hyp_idx
                best_corr       = mag
                best_corr_phase = cp

        if best_corr is None:
            z = np.zeros(n, dtype=np.float32)
            best_corr       = z
            best_corr_phase = z.astype(np.complex64)

        return {"best_corr":       best_corr,
                "best_corr_phase": best_corr_phase,
                "best_freq_index": best_freq_index}

    # Keep old name as an alias so any external callers are not broken.
    def correlate_tiled(self, iq_data: np.ndarray) -> Dict[str, np.ndarray]:
        return self.correlate(iq_data)


# ---------------------------------------------------------------------------
# Internal helper: frequency search range
# ---------------------------------------------------------------------------

# Fixed sync sequence rate used in the MATLAB reference implementation.
# The step size is always computed at 30.72 MHz (the acquisition rate),
# regardless of the resampled data rate.
_SYNC_SEQ_RATE_HZ: float = 30.72e6


def _freq_search_rng(data_len: int, seq_len: int,
                     num_cfo_steps: int = 401,
                     samp_rate: float = TARGET_SAMP_RATE,
                     cfo_range_hz: float = 200e3) -> Dict[str, np.ndarray]:
    """
    Build the CFO search axis directly in Hz, then convert it to FFT-bin shifts.

    The grid is defined by:
        step_hz = (2 * cfo_range_hz) / (num_cfo_steps - 1)

    and spans:
        [-cfo_range_hz, ..., +cfo_range_hz]

    This preserves the circular-shift optimization used by CFOFilterBank:
    the training-sequence FFT is still computed once, and each hypothesis is
    applied as an integer circular shift in the FFT domain. Only the method
    used to choose the candidate shift values changes.

    Parameters
    ----------
    data_len      : number of complex samples in the IQ buffer
    seq_len       : length of the sync sequence in samples (kept for API
                    compatibility; not used by the direct-grid method)
    num_cfo_steps : total number of CFO hypotheses in Hz before deduplication
    samp_rate     : data sample rate in Hz
    cfo_range_hz  : half-range of the CFO search window in Hz

    Returns
    -------
    dict with keys
        "sampled_freq_bins"  : int64 array of unique FFT-bin shifts
        "freq_hz"            : float32 array of corresponding CFO values in Hz
        "sampled_freq_step"  : float — CFO spacing in Hz before bin rounding
    """
    _ = seq_len  # kept for interface compatibility

    if data_len <= 0:
        raise ValueError(f"data_len must be > 0, got {data_len}")
    if num_cfo_steps <= 0:
        raise ValueError(f"num_cfo_steps must be > 0, got {num_cfo_steps}")
    if cfo_range_hz < 0:
        raise ValueError(f"cfo_range_hz must be >= 0, got {cfo_range_hz}")

    if num_cfo_steps == 1 or cfo_range_hz == 0:
        freq_hz = np.array([0.0], dtype=np.float64)
        step_hz = 0.0
    else:
        freq_hz = np.linspace(-cfo_range_hz, cfo_range_hz, int(num_cfo_steps), dtype=np.float64)
        step_hz = float(freq_hz[1] - freq_hz[0])

    data_bin_width_hz = samp_rate / data_len
    bins = np.round(freq_hz / data_bin_width_hz).astype(np.int64)

    # Multiple Hz hypotheses can quantize to the same FFT-bin shift.
    # Keep only the first occurrence of each unique bin to avoid redundant scans.
    bins, unique_idx = np.unique(bins, return_index=True)
    order = np.argsort(unique_idx)
    bins = bins[order]
    freq_hz = freq_hz[unique_idx][order]

    return {
        "sampled_freq_bins": bins,
        "freq_hz": freq_hz.astype(np.float32),
        "sampled_freq_step": float(step_hz),
    }


# ===========================================================================
# STAGE 1 — init()
# ===========================================================================

def init(cfg: Optional[SyncLongConfig] = None,
         data_len: int = 0) -> Optional[CFOFilterBank]:
    """
    Pre-compute the CFO filter bank for the long training sequence.

    Parameters
    ----------
    cfg      : SyncLongConfig, optional — defaults to SyncLongConfig().
    data_len : int — actual IQ array length.  Must be > 0 to build the bank.
               Pass 0 (or omit) to get None back; detect() will call init()
               again with the real length once the data is loaded.

    Returns
    -------
    CFOFilterBank, or None if data_len == 0.
    """
    cfg = cfg or SyncLongConfig()
    training = _as_c64(cfg.long_training if cfg.long_training is not None
                       else LONG_TRAINING)

    if data_len <= 0:
        print("[init] data_len not yet known — filter bank will be built inside detect()")
        return None

    print(f"[init] Building CFO filter bank  "
          f"fft_len={data_len:,}  "
          f"num_cfo_steps={cfg.num_cfo_steps}  "
          f"cfo_cap=±{cfg.cfo_range_hz/1e3:.0f} kHz  "
          f"samp_rate={cfg.samp_rate/1e6:.3f} MHz")

    t0 = time.perf_counter()
    freq_search  = _freq_search_rng(
        data_len, len(training),
        num_cfo_steps=cfg.num_cfo_steps,
        samp_rate=cfg.samp_rate,
        cfo_range_hz=cfg.cfo_range_hz,
    )
    sampled_bins = freq_search["sampled_freq_bins"]
    freq_hz      = freq_search["freq_hz"]

    # Only store the single FFT of the training sequence (~2 MB for 250 k samples).
    # Shifted templates are computed on-the-fly in correlate(), costing O(fft_len)
    # per hypothesis instead of pre-allocating an (n_freqs x fft_len) matrix.
    fft_seq = _as_c64(_fft(training, n=data_len))

    bank = CFOFilterBank(
        fft_len=data_len,
        freq_search=freq_search,
        fft_seq=fft_seq,
        tile_size=_CFO_TILE_SIZE,
    )

    dt = time.perf_counter() - t0
    hz_min    = float(freq_hz[0])  if len(freq_hz) else 0.0
    hz_max    = float(freq_hz[-1]) if len(freq_hz) else 0.0
    step_hz   = float(freq_search['sampled_freq_step'])
    unique_bin_width_khz = (cfg.samp_rate / data_len) / 1e3
    print(f"[init] Done — {len(sampled_bins)} unique-bin hypotheses  "
          f"range=[{hz_min/1e3:+.1f}, {hz_max/1e3:+.1f}] kHz  "
          f"grid_step={step_hz/1e3:.3f} kHz  "
          f"fft_bin_width={unique_bin_width_khz:.3f} kHz  "
          f"({dt*1e3:.1f} ms)")
    return bank


# ===========================================================================
# STAGE 1b — probe_data_len()
# ===========================================================================

def probe_data_len(path: str, samp_rate_in: Optional[float] = None,
                   target_rate: float = TARGET_SAMP_RATE) -> int:
    """
    Return the number of complex64 samples that will exist *after* resampling,
    without reading the file contents into memory.

    This lets you call init() with the correct fft_len before load_file(),
    so the filter bank is built exactly once.

    Parameters
    ----------
    path          : input file path (.mat / .iq / .cfile)
    samp_rate_in  : override source sample rate in Hz (auto-detected if None)
    target_rate   : desired output rate in Hz.

    Returns
    -------
    int — expected sample count after resampling to *target_rate*
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in SAMP_RATE_BY_EXT:
        raise ValueError(f"Unsupported extension '{ext}'")

    if ext == ".mat":
        # For .mat we must peek at the variable shape — scipy.io is fast for
        # this because it reads only the header, not the data.
        import scipy.io as sio
        info = sio.whosmat(path)          # [(name, shape, dtype), ...]
        if not info:
            raise ValueError(f"No variables found in {path}")
        # Pick the first non-private variable (same logic as load_file)
        var_name, shape, _ = info[0]
        raw_len = int(np.prod(shape))
    elif ext in (".iq", ".bin"):
        # interleaved int16 I,Q => 4 bytes per complex sample
        byte_size = os.path.getsize(path)
        raw_len   = byte_size // 4
    else:
        # .cfile: raw float32 I,Q => 8 bytes per complex64 sample
        byte_size = os.path.getsize(path)
        raw_len   = byte_size // 8

    src_rate = samp_rate_in if samp_rate_in is not None else SAMP_RATE_BY_EXT[ext]

    if abs(src_rate - target_rate) < 1.0:
        out_len = raw_len
    else:
        up   = int(round(target_rate))
        down = int(round(src_rate))
        g    = gcd(up, down)
        up  //= g
        down //= g
        # resample_poly output length formula
        out_len = int(math.ceil(raw_len * up / down))

    print(f"[probe_data_len] {os.path.basename(path)}  "
          f"raw={raw_len:,} → resampled≈{out_len:,} samples  "
          f"({src_rate/1e6:.3f} → {target_rate/1e6:.3f} MHz)")
    return out_len


# ===========================================================================
# STAGE 2 — load_file()
# ===========================================================================

def load_file(path: str) -> Tuple[np.ndarray, str]:
    """
    Load raw IQ samples from a .mat, .iq, .bin, or .cfile.

    Returns
    -------
    (raw_iq, ext)
        raw_iq : np.complex64 array of raw samples (un-resampled)
        ext    : lower-case extension including dot, e.g. ".iq"
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in SAMP_RATE_BY_EXT:
        raise ValueError(f"Unsupported extension '{ext}'. "
                         f"Supported: {list(SAMP_RATE_BY_EXT)}")

    print(f"[load_file] Reading {ext} file: {path}")
    t0 = time.perf_counter()

    if ext == ".mat":
        import scipy.io as sio
        mat = sio.loadmat(path)
        data_keys = [k for k in mat if not k.startswith("_")]
        if len(data_keys) != 1:
            raise ValueError(
                f".mat file must contain exactly one variable; found: {data_keys}")
        raw = np.asarray(mat[data_keys[0]]).flatten().astype(np.complex64)

    elif ext == ".iq":
        # MATLAB-compatible path:
        # Raw_IQ_data = fread(fid, inf, 'int16', 0, 'l')
        # IQ_data = double(Raw_IQ_data(1:2:end) + 1j * Raw_IQ_data(2:2:end))
        raw_i16 = np.fromfile(path, dtype='<i2')
        if raw_i16.size % 2 != 0:
            raw_i16 = raw_i16[:-1]
        i = raw_i16[0::2].astype(np.float32)
        q = raw_i16[1::2].astype(np.float32)
        raw = (i + 1j * q).astype(np.complex64)

    elif ext == ".bin":
        # MATLAB-compatible path:
        # xx = fread(fopen(path_to_file), 'int16')   — native endian
        # IQ_data = xx(1:2:end) + 1i * xx(2:2:end)
        raw_i16 = np.fromfile(path, dtype=np.int16)  # native endian, matches MATLAB fread
        if raw_i16.size % 2 != 0:
            raw_i16 = raw_i16[:-1]
        i = raw_i16[0::2].astype(np.float32)
        q = raw_i16[1::2].astype(np.float32)
        raw = (i + 1j * q).astype(np.complex64)

    else:  # .cfile — raw interleaved float32
        raw_f32 = np.fromfile(path, dtype=np.float32)
        if raw_f32.size % 2 != 0:
            raw_f32 = raw_f32[:-1]
        raw = raw_f32.view(np.complex64).copy()

    finite_ratio = float(np.mean(np.isfinite(raw))) if len(raw) else 1.0
    if finite_ratio < 1.0:
        bad = len(raw) - int(np.count_nonzero(np.isfinite(raw)))
        print(f"[load_file] Warning: {bad:,} non-finite samples found before resampling")

    dt = time.perf_counter() - t0
    src_rate = SAMP_RATE_BY_EXT[ext]
    print(f"[load_file] Loaded {len(raw):,} samples @ "
          f"{src_rate/1e6:.3f} MHz  ({dt*1e3:.1f} ms)")
    return raw, ext


# ===========================================================================
# STAGE 3 — resample()
# ===========================================================================

def resample(raw: np.ndarray, ext_or_src_rate,
             target_rate: float = TARGET_SAMP_RATE) -> np.ndarray:
    """
    Rational-rate resample raw IQ to *target_rate*.

    Parameters
    ----------
    raw            : raw complex64 samples
    ext_or_src_rate: file extension string (".mat", ".iq", ".cfile")
                     *or* a numeric source sample rate in Hz
    target_rate    : desired output rate in Hz.

    Returns
    -------
    np.complex64 array at target_rate
    """
    if isinstance(ext_or_src_rate, str):
        src_rate = SAMP_RATE_BY_EXT.get(ext_or_src_rate.lower())
        if src_rate is None:
            raise ValueError(f"Unknown extension '{ext_or_src_rate}'")
    else:
        src_rate = float(ext_or_src_rate)

    if abs(src_rate - target_rate) < 1.0:
        print(f"[resample] Source rate {src_rate/1e6:.3f} MHz == target — skipping")
        return np.ascontiguousarray(raw, dtype=np.complex64)

    up   = int(round(target_rate))
    down = int(round(src_rate))
    g    = gcd(up, down)
    up  //= g
    down //= g

    max_rate = max(up, down)
    num_taps = 20 * max_rate + 1
    taps = firwin(num_taps, cutoff=1.0 / max_rate, window=("kaiser", 8.6))

    print(f"[resample] {src_rate/1e6:.3f} MHz → {target_rate/1e6:.3f} MHz  "
          f"(×{up}/÷{down})  filter taps={num_taps}")
    t0 = time.perf_counter()

    if not np.all(np.isfinite(raw)):
        n_bad = int(np.count_nonzero(~np.isfinite(raw)))
        raise ValueError(f"Input contains {n_bad:,} non-finite complex samples before resampling")

    # resample_poly does not support complex input — split and recombine
    raw_f32 = raw.view(np.float32).reshape(-1, 2)   # shape (N, 2): col0=I, col1=Q
    i_out   = resample_poly(raw_f32[:, 0].astype(np.float64), up, down, window=taps)
    q_out   = resample_poly(raw_f32[:, 1].astype(np.float64), up, down, window=taps)
    out     = (i_out + 1j * q_out).astype(np.complex64)
    out     = np.ascontiguousarray(out)

    dt = time.perf_counter() - t0
    print(f"[resample] {len(raw):,} → {len(out):,} samples  ({dt*1e3:.1f} ms)")
    return out


# ===========================================================================
# STAGE 4 — detect()  (sync_long peak detection)
# ===========================================================================

# ---- small peak helpers (ported from sync_long_python.py) -----------------

def _find_peaks(corr: np.ndarray, gap_base: int, threshold: float) -> np.ndarray:
    win = max(1, int(round(gap_base / 4)))
    n_win = len(corr) // win
    if n_win <= 0:
        return np.zeros(0, dtype=np.int64)
    segs    = corr[:n_win * win].reshape(n_win, win)   # (n_windows, win_size)
    idx_max = np.argmax(segs, axis=1)                  # best sample inside each window
    base    = np.arange(n_win, dtype=np.int64) * win
    peaks = base + idx_max
    peaks = peaks[corr[peaks] > threshold]
    peaks = _best_peak_between_pairs(corr, peaks, gap_base)
    peaks = _best_peak_between_pairs(corr, peaks, gap_base)
    return np.sort(peaks.astype(np.int64))


def _best_peak_between_pairs(corr: np.ndarray, peaks: np.ndarray,
                              gap_base: int) -> np.ndarray:
    if len(peaks) == 0:
        return np.zeros(0, dtype=np.int64)
    rm = np.zeros(len(peaks), dtype=np.int64)
    for i in range(1, len(peaks)):
        pair = peaks[i - 1: i + 1]
        if (pair[1] - pair[0]) <= gap_base / 2:
            weaker = int(np.argmin(corr[pair]))
            rm[i] = int(pair[weaker])
    rm_set = {int(v) for v in np.unique(rm) if v != 0}
    return np.array([int(p) for p in peaks if int(p) not in rm_set], dtype=np.int64)


def _sort_long_peaks(peak_indices: np.ndarray, corr: np.ndarray,
                     cfg: SyncLongConfig) -> np.ndarray:
    filtered = []
    for pi in peak_indices:
        pi = int(pi)
        if pi <= cfg.peak_search_safe_len or pi >= len(corr) - cfg.peak_search_safe_len:
            continue
        pval   = corr[pi]
        r_seg  = corr[pi + cfg.peak_distance_from_peak:
                      pi + cfg.peak_search_max_len + 1]
        l_seg  = corr[pi - cfg.peak_search_max_len:
                      pi - cfg.peak_distance_from_peak + 1]
        if len(r_seg) == 0 or len(l_seg) == 0:
            continue
        r_pos  = int(np.argmax(r_seg)) + cfg.peak_distance_from_peak
        l_pos  = cfg.peak_search_max_len - int(np.argmax(l_seg))
        r_max  = float(np.max(r_seg))
        l_max  = float(np.max(l_seg))
        if (r_max > 0.8 * pval and abs(r_pos - cfg.expected_gap) < cfg.peak_tol) or \
           (l_max > 0.8 * pval and abs(l_pos - cfg.expected_gap) < cfg.peak_tol):
            filtered.append(pi)
    return np.array(filtered, dtype=np.int64)


def _pair_long_peaks(peaks: np.ndarray, corr: np.ndarray,
                     cfg: SyncLongConfig) -> np.ndarray:
    """Pair accepted peaks using only 63/64/65-sample gaps, preferring 64."""
    peaks = np.sort(np.asarray(peaks, dtype=np.int64).reshape(-1))
    if len(peaks) < 2:
        return np.zeros((0, 2), dtype=np.int64)

    target_gap = int(cfg.expected_gap)
    allowed_gaps = {target_gap - 1, target_gap, target_gap + 1}
    used = np.zeros(len(peaks), dtype=bool)
    pairs: List[tuple[int, int]] = []

    for i in range(len(peaks) - 1):
        if used[i]:
            continue

        best_j = None
        best_key = None
        p1 = int(peaks[i])

        for j in range(i + 1, len(peaks)):
            if used[j]:
                continue
            gap = int(peaks[j] - p1)
            if gap > target_gap + 1:
                break
            if gap not in allowed_gaps:
                continue

            # Prefer exact 64-sample spacing, then stronger paired peaks.
            key = (
                abs(gap - target_gap),
                -(float(corr[p1]) + float(corr[int(peaks[j])])),
                gap,
            )
            if best_key is None or key < best_key:
                best_key = key
                best_j = j

        if best_j is not None:
            used[i] = True
            used[best_j] = True
            pairs.append((p1, int(peaks[best_j])))

    if not pairs:
        return np.zeros((0, 2), dtype=np.int64)
    return np.asarray(pairs, dtype=np.int64)


# ---- public detect() -------------------------------------------------------

def detect(iq_data: np.ndarray,
           bank: Optional[CFOFilterBank] = None,
           cfg:  Optional[SyncLongConfig] = None) -> Dict[str, object]:
    """
    Run sync_long peak detection on frequency-corrected IQ data.

    If *bank* was built with a different fft_len (e.g. a hint that turned out
    wrong), it is transparently rebuilt here with the correct length.

    Parameters
    ----------
    iq_data : np.complex64 array at the configured target rate
    bank    : CFOFilterBank from init() — rebuilt if None
    cfg     : SyncLongConfig — defaults used if None

    Returns
    -------
    dict with keys:
        corr_long        : float32[N]    — correlation magnitude
        corr_long_phase  : complex64[N]  — complex correlation
        sorted_peaks     : int64[P]      — validated LTS peak indices
        shift_freq_bins  : int           — best CFO bin index
        best_freq_hz     : float         — best CFO in Hz
        threshold        : float
    """
    cfg = cfg or SyncLongConfig()
    training = _as_c64(cfg.long_training if cfg.long_training is not None
                       else LONG_TRAINING)

    if len(iq_data) == 0:
        z = np.zeros(0)
        return dict(corr_long=z.astype(np.float32),
                    corr_long_phase=z.astype(np.complex64),
                    sorted_peaks=z.astype(np.int64),
                    shift_freq_bins=0, best_freq_hz=0.0, threshold=0.0)

    print(f"[detect] Running sync_long on {len(iq_data):,} samples")
    t0 = time.perf_counter()

    if cfg.with_freqoffset_search:
        # Build (or reuse) the filter bank sized to this exact data length.
        if bank is None or bank.fft_len != len(iq_data):
            bank = init(cfg, data_len=len(iq_data))

        result          = bank.correlate_tiled(iq_data)
        corr_long       = np.asarray(result["best_corr"],       dtype=np.float32)
        corr_long_phase = np.asarray(result["best_corr_phase"], dtype=np.complex64)
        best_fi         = int(result["best_freq_index"])
        bins            = bank.freq_search["sampled_freq_bins"]
        shift_bins      = int(bins[best_fi]) if len(bins) else 0
        best_freq_hz    = float(bank.freq_search["freq_hz"][best_fi]) if len(bins) else 0.0

    else:
        n = len(iq_data)
        fft_iq          = _fft(iq_data.astype(np.complex64), n=n)
        fft_seq         = _fft(training, n=n)
        corr_long_phase = _as_c64(_ifft(fft_iq * fft_seq))
        corr_long       = np.abs(corr_long_phase).astype(np.float32)
        shift_bins      = 0
        best_freq_hz    = 0.0

    rms        = float(np.sqrt(np.mean(np.abs(iq_data[::max(1, cfg.rms_stride)].astype(np.complex128)) ** 2)))
    seq_energy = float(np.sum(np.abs(training) ** 2))
    threshold  = max(float(np.max(corr_long)) * cfg.threshold_scale,
                     5.0 * rms * math.sqrt(seq_energy))

    raw_peaks = _find_peaks(corr_long, cfg.expected_gap - 4, threshold)
    candidate_peaks = _sort_long_peaks(raw_peaks, corr_long, cfg)
    peak_pairs = _pair_long_peaks(candidate_peaks, corr_long, cfg)
    sorted_peaks = peak_pairs.reshape(-1) if len(peak_pairs) else np.zeros(0, dtype=np.int64)

    dt = time.perf_counter() - t0
    n_frames = len(peak_pairs)
    print(f"[detect] Done — {len(raw_peaks)} raw peaks → {n_frames} frame pair(s)  "
          f"best_cfo={best_freq_hz/1e3:+.1f} kHz  threshold={threshold:.4f}  "
          f"({dt*1e3:.1f} ms)")

    return dict(corr_long=corr_long, corr_long_phase=corr_long_phase,
                sorted_peaks=sorted_peaks, shift_freq_bins=shift_bins,
                best_freq_hz=best_freq_hz, threshold=threshold)


# ===========================================================================
# STAGE 5 — capture()  (build per-frame arrays + save .npz)
# ===========================================================================

def _lts_snr_db(iq: np.ndarray, p1: int, p2: int) -> Optional[float]:
    s1, s2 = iq[p1 - 64: p1], iq[p2 - 64: p2]
    if len(s1) != 64 or len(s2) != 64:
        return None
    sig_pwr   = float(np.mean(np.abs(0.5 * (s1 + s2)) ** 2))
    noise_pwr = float(0.5 * np.mean(np.abs(s1 - s2) ** 2))
    if noise_pwr <= 0 or sig_pwr <= 0:
        return None
    snr = sig_pwr / noise_pwr
    return float(10.0 * np.log10(snr)) if snr > 0 else None


def capture(iq_data:   np.ndarray,
            detection: Dict[str, object],
            cfg:       Optional[SyncLongConfig] = None,
            output_path: Optional[str] = None,
            fine_cfo_mode: str = "tags") -> Dict[str, object]:
    """
    Build per-frame capture arrays from detection results and optionally
    save them to a .npz file.

    Parameters
    ----------
    iq_data     : complex64 IQ at the configured target rate (same array passed to detect())
    detection   : dict returned by detect()
    cfg         : SyncLongConfig — defaults used if None
    output_path : if given, save the capture to this .npz path
    fine_cfo_mode : "tags" to pass fine CFO via tags only, "apply" to rotate
                    samples by the fine CFO and zero the fine-CFO tags.

    Returns
    -------
    dict with keys:
        samples          : complex64[N]   — concatenated CP-stripped samples
        tag_offsets      : uint64[T]
        tag_keys         : object[T]      — str array
        tag_values_f64   : float64[T]
        tag_values_u64   : uint64[T]
        tag_value_types  : object[T]      — "f64" or "u64"
        frame_count      : int
        best_freq_hz     : float
        threshold        : float
        sorted_peaks     : int64[P]
        lts_snr_db       : list[float|None]
        sync_long_peak_abs : list[tuple[int, int]]
        sync_long_peak_idx : list[tuple[int, int]]
    """
    cfg          = cfg or SyncLongConfig()
    fine_cfo_mode = str(fine_cfo_mode).lower()
    if fine_cfo_mode not in ("tags", "apply"):
        raise ValueError(f"Unsupported fine_cfo_mode={fine_cfo_mode!r}; expected 'tags' or 'apply'")
    corr_phase   = _as_c64(detection["corr_long_phase"])
    corr_long    = np.asarray(detection["corr_long"], dtype=np.float32)
    sorted_peaks = np.asarray(detection["sorted_peaks"], dtype=np.int64)
    shift_bins   = int(detection.get("shift_freq_bins", 0))

    print(f"[capture] Building frame capture from {len(sorted_peaks)//2} pair(s)")
    t0 = time.perf_counter()

    # Frequency-correct the full IQ stream
    n        = len(iq_data)
    fft_iq   = _fft(iq_data.astype(np.complex64))
    iq_fcorr = _as_c64(_ifft(np.roll(fft_iq, -shift_bins)))

    norm = 4.0 * float(np.mean(np.abs(iq_fcorr))) if n else 1.0
    if norm > 0:
        iq_fcorr = (iq_fcorr / norm).astype(np.complex64)

    pair_count = len(sorted_peaks) // 2
    if pair_count == 0:
        empty_u64 = np.zeros(0, dtype=np.uint64)
        empty_f64 = np.zeros(0, dtype=np.float64)
        result = dict(
            samples=np.zeros(0, dtype=np.complex64),
            tag_offsets=empty_u64, tag_keys=np.array([], dtype=object),
            tag_values_f64=empty_f64, tag_values_u64=empty_u64,
            tag_value_types=np.array([], dtype=object),
            frame_count=0,
            best_freq_hz=float(detection.get("best_freq_hz", 0.0)),
            threshold=float(detection.get("threshold", 0.0)),
            sorted_peaks=sorted_peaks, lts_snr_db=[],
            sync_long_peak_abs=np.zeros((0, 2), dtype=np.int32),
            sync_long_peak_idx=np.zeros((0, 2), dtype=np.int64),
        )
        print("[capture] No frames found — empty capture returned")
        return result

    peaks_per_frame = sorted_peaks[: pair_count * 2].reshape(pair_count, 2)
    corr_len = len(corr_phase)

    all_samples:       List[np.ndarray] = []
    tag_offsets:       List[int]   = []
    tag_keys:          List[str]   = []
    tag_values_f64:    List[float] = []
    tag_values_u64:    List[int]   = []
    tag_value_types:   List[str]   = []
    lts_snr_list:      List[Optional[float]] = []
    sync_long_peak_abs_list: List[tuple[int, int]] = []
    sync_long_peak_idx_list: List[tuple[int, int]] = []
    n_out_total = 0
    frame_count = 0

    for idx_fr, (p1, p2) in enumerate(peaks_per_frame, start=1):
        frame_start = int(p1) - 64 - 5
        if frame_start < 0 or int(p2) >= corr_len:
            continue

        cfo = float(
            np.angle(corr_phase[int(p1)] * np.conj(corr_phase[int(p2)])) / 64.0
        )

        raw_limit = frame_start + cfg.max_copy
        if idx_fr < len(peaks_per_frame):
            next_p1       = int(peaks_per_frame[idx_fr, 0])
            raw_limit     = min(raw_limit, next_p1 - 64 - 32 - 160 - 1)
        raw_limit = min(raw_limit, corr_len - 1)
        n_raw     = raw_limit - frame_start + 1
        if n_raw <= 128:
            continue

        n_sym_max = (n_raw - 128) // 80
        n_out     = 128 + n_sym_max * 64
        if n_out < cfg.min_symbols * 64:
            continue

        rel       = np.arange(n_raw, dtype=np.int64)
        emit_mask = (rel < 128) | ((rel - 128) % 80 > 15)   # strip CPs
        abs_idx   = frame_start + rel[emit_mask]
        if len(abs_idx) == 0:
            continue

        n_out = min(n_out, (len(abs_idx) // 64) * 64)
        if n_out == 0:
            continue
        abs_idx = abs_idx[:n_out]
        
        if fine_cfo_mode == "apply":
            phases = np.exp(1j * abs_idx.astype(np.float64) * cfo).astype(np.complex64)
            out    = (iq_fcorr[abs_idx] * phases).astype(np.complex64, copy=False)
        else:
            out = iq_fcorr[abs_idx].astype(np.complex64, copy=False)

        if n_out < cfg.min_symbols * 64:
            continue

        tag_off      = n_out_total
        n_out_total += n_out
        frame_count += 1
        sync_long_peak_abs_list.append((
            int(np.rint(float(corr_long[int(p1)]))),
            int(np.rint(float(corr_long[int(p2)]))),
        ))
        sync_long_peak_idx_list.append((int(p1), int(p2)))
        lts_snr_list.append(_lts_snr_db(iq_fcorr, int(p1), int(p2)))
        all_samples.append(out)

        # Emit 4 tags per frame (same layout as sync_long.cc).
        # cfo_long_rad_per_samp carries the fine residual CFO for the
        # downstream frame_equalizer to apply.  The bulk CFO has already
        # been removed from iq_fcorr via np.roll; the per-sample phase
        # ramp (phases) corrects the fine residual in the samples too,
        # so the tag value is set to 0 to avoid double-correction downstream.
        
        if fine_cfo_mode == "apply":
            tag_tuples = (
                ("wifi_start",             0.0, 0,           "f64"),
                ("frame_id",               0.0, frame_count, "u64"),
                ("cfo_short_rad_per_samp", 0.0, 0,           "f64"),
                ("cfo_long_rad_per_samp",  0.0, 0,           "f64"),  # already applied in samples
            )
        else:
            tag_tuples = (
                ("wifi_start",             cfo, 0,           "f64"),
                ("frame_id",               0.0, frame_count, "u64"),
                ("cfo_short_rad_per_samp", 0.0, 0,           "f64"),
                ("cfo_long_rad_per_samp",  cfo, 0,           "f64"),
            )

        for key, f64_v, u64_v, typ in tag_tuples:
            tag_offsets.append(tag_off)
            tag_keys.append(key)
            tag_values_f64.append(float(f64_v))
            tag_values_u64.append(int(u64_v))
            tag_value_types.append(typ)

    samples = (np.concatenate(all_samples).astype(np.complex64)
               if all_samples else np.zeros(0, dtype=np.complex64))

    dt = time.perf_counter() - t0
    print(f"[capture] {frame_count} frame(s)  "
          f"{len(samples):,} output samples  ({dt*1e3:.1f} ms)")

    # Log per-frame SNR
    for i, snr in enumerate(lts_snr_list, start=1):
        snr_str = f"{snr:.1f} dB" if snr is not None else "N/A"
        print(f"  frame {i:3d}: LTS SNR = {snr_str}")

    result = dict(
        samples         = samples,
        tag_offsets     = np.asarray(tag_offsets,     dtype=np.uint64),
        tag_keys        = np.asarray(tag_keys,        dtype=object),
        tag_values_f64  = np.asarray(tag_values_f64,  dtype=np.float64),
        tag_values_u64  = np.asarray(tag_values_u64,  dtype=np.uint64),
        tag_value_types = np.asarray(tag_value_types, dtype=object),
        frame_count     = frame_count,
        best_freq_hz    = float(detection.get("best_freq_hz", 0.0)),
        threshold       = float(detection.get("threshold", 0.0)),
        sorted_peaks    = sorted_peaks,
        lts_snr_db      = lts_snr_list,
        sync_long_peak_abs = np.asarray(sync_long_peak_abs_list, dtype=np.int32),
        sync_long_peak_idx = np.asarray(sync_long_peak_idx_list, dtype=np.int64),
        target_samp_rate_hz=float(cfg.samp_rate),
        fine_cfo_mode    = fine_cfo_mode,
    )

    if output_path:
        npz_path = output_path if output_path.endswith(".npz") else output_path + ".npz"
        np.savez(
            npz_path,
            samples         = result["samples"],
            tag_offsets     = result["tag_offsets"],
            tag_keys        = result["tag_keys"],
            tag_values_f64  = result["tag_values_f64"],
            tag_values_u64  = result["tag_values_u64"],
            tag_value_types = result["tag_value_types"],
            sync_long_peak_abs = np.asarray(result["sync_long_peak_abs"], dtype=np.int32),
            sync_long_peak_idx = np.asarray(result["sync_long_peak_idx"], dtype=np.int64),
            target_samp_rate_hz = np.asarray(result["target_samp_rate_hz"], dtype=np.float64),
            fine_cfo_mode = np.asarray(result["fine_cfo_mode"], dtype=object),
        )
        print(f"[capture] Saved → {npz_path}")

    return result


# ===========================================================================
# High-level convenience wrapper
# ===========================================================================

def process_file(path: str,
                 output_path: Optional[str] = None,
                 cfg: Optional[SyncLongConfig] = None,
                 target_rate: float = TARGET_SAMP_RATE) -> Dict[str, object]:
    """
    Run the full pipeline in one call:
        init → load_file → resample → detect → capture

    Parameters
    ----------
    path        : input IQ file (.mat / .iq / .cfile)
    output_path : save .npz here (optional)
    cfg         : SyncLongConfig — defaults used if None
    target_rate : output sample rate in Hz

    Returns the capture dict (same as capture()).
    """
    cfg = cfg or SyncLongConfig()
    cfg = _scale_timing(cfg, target_rate)

    # Stage 1 — init (deferred fft_len; will auto-correct inside detect)
    bank = init(cfg)

    # Stage 2 — load
    raw, ext = load_file(path)

    # Stage 3 — resample to target_rate
    iq = resample(raw, ext, target_rate=target_rate)

    # Stage 4 — update bank fft_len to actual data length, then detect
    detection = detect(iq, bank, cfg)

    # Stage 5 — capture
    cap = capture(iq, detection, cfg, output_path=output_path)

    return cap


# ===========================================================================
# CLI entry point
# ===========================================================================

def _float_si(s: str) -> float:
    """
    argparse type converter that accepts both plain floats ('20000000')
    and Python scientific notation ('20e6', '10E6', '200e3').
    Without this, argparse rejects strings like '20e6' with a type error.
    """
    try:
        return float(s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid float value: '{s}'. "
            "Use plain numbers (20000000) or scientific notation (20e6)."
        )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Stand-alone WiFi sync_long pipeline "
                    "(.mat/.iq/.cfile → detect → capture / optional direct replay)")
    p.add_argument("input",         help="Input IQ file (.mat / .iq / .cfile)")
    p.add_argument("--output", "-o", default=None,
                   help="Output .npz path (default: /tmp/out.npz)")
    p.add_argument("--no-cfo-search", action="store_true",
                   help="Disable CFO frequency-offset search (faster, less robust)")
    p.add_argument("--num-cfo-steps", type=int, default=401,
                   help=(
                       "Number of CFO hypotheses spanning the full search range.\n"
                       "The spacing is computed directly in Hz as:\n"
                       "  step_hz = (2 * cfo_range_hz) / (num_cfo_steps - 1)\n"
                       "Default: 401"
                   ))
    p.add_argument("--cfo-range",   type=_float_si, default=5000e3,
                   help="CFO search hard cap in Hz (default: 500000 = ±500 kHz). "
                        "Bins outside this range are dropped after the step-based "
                        "axis is built, keeping detect() fast on large buffers.")
    p.add_argument("--threshold-scale", type=float, default=0.7,
                   help="Peak threshold scale factor (default: 0.7)")
    p.add_argument("--max-copy",    type=int, default=None,
                   help="Max samples copied per frame before CP stripping "
                        "(default: 43200 = 540 × 80)")
    p.add_argument("--samp-rate-in", type=_float_si, default=None,
                   help="Override source sample rate in Hz "
                        "(auto-detected from extension by default)")
    p.add_argument("--channel-bw", type=int, default=None,
                   choices=[5, 10, 20],
                   help="Channel bandwidth in MHz. When --target-rate is omitted, this selects the processing rate.")
    p.add_argument("--fine-cfo-mode", choices=["tags", "apply"], default="tags",
                   help="How to handle fine CFO in capture output: 'tags' leaves samples unchanged and passes CFO via wifi_start/cfo_long tags; 'apply' rotates samples by the fine CFO and zeros those tags to avoid double correction downstream.")
    p.add_argument("--target-rate", type=_float_si, default=None,
                   help="Output sample rate in Hz. If omitted, it is derived from --channel-bw, or defaults to 20e6 when --channel-bw is also omitted.")
    p.add_argument("--replay-direct", action="store_true",
                   help="Send the in-memory capture straight into GNU Radio instead of saving a .npz capture.")
    p.add_argument("--output-pcap", default="/tmp/replay_output.pcap",
                   help="PCAP output path used with --replay-direct (default: /tmp/replay_output.pcap).")
    p.add_argument("--replay-freq", type=_float_si, default=5.180e9,
                   help="Center frequency in Hz used with --replay-direct (default: 5.180e9).")
    p.add_argument("--chan-est", choices=["ls", "lms", "sta", "comb"], default="ls",
                   help="Replay-side channel equalizer used with --replay-direct (default: ls).")
    p.add_argument("--replay-compact", action="store_true",
                   help="Reduce replay-side verbosity when using --replay-direct.")
    return p


# =============================================================================
# ↓↓↓  EDIT THESE LINES TO CHANGE THE DEFAULT INPUT FILE  ↓↓↓
# Used when running from Spyder (%runfile), Jupyter, or any IDE Run button.
# Use a raw string r"..." so Windows backslashes are handled automatically.
# =============================================================================

#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\DoodleLab-tx10MHz-Denmark\DoodleLab-2400MHz-06-18-25-15h41m30s589_0001_20mhz_SNR_600_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Owner\Downloads\All_record_foders\First batch\Skydio-10x-fly1.mat"
#-----------------------------------------
#DEFAULT_INPUT_FILE = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\snr_test\DoodleLab-2400MHz-06-18-25-15h41m30s589_0001_20mhz_SNR_600_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DoodleLab-tx10MHz-Denmark\DoodleLab-2400MHz-06-18-25-15h41m30s589.iq"
#-------------------------------------------------
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\DoodleLab-tx20MHz\DoddleLab-2425MHz-11-09-25-12h20m50s611_0001_20mhz_SNR_700_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\DoodleLab-tx20MHz\DoddleLab-2425MHz-11-09-25-12h20m50s611_0001_20mhz_SNR_800_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DoodleLab-tx20MHz-NTC-UGV-Doodlelab\DoddleLab-2425MHz-11-09-25-12h20m50s611.iq"

#------------------------------------------------------------------------------------------------

#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\snr_test\DJI-Mavic-mini-Wifi5MHz\IQ_DATA__LOCALIZATION__c1856d7e-0ea6-4d58-a999-c2918ab0a196__61_0001_20mhz_SNR_600_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\Py_script\cfiles\snr_test\DJI-Mavic-mini-Wifi5MHz\IQ_DATA__LOCALIZATION__c1856d7e-0ea6-4d58-a999-c2918ab0a196__62_0002_20mhz_SNR_600_dB.cfile"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DJI-Mavic-mini-Wifi5MHz\IQ_DATA__LOCALIZATION__c1856d7e-0ea6-4d58-a999-c2918ab0a196__62.bin"

#------------------------------------------------------------------------------------------------

#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DoodleLab-tx10MHz-Denmark\DoodleLab-2400MHz-06-18-25-15h41m30s589.iq"
#DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DoodleLab-tx20MHz-NTC-UGV-Doodlelab\DoddleLab-2425MHz-11-09-25-12h20m50s611.iq"
DEFAULT_INPUT_FILE  = r"C:\Users\Public\Documents\Wify\records_files\DJI-Mavic-mini-Wifi5MHz\IQ_DATA__LOCALIZATION__c1856d7e-0ea6-4d58-a999-c2918ab0a196__62.bin"

#------------------------------------------------------------------------------------------------------

#DEFAULT_OUTPUT_FILE = None
DEFAULT_OUTPUT_FILE = "/tmp/out"

# Channel bandwidth used when running from an IDE (Spyder / Jupyter).
# Set to 5, 10, or 20 MHz, or None to leave it unspecified.
DEFAULT_CHANNEL_BW: Optional[int] = None   # ← edit here: 5 / 10 / 20 / None

# CFO steps used when running from an IDE (Spyder / Jupyter).
# This defines the number of CFO hypotheses across ±cfo_range_hz.
DEFAULT_NUM_CFO_STEPS: int = 401   # ← edit here
# =============================================================================


def _detect_iq_dual_hypothesis(
    raw:         np.ndarray,
    rate_hypotheses: List[float],
    cfg_base:    "SyncLongConfig",
    target_rate: float = TARGET_SAMP_RATE,
) -> Tuple[np.ndarray, float, Dict[str, object], Dict[str, object]]:
    """
    Run sync_long detection for every input-rate hypothesis in *rate_hypotheses*
    and return the result from the hypothesis that produced the most frames
    (ties broken by highest correlation peak).

    Parameters
    ----------
    raw                      : raw complex64 samples loaded from the .iq/.bin file
    rate_hypotheses          : list of candidate input sample rates in Hz, e.g. [80e6, 40e6]
    cfg_base                 : base SyncLongConfig
    target_rate              : output rate
    Returns
    -------
    (best_iq, best_src_rate, best_detection, best_cfg)
    """
    best_frames    = -1
    best_peak      = -1.0
    best_iq        = None
    best_src_rate  = rate_hypotheses[0]
    best_detection = None
    best_cfg       = cfg_base

    for src_rate in rate_hypotheses:
        print(f"\n[dual_hyp] ── Hypothesis: input rate = {src_rate/1e6:.1f} MHz ──")
        iq_h   = resample(raw, src_rate, target_rate=target_rate)
        cfg_h  = _scale_timing(cfg_base, target_rate)
        cfg_h.num_cfo_steps = cfg_base.num_cfo_steps
        print(f"[dual_hyp]   Using num_cfo_steps = {cfg_h.num_cfo_steps}")
        bank_h = init(cfg_h, data_len=len(iq_h))
        det_h  = detect(iq_h, bank_h, cfg_h)

        n_frames = len(det_h["sorted_peaks"]) // 2
        peak_val = float(np.max(det_h["corr_long"])) if len(det_h["corr_long"]) else 0.0
        print(f"[dual_hyp]   → {n_frames} frame(s), max_corr={peak_val:.4f}")

        if (n_frames > best_frames) or (n_frames == best_frames and peak_val > best_peak):
            best_frames    = n_frames
            best_peak      = peak_val
            best_iq        = iq_h
            best_src_rate  = src_rate
            best_detection = det_h
            best_cfg       = cfg_h

        # Early exit: if this hypothesis already found frames, no need to try
        # slower (larger-buffer) hypotheses.
        if best_frames > 0:
            print(f"[dual_hyp] Early exit — frames found at {src_rate/1e6:.1f} MHz, "
                  f"skipping remaining hypotheses")
            break

    print(f"\n[dual_hyp] Best hypothesis: {best_src_rate/1e6:.1f} MHz "
          f"({best_frames} frame(s), max_corr={best_peak:.4f})")
    return best_iq, best_src_rate, best_detection, best_cfg


def main():
    # ----------------------------------------------------------------
    # Spyder / IDE friendly: when no CLI arguments are present, fall
    # back to DEFAULT_INPUT_FILE defined just above this function.
    #
    # From a real terminal you can still pass the path as an argument:
    #   python run_main_1.py "C:\\path\\to\\file.mat"
    #   python run_main_1.py capture.iq --target-rate 10e6
    # ----------------------------------------------------------------
    p = _build_parser()

    # sys.argv[0] is always the script name; anything beyond that are
    # real CLI args.  If nothing extra was passed we are in an IDE.
    if len(sys.argv) <= 1:
        print("[main] No CLI arguments — using DEFAULT_INPUT_FILE:")
        print(f"       {DEFAULT_INPUT_FILE}")
        print("       (edit DEFAULT_INPUT_FILE near the top of the script)\n")
        cli_args = [DEFAULT_INPUT_FILE]
        if DEFAULT_OUTPUT_FILE:
            cli_args += ["--output", DEFAULT_OUTPUT_FILE]
        if DEFAULT_CHANNEL_BW is not None:
            cli_args += ["--channel-bw", str(DEFAULT_CHANNEL_BW)]
        cli_args += ["--num-cfo-steps", str(DEFAULT_NUM_CFO_STEPS)]
        args = p.parse_args(cli_args)
    else:
        args = p.parse_args()

    target_rate: float = _resolve_target_rate(args.target_rate, args.channel_bw)
    print(f"[main] Target sample rate: {target_rate/1e6:.3f} MHz")

    channel_bw: Optional[int] = args.channel_bw
    if channel_bw is not None:
        print(f"[main] Channel bandwidth: {channel_bw} MHz  (target processing rate selected)")
    else:
        print("[main] Channel bandwidth: auto (multi-hypothesis detection)")

    user_num_cfo_steps: int = int(args.num_cfo_steps)
    fine_cfo_mode: str = str(args.fine_cfo_mode).lower()
    print(f"[main] CFO search steps: {user_num_cfo_steps}")
    print(f"[main] Fine CFO handling: {fine_cfo_mode}")

    # Build base config, then scale timing-dependent fields to target_rate.
    base_max_copy = args.max_copy if args.max_copy is not None else 540 * 80
    cfg_base = SyncLongConfig(
        with_freqoffset_search = not args.no_cfo_search,
        num_cfo_steps          = user_num_cfo_steps,
        cfo_range_hz           = args.cfo_range,
        threshold_scale        = args.threshold_scale,
        max_copy               = base_max_copy,
        # _scale_timing will update samp_rate to the selected processing rate
    )
    cfg = _scale_timing(cfg_base, target_rate)

    output = args.output or "/tmp/out.npz"
    capture_output = None if args.replay_direct else output

    t_total = time.perf_counter()

    # ---- Stage 1: probe file length (cheap: reads only header / file size) ----
    expected_len = probe_data_len(args.input,
                                  samp_rate_in=args.samp_rate_in,
                                  target_rate=target_rate)

    # ---- Stage 1b: init — filter bank built once, before any data loading ----
    cfg.num_cfo_steps = user_num_cfo_steps

    bank = init(cfg, data_len=expected_len)

    # ---- Stage 2: load ----
    raw, ext = load_file(args.input)

    # ---- Override sample rate if requested ----
    if args.samp_rate_in is not None:
        src_rate = args.samp_rate_in
        print(f"[main] Overriding source sample rate → {src_rate/1e6:.3f} MHz")
        cfg = _scale_timing(cfg_base, target_rate)
        cfg.num_cfo_steps = user_num_cfo_steps
        print(f"[main] Using num_cfo_steps = {cfg.num_cfo_steps}")
        # Single-hypothesis path (user pinned the rate explicitly)
        iq   = resample(raw, src_rate, target_rate=target_rate)
        bank = init(cfg, data_len=len(iq))
        detection = detect(iq, bank, cfg)

    elif ext == ".iq":
        # ----------------------------------------------------------------
        # .iq path: use channel-bw pin when given, else dual-hypothesis.
        # ----------------------------------------------------------------
        iq_hypotheses = _rates_for_channel_bw(channel_bw, ext) or IQ_RATE_HYPOTHESES
        print(f"[main] .iq file detected — running sync_long "
              f"({', '.join(f'{r/1e6:.0f} MHz' for r in iq_hypotheses)})")
        iq, src_rate, detection, cfg = _detect_iq_dual_hypothesis(
            raw, iq_hypotheses, cfg_base, target_rate=target_rate,
        )
        bank = None   # already consumed inside helper

    elif ext == ".bin":
        # ----------------------------------------------------------------
        # .bin path: use channel-bw pin when given, else triple-hypothesis.
        # ----------------------------------------------------------------
        bin_hypotheses = _rates_for_channel_bw(channel_bw, ext) or BIN_RATE_HYPOTHESES
        print(f"[main] .bin file detected — running sync_long "
              f"({', '.join(f'{r/1e6:.2f} MHz' for r in bin_hypotheses)})")
        iq, src_rate, detection, cfg = _detect_iq_dual_hypothesis(
            raw, bin_hypotheses, cfg_base, target_rate=target_rate,
        )
        bank = None   # already consumed inside helper

    else:
        src_rate = SAMP_RATE_BY_EXT[ext]
        cfg = _scale_timing(cfg_base, target_rate)
        cfg.num_cfo_steps = user_num_cfo_steps
        print(f"[main] Using num_cfo_steps = {cfg.num_cfo_steps}")
        # ---- Stage 3: resample to target_rate ----
        iq = resample(raw, src_rate, target_rate=target_rate)
        # ---- Stage 4: detect (reuses pre-built bank; rebuilds only if length differs) ----
        bank = init(cfg, data_len=len(iq))
        detection = detect(iq, bank, cfg)

    # ---- Stage 5: capture ----
    _dump_sync_long_debug(detection)
    cap = capture(iq, detection, cfg, output_path=capture_output, fine_cfo_mode=fine_cfo_mode)

    dt = time.perf_counter() - t_total
    print(f"\n[main] Pipeline complete — {cap['frame_count']} frame(s) captured  "
          f"total={dt*1e3:.1f} ms")
    if args.replay_direct:
        print(f"[main] Direct replay requested — skipping .npz save and replaying to {args.output_pcap}")
        from sync_long_replay_16 import run_replay_capture

        run_replay_capture(
            cap,
            output_pcap=args.output_pcap,
            freq=float(args.replay_freq),
            samp_rate=float(cfg.samp_rate),
            chan_est=_resolve_chan_est(args.chan_est),
            verbose=not args.replay_compact,
        )
    else:
        print(f"[main] Output: {output}.npz"
              if not output.endswith(".npz") else f"[main] Output: {output}")


if __name__ == "__main__":
    main()
