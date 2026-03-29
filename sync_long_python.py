#!/usr/bin/env python3
"""Python sync_long detector and frame packer derived from the MATLAB flow."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy.fft import fft as _scipy_fft
from scipy.fft import ifft as _scipy_ifft


_FFT_WORKERS = int(os.environ.get("SYNC_LONG_FFT_WORKERS", "-1"))
_CFO_TILE_SIZE = max(1, int(os.environ.get("SYNC_LONG_CFO_TILE", "4")))
_CFO_BANK_CACHE: Dict[Tuple[int, bytes, bytes], "CFOFilterBank"] = {}


def _fft(x: np.ndarray, n: Optional[int] = None, axis: int = -1) -> np.ndarray:
    return _scipy_fft(x, n=n, axis=axis, workers=_FFT_WORKERS)


def _ifft(x: np.ndarray, n: Optional[int] = None, axis: int = -1) -> np.ndarray:
    return _scipy_ifft(x, n=n, axis=axis, workers=_FFT_WORKERS)


def _as_complex64(x: np.ndarray) -> np.ndarray:
    return np.asarray(x, dtype=np.complex64)


LONG_TRAINING = np.array([
    complex(-0.0455, -1.0679), complex(0.3528, -0.9865),
    complex(0.8594, 0.7348), complex(0.1874, 0.2475),
    complex(0.5309, -0.7784), complex(-1.0218, -0.4897),
    complex(-0.3401, -0.9423), complex(0.8657, -0.2298),
    complex(0.4734, 0.0362), complex(0.0088, -1.0207),
    complex(-1.2142, -0.4205), complex(0.2172, -0.5195),
    complex(0.5207, -0.1326), complex(-0.1995, 1.4259),
    complex(1.0583, -0.0363), complex(0.5547, -0.5547),
    complex(0.3277, 0.8728), complex(-0.5077, 0.3488),
    complex(-1.1650, 0.5789), complex(0.7297, 0.8197),
    complex(0.6173, 0.1253), complex(-0.5353, 0.7214),
    complex(-0.5011, -0.1935), complex(-0.3110, -1.3392),
    complex(-1.0818, -0.1470), complex(-1.1300, -0.1820),
    complex(0.6663, -0.6571), complex(-0.0249, 0.4773),
    complex(-0.8155, 1.0218), complex(0.8140, 0.9396),
    complex(0.1090, 0.8662), complex(-1.3868, -0.0000),
    complex(0.1090, -0.8662), complex(0.8140, -0.9396),
    complex(-0.8155, -1.0218), complex(-0.0249, -0.4773),
    complex(0.6663, 0.6571), complex(-1.1300, 0.1820),
    complex(-1.0818, 0.1470), complex(-0.3110, 1.3392),
    complex(-0.5011, 0.1935), complex(-0.5353, -0.7214),
    complex(0.6173, -0.1253), complex(0.7297, -0.8197),
    complex(-1.1650, -0.5789), complex(-0.5077, -0.3488),
    complex(0.3277, -0.8728), complex(0.5547, 0.5547),
    complex(1.0583, 0.0363), complex(-0.1995, -1.4259),
    complex(0.5207, 0.1326), complex(0.2172, 0.5195),
    complex(-1.2142, 0.4205), complex(0.0088, 1.0207),
    complex(0.4734, -0.0362), complex(0.8657, 0.2298),
    complex(-0.3401, 0.9423), complex(-1.0218, 0.4897),
    complex(0.5309, 0.7784), complex(0.1874, -0.2475),
    complex(0.8594, -0.7348), complex(0.3528, 0.9865),
    complex(-0.0455, 1.0679), complex(1.3868, -0.0000),
], dtype=np.complex64)

# Alternate 64-sample long sequence derived from the provided long_seq_orin
# ordering. This is a circular shift of the sync_long.cc template and matches
# the first unique 64-sample block of the repeated sequence the user provided.
LONG_TRAINING_ORIN = np.concatenate([LONG_TRAINING[31:], LONG_TRAINING[:31]]).astype(np.complex64)


@dataclass
class SyncLongConfig:
    samp_rate: float = 20e6
    expected_gap: int = 64
    with_freqoffset_search: bool = True
    cfo_start_idx: int = -200
    cfo_end_idx: int = 200
    threshold_scale: float = 0.7
    rms_stride: int = 30
    max_copy: int = 540 * 80
    #max_copy: int = 3000000 * 80
    min_symbols: int = 3
    peak_search_safe_len: int = 700
    peak_search_max_len: int = 300
    peak_tol: int = 2
    peak_distance_from_peak: int = 4
    long_training: Optional[np.ndarray] = None


def load_complex64_file(path: str) -> np.ndarray:
    data = np.fromfile(path, dtype=np.complex64)
    return np.ascontiguousarray(data)


def resample_complex64(raw: np.ndarray, samp_rate_in: float, samp_rate_out: float = 20e6) -> np.ndarray:
    from scipy.signal import firwin, resample_poly
    from math import gcd

    raw = np.asarray(raw, dtype=np.complex64)
    up = int(round(samp_rate_out))
    down = int(round(samp_rate_in))
    g = gcd(up, down)
    up //= g
    down //= g

    if up != down:
        max_rate = max(up, down)
        # Use an explicit low-pass FIR instead of SciPy's default window so the
        # resampling path gets stronger stopband rejection.
        num_taps = 20 * max_rate + 1
        taps = firwin(
            num_taps,
            cutoff=1.0 / max_rate,
            window=("kaiser", 8.6),
        )
        raw = resample_poly(raw, up, down, window=taps).astype(np.complex64)

    return np.ascontiguousarray(raw)


def load_iq_file(path: str, samp_rate_in: float = 40e6, samp_rate_out: float = 20e6) -> np.ndarray:
    """Load raw complex64 IQ data and resample to the target rate."""
    raw = load_complex64_file(path)
    return resample_complex64(raw, samp_rate_in=samp_rate_in, samp_rate_out=samp_rate_out)


def load_mat_file(path: str, samp_rate_in: float = 30.72e6, samp_rate_out: float = 20e6) -> np.ndarray:
    """Load IQ data from a MATLAB .mat file and resample to the target rate."""
    import scipy.io as sio

    mat = sio.loadmat(path)
    data_keys = [key for key in mat.keys() if not key.startswith("_")]
    if len(data_keys) != 1:
        raise ValueError(f"Expected exactly one variable in .mat file, found: {data_keys}")

    raw = np.asarray(mat[data_keys[0]]).flatten().astype(np.complex64)
    return resample_complex64(raw, samp_rate_in=samp_rate_in, samp_rate_out=samp_rate_out)


def save_long_corr_debug_mat(path: str, iq_data: np.ndarray, detection: Dict[str, object], capture: Dict[str, object]) -> str:
    """Save sync-long-only debug data to a MATLAB .mat file."""
    import scipy.io as sio

    sorted_peaks = np.asarray(detection.get("sorted_peaks", []), dtype=np.int64)
    corr_long = np.asarray(detection.get("corr_long", []), dtype=np.float32)
    peak_values = corr_long[sorted_peaks] if len(sorted_peaks) else np.zeros((0,), dtype=np.float32)
    pair_count = len(sorted_peaks) // 2
    peak_pairs = sorted_peaks[: pair_count * 2].reshape(pair_count, 2) if pair_count else np.zeros((0, 2), dtype=np.int64)
    frame_ids = np.arange(1, pair_count + 1, dtype=np.uint64)
    lts_snr_db = np.asarray(capture.get("lts_snr_db", []), dtype=np.float32)

    out_path = path if path.endswith(".mat") else path + ".mat"
    sio.savemat(
        out_path,
        {
            "iq_abs": np.abs(np.asarray(iq_data, dtype=np.complex64)).astype(np.float32),
            "corr_long": corr_long,
            "sorted_peaks": sorted_peaks,
            "peak_values": peak_values.astype(np.float32),
            "peak_pairs": peak_pairs,
            "frame_ids": frame_ids,
            "threshold": np.array([float(detection.get("threshold", 0.0))], dtype=np.float32),
            "best_freq_hz": np.array([float(detection.get("best_freq_hz", 0.0))], dtype=np.float32),
            "lts_snr_db": lts_snr_db,
        },
        do_compression=True,
    )
    return out_path


def get_long_training_sequence(mode: str = "cc") -> np.ndarray:
    mode_norm = str(mode).strip().lower()
    if mode_norm in ("cc", "default", "sync_long_cc"):
        return LONG_TRAINING
    if mode_norm in ("orin", "long_seq_orin", "orig"):
        return LONG_TRAINING_ORIN
    raise ValueError(f"Unknown long training mode: {mode}")


def get_freq_search_rng(
    data_len: int,
    sync_seq_len: int,
    freq_start_steps: int,
    freq_end_steps: int,
    sync_seq_rate: float = 20e6,
    resolution_parameter: float = 4.0,
) -> Dict[str, np.ndarray]:
    sync_duration_sec = sync_seq_len / sync_seq_rate
    bin_width_hz = 0.5*sync_seq_rate / data_len
    sampled_freq_step = max(1, round(1 / resolution_parameter / sync_duration_sec / bin_width_hz))
    sampled_freq_bins = np.arange(freq_start_steps, freq_end_steps + 1, dtype=np.int64) * sampled_freq_step
    return {
        "freq_hz": sampled_freq_bins * bin_width_hz,
        "sampled_freq_bins": sampled_freq_bins,
        "sampled_freq_step": sampled_freq_step,
    }


def detector_original_seq(
    fft_input: np.ndarray,
    fft_orig_seq: np.ndarray,
    shift_freq: int,
) -> tuple[np.ndarray, np.ndarray]:
    fft_seq_shift = np.roll(fft_orig_seq, int(shift_freq))
    corr_phase = _ifft(fft_input * fft_seq_shift)
    return np.abs(corr_phase), corr_phase


@dataclass
class CFOFilterBank:
    fft_len: int
    freq_search: Dict[str, np.ndarray]
    templates: np.ndarray
    tile_size: int = _CFO_TILE_SIZE

    def correlate_tiled(self, iq_data: np.ndarray) -> Dict[str, np.ndarray]:
        fft_iq_input = _as_complex64(_fft(iq_data.astype(np.complex64), n=self.fft_len))
        sampled_freq_bins = self.freq_search["sampled_freq_bins"]
        if len(sampled_freq_bins) == 0:
            best_corr = np.zeros((self.fft_len,), dtype=np.float32)
            best_corr_phase = np.zeros((self.fft_len,), dtype=np.complex64)
            return {
                "best_corr": best_corr,
                "best_corr_phase": best_corr_phase,
                "best_freq_index": 0,
            }

        best_mag = -np.inf
        best_freq_index = 0
        best_corr = None
        best_corr_phase = None

        for start in range(0, len(sampled_freq_bins), self.tile_size):
            stop = min(start + self.tile_size, len(sampled_freq_bins))
            products = fft_iq_input[np.newaxis, :] * self.templates[start:stop]
            corr_phase_chunk = _as_complex64(_ifft(products, axis=1))
            corr_mag_chunk = np.abs(corr_phase_chunk).astype(np.float32, copy=False)
            chunk_max = corr_mag_chunk.max(axis=1)
            local_idx = int(np.argmax(chunk_max))
            local_mag = float(chunk_max[local_idx])
            if best_corr is None or local_mag > best_mag:
                best_mag = local_mag
                best_freq_index = start + local_idx
                best_corr = corr_mag_chunk[local_idx]
                best_corr_phase = corr_phase_chunk[local_idx]

        if best_corr is None or best_corr_phase is None:
            best_corr = np.zeros((self.fft_len,), dtype=np.float32)
            best_corr_phase = np.zeros((self.fft_len,), dtype=np.complex64)
        return {
            "best_corr": best_corr,
            "best_corr_phase": best_corr_phase,
            "best_freq_index": best_freq_index,
        }


def get_or_build_cfo_filter_bank(
    sync_seq: np.ndarray,
    fft_len: int,
    freq_search: Dict[str, np.ndarray],
    tile_size: int = _CFO_TILE_SIZE,
) -> CFOFilterBank:
    sampled_freq_bins = np.asarray(freq_search["sampled_freq_bins"], dtype=np.int64)
    training_seq = np.asarray(sync_seq, dtype=np.complex64)
    cache_key = (int(fft_len), training_seq.tobytes(), sampled_freq_bins.tobytes())
    bank = _CFO_BANK_CACHE.get(cache_key)
    if bank is not None:
        bank.tile_size = max(1, int(tile_size))
        return bank

    fft_sync_seq = _as_complex64(_fft(training_seq, n=fft_len))
    if len(sampled_freq_bins) == 0:
        templates = np.zeros((0, fft_len), dtype=np.complex64)
    else:
        freq_idx = np.arange(fft_len, dtype=np.int64)[np.newaxis, :]
        shifted_idx = (freq_idx - sampled_freq_bins[:, np.newaxis]) % fft_len
        templates = _as_complex64(fft_sync_seq[shifted_idx])
    bank = CFOFilterBank(
        fft_len=int(fft_len),
        freq_search=freq_search,
        templates=templates,
        tile_size=max(1, int(tile_size)),
    )
    _CFO_BANK_CACHE[cache_key] = bank
    return bank


def get_best_cfo(sync_seq: np.ndarray, iq_data: np.ndarray, freq_search: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
    bank = get_or_build_cfo_filter_bank(sync_seq, len(iq_data), freq_search)
    return bank.correlate_tiled(iq_data)


def find_peaks_like_rust(normalized_corr: np.ndarray, expected_gap_base: int, threshold_blue: float) -> np.ndarray:
    window = max(1, int(round(expected_gap_base / 4)))
    n_windows = len(normalized_corr) // window
    if n_windows <= 0:
        return np.zeros((0,), dtype=np.int64)

    segments = normalized_corr[: n_windows * window].reshape(window, n_windows, order="F")
    idx_max = np.argmax(segments, axis=0)
    base = np.arange(n_windows, dtype=np.int64) * window
    peaks_stage1 = base + idx_max
    peaks = peaks_stage1[normalized_corr[peaks_stage1] > threshold_blue]
    peaks = _get_best_peak_between_each_couple(normalized_corr, peaks, expected_gap_base)
    peaks = _get_best_peak_between_each_couple(normalized_corr, peaks, expected_gap_base)
    return np.sort(peaks.astype(np.int64))


def _get_best_peak_between_each_couple(
    normalized_corr: np.ndarray,
    peaks: np.ndarray,
    expected_gap_base: int,
) -> np.ndarray:
    if len(peaks) == 0:
        return np.zeros((0,), dtype=np.int64)

    inds_rm = np.zeros(len(peaks), dtype=np.int64)
    for idx in range(1, len(peaks)):
        pair = peaks[idx - 1:idx + 1]
        if (pair[1] - pair[0]) <= expected_gap_base / 2:
            weaker = int(np.argmin(normalized_corr[pair]))
            inds_rm[idx] = int(pair[weaker])

    rm_set = set(int(v) for v in np.unique(inds_rm) if v != 0)
    return np.array([int(p) for p in peaks if int(p) not in rm_set], dtype=np.int64)


def get_sort_long_peaks(peak_indices: np.ndarray, corr_long: np.ndarray, cfg: SyncLongConfig) -> np.ndarray:
    filtered = []
    for peak_idx in peak_indices:
        peak_idx = int(peak_idx)
        if peak_idx <= cfg.peak_search_safe_len or peak_idx >= len(corr_long) - cfg.peak_search_safe_len:
            continue

        peak_val = corr_long[peak_idx]
        right_seg = corr_long[
            peak_idx + cfg.peak_distance_from_peak: peak_idx + cfg.peak_search_max_len + 1
        ]
        left_seg = corr_long[
            peak_idx - cfg.peak_search_max_len: peak_idx - cfg.peak_distance_from_peak + 1
        ]
        if len(right_seg) == 0 or len(left_seg) == 0:
            continue

        right_pos = int(np.argmax(right_seg)) + cfg.peak_distance_from_peak
        left_pos = cfg.peak_search_max_len - int(np.argmax(left_seg))
        right_max = float(np.max(right_seg))
        left_max = float(np.max(left_seg))

        is_right_match = right_max > 0.8 * peak_val and abs(right_pos - cfg.expected_gap) < cfg.peak_tol
        is_left_match = left_max > 0.8 * peak_val and abs(left_pos - cfg.expected_gap) < cfg.peak_tol
        if is_right_match or is_left_match:
            filtered.append(peak_idx)

    return np.array(filtered, dtype=np.int64)


def compute_lts_snr_db(iq_freq_corr: np.ndarray, peak1: int, peak2: int) -> Optional[float]:
    """Estimate effective SNR from the two repeated LTS symbols."""
    lts1_start = peak1 - 64
    lts2_start = peak2 - 64
    if lts1_start < 0 or lts2_start < 0:
        return None
    if peak1 > len(iq_freq_corr) or peak2 > len(iq_freq_corr):
        return None

    lts1 = iq_freq_corr[lts1_start:peak1]
    lts2 = iq_freq_corr[lts2_start:peak2]
    if len(lts1) != 64 or len(lts2) != 64:
        return None

    signal_power = float(np.mean(np.abs(0.5 * (lts1 + lts2)) ** 2))
    diff = lts1 - lts2
    noise_power = float(0.5 * np.mean(np.abs(diff) ** 2))
    if noise_power <= 0.0 or signal_power <= 0.0:
        return None

    snr = signal_power / noise_power
    return float(10.0 * np.log10(snr)) if snr > 0.0 else None


def detect_sync_long_frames(iq_data: np.ndarray, cfg: SyncLongConfig | None = None) -> Dict[str, object]:
    cfg = cfg or SyncLongConfig()
    training_seq = np.asarray(cfg.long_training if cfg.long_training is not None else LONG_TRAINING, dtype=np.complex64)
    if len(iq_data) == 0:
        return {
            "corr_long": np.zeros((0,), dtype=np.float32),
            "corr_long_phase": np.zeros((0,), dtype=np.complex64),
            "sorted_peaks": np.zeros((0,), dtype=np.int64),
            "shift_freq_bins": 0,
            "best_freq_hz": 0.0,
        }

    if cfg.with_freqoffset_search:
        freq_search = get_freq_search_rng(
            len(iq_data),
            len(training_seq),
            cfg.cfo_start_idx,
            cfg.cfo_end_idx,
            sync_seq_rate=cfg.samp_rate,
        )
        search_result = get_best_cfo(training_seq, iq_data, freq_search)
        corr_long = np.asarray(search_result["best_corr"], dtype=np.float32)
        corr_long_phase = np.asarray(search_result["best_corr_phase"], dtype=np.complex64)
        best_freq_index = int(search_result["best_freq_index"])
        sampled_bins = freq_search["sampled_freq_bins"]
        shift_freq_bins = int(sampled_bins[best_freq_index]) if len(sampled_bins) else 0
        best_freq_hz = float(freq_search["freq_hz"][best_freq_index]) if len(sampled_bins) else 0.0
    else:
        fft_len = len(iq_data)
        fft_input = _fft(iq_data.astype(np.complex64), n=fft_len)
        fft_seq = _fft(training_seq, n=fft_len)
        corr_long_phase = _ifft(fft_input * fft_seq)
        corr_long = np.abs(corr_long_phase).astype(np.float32)
        shift_freq_bins = 0
        best_freq_hz = 0.0

    rms_iq = float(np.sqrt(np.mean(np.abs(iq_data[:: max(1, cfg.rms_stride)]) ** 2))) if len(iq_data) else 0.0
    sequence_energy = float(np.sum(np.abs(training_seq) ** 2))
    threshold = max(float(np.max(corr_long)) * cfg.threshold_scale, 5.0 * rms_iq * math.sqrt(sequence_energy))

    peak_indices = find_peaks_like_rust(corr_long, cfg.expected_gap - 4, threshold)
    sorted_peaks = get_sort_long_peaks(peak_indices, corr_long, cfg)
    return {
        "corr_long": corr_long,
        "corr_long_phase": corr_long_phase,
        "sorted_peaks": sorted_peaks,
        "shift_freq_bins": shift_freq_bins,
        "best_freq_hz": best_freq_hz,
        "threshold": threshold,
    }


def build_sync_long_capture(iq_data: np.ndarray, detection: Dict[str, object], cfg: SyncLongConfig | None = None) -> Dict[str, np.ndarray]:
    cfg = cfg or SyncLongConfig()
    corr_long_phase = np.asarray(detection["corr_long_phase"], dtype=np.complex64)
    sorted_peaks = np.asarray(detection["sorted_peaks"], dtype=np.int64)
    shift_freq_bins = int(detection.get("shift_freq_bins", 0))

    fft_input = _fft(iq_data.astype(np.complex64))
    iq_data_freq_corr = _ifft(np.roll(fft_input, -shift_freq_bins)).astype(np.complex64)

    norm_factor = 4.0 * float(np.mean(np.abs(iq_data_freq_corr))) if len(iq_data_freq_corr) else 1.0
    if norm_factor > 0:
        iq_data_freq_corr = (iq_data_freq_corr / norm_factor).astype(np.complex64)

    pair_count = len(sorted_peaks) // 2
    if pair_count <= 0:
        empty_u64 = np.zeros((0,), dtype=np.uint64)
        empty_f64 = np.zeros((0,), dtype=np.float64)
        return {
            "samples": np.zeros((0,), dtype=np.complex64),
            "tag_offsets": empty_u64,
            "tag_keys": np.array([], dtype=object),
            "tag_values_f64": empty_f64,
            "tag_values_u64": empty_u64,
            "tag_value_types": np.array([], dtype=object),
            "frame_count": 0,
        }

    peaks_per_frame = sorted_peaks[: pair_count * 2].reshape(pair_count, 2)
    all_samples: List[np.ndarray] = []
    tag_offsets: List[int] = []
    tag_keys: List[str] = []
    tag_values_f64: List[float] = []
    tag_values_u64: List[int] = []
    tag_value_types: List[str] = []
    lts_snr_db_list: List[Optional[float]] = []

    n_out_total = 0
    frame_count = 0
    corr_len = len(corr_long_phase)

    for idx_fr, (peak1, peak2) in enumerate(peaks_per_frame, start=1):
        frame_start = int(peak1) - 64
        if frame_start < 0 or int(peak2) >= corr_len:
            continue

        cfo = float(np.angle(corr_long_phase[int(peak1)] * np.conj(corr_long_phase[int(peak2)])) / 64.0)
        raw_limit = frame_start + cfg.max_copy
        if idx_fr < len(peaks_per_frame):
            next_peak1 = int(peaks_per_frame[idx_fr, 0])
            next_frame_boundary = next_peak1 - 64 - 32 - 160
            raw_limit = min(raw_limit, next_frame_boundary - 1)
        raw_limit = min(raw_limit, corr_len - 1)
        n_raw = raw_limit - frame_start + 1
        if n_raw <= 128:
            continue

        n_sym_max = (n_raw - 128) // 80
        n_out = 128 + n_sym_max * 64
        if n_out < cfg.min_symbols * 64:
            continue

        rel = np.arange(n_raw, dtype=np.int64)
        emit_mask = (rel < 128) | ((rel - 128) % 80 > 15)
        abs_indices = frame_start + rel[emit_mask]
        if len(abs_indices) == 0:
            continue

        if len(abs_indices) < n_out:
            n_out = (len(abs_indices) // 64) * 64
            if n_out == 0:
                continue
            abs_indices = abs_indices[:n_out]
        else:
            abs_indices = abs_indices[:n_out]

        phases = np.exp(1j * abs_indices.astype(np.float64) * cfo).astype(np.complex64)
        out = (iq_data_freq_corr[abs_indices] * phases).astype(np.complex64, copy=False)

        if n_out < cfg.min_symbols * 64:
            continue

        tag_off = n_out_total
        n_out_total += n_out
        frame_count += 1
        lts_snr_db = compute_lts_snr_db(iq_data_freq_corr, int(peak1), int(peak2))
        lts_snr_db_list.append(lts_snr_db)
        all_samples.append(out)

        for key, f64_val, u64_val, typ in (
            ("wifi_start", 0.0, 0, "f64"),
            ("frame_id", 0.0, frame_count, "u64"),
            ("cfo_short_rad_per_samp", 0.0, 0, "f64"),
            ("cfo_long_rad_per_samp", cfo, 0, "f64"),
        ):
            tag_offsets.append(tag_off)
            tag_keys.append(key)
            tag_values_f64.append(float(f64_val))
            tag_values_u64.append(int(u64_val))
            tag_value_types.append(typ)

    samples = np.concatenate(all_samples).astype(np.complex64) if all_samples else np.zeros((0,), dtype=np.complex64)
    return {
        "samples": samples,
        "tag_offsets": np.asarray(tag_offsets, dtype=np.uint64),
        "tag_keys": np.asarray(tag_keys, dtype=object),
        "tag_values_f64": np.asarray(tag_values_f64, dtype=np.float64),
        "tag_values_u64": np.asarray(tag_values_u64, dtype=np.uint64),
        "tag_value_types": np.asarray(tag_value_types, dtype=object),
        "frame_count": frame_count,
        "best_freq_hz": float(detection.get("best_freq_hz", 0.0)),
        "threshold": float(detection.get("threshold", 0.0)),
        "sorted_peaks": sorted_peaks,
        "lts_snr_db": lts_snr_db_list,
    }
