#!/usr/bin/env python3
"""Python sync_long detector and frame packer derived from the MATLAB flow."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Dict, List, Optional

import numpy as np


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


@dataclass
class SyncLongConfig:
    samp_rate: float = 20e6
    expected_gap: int = 64
    with_freqoffset_search: bool = True
    cfo_start_idx: int = -100
    cfo_end_idx: int = 100
    threshold_scale: float = 0.7
    rms_stride: int = 30
    max_copy: int = 540 * 80
    #max_copy: int = 3000000 * 80
    min_symbols: int = 3
    peak_search_safe_len: int = 700
    peak_search_max_len: int = 300
    peak_tol: int = 2
    peak_distance_from_peak: int = 4


def load_complex64_file(path: str) -> np.ndarray:
    data = np.fromfile(path, dtype=np.complex64)
    return np.ascontiguousarray(data)


def get_freq_search_rng(
    data_len: int,
    sync_seq_len: int,
    freq_start_steps: int,
    freq_end_steps: int,
    sync_seq_rate: float = 20e6,
    resolution_parameter: float = 2.0,
) -> Dict[str, np.ndarray]:
    sync_duration_sec = sync_seq_len / sync_seq_rate
    bin_width_hz = sync_seq_rate / data_len
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
    corr_phase = np.fft.ifft(fft_input * fft_seq_shift)
    return np.abs(corr_phase), corr_phase


def get_best_cfo(sync_seq: np.ndarray, iq_data: np.ndarray, freq_search: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
    fft_iq_input = np.fft.fft(iq_data.astype(np.complex64))
    fft_sync_seq = np.fft.fft(sync_seq.astype(np.complex64), len(iq_data))

    sampled_freq_bins = freq_search["sampled_freq_bins"]
    max_per_freq = np.zeros(len(sampled_freq_bins), dtype=np.float64)

    for idx, freq_bin in enumerate(sampled_freq_bins):
        detector_res, _ = detector_original_seq(fft_iq_input, fft_sync_seq, int(freq_bin))
        max_per_freq[idx] = float(np.max(detector_res)) if len(detector_res) else 0.0

    best_freq_index = int(np.argmax(max_per_freq)) if len(max_per_freq) else 0
    best_corr, best_corr_phase = detector_original_seq(
        fft_iq_input,
        fft_sync_seq,
        int(sampled_freq_bins[best_freq_index]) if len(sampled_freq_bins) else 0,
    )
    return {
        "best_corr": best_corr,
        "best_corr_phase": best_corr_phase,
        "best_freq_index": best_freq_index,
    }


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
            len(LONG_TRAINING),
            cfg.cfo_start_idx,
            cfg.cfo_end_idx,
            sync_seq_rate=cfg.samp_rate,
        )
        search_result = get_best_cfo(LONG_TRAINING, iq_data, freq_search)
        corr_long = np.asarray(search_result["best_corr"], dtype=np.float32)
        corr_long_phase = np.asarray(search_result["best_corr_phase"], dtype=np.complex64)
        best_freq_index = int(search_result["best_freq_index"])
        sampled_bins = freq_search["sampled_freq_bins"]
        shift_freq_bins = int(sampled_bins[best_freq_index]) if len(sampled_bins) else 0
        best_freq_hz = float(freq_search["freq_hz"][best_freq_index]) if len(sampled_bins) else 0.0
    else:
        fft_len = len(iq_data)
        fft_input = np.fft.fft(iq_data.astype(np.complex64), fft_len)
        fft_seq = np.fft.fft(LONG_TRAINING.astype(np.complex64), fft_len)
        corr_long_phase = np.fft.ifft(fft_input * fft_seq)
        corr_long = np.abs(corr_long_phase).astype(np.float32)
        shift_freq_bins = 0
        best_freq_hz = 0.0

    rms_iq = float(np.sqrt(np.mean(np.abs(iq_data[:: max(1, cfg.rms_stride)]) ** 2))) if len(iq_data) else 0.0
    sequence_energy = float(np.sum(np.abs(LONG_TRAINING) ** 2))
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

    fft_input = np.fft.fft(iq_data.astype(np.complex64))
    iq_data_freq_corr = np.fft.ifft(np.roll(fft_input, -shift_freq_bins)).astype(np.complex64)

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

        out = np.zeros((n_out,), dtype=np.complex64)
        out_idx = 0
        for rel in range(n_raw):
            emit = rel < 128 or ((rel - 128) % 80) > 15
            if not emit:
                continue
            if out_idx >= n_out:
                break
            abs_idx = frame_start + rel
            out[out_idx] = iq_data_freq_corr[abs_idx] * np.exp(1j * abs_idx * cfo)
            out_idx += 1

        if out_idx < n_out:
            n_out = (out_idx // 64) * 64
            if n_out == 0:
                continue
            out = out[:n_out]

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
