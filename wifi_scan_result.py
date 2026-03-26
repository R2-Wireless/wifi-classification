#!/usr/bin/env python3
"""
Typed result object for sync-long-only WiFi scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np


_ENCODING_INFO = {
    0: ("3 Mbit/s", "BPSK 1/2"),
    1: ("4.5 Mbit/s", "BPSK 3/4"),
    2: ("6 Mbit/s", "QPSK 1/2"),
    3: ("9 Mbit/s", "QPSK 3/4"),
    4: ("12 Mbit/s", "16-QAM 1/2"),
    5: ("18 Mbit/s", "16-QAM 3/4"),
    6: ("24 Mbit/s", "64-QAM 2/3"),
    7: ("27 Mbit/s", "64-QAM 3/4"),
}


def _rate_str(encoding: Optional[int]) -> str:
    if encoding is None:
        return "unknown"
    info = _ENCODING_INFO.get(encoding)
    if info:
        return f"{info[0]} ({info[1]})"
    return f"encoding={encoding}"


def _infer_frame_type(signal_encoding: Optional[int], signal_frame_bytes: int, neighbour_types: List[str]) -> str:
    has_block_ack_neighbour = any("Block Ack" in (frame_type or "") for frame_type in neighbour_types)
    is_small_frame = 0 < signal_frame_bytes <= 100

    if has_block_ack_neighbour and is_small_frame:
        return "Data/QoS Data (inferred: Block Ack neighbour + SIGNAL field)"
    if signal_encoding == 0 and is_small_frame:
        return "Data/QoS Data (inferred: BPSK 1/2 + small frame)"
    return "unknown (garbled FC)"


# FCS-stripped lengths because decode_mac publishes the PSDU without the 4-byte FCS.
_CTRL_FIXED_LENS: Dict[int, int] = {
    7: 28,
    8: 20,
    9: 28,
    10: 16,
    11: 16,
    12: 10,
    13: 10,
    14: 16,
    15: 16,
}

_MGMT_FIXED_LENS: Dict[int, Tuple[int, Optional[int]]] = {
    0: (24, None),
    1: (26, None),
    2: (30, None),
    3: (26, None),
    4: (20, None),
    5: (32, None),
    8: (32, None),
    9: (20, 20),
    10: (22, 22),
    11: (26, None),
    12: (22, 22),
    13: (21, None),
    14: (21, None),
}


def _expected_length_str(fc_info: dict, data_len: int) -> str:
    ftype = fc_info.get("type", -1)
    subtype = fc_info.get("subtype", -1)

    if ftype == 1:
        fixed = _CTRL_FIXED_LENS.get(subtype)
        if fixed is not None:
            match = "✓" if data_len == fixed else f"actual {data_len}"
            return f"{fixed} bytes (fixed) [{match}]"
        return "variable"

    if ftype == 0:
        rng = _MGMT_FIXED_LENS.get(subtype)
        if rng is not None:
            lo, hi = rng
            if hi is not None:
                match = "✓" if lo <= data_len <= hi else f"actual {data_len}"
                return f"{lo}-{hi} bytes [{match}]"
            match = "✓" if data_len >= lo else f"actual {data_len}"
            return f">={lo} bytes (variable IEs) [{match}]"
        return "variable"

    if ftype == 2:
        return f">=24 bytes (variable payload) [actual {data_len}]"

    return "variable"


class WifiClass:
    DEFINITE = "definite_wifi"
    PROBABLE = "probable_wifi"
    POSSIBLE = "possible_wifi"
    NOT_WIFI = "not_wifi"


_P_FCS = 2.33e-10
_P_SIGNAL_FC = 1 / 512 * 1 / 16
_P_SIGNAL_ONLY = 1 / 512
_P_LTS_PAIR = 1 / 50

_THRESH_DEFINITE = 1e-10
_THRESH_PROBABLE = 1e-5
_THRESH_POSSIBLE = 1e-2


@dataclass
class FrameEvidence:
    frame_id: int
    fcs_ok: bool
    fc_valid: bool
    signal_ok: bool
    lts_pair_ok: bool
    peak1_val: float
    peak2_val: float
    peak_gap: int
    drop_reason: Optional[str]
    frame_type_str: str


def _fc_is_valid(fc_info: dict) -> bool:
    if not fc_info:
        return False
    if fc_info.get("version", -1) != 0:
        return False
    ftype = fc_info.get("type", -1)
    subtype = fc_info.get("subtype", -1)
    if ftype not in (0, 1, 2):
        return False
    if ftype == 1 and subtype < 7:
        return False
    return True


def _frame_false_positive_prob(ev: FrameEvidence) -> float:
    if ev.fcs_ok:
        return _P_FCS
    if ev.signal_ok and ev.fc_valid:
        return _P_SIGNAL_FC
    if ev.signal_ok:
        return _P_SIGNAL_ONLY
    if ev.lts_pair_ok:
        return _P_LTS_PAIR
    return 1.0


def classify_wifi(scan_result: "WifiScanResult"):
    evidences: List[FrameEvidence] = []

    for fd in scan_result.frames:
        p1, p2 = fd.peak_indices
        gap = abs(p2 - p1)
        lts_pair_ok = p1 > 0 and p2 > 0 and abs(gap - 64) <= 2
        signal_ok = fd.signal_encoding is not None and fd.decode_drop_reason != "not_reached"
        fc_valid = _fc_is_valid(fd.fc_info)

        evidences.append(FrameEvidence(
            frame_id=fd.frame_id,
            fcs_ok=fd.fcs_ok,
            fc_valid=fc_valid,
            signal_ok=signal_ok,
            lts_pair_ok=lts_pair_ok,
            peak1_val=fd.peak_values[0],
            peak2_val=fd.peak_values[1],
            peak_gap=gap,
            drop_reason=fd.decode_drop_reason,
            frame_type_str=fd.frame_type_str,
        ))

    if not evidences:
        stats = {
            "joint_fp_prob": 1.0,
            "n_fcs_pass": 0,
            "n_signal_ok": 0,
            "n_signal_fc": 0,
            "n_lts_only": 0,
            "per_frame_probs": [],
        }
        return WifiClass.NOT_WIFI, evidences, stats

    per_frame_probs = [_frame_false_positive_prob(ev) for ev in evidences]
    contributing = [p for p in per_frame_probs if p < 1.0]
    joint_fp_prob = 1.0
    for prob in contributing:
        joint_fp_prob *= prob

    n_fcs_pass = sum(1 for ev in evidences if ev.fcs_ok)
    n_signal_fc = sum(1 for ev in evidences if ev.signal_ok and ev.fc_valid)
    n_signal_ok = sum(1 for ev in evidences if ev.signal_ok)
    n_lts_only = sum(1 for ev in evidences if ev.lts_pair_ok and not ev.signal_ok)

    stats = {
        "joint_fp_prob": joint_fp_prob,
        "n_fcs_pass": n_fcs_pass,
        "n_signal_ok": n_signal_ok,
        "n_signal_fc": n_signal_fc,
        "n_lts_only": n_lts_only,
        "per_frame_probs": per_frame_probs,
    }

    if n_fcs_pass >= 1 or joint_fp_prob < _THRESH_DEFINITE:
        classification = WifiClass.DEFINITE
    elif joint_fp_prob < _THRESH_PROBABLE:
        classification = WifiClass.PROBABLE
    elif joint_fp_prob < _THRESH_POSSIBLE:
        classification = WifiClass.POSSIBLE
    else:
        classification = WifiClass.NOT_WIFI

    return classification, evidences, stats


@dataclass
class FrameDetail:
    peak_indices: Tuple[int, int]
    peak_values: Tuple[float, float]
    frame_id: int
    fcs_ok: bool
    data_len: int
    frame_type_str: str
    expected_length_str: str
    ssid: Optional[str]
    vendor: Optional[str]
    decode_drop_reason: Optional[str] = None
    signal_encoding: Optional[int] = None
    signal_frame_bytes: int = 0
    signal_rate_str: str = "unknown"
    snr_db: Optional[float] = None
    lts_snr_db: Optional[float] = None
    fc_info: dict = field(default_factory=dict)
    data: bytes = field(default_factory=bytes)


@dataclass
class WifiScanResult:
    regular_peaks_indices: np.ndarray
    regular_peaks_values: np.ndarray
    is_wifi: bool
    is_vendor: bool
    vendor_names: List[str]
    vendor_wifi_peaks_indices: np.ndarray
    SSID: Optional[str]
    SSID_all: List[str]
    SSID_wifi_peaks_indices: np.ndarray
    frames_type: List[str]
    frames_expected_length: List[str]
    frames: List[FrameDetail]
    frame_count: int
    fcs_pass_count: int
    fcs_fail_count: int
    classification: str = WifiClass.NOT_WIFI
    classification_stats: dict = field(default_factory=dict)


def build_wifi_scan_result(
    capture: dict,
    corr_long: np.ndarray,
    decoded_frames: List[dict],
    resolver=None,
    lts_snr_db_list: Optional[List[Optional[float]]] = None,
) -> WifiScanResult:
    sorted_peaks = np.asarray(capture.get("sorted_peaks", []), dtype=np.int64)
    pair_count = len(sorted_peaks) // 2
    corr_long = np.asarray(corr_long, dtype=np.float32)

    if pair_count > 0:
        peaks_per_frame = sorted_peaks[: pair_count * 2].reshape(pair_count, 2)
    else:
        peaks_per_frame = np.empty((0, 2), dtype=np.int64)

    def _peak_values(p1: int, p2: int) -> Tuple[float, float]:
        v1 = float(corr_long[p1]) if 0 <= p1 < len(corr_long) else 0.0
        v2 = float(corr_long[p2]) if 0 <= p2 < len(corr_long) else 0.0
        return v1, v2

    frames_by_id: Dict[int, dict] = {}
    for pdu in decoded_frames:
        fid = int(pdu.get("frame_id", 0))
        if fid and (fid not in frames_by_id or pdu.get("fcs_ok", False)):
            frames_by_id[fid] = pdu

    all_peak_indices_list: List[int] = []
    all_peak_values_list: List[float] = []
    vendor_peak_indices_list: List[int] = []
    ssid_peak_indices_list: List[int] = []
    frame_details: List[FrameDetail] = []
    frames_type_list: List[str] = []
    frames_explen_list: List[str] = []
    found_vendors: List[str] = []
    found_ssids: List[str] = []
    fcs_pass = 0
    fcs_fail = 0

    for fr_idx in range(pair_count):
        frame_id = fr_idx + 1
        p1, p2 = int(peaks_per_frame[fr_idx, 0]), int(peaks_per_frame[fr_idx, 1])
        v1, v2 = _peak_values(p1, p2)
        lts_snr = lts_snr_db_list[fr_idx] if lts_snr_db_list and fr_idx < len(lts_snr_db_list) else None
        all_peak_indices_list.extend([p1, p2])
        all_peak_values_list.extend([v1, v2])

        pdu = frames_by_id.get(frame_id)
        if pdu is None:
            frame_details.append(FrameDetail(
                peak_indices=(p1, p2),
                peak_values=(v1, v2),
                frame_id=frame_id,
                fcs_ok=False,
                data_len=0,
                frame_type_str="unknown (not reached)",
                expected_length_str="n/a",
                ssid=None,
                vendor=None,
                decode_drop_reason="not_reached",
                lts_snr_db=lts_snr,
            ))
            frames_type_list.append("unknown (not reached)")
            frames_explen_list.append("n/a")
            fcs_fail += 1
            continue

        fcs_ok = bool(pdu.get("fcs_ok", False))
        data = bytes(pdu.get("data", b""))
        fc_info = pdu.get("fc_info", {})
        roles = pdu.get("roles", {})
        ssid = pdu.get("ssid")
        drop_reason = pdu.get("decode_drop_reason")
        sig_encoding_raw = pdu.get("signal_encoding")
        sig_encoding = None if sig_encoding_raw in (None, "") else int(sig_encoding_raw)
        sig_frame_bytes = int(pdu.get("signal_frame_bytes", 0))
        sig_rate_str = _rate_str(sig_encoding)
        sig_snr_db = pdu.get("snr_db")

        if drop_reason == "version_fail":
            neighbour_types = [frame.frame_type_str for frame in frame_details] + frames_type_list
            frame_type_str = _infer_frame_type(sig_encoding, sig_frame_bytes, neighbour_types)
            stripped = max(0, sig_frame_bytes - 4)
            expected_length = (
                f"{sig_frame_bytes} bytes on-air "
                f"({stripped} after FCS strip) [{sig_rate_str}]"
            )
        else:
            frame_type_str = f"{fc_info.get('type_name', '?')}/{fc_info.get('subtype_name', '?')}"
            expected_length = _expected_length_str(fc_info, len(data))

        if fcs_ok:
            fcs_pass += 1
        else:
            fcs_fail += 1

        vendor_str = None
        if resolver is not None:
            for mac_key in ("addr1", "addr2", "addr3", "ta", "ra", "sa", "da", "ta_sa", "ra_da", "bssid"):
                mac = roles.get(mac_key)
                if not mac:
                    continue
                vendor = resolver.vendor_of(mac)
                if vendor:
                    vendor_str = vendor
                    break

        if vendor_str and vendor_str not in found_vendors:
            found_vendors.append(vendor_str)
        if vendor_str:
            vendor_peak_indices_list.extend([p1, p2])

        if ssid:
            if ssid not in found_ssids:
                found_ssids.append(ssid)
            ssid_peak_indices_list.extend([p1, p2])

        frame_details.append(FrameDetail(
            peak_indices=(p1, p2),
            peak_values=(v1, v2),
            frame_id=frame_id,
            fcs_ok=fcs_ok,
            data_len=len(data),
            frame_type_str=frame_type_str,
            expected_length_str=expected_length,
            ssid=ssid,
            vendor=vendor_str,
            decode_drop_reason=drop_reason,
            signal_encoding=sig_encoding,
            signal_frame_bytes=sig_frame_bytes,
            signal_rate_str=sig_rate_str,
            snr_db=None if sig_snr_db is None else float(sig_snr_db),
            lts_snr_db=lts_snr,
            fc_info=fc_info,
            data=data,
        ))
        frames_type_list.append(frame_type_str)
        frames_explen_list.append(expected_length)

    result = WifiScanResult(
        regular_peaks_indices=np.array(all_peak_indices_list, dtype=np.int64),
        regular_peaks_values=np.array(all_peak_values_list, dtype=np.float32),
        is_wifi=fcs_pass > 0,
        is_vendor=bool(found_vendors),
        vendor_names=found_vendors,
        vendor_wifi_peaks_indices=np.array(vendor_peak_indices_list, dtype=np.int64),
        SSID=found_ssids[0] if found_ssids else None,
        SSID_all=found_ssids,
        SSID_wifi_peaks_indices=np.array(ssid_peak_indices_list, dtype=np.int64),
        frames_type=frames_type_list,
        frames_expected_length=frames_explen_list,
        frames=frame_details,
        frame_count=pair_count,
        fcs_pass_count=fcs_pass,
        fcs_fail_count=fcs_fail,
    )
    result.classification, _, result.classification_stats = classify_wifi(result)
    return result
