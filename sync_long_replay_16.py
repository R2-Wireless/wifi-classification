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
import re
import struct
import tempfile
import time
from collections import defaultdict

import numpy as np
import pmt

from gnuradio import gr, blocks, fft as gr_fft
from gnuradio.fft import window
import ieee802_11

# Reuse the loader from the capture module
sys.path.insert(0, os.path.dirname(__file__))
from sync_long_capture_probe import load_sync_long_capture

_WIRESHARK_MANUF_CACHE = None


def load_wireshark_manuf(path="/usr/share/wireshark/manuf"):
    global _WIRESHARK_MANUF_CACHE
    if _WIRESHARK_MANUF_CACHE is not None:
        return _WIRESHARK_MANUF_CACHE
    mapping = {}
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                prefix = parts[0].lower()
                if "/" in prefix:
                    continue
                if re.fullmatch(r"[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", prefix):
                    mapping[prefix] = " ".join(parts[1:])
    except FileNotFoundError:
        pass
    _WIRESHARK_MANUF_CACHE = mapping
    return mapping


class MacResolver:
    def __init__(self):
        self.oui_map = load_wireshark_manuf()

    def vendor_of(self, mac: str):
        if not mac or mac == "00:00:00:00:00:00":
            return None
        oui = ":".join(mac.split(":")[:3]).lower()
        return self.oui_map.get(oui)


TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Reserved"}
DECODE_FRAME_TYPE = {0: True, 1: True, 2: True, 3: True}
MGMT_SUBTYPE_NAMES = {
    0: "Association Request", 1: "Association Response", 2: "Reassociation Request",
    3: "Reassociation Response", 4: "Probe Request", 5: "Probe Response",
    8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication",
    12: "Deauthentication", 13: "Action", 14: "Action No Ack",
}
CTRL_SUBTYPE_NAMES = {
    7: "Control Wrapper", 8: "Block Ack Request", 9: "Block Ack",
    10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK",
    14: "CF-End", 15: "CF-End + CF-Ack",
}
DATA_SUBTYPE_NAMES = {0: "Data", 4: "Null", 8: "QoS Data", 12: "QoS Null"}


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_frame_control(fc: int) -> dict:
    version = fc & 0x3
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    flags = {
        "to_ds": bool((fc >> 8) & 1),
        "from_ds": bool((fc >> 9) & 1),
    }
    if not flags["to_ds"] and not flags["from_ds"]:
        ds_dir = "IBSS/ad-hoc"
    elif flags["to_ds"] and not flags["from_ds"]:
        ds_dir = "To DS"
    elif not flags["to_ds"] and flags["from_ds"]:
        ds_dir = "From DS"
    else:
        ds_dir = "WDS"

    if ftype == 0:
        subtype_name = MGMT_SUBTYPE_NAMES.get(subtype, f"Mgmt-{subtype}")
    elif ftype == 1:
        subtype_name = CTRL_SUBTYPE_NAMES.get(subtype, f"Ctrl-{subtype}")
    elif ftype == 2:
        subtype_name = DATA_SUBTYPE_NAMES.get(subtype, f"Data-{subtype}")
    else:
        subtype_name = f"Subtype-{subtype}"

    return {
        "version": version,
        "type": ftype,
        "subtype": subtype,
        "type_name": TYPE_NAMES.get(ftype, "Unknown"),
        "subtype_name": subtype_name,
        "flags": flags,
        "ds_direction": ds_dir,
    }


def _is_qos_data_subtype(subtype: int) -> bool:
    return subtype in (8, 12)


def derive_address_roles(data: bytes, fc_info: dict):
    if len(data) < 10:
        return {}

    ftype = fc_info["type"]
    subtype = fc_info["subtype"]
    to_ds = fc_info["flags"]["to_ds"]
    from_ds = fc_info["flags"]["from_ds"]
    roles = {}

    def mac_at(off: int):
        if off + 6 <= len(data):
            return _fmt_mac(data[off:off + 6])
        return None

    addr1 = mac_at(4)
    addr2 = mac_at(10)
    addr3 = mac_at(16)
    if addr1:
        roles["addr1"] = addr1
    if addr2:
        roles["addr2"] = addr2
    if addr3:
        roles["addr3"] = addr3

    if ftype == 0:
        if addr1:
            roles["ra_da"] = addr1
        if addr2:
            roles["ta_sa"] = addr2
        if addr3:
            roles["bssid"] = addr3
        return roles

    if ftype == 1:
        if addr1:
            roles["ra"] = addr1
        if subtype in (11, 8, 9) and addr2:
            roles["ta"] = addr2
        return roles

    if ftype == 2:
        has_addr4 = to_ds and from_ds
        addr4 = mac_at(24 + (2 if _is_qos_data_subtype(subtype) else 0)) if has_addr4 else None
        if addr4:
            roles["addr4"] = addr4
        if not to_ds and not from_ds:
            if addr1:
                roles["da"] = addr1
            if addr2:
                roles["sa"] = addr2
            if addr3:
                roles["bssid"] = addr3
        elif to_ds and not from_ds:
            if addr1:
                roles["bssid"] = addr1
            if addr2:
                roles["sa"] = addr2
            if addr3:
                roles["da"] = addr3
        elif not to_ds and from_ds:
            if addr1:
                roles["da"] = addr1
            if addr2:
                roles["bssid"] = addr2
            if addr3:
                roles["sa"] = addr3
        else:
            if addr1:
                roles["ra"] = addr1
            if addr2:
                roles["ta"] = addr2
            if addr3:
                roles["da"] = addr3
            if addr4:
                roles["sa"] = addr4
    return roles


def parse_ies(ies: bytes):
    i = 0
    out = {"ssid": None}
    while i + 2 <= len(ies):
        eid = ies[i]
        elen = ies[i + 1]
        i += 2
        if i + elen > len(ies):
            break
        body = ies[i:i + elen]
        i += elen
        if eid == 0:
            out["ssid"] = body.decode("utf-8", errors="replace")
    return out


class PCAPWriter:
    DLT_IEEE802_11_RADIOTAP = 127

    def __init__(self, filename):
        self.f = open(filename, "wb")
        self.f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.DLT_IEEE802_11_RADIOTAP))
        self.packet_count = 0

    def _radiotap_header(self, center_freq_hz: float | None) -> bytes:
        chan_freq_mhz = int(round(center_freq_hz / 1e6)) if center_freq_hz else 0
        chan_flags = 0x0100 | 0x0040 if center_freq_hz and center_freq_hz >= 4e9 else 0x0080 | 0x0040
        present = (1 << 1) | (1 << 2)
        fields = struct.pack("<B", 0) + b"\x00" + struct.pack("<HH", chan_freq_mhz & 0xFFFF, chan_flags & 0xFFFF)
        rt_len = 8 + len(fields)
        return struct.pack("<BBHI", 0, 0, rt_len, present) + fields

    def write_packet(self, mac_frame_bytes: bytes, timestamp: float | None = None, center_freq_hz: float | None = None, **_kwargs):
        if timestamp is None:
            timestamp = time.time()
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        pkt = self._radiotap_header(center_freq_hz) + mac_frame_bytes
        self.f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
        self.f.write(pkt)
        self.f.flush()
        self.packet_count += 1

    def close(self):
        self.f.close()


class FrameStats:
    def __init__(self):
        self.total_frames = 0
        self.passed_frames = 0
        self.failed_frames = 0

    def add_success(self):
        self.total_frames += 1
        self.passed_frames += 1

    def add_failure(self, _reason: str = "Unknown"):
        self.total_frames += 1
        self.failed_frames += 1

    def print_summary(self):
        print(
            f"[replay] Summary: total={self.total_frames} "
            f"passed={self.passed_frames} failed={self.failed_frames}"
        )


class message_handler(gr.sync_block):
    def __init__(self, pcap, center_freq_hz=5.18e9, samp_rate_hz=20e6, verbose=True):
        gr.sync_block.__init__(self, "message_handler", in_sig=None, out_sig=None)
        self.pcap = pcap
        self.center_freq_hz = float(center_freq_hz)
        self.samp_rate_hz = float(samp_rate_hz)
        self.verbose = bool(verbose)
        self.packet_count = 0
        self.total_msg_time_ns = 0
        self.stats = FrameStats()
        self.resolver = MacResolver()
        self.decoded_frames = []
        self.stage_time_ns = defaultdict(int)
        self.stage_count = defaultdict(int)
        self.message_port_register_in(pmt.intern("in"))
        self.set_msg_handler(pmt.intern("in"), self.handle_msg)

    @staticmethod
    def _meta_get_bool(meta, key: str, default: bool = False) -> bool:
        try:
            return bool(pmt.to_bool(pmt.dict_ref(meta, pmt.intern(key), pmt.from_bool(default))))
        except Exception:
            return bool(default)

    @staticmethod
    def _meta_get_double(meta, key: str, default: float = 0.0) -> float:
        try:
            return float(pmt.to_double(pmt.dict_ref(meta, pmt.intern(key), pmt.from_double(default))))
        except Exception:
            return float(default)

    @staticmethod
    def _meta_get_uint64(meta, key: str, default: int = 0) -> int:
        try:
            return int(pmt.to_uint64(pmt.dict_ref(meta, pmt.intern(key), pmt.from_uint64(default))))
        except Exception:
            return int(default)

    def handle_msg(self, msg):
        t_msg_start_ns = time.perf_counter_ns()
        try:
            meta = pmt.car(msg)
            frame_bytes = pmt.cdr(msg)
            if pmt.is_u8vector(frame_bytes):
                data = bytes(pmt.u8vector_elements(frame_bytes))
            elif pmt.is_blob(frame_bytes):
                data = bytes(pmt.blob_data(frame_bytes))
            else:
                self.stats.add_failure("Invalid PMT type")
                return

            if len(data) < 2:
                self.stats.add_failure("Frame too short")
                return

            fcs_ok = self._meta_get_bool(meta, "fcs_ok", False)
            snr_db = self._meta_get_double(meta, "snr", 0.0)
            fc = struct.unpack_from("<H", data, 0)[0]
            fc_info = parse_frame_control(fc)
            if not DECODE_FRAME_TYPE.get(fc_info["type"], False):
                return

            roles = derive_address_roles(data, fc_info)
            ssid = None
            if fc_info["type"] == 0 and fc_info["subtype"] in (4, 5, 8):
                ie_off = 24 if fc_info["subtype"] == 4 else 36
                if len(data) > ie_off:
                    ssid = parse_ies(data[ie_off:]).get("ssid")

            self.packet_count += 1
            self.decoded_frames.append({
                "frame_id": self._meta_get_uint64(meta, "frame_id", 0),
                "fcs_ok": bool(fcs_ok),
                "data": data,
                "fc_info": fc_info,
                "roles": roles,
                "ssid": ssid,
                "decode_drop_reason": None if fcs_ok else "fcs_fail",
                "signal_encoding": self._meta_get_uint64(meta, "encoding", 0),
                "signal_frame_bytes": self._meta_get_uint64(meta, "frame bytes", 0),
                "snr_db": snr_db,
            })

            if fcs_ok:
                self.stats.add_success()
                self.pcap.write_packet(data, timestamp=time.time(), center_freq_hz=self.center_freq_hz)
            else:
                self.stats.add_failure("FCS")

            if self.verbose:
                print(
                    f"[replay] PDU #{self.packet_count} "
                    f"type={fc_info['type_name']}/{fc_info['subtype_name']} "
                    f"fcs_ok={fcs_ok} bytes={len(data)} snr={snr_db:.1f}dB"
                )
        finally:
            self.total_msg_time_ns += time.perf_counter_ns() - t_msg_start_ns


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


def _rate_str(encoding):
    if encoding in (None, ""):
        return ""
    try:
        enc = int(encoding)
    except Exception:
        return str(encoding)
    info = _ENCODING_INFO.get(enc)
    if info:
        return f"{info[0]} ({info[1]})"
    return f"encoding={enc}"




def _npz_path_with_suffix(npz_path: str) -> str:
    return npz_path if npz_path.endswith('.npz') else npz_path + '.npz'


def _infer_capture_samp_rate(npz_obj, explicit_samp_rate: float | None) -> float:
    if explicit_samp_rate is not None:
        return float(explicit_samp_rate)
    for key in ('target_samp_rate_hz', 'capture_samp_rate_hz', 'samp_rate_hz', 'samp_rate'):
        if key in npz_obj:
            try:
                return float(np.asarray(npz_obj[key]).reshape(-1)[0])
            except Exception:
                pass
    return 20e6


def _cap_dict_to_tags_raw(cap: dict) -> list[dict]:
    tag_offsets = np.asarray(cap["tag_offsets"])
    tag_keys = np.asarray(cap["tag_keys"])
    tag_values_f64 = np.asarray(cap["tag_values_f64"])
    tag_values_u64 = np.asarray(cap["tag_values_u64"])
    tag_value_types = np.asarray(cap["tag_value_types"])

    tags_raw = []
    for i in range(len(tag_keys)):
        vtype = str(tag_value_types[i])
        value = float(tag_values_f64[i]) if vtype == "f64" else int(tag_values_u64[i])
        tags_raw.append({
            "offset": int(tag_offsets[i]),
            "key": str(tag_keys[i]),
            "value": value,
            "type": vtype,
        })
    return tags_raw


def _capture_payload_from_npz(npz_path: str, samp_rate: float | None):
    print(f"[replay] Loading capture: {npz_path}")

    npz_path_full = _npz_path_with_suffix(npz_path)
    d = np.load(npz_path_full, allow_pickle=True)

    samples = np.asarray(d["samples"], dtype=np.complex64)
    tags_raw = _cap_dict_to_tags_raw(d)
    inferred_samp_rate = _infer_capture_samp_rate(d, samp_rate)
    return samples, tags_raw, inferred_samp_rate


def _capture_payload_from_dict(cap: dict, samp_rate: float | None):
    print("[replay] Loading capture from memory")

    samples = np.asarray(cap["samples"], dtype=np.complex64)
    tags_raw = _cap_dict_to_tags_raw(cap)
    inferred_samp_rate = _infer_capture_samp_rate(cap, samp_rate)
    return samples, tags_raw, inferred_samp_rate


def _vendor_for_roles(resolver, roles: dict) -> str | None:
    if resolver is None:
        return None
    for mac_key in ("addr1", "addr2", "addr3", "ta", "ra", "sa", "da", "ta_sa", "ra_da", "bssid"):
        mac = roles.get(mac_key)
        if not mac:
            continue
        try:
            vendor = resolver.vendor_of(mac)
        except Exception:
            vendor = None
        if vendor:
            return vendor
    return None


def _print_replay_frame_table(cap: dict, decoded_frames: list[dict], resolver=None):
    tag_offsets = np.asarray(cap.get("tag_offsets", []), dtype=np.uint64)
    tag_keys = np.asarray(cap.get("tag_keys", []))
    tag_values_f64 = np.asarray(cap.get("tag_values_f64", []), dtype=np.float64)
    tag_value_types = np.asarray(cap.get("tag_value_types", []))
    frame_count = int(cap.get("frame_count", 0))
    sync_long_peak_abs = np.asarray(cap.get("sync_long_peak_abs", []), dtype=np.int32)
    lts_snr_db = list(cap.get("lts_snr_db", []) or [])
    samp_rate_hz = float(np.asarray(cap.get("target_samp_rate_hz", 20e6)).reshape(-1)[0])
    cfo_long_rad_by_frame: dict[int, float] = {}
    cfo_long_hz_by_frame: dict[int, float] = {}
    cfo_idx = 0
    for idx in range(len(tag_keys)):
        if str(tag_keys[idx]) != "cfo_long_rad_per_samp":
            continue
        if str(tag_value_types[idx]) != "f64":
            continue
        frame_id = cfo_idx + 1
        cfo_rad_per_samp = float(tag_values_f64[idx])
        cfo_long_rad_by_frame[frame_id] = cfo_rad_per_samp
        cfo_long_hz_by_frame[frame_id] = cfo_rad_per_samp * samp_rate_hz / (2.0 * np.pi)
        cfo_idx += 1

    width_id = 10
    width_peak1 = 8
    width_peak2 = 8
    width_lts = 8
    width_eq = 22
    width_type = 28
    width_rate = 22
    width_bytes = 7
    width_cfo_rad = 14
    width_cfo = 12
    width_dec = 16
    width_out = 30

    def cell(text: str, width: int) -> str:
        if len(text) >= width:
            if width <= 1:
                return text[:width]
            return text[: width - 1] + "."
        return text + (" " * (width - len(text)))

    sep = (
        "+" + "-" * (width_id + 2) +
        "+" + "-" * (width_peak1 + 2) +
        "+" + "-" * (width_peak2 + 2) +
        "+" + "-" * (width_lts + 2) +
        "+" + "-" * (width_eq + 2) +
        "+" + "-" * (width_type + 2) +
        "+" + "-" * (width_rate + 2) +
        "+" + "-" * (width_bytes + 2) +
        "+" + "-" * (width_cfo_rad + 2) +
        "+" + "-" * (width_cfo + 2) +
        "+" + "-" * (width_dec + 2) +
        "+" + "-" * (width_out + 2) + "+"
    )

    print("\n[frame_trace] Per-Frame Replay Table")
    print(f"[frame_trace] {sep}")
    print(
        "[frame_trace] | "
        f"{cell('frame_id', width_id)} | "
        f"{cell('peak_1', width_peak1)} | "
        f"{cell('peak_2', width_peak2)} | "
        f"{cell('lts_snr', width_lts)} | "
        f"{cell('equalizer', width_eq)} | "
        f"{cell('frame_type', width_type)} | "
        f"{cell('rate', width_rate)} | "
        f"{cell('bytes', width_bytes)} | "
        f"{cell('cfo_long_rad', width_cfo_rad)} | "
        f"{cell('cfo_long_hz', width_cfo)} | "
        f"{cell('decode_mac', width_dec)} | "
        f"{cell('outcome', width_out)} |"
    )
    print(f"[frame_trace] {sep}")

    for idx in range(frame_count):
        frame_id = idx + 1
        pdu = next((item for item in decoded_frames if int(item.get("frame_id", 0)) == frame_id), None)
        if pdu is None:
            eq_status = "-"
            dec_status = "not_reached"
            frame_type = "-"
            rate_text = ""
            bytes_text = ""
            cfo_rad_text = ""
            cfo_text = ""
            outcome = ""
        else:
            eq_status = "signal_ok" if pdu.get("signal_encoding") not in (None, "") else "-"
            dec_status = "fcs_pass" if pdu.get("fcs_ok", False) else str(pdu.get("decode_drop_reason") or "fcs_fail")
            fc_info = pdu.get("fc_info", {}) or {}
            type_name = fc_info.get("type_name", "?")
            subtype_name = fc_info.get("subtype_name", "?")
            frame_type = f"{type_name}/{subtype_name}"
            rate_text = _rate_str(pdu.get("signal_encoding"))
            bytes_text = str(len(bytes(pdu.get("data", b""))))
            cfo_rad = cfo_long_rad_by_frame.get(frame_id)
            cfo_hz = cfo_long_hz_by_frame.get(frame_id)
            cfo_rad_text = f"{cfo_rad:.6g}" if cfo_rad is not None else ""
            cfo_text = f"{cfo_hz:.1f}" if cfo_hz is not None else ""

            vendor = _vendor_for_roles(resolver, pdu.get("roles", {}) or {})
            snr_db = pdu.get("snr_db")
            outcome = vendor or (f"SNR={float(snr_db):.1f} dB" if snr_db is not None else "")

        lts_text = "-"
        peak1_text = "-"
        peak2_text = "-"
        if idx < len(sync_long_peak_abs):
            peaks = np.asarray(sync_long_peak_abs[idx]).reshape(-1)
            if len(peaks) >= 1:
                peak1_text = str(int(peaks[0]))
            if len(peaks) >= 2:
                peak2_text = str(int(peaks[1]))
        if idx < len(lts_snr_db) and lts_snr_db[idx] is not None:
            lts_text = f"{float(lts_snr_db[idx]):.1f} dB"

        print(
            "[frame_trace] | "
            f"{cell(str(frame_id), width_id)} | "
            f"{cell(peak1_text, width_peak1)} | "
            f"{cell(peak2_text, width_peak2)} | "
            f"{cell(lts_text, width_lts)} | "
            f"{cell(eq_status, width_eq)} | "
            f"{cell(frame_type, width_type)} | "
            f"{cell(rate_text, width_rate)} | "
            f"{cell(bytes_text, width_bytes)} | "
            f"{cell(cfo_rad_text, width_cfo_rad)} | "
            f"{cell(cfo_text, width_cfo)} | "
            f"{cell(dec_status, width_dec)} | "
            f"{cell(outcome, width_out)} |"
        )

    print(f"[frame_trace] {sep}")

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
        samples, tags_raw, inferred_samp_rate = _capture_payload_from_npz(npz_path, samp_rate)
        self._init_from_capture_payload(
            samples=samples,
            tags_raw=tags_raw,
            output_pcap=output_pcap,
            freq=freq,
            samp_rate=inferred_samp_rate,
            chan_est=chan_est,
            verbose=verbose,
        )

    def _init_from_capture_payload(self, samples, tags_raw, output_pcap: str,
                                   freq: float, samp_rate: float,
                                   chan_est=None, verbose: bool = True):

        # Count frames from wifi_start tags
        frame_offsets = sorted(set(
            t["offset"] for t in tags_raw if t["key"] == "wifi_start"
        ))
        n_frames = len(frame_offsets)

        print(f"[replay] {len(samples):,} samples, {len(tags_raw)} tags, "
            f"{n_frames} detected frames, samp_rate={samp_rate/1e6:.2f} MHz") 

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


class wifi_rx_replay_capture(wifi_rx_replay):
    def __init__(self, cap: dict, output_pcap: str,
                 freq: float = 5.180e9, samp_rate: float | None = None,
                 chan_est=None, verbose: bool = True):
        gr.top_block.__init__(self, "WiFi RX Replay")

        samples, tags_raw, inferred_samp_rate = _capture_payload_from_dict(cap, samp_rate)
        self._init_from_capture_payload(
            samples=samples,
            tags_raw=tags_raw,
            output_pcap=output_pcap,
            freq=freq,
            samp_rate=inferred_samp_rate,
            chan_est=chan_est,
            verbose=verbose,
        )


# =============================================================================
# Entry point
# =============================================================================

def run_replay(npz_path: str, output_pcap: str = "/tmp/replay_output.pcap",
               freq: float = 5.180e9, samp_rate: float | None = None,
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


def run_replay_capture(cap: dict, output_pcap: str = "/tmp/replay_output.pcap",
                       freq: float = 5.180e9, samp_rate: float | None = None,
                       verbose: bool = True):
    os.environ["WIFI_FRAME_TRACE_DISABLE"] = "1"
    tb = wifi_rx_replay_capture(
        cap, output_pcap,
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
    try:
        _print_replay_frame_table(cap, tb.msg_handler.decoded_frames, resolver=getattr(tb.msg_handler, "resolver", None))
    except Exception:
        pass


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Replay sync_long capture through downstream pipeline")
    p.add_argument("npz_path",     help="Path to .npz capture (with or without .npz suffix)")
    p.add_argument("output_pcap",  nargs="?", default="/tmp/replay_output.pcap")
    p.add_argument("--freq",       type=float, default=5.180e9,
                   help="Center frequency in Hz (default: 5.180e9)")
    p.add_argument("--samp-rate",  type=float, default=None,
                   help="Sample rate in Hz. If omitted, use target_samp_rate_hz from the NPZ when present.")
    p.add_argument("--compact",    action="store_true")
    args = p.parse_args()

    run_replay(
        args.npz_path,
        args.output_pcap,
        freq=args.freq,
        samp_rate=args.samp_rate,
        verbose=not args.compact,
    )
