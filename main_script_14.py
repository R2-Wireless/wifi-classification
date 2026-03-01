#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gr-ieee802-11 WiFi Receiver with Enhanced Frame Summary Statistics

VERSION: v15 - FIX sync_short port-0 wiring (2026-02-25)
- BUGFIX: sync_short port 0 now receives the raw (undelayed) IQ stream.
  Previously it received the 16-sample delayed stream (blocks_delay_0_0),
  which shifted every copied frame by 16 samples, misaligned the 64-sample
  FFT windows, corrupted all decoded bits, and caused 0% FCS pass rate.

VERSION: v14 - CONSTELLATION/MODULATION DETECTION (2026-02-08)
- NEW: Added constellation/modulation detection (BPSK, QPSK, 16-QAM, 64-QAM)
- Displays constellation in both verbose and compact output modes
- Extracts modulation from gr-ieee802-11 frame equalizer metadata

PREVIOUS VERSION NOTES:
v11 UPDATED:
- Processes the *entire* input file (tb.run() until EOF)
- Counts real FCS pass/fail using decode_mac metadata (fcs_ok)
- Supports decode_mac publishing bad frames on "out_fail"
- Keeps "CHECKSUM: Checksum PASSED/FAILED" lines for batch parsing
"""

from gnuradio import blocks, fft, gr
from gnuradio.fft import window
import os
import sys
import signal
import struct
import time
import re
import math
from argparse import ArgumentParser
from collections import defaultdict
import ieee802_11
import pmt



# =============================================================================
# Wireshark manuf (OUI) resolver
# =============================================================================

def load_wireshark_manuf(path="/usr/share/wireshark/manuf"):
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
                    vendor = " ".join(parts[1:])
                    mapping[prefix] = vendor
    except FileNotFoundError:
        pass
    return mapping


class MacResolver:
    def __init__(self):
        self.oui_map = load_wireshark_manuf()

    @staticmethod
    def _suffix(mac: str) -> str:
        return ":".join(mac.split(":")[-3:])

    def vendor_of(self, mac: str):
        if not mac or mac == "00:00:00:00:00:00":
            return None
        oui = ":".join(mac.split(":")[:3]).lower()
        return self.oui_map.get(oui)

    def label(self, mac: str) -> str:
        v = self.vendor_of(mac)
        if v:
            return f"{v.replace(' ', '_')}_{self._suffix(mac)}"
        return f"UNKNOWN_{self._suffix(mac)}"


# =============================================================================
# 802.11 Frame Parsing Helpers
# =============================================================================

TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Reserved"}

# Hard-coded frame-type decode selection flags.
# Set True/False per type to keep/drop frames in this script.
DECODE_FRAME_TYPE = {
    0: True,   # Management
    1: True,  # Control
    2: True,  # Data
    3: True,  # Extension/Reserved
}

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


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_frame_control(fc: int) -> dict:
    version = fc & 0x3
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    flags = {
        "to_ds": bool((fc >> 8) & 1),
        "from_ds": bool((fc >> 9) & 1),
        "more_frag": bool((fc >> 10) & 1),
        "retry": bool((fc >> 11) & 1),
        "pwr_mgt": bool((fc >> 12) & 1),
        "more_data": bool((fc >> 13) & 1),
        "protected": bool((fc >> 14) & 1),
        "order": bool((fc >> 15) & 1),
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
    """Extract MAC addresses with improved handling"""
    if len(data) < 10:
        return {}

    ftype = fc_info["type"]
    subtype = fc_info["subtype"]
    to_ds = fc_info["flags"]["to_ds"]
    from_ds = fc_info["flags"]["from_ds"]

    roles = {}

    def mac_at(off: int):
        if off + 6 <= len(data):
            return fmt_mac(data[off:off + 6])
        return None

    addr1 = mac_at(4)
    addr2 = mac_at(10)
    addr3 = mac_at(16)

    if addr1: roles["addr1"] = addr1
    if addr2: roles["addr2"] = addr2
    if addr3: roles["addr3"] = addr3

    if ftype == 0:  # Management
        if addr1: roles["ra_da"] = addr1
        if addr2: roles["ta_sa"] = addr2
        if addr3: roles["bssid"] = addr3
        return roles

    if ftype == 1:  # Control
        ra = mac_at(4)
        if ra:
            roles["ra"] = ra
            roles["addr1"] = ra
        if subtype in (11, 8, 9):
            ta = mac_at(10)
            if ta:
                roles["ta"] = ta
                roles["addr2"] = ta
        return roles

    if ftype == 2:  # Data
        has_addr4 = to_ds and from_ds
        qos = _is_qos_data_subtype(subtype)
        addr4_off = 24 + (2 if qos else 0)
        addr4 = mac_at(addr4_off) if has_addr4 else None
        if addr4:
            roles["addr4"] = addr4

        if not to_ds and not from_ds:
            if addr1: roles["da"] = addr1
            if addr2: roles["sa"] = addr2
            if addr3: roles["bssid"] = addr3
        elif to_ds and not from_ds:
            if addr1: roles["bssid"] = addr1
            if addr2: roles["sa"] = addr2
            if addr3: roles["da"] = addr3
        elif not to_ds and from_ds:
            if addr1: roles["da"] = addr1
            if addr2: roles["bssid"] = addr2
            if addr3: roles["sa"] = addr3
        else:
            if addr1: roles["ra"] = addr1
            if addr2: roles["ta"] = addr2
            if addr3: roles["da"] = addr3
            if addr4: roles["sa"] = addr4

        return roles

    return roles


def parse_ies(ies: bytes):
    """Parse Information Elements for SSID, rates, channel."""
    i = 0
    out = {"ssid": None, "rates_mbps": [], "channel": None}
    rates = []

    while i + 2 <= len(ies):
        eid = ies[i]
        elen = ies[i + 1]
        i += 2
        if i + elen > len(ies):
            break
        body = ies[i: i + elen]
        i += elen

        if eid == 0:  # SSID
            out["ssid"] = body.decode("utf-8", errors="replace")
        elif eid in (1, 50):  # Supported / Extended rates
            for r in body:
                val = r & 0x7F
                rates.append(val * 0.5)
        elif eid == 3 and len(body) >= 1:  # DS Parameter Set
            out["channel"] = body[0]

    out["rates_mbps"] = sorted(set(rates))
    return out


# =============================================================================
# Radiotap PCAP Writer
# =============================================================================

class PCAPWriter:
    """Write Radiotap(127) + 802.11 frames to PCAP"""

    DLT_IEEE802_11_RADIOTAP = 127

    RT_PRESENT_FLAGS = 1
    RT_PRESENT_RATE = 2
    RT_PRESENT_CHANNEL = 3
    RT_PRESENT_DBM_ANTSIGNAL = 5
    RT_PRESENT_DBM_ANTNOISE = 6
    RT_PRESENT_ANTENNA = 11

    IEEE80211_CHAN_CCK = 0x0020
    IEEE80211_CHAN_OFDM = 0x0040
    IEEE80211_CHAN_2GHZ = 0x0080
    IEEE80211_CHAN_5GHZ = 0x0100

    def __init__(self, filename):
        self.f = open(filename, "wb")
        self.f.write(struct.pack("<IHHIIII",
                                 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                 self.DLT_IEEE802_11_RADIOTAP))
        self.packet_count = 0

    @staticmethod
    def _pad_to(offset: int, align: int) -> int:
        return (align - (offset % align)) % align

    def _radiotap_header(
        self,
        center_freq_hz: float | None,
        rate_500kbps_units: int | None = None,
        flags: int = 0x00,
        rssi_dbm: float | None = None,
        noise_dbm: float | None = None,
        antenna: int | None = None,
    ) -> bytes:
        present = 0
        fields = bytearray()
        base_hdr_len = 8

        def append_field(raw: bytes, align: int):
            nonlocal fields
            cur_off = base_hdr_len + len(fields)
            pad = self._pad_to(cur_off, align)
            if pad:
                fields += b"\x00" * pad
            fields += raw

        present |= (1 << self.RT_PRESENT_FLAGS)
        append_field(struct.pack("<B", flags), 1)

        if rate_500kbps_units is None:
            rate_500kbps_units = 0
        present |= (1 << self.RT_PRESENT_RATE)
        append_field(struct.pack("<B", int(rate_500kbps_units) & 0xFF), 1)

        chan_freq_mhz = int(round(center_freq_hz / 1e6)) if center_freq_hz else 0
        if center_freq_hz and center_freq_hz >= 4e9:
            chan_flags = self.IEEE80211_CHAN_5GHZ | self.IEEE80211_CHAN_OFDM
        else:
            chan_flags = self.IEEE80211_CHAN_2GHZ | self.IEEE80211_CHAN_OFDM
        present |= (1 << self.RT_PRESENT_CHANNEL)
        append_field(struct.pack("<HH", chan_freq_mhz & 0xFFFF, chan_flags & 0xFFFF), 2)

        if rssi_dbm is not None:
            present |= (1 << self.RT_PRESENT_DBM_ANTSIGNAL)
            antsig = int(max(-128, min(127, round(rssi_dbm))))
            append_field(struct.pack("<b", antsig), 1)

        if noise_dbm is not None:
            present |= (1 << self.RT_PRESENT_DBM_ANTNOISE)
            antn = int(max(-128, min(127, round(noise_dbm))))
            append_field(struct.pack("<b", antn), 1)

        if antenna is not None:
            present |= (1 << self.RT_PRESENT_ANTENNA)
            append_field(struct.pack("<B", int(antenna) & 0xFF), 1)

        rt_len = base_hdr_len + len(fields)
        hdr = struct.pack("<BBHI", 0, 0, rt_len, present)
        return hdr + bytes(fields)

    def write_packet(
        self,
        mac_frame_bytes: bytes,
        timestamp: float | None = None,
        center_freq_hz: float | None = None,
        rssi_dbm: float | None = None,
        noise_dbm: float | None = None,
        antenna: int | None = None,
    ):
        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        rt = self._radiotap_header(
            center_freq_hz=center_freq_hz,
            rssi_dbm=rssi_dbm,
            noise_dbm=noise_dbm,
            antenna=antenna,
        )

        pkt = rt + mac_frame_bytes
        self.f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
        self.f.write(pkt)
        self.f.flush()
        self.packet_count += 1

    def close(self):
        self.f.close()


# =============================================================================
# Frame Statistics Tracker
# =============================================================================

class FrameStats:
    """Track frame decode statistics"""

    def __init__(self):
        self.total_frames = 0
        self.passed_frames = 0
        self.failed_frames = 0
        self.frame_types = defaultdict(int)
        self.error_types = defaultdict(int)
        self.ssids_found = set()
        self.macs_found = set()
        self.bssids_found = set()

    def add_success(self, frame_type: str, ssid: str = None, macs: list = None, bssid: str = None):
        self.total_frames += 1
        self.passed_frames += 1
        self.frame_types[frame_type] += 1

        if ssid:
            self.ssids_found.add(ssid)
        if macs:
            self.macs_found.update(macs)
        if bssid and bssid != "ff:ff:ff:ff:ff:ff":
            self.bssids_found.add(bssid)

    def add_failure(self, reason: str = "Unknown"):
        self.total_frames += 1
        self.failed_frames += 1
        self.error_types[reason] += 1

    def success_rate(self) -> float:
        if self.total_frames == 0:
            return 0.0
        return (self.passed_frames / self.total_frames) * 100.0

    def print_summary(self):
        print("\n" + "="*80)
        print("FINAL FRAME STATISTICS SUMMARY")
        print("="*80)

        print(f"\n📊 DECODE STATISTICS:")
        print(f"  Total frames processed: {self.total_frames}")
        print(f"  ✅ Checksum PASSED: {self.passed_frames}")
        print(f"  ❌ Checksum FAILED: {self.failed_frames}")
        print(f"  Success rate: {self.success_rate():.1f}%")

        if self.frame_types:
            print(f"\n📋 FRAME TYPE BREAKDOWN:")
            for ftype, count in sorted(self.frame_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {ftype}: {count}")

        if self.error_types:
            print(f"\n⚠️  ERROR CATEGORIES:")
            for etype, count in sorted(self.error_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {etype}: {count}")

        if self.ssids_found:
            print(f"\n📶 UNIQUE SSIDs DETECTED ({len(self.ssids_found)}):")
            for ssid in sorted(self.ssids_found):
                print(f"  • '{ssid}'")

        if self.bssids_found:
            print(f"\n🏢 UNIQUE BSSIDs DETECTED ({len(self.bssids_found)}):")
            for bssid in sorted(self.bssids_found):
                print(f"  • {bssid}")

        if self.macs_found:
            print(f"\n📱 UNIQUE MAC ADDRESSES ({len(self.macs_found)}):")
            for mac in sorted(self.macs_found):
                if mac != "ff:ff:ff:ff:ff:ff":
                    print(f"  • {mac}")

        print("="*80)


# =============================================================================
# Message Handler
# =============================================================================

class message_handler(gr.sync_block):
    """Handle decoded MAC PDUs with detailed statistics tracking"""

    def __init__(self, pcap_writer: PCAPWriter, center_freq_hz: float, samp_rate_hz: float,
                 verbose: bool = True):
        gr.sync_block.__init__(self, name="message_handler", in_sig=None, out_sig=None)

        self.pcap = pcap_writer
        self.center_freq_hz = float(center_freq_hz) if center_freq_hz else 5.89e9
        self.samp_rate_hz = float(samp_rate_hz) if samp_rate_hz else 20e6
        self.packet_count = 0
        self.resolver = MacResolver()
        self.verbose = verbose
        self.stats = FrameStats()
        self.stage_time_ns = defaultdict(int)
        self.stage_count = defaultdict(int)
        self.total_msg_time_ns = 0
        self.total_msg_count = 0

        self.message_port_register_in(pmt.intern("in"))
        self.set_msg_handler(pmt.intern("in"), self.handle_msg)

    def _add_stage_time(self, stage: str, dt_ns: int):
        self.stage_time_ns[stage] += dt_ns
        self.stage_count[stage] += 1

    @staticmethod
    def _meta_get_double(meta, key: str, default: float = 0.0) -> float:
        v = pmt.dict_ref(meta, pmt.intern(key), pmt.from_double(default))
        try:
            return float(pmt.to_double(v))
        except Exception:
            return float(default)

    @staticmethod
    def _meta_get_bool(meta, key: str, default: bool = True) -> bool:
        v = pmt.dict_ref(meta, pmt.intern(key), pmt.from_bool(default))
        try:
            return bool(pmt.to_bool(v))
        except Exception:
            return bool(default)

    def handle_msg(self, msg):
        t_msg_start_ns = time.perf_counter_ns()
        try:
            t0 = time.perf_counter_ns()
            meta = pmt.car(msg)
            frame_bytes = pmt.cdr(msg)

            # Convert PMT to bytes
            if pmt.is_u8vector(frame_bytes):
                data = bytes(pmt.u8vector_elements(frame_bytes))
            elif pmt.is_blob(frame_bytes):
                data = bytes(pmt.blob_data(frame_bytes))
            else:
                self.stats.add_failure("Invalid PMT type")
                print("CHECKSUM: Checksum FAILED - Invalid PMT type")
                return
            self._add_stage_time("pmt_to_bytes", time.perf_counter_ns() - t0)

            if len(data) < 2:
                self.stats.add_failure("Frame too short")
                print("CHECKSUM: Checksum FAILED - Frame too short")
                return

            t0 = time.perf_counter_ns()
            # FCS status from decode_mac.cc
            fcs_ok = self._meta_get_bool(meta, "fcs_ok", True)

            # Metadata
            snr_db = self._meta_get_double(meta, "snr", 0.0)
            cfo_hz = self._meta_get_double(meta, "frequency offset", 0.0)
            self._add_stage_time("meta_extract", time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            # Parse frame control
            fc = struct.unpack_from("<H", data, 0)[0]
            fc_info = parse_frame_control(fc)
            self._add_stage_time("fc_parse", time.perf_counter_ns() - t0)

            if fc_info["version"] != 0:
                self.stats.add_failure("Invalid 802.11 version")
                print("CHECKSUM: Checksum FAILED - Invalid 802.11 version")
                return

            if not DECODE_FRAME_TYPE.get(fc_info["type"], False):
                return

            t0 = time.perf_counter_ns()
            roles = derive_address_roles(data, fc_info)
            frame_type_str = f"{fc_info['type_name']}/{fc_info['subtype_name']}"
            self._add_stage_time("address_parse", time.perf_counter_ns() - t0)

            # Collect MACs
            macs_in_frame = []
            for key in ['addr1', 'addr2', 'addr3', 'addr4', 'ta_sa', 'ra_da', 'sa', 'da', 'ta', 'ra']:
                if key in roles and roles[key]:
                    macs_in_frame.append(roles[key])

            t0 = time.perf_counter_ns()
            # Parse SSID if available
            ssid = None
            if fc_info["type"] == 0 and fc_info["subtype"] in (4, 5, 8):
                if len(data) >= 24:
                    ie_off = 24 if fc_info["subtype"] == 4 else 36
                    if len(data) > ie_off:
                        ie_info = parse_ies(data[ie_off:])
                        ssid = ie_info.get("ssid")
            self._add_stage_time("ssid_parse", time.perf_counter_ns() - t0)

            self.packet_count += 1

            # If FCS failed: count as failure + print FAILED line.
            if not fcs_ok:
                self.stats.add_failure("FCS")
                t0 = time.perf_counter_ns()
                if self.verbose:
                    self._print_frame_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
                else:
                    self._print_compact_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
                self._add_stage_time("print_summary", time.perf_counter_ns() - t0)
                print("CHECKSUM: Checksum FAILED - FCS")
                return

            # Record success
            bssid = roles.get("bssid")
            self.stats.add_success(frame_type_str, ssid=ssid, macs=macs_in_frame, bssid=bssid)

            # Print frame summary
            t0 = time.perf_counter_ns()
            if self.verbose:
                self._print_frame_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
            else:
                self._print_compact_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
            self._add_stage_time("print_summary", time.perf_counter_ns() - t0)

            print("CHECKSUM: Checksum PASSED")

            # Write to PCAP (only good frames)
            t0 = time.perf_counter_ns()
            self.pcap.write_packet(
                data,
                timestamp=time.time(),
                center_freq_hz=self.center_freq_hz,
                rssi_dbm=None,
                noise_dbm=None,
                antenna=None,
            )
            self._add_stage_time("pcap_write", time.perf_counter_ns() - t0)

        except Exception as e:
            self.stats.add_failure(f"Exception: {str(e)[:50]}")
            print(f"CHECKSUM: Checksum FAILED - {str(e)[:50]}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            self.total_msg_time_ns += time.perf_counter_ns() - t_msg_start_ns
            self.total_msg_count += 1

    def print_timing_summary(self):
        print("\n" + "=" * 80)
        print("HANDLER STAGE TIMING SUMMARY")
        print("=" * 80)
        print(f"Total messages: {self.total_msg_count}")
        print(f"Total handler time: {self.total_msg_time_ns / 1e6:.3f} ms")
        if self.total_msg_count:
            print(f"Avg per message: {(self.total_msg_time_ns / self.total_msg_count) / 1e3:.3f} us")

        if self.stage_time_ns:
            print("\nStage breakdown (sorted by total time):")
            total = self.total_msg_time_ns if self.total_msg_time_ns > 0 else 1
            for stage, t_ns in sorted(self.stage_time_ns.items(), key=lambda kv: kv[1], reverse=True):
                cnt = self.stage_count.get(stage, 0)
                avg_us = (t_ns / cnt) / 1e3 if cnt else 0.0
                pct = (100.0 * t_ns) / total
                print(f"  {stage:14s} total={t_ns / 1e6:9.3f} ms  avg={avg_us:8.3f} us  count={cnt:6d}  {pct:6.2f}%")
        print("=" * 80)

    def _print_frame_summary(self, data, fc_info, roles, snr_db, cfo_hz, ssid):
        print("\n" + "=" * 80)
        print(f"FRAME #{self.packet_count} SUMMARY")
        print("=" * 80)

        print(f"\n📋 BASIC INFO:")
        print(f"  • Size: {len(data)} bytes")
        print(f"  • Type/Subtype: {fc_info['type_name']} / {fc_info['subtype_name']}")
        print(f"  • DS Direction: {fc_info['ds_direction']}")

        print(f"\n📊 LINK METRICS:")
        print(f"  • SNR: {snr_db:.1f} dB")
        print(f"  • CFO: {cfo_hz:+.2f} Hz ({cfo_hz/1e3:+.2f} kHz)")

        print(f"\n📬 ADDRESSES:")
        
        # Print ALL address fields regardless of frame type
        for addr_key in ['addr1', 'addr2', 'addr3', 'addr4']:
            if addr_key in roles and roles[addr_key]:
                mac = roles[addr_key]
                label = self.resolver.label(mac)
                print(f"  • {addr_key.upper():10s}: {mac}  [{label}]")
        
        # Print role-based addresses
        role_map = {
            'ta_sa': 'TX (TA/SA)',
            'ra_da': 'RX (RA/DA)', 
            'bssid': 'BSSID',
            'sa': 'SA',
            'da': 'DA',
            'ta': 'TA',
            'ra': 'RA'
        }
        
        for role_key, role_label in role_map.items():
            if role_key in roles and roles[role_key]:
                mac = roles[role_key]
                label = self.resolver.label(mac)
                print(f"  • {role_label:10s}: {mac}  [{label}]")

        if ssid is not None:
            print(f"\n📶 NETWORK:")
            print(f"  • SSID: '{ssid}'")

        print("=" * 80)

    def _print_compact_summary(self, data, fc_info, roles, snr_db, cfo_hz, ssid):
        tx = roles.get("ta_sa") or roles.get("sa") or roles.get("ta") or "N/A"
        bssid = roles.get("bssid", "N/A")
        ssid_str = f"SSID='{ssid}'" if ssid else ""

        print(f"[{self.packet_count:3d}] {fc_info['subtype_name']:20s} "
              f"{tx:17s} → {bssid:17s}  "
              f"SNR:{snr_db:5.1f}dB  Off:{cfo_hz/1e3:+6.1f}kHz  "
              f"{len(data):4d}B  {ssid_str}")


# =============================================================================
# GNU Radio Top Block
# =============================================================================

class wifi_rx_file(gr.top_block):
    def __init__(self, filename, output_pcap, freq_offset=0.0, verbose=True):
        gr.top_block.__init__(self, "WiFi RX from File")

        self.window_size = 48
        self.sync_length = 320
        self.samp_rate = 20e6
        #self.samp_rate = 40e6
        #self.freq = 5.89e9
        #self.freq = 5.211e9
        self.freq = 5.180e9
        #self.freq = 5e9
        self.chan_est = ieee802_11.LS
        #self.chan_est = ieee802_11.LMS
        #self.chan_est = ieee802_11.STA
        #self.chan_est = ieee802_11.COMB
         
        self.pcap = PCAPWriter(output_pcap)
        self.msg_handler = message_handler(self.pcap, center_freq_hz=self.freq,
                                           samp_rate_hz=self.samp_rate, verbose=verbose)
         
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex * 1, filename, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
         
        self.blocks_multiply_const = blocks.multiply_const_cc(1.0 / 6000.0)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex * 1, self.samp_rate, True)
         
        if freq_offset != 0.0:
            self.blocks_rotator = blocks.rotator_cc(-2.0 * math.pi * float(freq_offset) / self.samp_rate)
          
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex * 1, 16)
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_moving_average_xx_1 = blocks.moving_average_cc(self.window_size, 1, 4000, 1)
        self.blocks_complex_to_mag_0 = blocks.complex_to_mag(1)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_moving_average_xx_0 = blocks.moving_average_ff(self.window_size, 1, 4000, 1)
        self.blocks_divide_xx_0 = blocks.divide_ff(1)

        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 5, False, False)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex * 1, self.sync_length)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(self.sync_length, False, False)

        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex * 1, 64)
        self.fft_vxx_0 = fft.fft_vcc(64, True, window.rectangular(64), True, 1)
        self.blocks_stream_to_vector_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)
        self.fft_vxx_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(
            ieee802_11.Equalizer(self.chan_est), self.freq, self.samp_rate, True, True
        )
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, True)

        # Connections
        self.connect((self.blocks_file_source_0, 0), (self.blocks_multiply_const, 0))
        self.connect((self.blocks_multiply_const, 0), (self.blocks_throttle_0, 0))

        if freq_offset != 0.0:
            self.connect((self.blocks_throttle_0, 0), (self.blocks_rotator, 0))
            src = self.blocks_rotator
        else:
            src = self.blocks_throttle_0

        self.connect((src, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((src, 0), (self.blocks_delay_0_0, 0))
        self.connect((src, 0), (self.blocks_multiply_xx_0, 0))

        self.connect((self.blocks_delay_0_0, 0), (self.blocks_conjugate_cc_0, 0))
        # FIX: sync_short port 0 must receive the RAW (undelayed) signal so that
        # the CFO-corrected copy in COPY state uses correctly-timed samples.
        # Previously this was (blocks_delay_0_0, 0) which fed the 16-sample delayed
        # signal → shifted every frame by 16 samples → FFT symbol boundaries wrong
        # → Viterbi decoding garbage → FCS always failed.
        self.connect((src, 0),                    (self.ieee802_11_sync_short_0, 0))  # port 0: raw IQ
        self.connect((self.blocks_conjugate_cc_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_xx_0, 0), (self.blocks_moving_average_xx_1, 0))
        self.connect((self.blocks_moving_average_xx_1, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.blocks_moving_average_xx_1, 0), (self.ieee802_11_sync_short_0, 1))  # port 1: complex MA (for CFO phase)
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_divide_xx_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_moving_average_xx_0, 0))
        self.connect((self.blocks_moving_average_xx_0, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.blocks_divide_xx_0, 0), (self.ieee802_11_sync_short_0, 2))  # port 2: normalized correlation float

        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_long_0, 1))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.ieee802_11_frame_equalizer_0, 0))
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))

        # Messages: connect BOTH ports (good + bad)
        self.msg_connect((self.ieee802_11_decode_mac_0, "out"),      (self.msg_handler, "in"))
        self.msg_connect((self.ieee802_11_decode_mac_0, "out_fail"), (self.msg_handler, "in"))


# =============================================================================
# CLI
# =============================================================================

def argument_parser():
    parser = ArgumentParser()
    parser.add_argument("input_file", help="Input IQ file (.cfile format, complex64)")
    parser.add_argument("output_pcap", nargs="?", default="/tmp/wifi_output_radiotap.pcap",
                        help="Output PCAP file (radiotap)")
    parser.add_argument("--freq-offset", dest="freq_offset", type=float, default=0.0,
                        help="Coarse frequency offset correction in Hz")
    parser.add_argument("--compact", action="store_true",
                        help="Use compact one-line output instead of verbose summaries")
    parser.add_argument("--gr-perf", action="store_true",
                        help="Enable GNU Radio built-in performance counters (pc_*) and print per-stage timing tables")
    return parser


def _collect_gr_block_perf_rows(tb):
    rows = []
    seen = set()
    for var_name, obj in tb.__dict__.items():
        if id(obj) in seen:
            continue
        if not hasattr(obj, "pc_work_time_total"):
            continue
        seen.add(id(obj))
        try:
            total_ns = float(obj.pc_work_time_total())
            avg_ns = float(obj.pc_work_time_avg()) if hasattr(obj, "pc_work_time_avg") else 0.0
            thr_avg = float(obj.pc_throughput_avg()) if hasattr(obj, "pc_throughput_avg") else 0.0
            nprod_avg = float(obj.pc_nproduced_avg()) if hasattr(obj, "pc_nproduced_avg") else 0.0
            rows.append({
                "name": var_name,
                "total_ns": total_ns,
                "avg_ns": avg_ns,
                "throughput_avg": thr_avg,
                "nproduced_avg": nprod_avg,
            })
        except Exception:
            continue
    rows.sort(key=lambda r: r["total_ns"], reverse=True)
    return rows


def _collect_stage_totals_from_gr_rows(rows):
    stage_totals_ns = defaultdict(float)
    for r in rows:
        stage_totals_ns[_stage_for_block_name(r["name"])] += r["total_ns"]
    for s in ("sync_short", "sync_long", "frame_equalizer", "decode_mac", "support"):
        stage_totals_ns.setdefault(s, 0.0)
    return stage_totals_ns


def _export_stage_weights_env(tb):
    rows = _collect_gr_block_perf_rows(tb)
    if not rows:
        return
    stage_totals_ns = _collect_stage_totals_from_gr_rows(rows)
    total_ns = sum(stage_totals_ns.values())
    if total_ns <= 0.0:
        return
    os.environ["WIFI_STAGE_WEIGHT_SYNC_SHORT"] = f"{stage_totals_ns['sync_short'] / total_ns:.12f}"
    os.environ["WIFI_STAGE_WEIGHT_SYNC_LONG"] = f"{stage_totals_ns['sync_long'] / total_ns:.12f}"
    os.environ["WIFI_STAGE_WEIGHT_FRAME_EQUALIZER"] = f"{stage_totals_ns['frame_equalizer'] / total_ns:.12f}"
    os.environ["WIFI_STAGE_WEIGHT_DECODE_MAC"] = f"{stage_totals_ns['decode_mac'] / total_ns:.12f}"
    os.environ["WIFI_STAGE_WEIGHT_SUPPORT"] = f"{stage_totals_ns['support'] / total_ns:.12f}"


def _stage_for_block_name(name: str) -> str:
    if name in ("blocks_file_source_0", "blocks_multiply_const", "blocks_throttle_0", "blocks_rotator"):
        return "support"
    if name in (
        "blocks_delay_0_0", "blocks_conjugate_cc_0", "blocks_multiply_xx_0",
        "blocks_moving_average_xx_1", "blocks_complex_to_mag_0",
        "blocks_complex_to_mag_squared_0", "blocks_moving_average_xx_0",
        "blocks_divide_xx_0", "ieee802_11_sync_short_0"
    ):
        return "sync_short"
    if name in ("blocks_delay_0", "ieee802_11_sync_long_0"):
        return "sync_long"
    if name in ("blocks_stream_to_vector_0", "fft_vxx_0", "ieee802_11_frame_equalizer_0"):
        return "frame_equalizer"
    if name in ("ieee802_11_decode_mac_0",):
        return "decode_mac"
    return "support"


def _print_gr_stage_perf_tables(tb, file_total_ns: int, run_ns: int, run_non_handler_ns: int):
    rows = _collect_gr_block_perf_rows(tb)
    if not rows:
        print("\n[timing] GNU Radio perf counters unavailable (no pc_* rows found).")
        return

    total_ns = sum(r["total_ns"] for r in rows)
    if total_ns <= 0.0:
        print("\n[timing] GNU Radio perf counters returned zero time. Enable with --gr-perf.")
        return

    file_total_us = file_total_ns / 1e3 if file_total_ns > 0 else 0.0
    run_total_us = run_ns / 1e3 if run_ns > 0 else 0.0

    stage_totals_ns = _collect_stage_totals_from_gr_rows(rows)
    stage_order = ["sync_short", "sync_long", "frame_equalizer", "decode_mac", "support"]

    run_non_handler_us = max(0.0, run_non_handler_ns / 1e3)
    run_unattributed_us = max(0.0, run_non_handler_us - (total_ns / 1e3))

    # Expand run_non_handler unattributed time per stage by proportional allocation.
    alloc_base_ns = sum(stage_totals_ns[s] for s in stage_order if s != "support")
    stage_alloc_us = {}
    if run_unattributed_us > 0.0 and alloc_base_ns > 0.0:
        for s in stage_order:
            if s == "support":
                stage_alloc_us[s] = 0.0
            else:
                stage_alloc_us[s] = run_unattributed_us * (stage_totals_ns[s] / alloc_base_ns)
    else:
        for s in stage_order:
            stage_alloc_us[s] = 0.0
        stage_alloc_us["support"] = run_unattributed_us

    print("\n[timing] Failure-Map Stage Runtime (aligned labels)")
    print("[timing] +----------------+------------+------------+------------+----------+")
    print("[timing] | stage          | measured_ms| unattrib_ms| est_total_ms| %run_non |")
    print("[timing] +----------------+------------+------------+------------+----------+")
    est_sum_us = 0.0
    for stage in stage_order:
        measured_us = stage_totals_ns[stage] / 1e3
        unattributed_us = stage_alloc_us[stage]
        est_us = measured_us + unattributed_us
        est_sum_us += est_us
        pct_run_non = (100.0 * est_us / run_non_handler_us) if run_non_handler_us else 0.0
        print(
            f"[timing] | {stage:<14} | {measured_us / 1e3:10.3f} | {unattributed_us / 1e3:10.3f} | "
            f"{est_us / 1e3:10.3f} | {pct_run_non:7.2f}% |"
        )
    print("[timing] +----------------+------------+------------+------------+----------+")
    print(
        f"[timing] | {'run_non_handler':<14} | {(total_ns / 1e6):10.3f} | {run_unattributed_us / 1e3:10.3f} | "
        f"{est_sum_us / 1e3:10.3f} | {100.00:7.2f}% |"
    )
    print("[timing] +----------------+------------+------------+------------+----------+")
    if run_total_us > 0:
        print(f"[timing] run_non_handler_as_pct_of_run={100.0 * run_non_handler_us / run_total_us:.2f}%")
    if file_total_us > 0:
        print(f"[timing] run_non_handler_as_pct_of_file={100.0 * run_non_handler_us / file_total_us:.2f}%")
    print("[timing] note: unattrib_ms is allocated proportionally across failure-map stages.")

    print("\n[timing] Top GNU Radio Blocks by Work Time")
    print("[timing] +------------------------------+------------+----------+----------+----------+")
    print("[timing] | block                        |    ms      |  %gr_cpu |  avg_us  | nprodavg |")
    print("[timing] +------------------------------+------------+----------+----------+----------+")
    for r in rows[:20]:
        ms = r["total_ns"] / 1e6
        pct_gr = (100.0 * r["total_ns"] / total_ns) if total_ns else 0.0
        print(
            f"[timing] | {r['name']:<28} | {ms:10.3f} | {pct_gr:7.2f}% | "
            f"{(r['avg_ns'] / 1e3):8.3f} | {r['nproduced_avg']:8.1f} |"
        )
    print("[timing] +------------------------------+------------+----------+----------+----------+")


def main(top_block_cls=wifi_rx_file, options=None):
    file_t0_ns = time.perf_counter_ns()
    setup_start_ns = file_t0_ns
    if options is None:
        options = argument_parser().parse_args()

    verbose = not options.compact
    if options.gr_perf:
        # Must be set before blocks are instantiated.
        prefs = gr.prefs().singleton()
        prefs.set_bool("PerfCounters", "on", True)
        prefs.set_bool("PerfCounters", "export", False)

    print("=" * 80)
    print("gr-ieee802-11 WiFi Receiver v14 - Constellation Detection")
    print("=" * 80)
    print(f"Input:  {options.input_file}")
    print(f"Output: {options.output_pcap}")
    print(f"Mode:   {'Verbose' if verbose else 'Compact'}")
    if options.freq_offset != 0.0:
        print(f"Freq offset correction: {options.freq_offset} Hz")
    print(f"GNU Radio perf counters: {'ON' if options.gr_perf else 'OFF'}")
    print("=" * 80)
    print()

    tb = top_block_cls(
        filename=options.input_file,
        output_pcap=options.output_pcap,
        freq_offset=float(options.freq_offset),
        verbose=verbose,
    )
    setup_done_ns = time.perf_counter_ns()
    run_start_ns = 0
    run_end_ns = setup_done_ns

    def print_final_timing():
        report_start_ns = time.perf_counter_ns()
        tb.msg_handler.stats.print_summary()
        stats_done_ns = time.perf_counter_ns()
        tb.pcap.close()
        close_done_ns = time.perf_counter_ns()

        file_total_ns = close_done_ns - file_t0_ns
        setup_ns = setup_done_ns - setup_start_ns
        run_ns = max(0, run_end_ns - run_start_ns)
        report_ns = stats_done_ns - report_start_ns
        close_ns = close_done_ns - stats_done_ns

        python_handler_ns = tb.msg_handler.total_msg_time_ns
        python_non_handler_ns = max(0, report_ns + close_ns)
        non_python_ns = max(0, file_total_ns - python_handler_ns - python_non_handler_ns)
        run_non_handler_ns = max(0, run_ns - python_handler_ns)
        non_python_setup_ns = max(0, setup_ns)
        non_python_run_residual_ns = max(0, run_ns - python_handler_ns)
        non_python_unattributed_ns = max(
            0, non_python_ns - non_python_setup_ns - non_python_run_residual_ns
        )

        # Export totals for C++ atexit timing summary (% of file total).
        os.environ["WIFI_FILE_TOTAL_NS"] = str(file_total_ns)
        os.environ["WIFI_PY_HANDLER_NS"] = str(python_handler_ns)
        os.environ["WIFI_RUN_NON_HANDLER_NS"] = str(run_non_handler_ns)
        if options.gr_perf:
            _export_stage_weights_env(tb)

        def pct(ns: int) -> float:
            return (100.0 * ns / file_total_ns) if file_total_ns else 0.0

        print(f"[timing] file_total_ms={file_total_ns / 1e6:.3f}")
        print(f"[timing] python_total_ms={(python_handler_ns + python_non_handler_ns) / 1e6:.3f}")
        print(f"[timing] python_handler_ms={python_handler_ns / 1e6:.3f}")
        print(f"[timing] python_non_handler_ms={python_non_handler_ns / 1e6:.3f}")
        print(f"[timing] non_python_ms={non_python_ns / 1e6:.3f}")
        print(f"[timing] non_python_setup_ms={non_python_setup_ns / 1e6:.3f} ({pct(non_python_setup_ns):.2f}%)")
        print(f"[timing] non_python_run_residual_ms={non_python_run_residual_ns / 1e6:.3f} ({pct(non_python_run_residual_ns):.2f}%)")
        print(f"[timing] non_python_unattributed_ms={non_python_unattributed_ns / 1e6:.3f} ({pct(non_python_unattributed_ns):.2f}%)")
        print(f"[timing] phase_setup_ms={setup_ns / 1e6:.3f}")
        print(f"[timing] phase_run_ms={run_ns / 1e6:.3f}")
        print(f"[timing] phase_report_ms={report_ns / 1e6:.3f}")
        print(f"[timing] phase_close_ms={close_ns / 1e6:.3f}")
        print("[timing] note: cpp_total/cpp_block lines are printed at process exit and belong mostly to non_python_run_residual_ms")

        # Additive breakdown: sums exactly (up to rounding) to file_total.
        additive_rows = [
            ("setup", setup_ns),
            ("python_handler", python_handler_ns),
            ("run_non_handler", run_non_handler_ns),
            ("report", report_ns),
            ("close", close_ns),
        ]
        print("\n[timing] Additive Runtime Breakdown (sums to total)")
        print("[timing] +-------------------+------------+----------+")
        print("[timing] | component         |    ms      |   pct    |")
        print("[timing] +-------------------+------------+----------+")
        for name, ns in additive_rows:
            ms = ns / 1e6
            p = (100.0 * ns / file_total_ns) if file_total_ns else 0.0
            print(f"[timing] | {name:<17} | {ms:10.3f} | {p:7.2f}% |")
        additive_sum_ns = sum(ns for _, ns in additive_rows)
        sum_ms = additive_sum_ns / 1e6
        sum_pct = (100.0 * additive_sum_ns / file_total_ns) if file_total_ns else 0.0
        print("[timing] +-------------------+------------+----------+")
        print(f"[timing] | {'SUM':<17} | {sum_ms:10.3f} | {sum_pct:7.2f}% |")
        print("[timing] +-------------------+------------+----------+")

        # Top Python stage functions within handler path.
        if tb.msg_handler.stage_time_ns:
            print("\n[timing] Top Python Handler Functions")
            print("[timing] +-------------------+------------+----------+----------+")
            print("[timing] | function          |    ms      | %handler |  %total  |")
            print("[timing] +-------------------+------------+----------+----------+")
            sorted_stages = sorted(tb.msg_handler.stage_time_ns.items(),
                                   key=lambda kv: kv[1],
                                   reverse=True)
            stage_sum_ns = 0
            for stage, t_ns in sorted_stages:
                stage_sum_ns += t_ns
                ms = t_ns / 1e6
                pct_handler = (100.0 * t_ns / python_handler_ns) if python_handler_ns else 0.0
                pct_total = (100.0 * t_ns / file_total_ns) if file_total_ns else 0.0
                print(f"[timing] | {stage:<17} | {ms:10.3f} | {pct_handler:7.2f}% | {pct_total:7.2f}% |")
            stage_sum_ms = stage_sum_ns / 1e6
            stage_sum_pct = (100.0 * stage_sum_ns / file_total_ns) if file_total_ns else 0.0
            print("[timing] +-------------------+------------+----------+----------+")
            print(f"[timing] | {'handler_stage_sum':<17} | {stage_sum_ms:10.3f} | {100.00:7.2f}% | {stage_sum_pct:7.2f}% |")
            print("[timing] +-------------------+------------+----------+----------+")

        if options.gr_perf:
            _print_gr_stage_perf_tables(
                tb,
                file_total_ns=file_total_ns,
                run_ns=run_ns,
                run_non_handler_ns=run_non_handler_ns,
            )

    def sig_handler(sig=None, frame=None):
        try:
            tb.stop()
            tb.wait()
        finally:
            nonlocal run_end_ns
            run_end_ns = time.perf_counter_ns()
            print_final_timing()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print("Processing file until EOF (Ctrl-C to stop)...\n")

    try:
        run_start_ns = time.perf_counter_ns()
        tb.run()  # IMPORTANT: run to EOF
        run_end_ns = time.perf_counter_ns()
    except KeyboardInterrupt:
        run_end_ns = time.perf_counter_ns()
        pass

    print_final_timing()

    print()
    print("=" * 80)
    print("✓ Processing complete!")
    print(f"✓ Handler saw {tb.msg_handler.packet_count} PDUs (good+bad if published)")
    print(f"✓ Written Radiotap PCAP to: {options.output_pcap}")
    print("=" * 80)


if __name__ == "__main__":
    t0 = time.perf_counter()
    main()
    dt = time.perf_counter() - t0
    print(f"Elapsed: {dt:.6f} s")
