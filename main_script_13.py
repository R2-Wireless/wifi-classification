#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gr-ieee802-11 WiFi Receiver with Enhanced Frame Summary Statistics

UPDATED VERSION:
- Processes the *entire* input file (tb.run() until EOF)
- Counts real FCS pass/fail using decode_mac metadata (fcs_ok)
- Supports decode_mac publishing bad frames on "out_fail"
- Keeps "CHECKSUM: Checksum PASSED/FAILED" lines for batch parsing
"""

from gnuradio import blocks, fft, gr
from gnuradio.fft import window
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

        self.message_port_register_in(pmt.intern("in"))
        self.set_msg_handler(pmt.intern("in"), self.handle_msg)

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
        try:
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

            if len(data) < 2:
                self.stats.add_failure("Frame too short")
                print("CHECKSUM: Checksum FAILED - Frame too short")
                return

            # FCS status from decode_mac.cc
            fcs_ok = self._meta_get_bool(meta, "fcs_ok", True)

            # Metadata
            snr_db = self._meta_get_double(meta, "snr", 0.0)
            cfo_hz = self._meta_get_double(meta, "frequency offset", 0.0)

            # Parse frame control
            fc = struct.unpack_from("<H", data, 0)[0]
            fc_info = parse_frame_control(fc)

            if fc_info["version"] != 0:
                self.stats.add_failure("Invalid 802.11 version")
                print("CHECKSUM: Checksum FAILED - Invalid 802.11 version")
                return

            roles = derive_address_roles(data, fc_info)
            frame_type_str = f"{fc_info['type_name']}/{fc_info['subtype_name']}"

            # Collect MACs
            macs_in_frame = []
            for key in ['addr1', 'addr2', 'addr3', 'addr4', 'ta_sa', 'ra_da', 'sa', 'da', 'ta', 'ra']:
                if key in roles and roles[key]:
                    macs_in_frame.append(roles[key])

            # Parse SSID if available
            ssid = None
            if fc_info["type"] == 0 and fc_info["subtype"] in (4, 5, 8):
                if len(data) >= 24:
                    ie_off = 24 if fc_info["subtype"] == 4 else 36
                    if len(data) > ie_off:
                        ie_info = parse_ies(data[ie_off:])
                        ssid = ie_info.get("ssid")

            self.packet_count += 1

            # If FCS failed: count as failure + print FAILED line.
            if not fcs_ok:
                self.stats.add_failure("FCS")
                if self.verbose:
                    self._print_frame_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
                else:
                    self._print_compact_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
                print("CHECKSUM: Checksum FAILED - FCS")
                return

            # Record success
            bssid = roles.get("bssid")
            self.stats.add_success(frame_type_str, ssid=ssid, macs=macs_in_frame, bssid=bssid)

            # Print frame summary
            if self.verbose:
                self._print_frame_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)
            else:
                self._print_compact_summary(data, fc_info, roles, snr_db, cfo_hz, ssid)

            print("CHECKSUM: Checksum PASSED")

            # Write to PCAP (only good frames)
            self.pcap.write_packet(
                data,
                timestamp=time.time(),
                center_freq_hz=self.center_freq_hz,
                rssi_dbm=None,
                noise_dbm=None,
                antenna=None,
            )

        except Exception as e:
            self.stats.add_failure(f"Exception: {str(e)[:50]}")
            print(f"CHECKSUM: Checksum FAILED - {str(e)[:50]}")
            if self.verbose:
                import traceback
                traceback.print_exc()

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
        self.freq = 5.89e9
        self.chan_est = ieee802_11.LS

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

        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 2, False, False)
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
        self.connect((self.blocks_delay_0_0, 0), (self.ieee802_11_sync_short_0, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_xx_0, 0), (self.blocks_moving_average_xx_1, 0))
        self.connect((self.blocks_moving_average_xx_1, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.blocks_moving_average_xx_1, 0), (self.ieee802_11_sync_short_0, 1))
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_divide_xx_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_moving_average_xx_0, 0))
        self.connect((self.blocks_moving_average_xx_0, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.blocks_divide_xx_0, 0), (self.ieee802_11_sync_short_0, 2))

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
    return parser


def main(top_block_cls=wifi_rx_file, options=None):
    if options is None:
        options = argument_parser().parse_args()

    verbose = not options.compact

    print("=" * 80)
    print("gr-ieee802-11 WiFi Receiver v11 UPDATED - Real FCS Pass/Fail + Full-File Run")
    print("=" * 80)
    print(f"Input:  {options.input_file}")
    print(f"Output: {options.output_pcap}")
    print(f"Mode:   {'Verbose' if verbose else 'Compact'}")
    if options.freq_offset != 0.0:
        print(f"Freq offset correction: {options.freq_offset} Hz")
    print("=" * 80)
    print()

    tb = top_block_cls(
        filename=options.input_file,
        output_pcap=options.output_pcap,
        freq_offset=float(options.freq_offset),
        verbose=verbose,
    )

    def sig_handler(sig=None, frame=None):
        try:
            tb.stop()
            tb.wait()
        finally:
            tb.msg_handler.stats.print_summary()
            tb.pcap.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print("Processing file until EOF (Ctrl-C to stop)...\n")

    try:
        tb.run()  # IMPORTANT: run to EOF
    except KeyboardInterrupt:
        pass

    tb.msg_handler.stats.print_summary()
    tb.pcap.close()

    print()
    print("=" * 80)
    print("✓ Processing complete!")
    print(f"✓ Handler saw {tb.msg_handler.packet_count} PDUs (good+bad if published)")
    print(f"✓ Written Radiotap PCAP to: {options.output_pcap}")
    print("=" * 80)


if __name__ == "__main__":
    main()

