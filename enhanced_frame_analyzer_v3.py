#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Batch WiFi .cfile MAC Address Analyzer - ENHANCED WITH CONSTELLATION DETECTION

VERSION: v3.0 - CONSTELLATION/MODULATION TRACKING (2026-02-08)
- NEW: Added "Constellation" column to per_frame_detail.csv showing modulation scheme
- Constellation types: BPSK, QPSK, 16-QAM, 64-QAM
- Works in both compact and verbose modes
- Parses constellation from frame metadata provided by gr-ieee802-11

PREVIOUS VERSION NOTES:
v2.2 - ROBUST BULLET-STYLE PARSING (2026-02-05)
- FIX: Robust parsing of verbose address bullets
- RESULT: BSSID, TX_MAC, Addr1-4 are consistently populated in verbose mode.
v2.1 - FIXED ADDR1-4 IN COMPACT MODE (2025-02-03)
"""

import os
import sys
import subprocess
import tempfile
import re
import csv
from pathlib import Path
from collections import defaultdict
from argparse import ArgumentParser
import time


class OUIDatabase:
    def __init__(self):
        self.oui_map = self._load_oui_database()

    def _load_oui_database(self):
        """Load OUI database from Wireshark manuf file"""
        oui_map = {}

        possible_paths = [
            "/usr/share/wireshark/manuf",
            "/usr/local/share/wireshark/manuf",
            "/opt/wireshark/manuf",
            os.path.expanduser("~/.wireshark/manuf"),
        ]

        manuf_file = None
        for path in possible_paths:
            if os.path.exists(path):
                manuf_file = path
                break

        if not manuf_file:
            print("⚠️  Warning: Wireshark manuf database not found. Vendor lookup disabled.")
            return oui_map

        try:
            with open(manuf_file, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue

                    mac_prefix = parts[0].upper()

                    if "/" in mac_prefix:
                        continue

                    oui_pattern = r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$"
                    if re.match(oui_pattern, mac_prefix):
                        vendor_info = parts[1].split("\t")[0]
                        oui_map[mac_prefix] = vendor_info
        except Exception as e:
            print(f"Error loading OUI database: {e}")

        return oui_map

    def lookup_vendor(self, mac_address):
        """Look up vendor for a MAC address"""
        if not mac_address or not self.oui_map:
            return None

        oui = ":".join(mac_address.upper().split(":")[:3])
        vendor = self.oui_map.get(oui)

        # Check if it's a locally administered address
        if not vendor and mac_address:
            first_octet = int(mac_address.split(":")[0], 16)
            if first_octet & 0x02:  # locally administered bit
                return "Locally Administered"

        return vendor

    def classify_device(self, vendor):
        """Classify device type based on vendor"""
        if not vendor:
            return "Unknown Device"

        vendor_lower = vendor.lower()

        if vendor == "Locally Administered":
            return "🔒 Randomized/Private MAC"

        drone_keywords = ["dji", "parrot", "yuneec", "autel", "skydio"]
        if any(x in vendor_lower for x in drone_keywords):
            return "🚁 Drone"

        elif any(
            x in vendor_lower
            for x in [
                "cisco",
                "linksys",
                "netgear",
                "tp-link",
                "tplink",
                "asus",
                "d-link",
                "ubiquiti",
                "mikrotik",
                "aruba",
            ]
        ):
            return "📡 WiFi Router/AP"

        elif any(
            x in vendor_lower
            for x in [
                "apple",
                "samsung",
                "huawei",
                "xiaomi",
                "oppo",
                "vivo",
                "oneplus",
                "google",
                "motorola",
                "lg",
            ]
        ):
            return "📱 Mobile Device"

        elif any(x in vendor_lower for x in ["dell", "lenovo", "hp", "acer", "microsoft"]):
            return "💻 Computer/Laptop"

        elif any(x in vendor_lower for x in ["raspberry", "arduino", "espressif", "texas instruments"]):
            return "🔧 IoT/Embedded"

        elif any(x in vendor_lower for x in ["intel", "broadcom", "qualcomm", "realtek", "ralink"]):
            return "🔌 Network Interface"

        else:
            return "📶 WiFi Device"


class FrameParser:
    """Parse individual frame data from log output"""
    
    @staticmethod
    def _encoding_to_constellation(encoding: int) -> str:
        """Map 802.11a/g encoding value to constellation type
        
        Encoding | Data Rate | Modulation | Coding Rate
        ---------|-----------|------------|------------
        0        | 6 Mbit/s  | BPSK       | 1/2
        1        | 9 Mbit/s  | BPSK       | 3/4
        2        | 12 Mbit/s | QPSK       | 1/2
        3        | 18 Mbit/s | QPSK       | 3/4
        4        | 24 Mbit/s | 16-QAM     | 1/2
        5        | 36 Mbit/s | 16-QAM     | 3/4
        6        | 48 Mbit/s | 64-QAM     | 2/3
        7        | 54 Mbit/s | 64-QAM     | 3/4
        """
        if encoding in [0, 1]:
            return "BPSK"
        elif encoding in [2, 3]:
            return "QPSK"
        elif encoding in [4, 5]:
            return "16-QAM"
        elif encoding in [6, 7]:
            return "64-QAM"
        else:
            return f"UNKNOWN({encoding})"

    @staticmethod
    def parse_frames(log_lines):
        """Extract detailed information for each frame including all MAC addresses

        Handles both compact and verbose output formats:
        - Compact: [  1] Beacon   tx → bssid  SNR:...
        - Verbose: FRAME #1 SUMMARY with detailed breakdown
        """
        frames = []
        current_frame = None
        in_frame_block = False
        pending_encoding = None  # Store encoding from frame_equalizer line

        # Helper: parse bullet-style MAC lines like:
        # "  • BSSID     : xx:xx:xx:xx:xx:xx"
        # "  • TA        : xx:xx:xx:xx:xx:xx"
        # "  • RA        : xx:xx:xx:xx:xx:xx"
        # "  • ADDR1     : xx:xx:xx:xx:xx:xx  [vendor]"
        def _bullet_mac(label: str, line: str):
            # accepts bullets • or * and arbitrary spacing before colon
            m = re.search(
                rf"(?:•|\*)\s*{re.escape(label)}\s*:\s*([0-9a-fA-F:]{{17}})",
                line,
            )
            return m.group(1).lower() if m else None

        for line in log_lines:
            # Check for frame_equalizer encoding line (appears before frame summary)
            # Example: "frame_equalizer :info: encoding: 5 - length: 1047 - symbols: 59"
            encoding_match = re.search(r"frame_equalizer.*?encoding:\s*(\d+)", line)
            if encoding_match:
                encoding_val = int(encoding_match.group(1))
                pending_encoding = FrameParser._encoding_to_constellation(encoding_val)
                continue
            
            # Detect verbose format: FRAME #N SUMMARY
            verbose_frame_match = re.match(r"FRAME #(\d+) SUMMARY", line)
            if verbose_frame_match:
                frame_num = int(verbose_frame_match.group(1))
                in_frame_block = True
                current_frame = {
                    "frame_num": frame_num,
                    "frame_type": None,
                    "tx_mac": None,
                    "bssid": None,
                    "snr_db": None,
                    "cfo_hz": None,
                    "size_bytes": None,
                    "ssid": None,
                    "checksum_passed": None,
                    "macs": set(),
                    "addr1": None,
                    "addr2": None,
                    "addr3": None,
                    "addr4": None,
                    "ds_direction": None,
                    "retry_flag": None,
                    "protected_flag": None,
                    "constellation": pending_encoding,  # Use the encoding from frame_equalizer
                }
                frames.append(current_frame)
                pending_encoding = None  # Reset after using
                continue

            # Detect compact format (without constellation in output line)
            compact_match = re.match(
                r"\[\s*(\d+)\]\s+(\S+.*?)\s+([0-9a-fA-F:]{17})\s+→\s+([0-9a-fA-F:]{17})\s+"
                r"SNR:\s*(-?\d+\.?\d*)\s*dB\s+Off:\s*([+-]?\d+\.?\d*)\s*kHz\s+"
                r"(\d+)B(?:\s+SSID=\'([^\']*)\')?",
                line,
                re.IGNORECASE,
            )

            if compact_match:
                frame_num = int(compact_match.group(1))
                frame_type = compact_match.group(2).strip()
                tx_mac = compact_match.group(3).lower()
                bssid = compact_match.group(4).lower()
                snr = float(compact_match.group(5))
                cfo = float(compact_match.group(6)) * 1000  # kHz -> Hz
                size = int(compact_match.group(7))
                ssid = compact_match.group(8) if compact_match.group(8) else None
                
                # Constellation comes from pending_encoding (from frame_equalizer log)
                constellation = pending_encoding

                current_frame = {
                    "frame_num": frame_num,
                    "frame_type": frame_type,
                    "tx_mac": tx_mac,
                    "bssid": bssid,
                    "snr_db": snr,
                    "cfo_hz": cfo,
                    "size_bytes": size,
                    "ssid": ssid,
                    "checksum_passed": None,
                    "macs": set([tx_mac, bssid]),
                    "addr1": bssid,
                    "addr2": tx_mac,
                    "addr3": bssid,
                    "addr4": "",
                    "ds_direction": "Compact",
                    "retry_flag": False,
                    "protected_flag": False,
                    "constellation": constellation,
                }
                frames.append(current_frame)
                pending_encoding = None  # Reset after using
                in_frame_block = False
                continue

            # Parse verbose frame details
            if current_frame and in_frame_block:
                # Size
                size_match = re.search(r"Size:\s*(\d+)\s*bytes", line)
                if size_match:
                    current_frame["size_bytes"] = int(size_match.group(1))

                # Frame type
                type_match = re.search(r"Type/Subtype:\s*(.+?)\s*/\s*(.+)", line)
                if type_match:
                    current_frame["frame_type"] = type_match.group(2).strip()

                # DS Direction
                ds_match = re.search(r"DS Direction:\s*(.+)", line)
                if ds_match:
                    current_frame["ds_direction"] = ds_match.group(1).strip()

                # SNR
                snr_match = re.search(r"SNR:\s*(-?\d+\.?\d*)\s*dB", line)
                if snr_match:
                    current_frame["snr_db"] = float(snr_match.group(1))

                # CFO
                cfo_match = re.search(r"CFO:\s*([+-]?\d+\.?\d*)\s*Hz", line)
                if cfo_match:
                    current_frame["cfo_hz"] = float(cfo_match.group(1))
                
                # Constellation
                const_match = re.search(r"Constellation:\s*(\S+)", line)
                if const_match:
                    current_frame["constellation"] = const_match.group(1)

                # --- Robust bullet-style parsing of addresses ---
                # Prefer explicit ADDR fields when present
                a1 = _bullet_mac("ADDR1", line)
                a2 = _bullet_mac("ADDR2", line)
                a3 = _bullet_mac("ADDR3", line)
                a4 = _bullet_mac("ADDR4", line)

                if a1:
                    current_frame["addr1"] = a1
                    current_frame["macs"].add(a1)

                if a2:
                    current_frame["addr2"] = a2
                    current_frame["tx_mac"] = current_frame["tx_mac"] or a2
                    current_frame["macs"].add(a2)

                if a3:
                    current_frame["addr3"] = a3
                    current_frame["macs"].add(a3)

                if a4:
                    current_frame["addr4"] = a4
                    current_frame["macs"].add(a4)

                # TA/RA/SA/DA/BSSID bullets (some outputs print TA/RA, others SA/DA)
                ta = _bullet_mac("TA", line) or _bullet_mac("SA", line)
                ra = _bullet_mac("RA", line) or _bullet_mac("DA", line)
                b = _bullet_mac("BSSID", line)

                if ta:
                    current_frame["tx_mac"] = current_frame["tx_mac"] or ta
                    current_frame["addr2"] = current_frame["addr2"] or ta
                    current_frame["macs"].add(ta)

                if ra:
                    current_frame["addr1"] = current_frame["addr1"] or ra
                    current_frame["macs"].add(ra)

                if b:
                    current_frame["bssid"] = b
                    current_frame["addr3"] = current_frame["addr3"] or b
                    current_frame["macs"].add(b)

                # Fallback: match non-bullet "BSSID     : xx:.." too
                if not current_frame.get("bssid"):
                    m = re.search(r"BSSID\s*:\s*([0-9a-fA-F:]{17})", line, re.IGNORECASE)
                    if m:
                        b2 = m.group(1).lower()
                        current_frame["bssid"] = b2
                        current_frame["addr3"] = current_frame["addr3"] or b2
                        current_frame["macs"].add(b2)

                # SSID
                ssid_match = re.search(r"SSID:\s*'([^']*)'", line)
                if ssid_match:
                    current_frame["ssid"] = ssid_match.group(1)

            # Check checksum status (works for both formats)
            if current_frame and current_frame["checksum_passed"] is None:
                if "Checksum PASSED" in line or "CHECKSUM: Checksum PASSED" in line:
                    current_frame["checksum_passed"] = True
                elif "Checksum FAILED" in line or "CHECKSUM: Checksum FAILED" in line:
                    current_frame["checksum_passed"] = False

        return frames


class OutputParser:
    """Parse output from the main decoder script"""

    @staticmethod
    def extract_macs(log_lines):
        """Extract all MAC addresses from log lines"""
        mac_addresses = set()
        mac_pattern = r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})"

        for line in log_lines:
            matches = re.finditer(mac_pattern, line.lower())
            for match in matches:
                mac = match.group(1)
                if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                    mac_addresses.add(mac)

        return mac_addresses

    @staticmethod
    def extract_ssids(log_lines):
        """Extract SSIDs from log output. Returns dict: bssid -> ssid"""
        ssids = {}

        compact_pattern = r"\[\s*\d+\]\s+.*?\s([0-9a-f:]{17})\s+→\s+([0-9a-f:]{17}).*?ssid='([^']*)'"

        verbose_bssid_pattern = r"bssid:\s*([0-9a-f:]{17})"
        verbose_ssid_pattern = r"SSID:\s*'([^']*)'"

        current_bssid = None

        for line in log_lines:
            line_l = line.lower()

            m = re.search(compact_pattern, line_l, re.IGNORECASE)
            if m:
                bssid = m.group(2)
                ssid = m.group(3)
                if ssid:
                    ssids[bssid] = ssid

            m = re.search(verbose_bssid_pattern, line_l)
            if m:
                current_bssid = m.group(1)

            m = re.search(verbose_ssid_pattern, line)
            if m and current_bssid:
                ssids[current_bssid] = m.group(1)

        return ssids

    @staticmethod
    def parse_stats(log_lines):
        """Parse frame statistics from the output"""
        stats = {
            "frames_total": 0,
            "frames_passed": 0,
            "frames_failed": 0,
            "snr_stats": {},
            "cfo_stats": {},
        }

        for line in log_lines:
            if "Handler saw" in line:
                match = re.search(r"Handler saw (\d+) PDUs", line)
                if match:
                    stats["frames_total"] = int(match.group(1))

            if "Checksum PASSED" in line:
                stats["frames_passed"] += 1
            elif "Checksum FAILED" in line:
                stats["frames_failed"] += 1

        return stats


class FileProcessor:
    """Process individual .cfile and extract information"""

    def __init__(self, main_script_path, oui_db, use_compact=True, dump_bin=False, dump_dir=None):
        self.main_script = main_script_path
        self.oui_db = oui_db
        self.use_compact = use_compact
        self.dump_bin = dump_bin
        self.dump_dir = dump_dir

    @staticmethod
    def _safe_name(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", name)

    def _build_dump_env(self, cfile_path: str):
        if not self.dump_bin:
            return None, None

        cfile = Path(cfile_path)
        parent = self._safe_name(cfile.parent.name)
        stem = self._safe_name(cfile.stem)
        prefix = f"{parent}__{stem}"

        dump_root = Path(self.dump_dir if self.dump_dir else cfile.parent / "dumps")
        dump_root.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env["WIFI_DUMP_CORR"] = "1"
        env["WIFI_DUMP_SHORT_COR_PATH"] = str(dump_root / f"{prefix}_short_cor.bin")
        env["WIFI_DUMP_SHORT_ABS_PATH"] = str(dump_root / f"{prefix}_short_abs.bin")
        env["WIFI_DUMP_SHORT_DET_PATH"] = str(dump_root / f"{prefix}_short_det.bin")
        env["WIFI_DUMP_SHORT_DET_META_PATH"] = str(dump_root / f"{prefix}_short_det_meta.bin")
        env["WIFI_DUMP_SHORT_COPY_REGIONS_PATH"] = str(
            dump_root / f"{prefix}_short_copy_regions.txt"
        )
        env["WIFI_DUMP_LONG_MAG_PATH"] = str(dump_root / f"{prefix}_long_mag.bin")
        env["WIFI_DUMP_LONG_CPLX_PATH"] = str(dump_root / f"{prefix}_long_cplx.bin")
        env["WIFI_DUMP_LONG_DET_PATH"] = str(dump_root / f"{prefix}_long_det.bin")
        env["WIFI_DUMP_LONG_DET_META_PATH"] = str(dump_root / f"{prefix}_long_det_meta.bin")
        return env, dump_root

    def process_file(self, cfile_path, timeout=30):
        """Process a single .cfile and return analysis results"""

        filename = os.path.basename(cfile_path)
        parent_dir = os.path.basename(os.path.dirname(cfile_path))
        print(f"📁 Processing: {parent_dir}/{filename}")
        proc_env, dump_root = self._build_dump_env(cfile_path)
        if self.dump_bin and dump_root is not None:
            print(f"  🧪 Dump bin enabled: {dump_root}")

        result = {
            "filename": filename,
            "filepath": cfile_path,
            "parent_dir": parent_dir,
            "macs": set(),
            "ssids": {},
            "frames": [],
            "frames_total": 0,
            "frames_passed": 0,
            "frames_failed": 0,
            "snr_stats": {},
            "cfo_stats": {},
            "device_types": {},
            "vendors": {},
            "error": None,
        }

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
            pcap_path = tmp_pcap.name

        try:
            cmd = ["python3", self.main_script, cfile_path, pcap_path]

            if hasattr(self, "use_compact") and self.use_compact:
                cmd.append("--compact")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=proc_env,
            )

            output_lines = []
            try:
                for line in proc.stdout:
                    output_lines.append(line.rstrip("\n"))

                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                result["error"] = f"Timeout after {timeout}s"
                print("  ⚠️  Timeout")
                return result

            if proc.returncode != 0 and proc.returncode != -15:
                result["error"] = f"Exit code {proc.returncode}"
                print(f"  ⚠️  Non-zero exit: {proc.returncode}")

            frames = FrameParser.parse_frames(output_lines)
            result["frames"] = frames

            total_checksum_lines = sum(
                1 for line in output_lines if "Checksum PASSED" in line or "Checksum FAILED" in line
            )
            if total_checksum_lines > len(frames):
                print(
                    f"  ⚠️  Warning: Found {total_checksum_lines} checksum lines "
                    f"but only parsed {len(frames)} frames"
                )

            for frame in frames:
                result["macs"].update(frame["macs"])

            result["ssids"] = OutputParser.extract_ssids(output_lines)

            result["frames_total"] = len(frames)
            result["frames_passed"] = sum(1 for f in frames if f.get("checksum_passed") is True)
            result["frames_failed"] = sum(1 for f in frames if f.get("checksum_passed") is False)

            snr_values = [f["snr_db"] for f in frames if f.get("snr_db") is not None]
            cfo_values = [f["cfo_hz"] for f in frames if f.get("cfo_hz") is not None]

            if snr_values:
                result["snr_stats"] = {
                    "snr_avg": sum(snr_values) / len(snr_values),
                    "snr_min": min(snr_values),
                    "snr_max": max(snr_values),
                }

            if cfo_values:
                result["cfo_stats"] = {
                    "cfo_avg": sum(cfo_values) / len(cfo_values),
                    "cfo_min": min(cfo_values),
                    "cfo_max": max(cfo_values),
                }

            for mac in result["macs"]:
                vendor = self.oui_db.lookup_vendor(mac)
                result["vendors"][mac] = vendor if vendor else "Unknown"
                result["device_types"][mac] = self.oui_db.classify_device(vendor)

            drone_count = sum(
                1 for mac in result["macs"] if "🚁" in result["device_types"].get(mac, "")
            )

            print(
                f"  ✅ {len(frames)} frames | {len(result['macs'])} MACs | "
                f"{len(result['ssids'])} SSIDs"
                + (f" | 🚁 {drone_count} drones" if drone_count > 0 else "")
            )

        except Exception as e:
            result["error"] = str(e)
            print(f"  ❌ Error: {e}")

        finally:
            try:
                os.unlink(pcap_path)
            except Exception:
                pass

        return result


def find_cfiles(directory, pattern="*.cfile"):
    """Recursively find all .cfile files"""
    cfiles = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".cfile"):
                cfiles.append(os.path.join(root, file))
    return sorted(cfiles)


def sanitize_csv_text(text, max_len=None):
    """Sanitize text for CSV output"""
    if text is None:
        return ""

    text = str(text)
    text = "".join(c if c.isprintable() or c in "\t\n\r" else " " for c in text)

    if max_len and len(text) > max_len:
        text = text[: max_len - 3] + "..."

    return text


def export_to_csv(results, output_dir):
    """Export all results to multiple CSV files"""

    enc = "utf-8"

    def make_writer(file_obj):
        return csv.writer(file_obj, lineterminator="\n")

    # 1) PER-FRAME DETAILS CSV
    per_frame_path = os.path.join(output_dir, "per_frame_detail.csv")

    with open(per_frame_path, "w", newline="", encoding=enc) as f:
        writer = make_writer(f)
        writer.writerow(
            [
                "Parent_Directory",
                "File",
                "Frame_Number",
                "Frame_Type",
                "TX_MAC",
                "BSSID",
                "Addr1",
                "Addr2",
                "Addr3",
                "Addr4",
                "SSID",
                "SNR_dB",
                "CFO_Hz",
                "Size_Bytes",
                "Checksum_Passed",
                "Constellation",
                "DS_Direction",
                "Retry_Flag",
                "Protected_Flag",
                "TX_Vendor",
                "TX_Device_Type",
                "BSSID_Vendor",
                "BSSID_Device_Type",
            ]
        )

        for result in results:
            parent_dir = sanitize_csv_text(result.get("parent_dir", ""), max_len=40)
            filename = sanitize_csv_text(result["filename"], max_len=60)
            vendors = result.get("vendors", {})
            device_types = result.get("device_types", {})

            for frame in result.get("frames", []):
                tx_mac = frame.get("tx_mac", "") or ""
                bssid = frame.get("bssid", "") or ""

                writer.writerow(
                    [
                        parent_dir,
                        filename,
                        frame.get("frame_num", ""),
                        sanitize_csv_text(frame.get("frame_type", ""), max_len=40),
                        tx_mac,
                        bssid,
                        frame.get("addr1", "") or "",
                        frame.get("addr2", "") or "",
                        frame.get("addr3", "") or "",
                        frame.get("addr4", "") or "",
                        sanitize_csv_text(frame.get("ssid", ""), max_len=64),
                        f"{frame.get('snr_db', 0.0):.2f}",
                        f"{frame.get('cfo_hz', 0.0):.2f}",
                        frame.get("size_bytes", ""),
                        "Yes"
                        if frame.get("checksum_passed") is True
                        else "No"
                        if frame.get("checksum_passed") is False
                        else "Unknown",
                        sanitize_csv_text(frame.get("constellation", "UNKNOWN"), max_len=20),
                        sanitize_csv_text(frame.get("ds_direction", ""), max_len=20),
                        "Yes"
                        if frame.get("retry_flag") is True
                        else "No"
                        if frame.get("retry_flag") is False
                        else "",
                        "Yes"
                        if frame.get("protected_flag") is True
                        else "No"
                        if frame.get("protected_flag") is False
                        else "",
                        sanitize_csv_text(vendors.get(tx_mac, "Unknown"), max_len=40),
                        sanitize_csv_text(device_types.get(tx_mac, "Unknown Device"), max_len=40),
                        sanitize_csv_text(vendors.get(bssid, "Unknown"), max_len=40),
                        sanitize_csv_text(device_types.get(bssid, "Unknown Device"), max_len=40),
                    ]
                )

    print(f"✅ Per-frame details exported to: {per_frame_path}")

    # 2) FILE SUMMARY CSV
    file_summary_path = os.path.join(output_dir, "file_summary.csv")

    with open(file_summary_path, "w", newline="", encoding=enc) as f:
        writer = make_writer(f)
        writer.writerow(
            [
                "Parent_Directory",
                "Filename",
                "Total_Frames",
                "Passed_Frames",
                "Failed_Frames",
                "Unique_MACs",
                "Unique_SSIDs",
                "Drone_Count",
                "Avg_SNR_dB",
                "Avg_CFO_Hz",
                "Error",
            ]
        )

        for result in results:
            drone_count = sum(
                1 for mac in result["macs"] if "🚁" in result["device_types"].get(mac, "")
            )

            snr_avg = result["snr_stats"].get("snr_avg", 0.0)
            cfo_avg = result["cfo_stats"].get("cfo_avg", 0.0)

            writer.writerow(
                [
                    sanitize_csv_text(result.get("parent_dir", ""), max_len=40),
                    sanitize_csv_text(result["filename"], max_len=80),
                    result["frames_total"],
                    result["frames_passed"],
                    result["frames_failed"],
                    len(result["macs"]),
                    len(result["ssids"]),
                    drone_count,
                    f"{snr_avg:.2f}",
                    f"{cfo_avg:.2f}",
                    sanitize_csv_text(result.get("error", ""), max_len=100),
                ]
            )

    print(f"✅ File summary exported to: {file_summary_path}")

    # 3) MAC DETAILS CSV
    mac_details_path = os.path.join(output_dir, "mac_details.csv")

    all_macs_info = {}
    for result in results:
        for mac in result["macs"]:
            if mac not in all_macs_info:
                all_macs_info[mac] = {
                    "vendor": result["vendors"].get(mac, "Unknown"),
                    "device_type": result["device_types"].get(mac, "Unknown Device"),
                    "files": set(),
                    "parent_dirs": set(),
                    "frame_count": 0,
                }
            all_macs_info[mac]["files"].add(result["filename"])
            all_macs_info[mac]["parent_dirs"].add(result.get("parent_dir", ""))
            all_macs_info[mac]["frame_count"] += sum(
                1
                for f in result.get("frames", [])
                if f.get("tx_mac") == mac or f.get("bssid") == mac
            )

    with open(mac_details_path, "w", newline="", encoding=enc) as f:
        writer = make_writer(f)
        writer.writerow(
            [
                "MAC_Address",
                "Vendor",
                "Device_Type",
                "Frame_Count",
                "File_Count",
                "Parent_Directories",
                "Files",
            ]
        )

        for mac, info in sorted(all_macs_info.items()):
            writer.writerow(
                [
                    mac,
                    sanitize_csv_text(info["vendor"], max_len=40),
                    sanitize_csv_text(info["device_type"], max_len=40),
                    info["frame_count"],
                    len(info["files"]),
                    "; ".join(sorted(info["parent_dirs"])),
                    "; ".join(sorted(info["files"])),
                ]
            )

    print(f"✅ MAC details exported to: {mac_details_path}")

    # 4) DRONE DETECTIONS CSV (if any)
    drone_macs = {mac: info for mac, info in all_macs_info.items() if "🚁" in info["device_type"]}

    drones_path = None
    if drone_macs:
        drones_path = os.path.join(output_dir, "drone_detections.csv")

        with open(drones_path, "w", newline="", encoding=enc) as f:
            writer = make_writer(f)
            writer.writerow(
                [
                    "MAC_Address",
                    "Vendor",
                    "Device_Type",
                    "Frame_Count",
                    "File_Count",
                    "Parent_Directories",
                    "Files",
                ]
            )

            for mac, info in sorted(drone_macs.items()):
                writer.writerow(
                    [
                        mac,
                        sanitize_csv_text(info["vendor"], max_len=40),
                        sanitize_csv_text(info["device_type"], max_len=40),
                        info["frame_count"],
                        len(info["files"]),
                        "; ".join(sorted(info["parent_dirs"])),
                        "; ".join(sorted(info["files"])),
                    ]
                )

        print(f"✅ Drone detections exported to: {drones_path}")

    # 5) NETWORKS SUMMARY CSV
    networks_path = os.path.join(output_dir, "networks_summary.csv")

    all_networks = {}
    for result in results:
        ssid_map = result.get("ssids") or {}
        for bssid, ssid in ssid_map.items():
            ssid_key = ssid if ssid is not None else ""
            if ssid_key not in all_networks:
                all_networks[ssid_key] = {"bssids": set(), "files": [], "parent_dirs": set()}
            all_networks[ssid_key]["bssids"].add(bssid)
            all_networks[ssid_key]["files"].append(result.get("filename", ""))
            all_networks[ssid_key]["parent_dirs"].add(result.get("parent_dir", ""))

    with open(networks_path, "w", newline="", encoding=enc) as f:
        writer = make_writer(f)
        writer.writerow(
            ["SSID", "BSSIDs", "BSSID_Count", "File_Count", "Parent_Directories", "Files"]
        )

        for ssid, info in sorted(all_networks.items(), key=lambda kv: sanitize_csv_text(kv[0]).lower()):
            writer.writerow(
                [
                    sanitize_csv_text(ssid, max_len=64),
                    "; ".join(sorted(info["bssids"])),
                    len(info["bssids"]),
                    len(info["files"]),
                    "; ".join(sorted(info["parent_dirs"])),
                    "; ".join(sorted(set(info["files"]))),
                ]
            )

    print(f"✅ Networks summary exported to: {networks_path}")

    return {
        "per_frame_details": per_frame_path,
        "file_summary": file_summary_path,
        "mac_details": mac_details_path,
        "networks": networks_path,
        "drones": drones_path,
    }


def print_summary_table(results):
    """Print a formatted table of file summary"""
    print("\n" + "=" * 160)
    print("FILE SUMMARY TABLE")
    print("=" * 160)

    header = (
        f"{'Parent Dir':<20} | {'File Name':<35} | {'Frames':<7} | {'Pass':<5} | {'Fail':<5} | "
        f"{'MACs':<5} | {'SSIDs':<6} | {'Drones':<7} | {'SNR':<8} | {'CFO':<9}"
    )
    print(header)
    print("-" * 160)

    for result in results:
        drones = sum(1 for mac in result["macs"] if "🚁" in result["device_types"].get(mac, ""))

        parent_dir = result.get("parent_dir", "")
        if len(parent_dir) > 18:
            parent_dir = parent_dir[:15] + "..."

        filename = result["filename"]
        if len(filename) > 33:
            filename = filename[:30] + "..."

        snr_avg = result["snr_stats"].get("snr_avg", 0.0)
        cfo_avg = result["cfo_stats"].get("cfo_avg", 0.0)

        row = (
            f"{parent_dir:<20} | "
            f"{filename:<35} | "
            f"{result['frames_total']:<7} | "
            f"{result['frames_passed']:<5} | "
            f"{result['frames_failed']:<5} | "
            f"{len(result['macs']):<5} | "
            f"{len(result['ssids']):<6} | "
            f"{drones:<7} | "
            f"{snr_avg:>6.1f}dB | "
            f"{cfo_avg/1000:>+6.1f}kHz"
        )

        if drones > 0:
            print(f"🚁 {row}")
        elif result["error"]:
            print(f"❌ {row}")
        else:
            print(f"   {row}")

    print("-" * 160)
    total_frames = sum(r["frames_total"] for r in results)
    total_passed = sum(r["frames_passed"] for r in results)
    total_failed = sum(r["frames_failed"] for r in results)
    total_macs = len(set(mac for r in results for mac in r["macs"]))
    total_ssids = len(set(ssid for r in results for ssid in r["ssids"].values()))

    avg_snr = sum(r["snr_stats"].get("snr_avg", 0.0) for r in results if r["snr_stats"]) / max(
        1, len([r for r in results if r["snr_stats"]])
    )
    avg_cfo = sum(r["cfo_stats"].get("cfo_avg", 0.0) for r in results if r["cfo_stats"]) / max(
        1, len([r for r in results if r["cfo_stats"]])
    )

    total_row = (
        f"{'TOTALS':<20} | "
        f"{'':<35} | "
        f"{total_frames:<7} | "
        f"{total_passed:<5} | "
        f"{total_failed:<5} | "
        f"{total_macs:<5} | "
        f"{total_ssids:<6} | "
        f"{'-':<7} | "
        f"{avg_snr:>6.1f}dB | "
        f"{avg_cfo/1000:>+6.1f}kHz"
    )
    print(total_row)
    print("=" * 160)


def print_overall_summary(results):
    """Print overall summary across all files"""

    print_summary_table(results)

    print("\n" + "=" * 80)
    print("OVERALL SUMMARY - ALL FILES")
    print("=" * 80)

    total_files = len(results)
    successful_files = sum(1 for r in results if not r["error"])
    total_frames = sum(r["frames_total"] for r in results)
    total_passed = sum(r["frames_passed"] for r in results)
    total_failed = sum(r["frames_failed"] for r in results)

    print(f"\n📁 Files Processed: {successful_files}/{total_files}")
    print(f"📊 Total Frames: {total_frames}")
    print(f"  ✅ Passed: {total_passed}")
    print(f"  ❌ Failed: {total_failed}")

    all_ssids = {}
    for result in results:
        for bssid, ssid in result["ssids"].items():
            if ssid not in all_ssids:
                all_ssids[ssid] = set()
            all_ssids[ssid].add(bssid)

    if all_ssids:
        print(f"\n📶 NETWORKS DETECTED ({len(all_ssids)}):")
        for ssid, bssids in sorted(all_ssids.items()):
            print(f"  • SSID: '{ssid}'")
            print(f"    BSSIDs: {', '.join(sorted(bssids))}")

    print("\n" + "=" * 80)


def main():
    parser = ArgumentParser(
        description="Batch process .cfile files with per-frame details and parent directory"
    )
    parser.add_argument("input_dir", help="Directory containing .cfile files")
    parser.add_argument(
        "--main-script",
        default="./main_script_14.py",
        help="Path to main_script_14.py (default: ./main_script_14.py)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Timeout per file in seconds (default: 30)")
    parser.add_argument("--pattern", default="*.cfile", help="File pattern to match (default: *.cfile)")
    parser.add_argument("--output-dir", default=None, help="Output directory for CSV files (default: input_dir)")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Run main_script in verbose mode (slower but includes Addr1-4, DS direction, flags)",
    )
    parser.add_argument(
        "--dump-bin",
        action="store_true",
        help="Enable WIFI_DUMP_CORR and write per-file dump bin files.",
    )
    parser.add_argument(
        "--dump-dir",
        default=None,
        help="Directory for dump bin files (default: <each cfile parent>/dumps).",
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"❌ Error: {args.input_dir} is not a directory")
        sys.exit(1)

    if not os.path.exists(args.main_script):
        print(f"❌ Error: Main script not found: {args.main_script}")
        sys.exit(1)

    output_dir = args.output_dir if args.output_dir else args.input_dir
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"🔍 Searching for .cfile files in: {args.input_dir}")
    cfiles = find_cfiles(args.input_dir)

    if not cfiles:
        print(f"❌ No .cfile files found in {args.input_dir}")
        sys.exit(1)

    print(f"✅ Found {len(cfiles)} .cfile file(s)")

    print("\n📚 Loading OUI database...")
    oui_db = OUIDatabase()
    print(f"✅ Loaded {len(oui_db.oui_map)} OUI entries")

    use_compact = not args.verbose
    processor = FileProcessor(
        args.main_script,
        oui_db,
        use_compact=use_compact,
        dump_bin=args.dump_bin,
        dump_dir=args.dump_dir,
    )
    results = []

    mode_str = "COMPACT" if use_compact else "VERBOSE (with full address details)"
    print(f"\n🚀 Starting batch processing in {mode_str} mode...")
    start_time = time.time()

    for i, cfile in enumerate(cfiles, 1):
        print(f"\n[{i}/{len(cfiles)}]")
        result = processor.process_file(cfile, timeout=args.timeout)
        results.append(result)

    elapsed = time.time() - start_time

    print_overall_summary(results)

    print("\n📊 Exporting results to CSV...")
    csv_files = export_to_csv(results, output_dir)

    print(f"\n⏱️  Total processing time: {elapsed:.1f}s")
    print("✅ Batch processing complete!")
    print(f"\n📁 Output files in: {output_dir}")
    print(f"   • Per-frame details: {os.path.basename(csv_files['per_frame_details'])}")
    print(f"   • File summary: {os.path.basename(csv_files['file_summary'])}")
    print(f"   • MAC details: {os.path.basename(csv_files['mac_details'])}")
    print(f"   • Networks: {os.path.basename(csv_files['networks'])}")
    if csv_files["drones"]:
        print(f"   • Drone detections: {os.path.basename(csv_files['drones'])}")


if __name__ == "__main__":
    main()
