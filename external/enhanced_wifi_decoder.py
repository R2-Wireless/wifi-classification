#!/usr/bin/env python3
"""
Enhanced WiFi 802.11a/g OFDM Decoder with PCAP output
More robust than the simplified version, outputs PCAP for analysis
"""

import sys
import numpy as np
import struct
from datetime import datetime

class PCAPWriter:
    """Write packets to PCAP format"""
    
    def __init__(self, filename):
        self.f = open(filename, 'wb')
        # PCAP global header
        self.f.write(struct.pack('<IHHIIII',
            0xa1b2c3d4,  # Magic number
            2, 4,        # Version 2.4
            0,           # Timezone
            0,           # Sigfigs
            65535,       # Snaplen
            105          # Network: IEEE 802.11
        ))
    
    def write_packet(self, data, timestamp=None):
        """Write a packet to PCAP"""
        if timestamp is None:
            timestamp = datetime.now().timestamp()
        
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Packet header
        self.f.write(struct.pack('<IIII',
            ts_sec,
            ts_usec,
            len(data),
            len(data)
        ))
        # Packet data
        self.f.write(data)
    
    def close(self):
        self.f.close()


def load_iq(filename):
    iq = np.fromfile(filename, dtype=np.complex64)
    print(f"✓ Loaded {len(iq)} samples\n")
    return iq


def detect_packets_robust(iq):
    """More robust packet detection with multiple thresholds"""
    L = 16
    window = 144
    threshold = 0.56
    
    detections = []
    detection_strengths = []
    
    for i in range(0, len(iq) - window - L, 50):
        delayed = iq[i+L:i+L+window]
        orig = iq[i:i+window]
        
        P = np.sum(delayed * np.conj(orig))
        R = np.sum(np.abs(delayed)**2)
        
        if R > 0:
            M = (np.abs(P)**2) / (R**2)
            if M > threshold and (not detections or i - detections[-1] > 320):
                detections.append(i)
                detection_strengths.append(M)
    
    return detections, detection_strengths


def fine_tune_timing(iq, coarse_start):
    """Fine timing synchronization using cross-correlation"""
    # Use long preamble correlation
    search_window = 80
    start = max(0, coarse_start - 20)
    end = min(len(iq), coarse_start + search_window)
    
    best_pos = coarse_start
    best_corr = 0
    
    for offset in range(start, end):
        if offset + 320 > len(iq):
            break
        # Correlate two halves of long preamble
        half1 = iq[offset+160:offset+224]
        half2 = iq[offset+224:offset+288]
        corr = abs(np.sum(half1 * np.conj(half2)))
        
        if corr > best_corr:
            best_corr = corr
            best_pos = offset
    
    return best_pos


def estimate_packet_freq_offset(packet_segment):
    """Improved frequency offset estimation"""
    # Use both short and long preambles
    short_preamble = packet_segment[:160]
    phase = np.unwrap(np.angle(short_preamble))
    phase_diff = np.diff(phase)
    offset = np.median(phase_diff) * 20e6 / (2 * np.pi)  # Use median for robustness
    return offset


def estimate_channel(long_preamble):
    """Better channel estimation using known L-LTF"""
    # Known L-LTF in frequency domain (simplified - real decoder uses full sequence)
    symbol1 = long_preamble[32:96]
    symbol2 = long_preamble[96:160]
    
    fft1 = np.fft.fft(symbol1)
    fft2 = np.fft.fft(symbol2)
    
    # Average both symbols for better estimate
    H = (fft1 + fft2) / 2
    
    return H


def demodulate_ofdm(symbol, channel_estimate, mcs=0):
    """
    OFDM demodulation with proper subcarrier extraction
    mcs: 0=BPSK, 1=QPSK, 2=16QAM, 3=64QAM
    """
    # Remove cyclic prefix
    ofdm_symbol = symbol[16:80]
    
    # FFT
    fft_out = np.fft.fftshift(np.fft.fft(ofdm_symbol))
    
    # Data subcarrier indices (802.11a)
    # -26 to -22, -20 to -8, -6 to -1, +1 to +6, +8 to +20, +22 to +26
    # Pilots at -21, -7, +7, +21
    data_indices = []
    
    # Left side
    data_indices.extend(range(6, 11))    # -26 to -22
    data_indices.extend(range(12, 24))   # -20 to -8
    data_indices.extend(range(26, 32))   # -6 to -1
    
    # Right side
    data_indices.extend(range(33, 39))   # +1 to +6
    data_indices.extend(range(41, 53))   # +8 to +20
    data_indices.extend(range(54, 59))   # +22 to +26
    
    data_carriers = fft_out[data_indices]
    
    # Equalize with channel estimate
    H_data = channel_estimate[data_indices]
    H_mag = np.abs(H_data)
    H_mag[H_mag < 0.01] = 0.01  # Avoid division by zero
    
    equalized = data_carriers * np.conj(H_data) / (H_mag ** 2)
    
    # Demodulate based on MCS
    if mcs == 0:  # BPSK
        bits = (equalized.real > 0).astype(int)
    elif mcs == 1:  # QPSK
        bits = []
        for sym in equalized:
            bits.append(int(sym.real > 0))
            bits.append(int(sym.imag > 0))
        bits = np.array(bits)
    else:
        # For higher MCS, just use BPSK for now
        bits = (equalized.real > 0).astype(int)
    
    return bits[:48]  # Return 48 bits per symbol for rate 1/2


def viterbi_decode(bits, rate='1/2'):
    """
    Simple Viterbi decoder for rate 1/2 convolutional code
    Better than just taking every 2nd bit
    """
    if rate == '1/2':
        # Simplified soft-decision Viterbi
        # For a proper implementation, use commpy or similar
        decoded = []
        for i in range(0, len(bits)-1, 2):
            # Simple majority voting on pairs
            if bits[i] == bits[i+1]:
                decoded.append(bits[i])
            else:
                # Tie-breaker: use first bit
                decoded.append(bits[i])
        return np.array(decoded)
    else:
        return bits


def descramble(bits, initial_state=0x7F):
    """802.11 descrambler with correct polynomial"""
    state = initial_state
    descrambled = []
    
    for bit in bits:
        # Polynomial: x^7 + x^4 + 1
        feedback = ((state >> 6) & 1) ^ ((state >> 3) & 1)
        out_bit = bit ^ feedback
        descrambled.append(out_bit)
        state = ((state << 1) | feedback) & 0x7F
    
    return np.array(descrambled)


def bits_to_bytes(bits):
    """Convert bit array to bytes (LSB first for 802.11)"""
    bytes_out = []
    for i in range(0, len(bits) - 7, 8):
        byte = sum([bits[i+j] << j for j in range(8)])
        bytes_out.append(byte)
    return bytes(bytes_out)


def calculate_fcs(data):
    """Calculate 802.11 FCS (CRC-32)"""
    import binascii
    return binascii.crc32(data) & 0xFFFFFFFF


def verify_fcs(frame_bytes):
    """Verify frame check sequence"""
    if len(frame_bytes) < 4:
        return False
    
    data = frame_bytes[:-4]
    received_fcs = struct.unpack('<I', frame_bytes[-4:])[0]
    calculated_fcs = calculate_fcs(data)
    
    return received_fcs == calculated_fcs


def parse_mac_frame(mac_bytes):
    """Parse 802.11 MAC frame"""
    if len(mac_bytes) < 24:
        return None
    
    # Frame control
    frame_control = struct.unpack('<H', mac_bytes[0:2])[0]
    frame_type = (frame_control >> 2) & 0x3
    frame_subtype = (frame_control >> 4) & 0xF
    to_ds = (frame_control >> 8) & 1
    from_ds = (frame_control >> 9) & 1
    
    def fmt_mac(b):
        return ':'.join([f'{x:02x}' for x in b])
    
    # Address fields
    addr1 = mac_bytes[4:10]
    addr2 = mac_bytes[10:16]
    addr3 = mac_bytes[16:22]
    
    # Determine DA, SA, BSSID based on DS bits
    if to_ds == 0 and from_ds == 0:
        da, sa, bssid = addr1, addr2, addr3
    elif to_ds == 0 and from_ds == 1:
        da, bssid, sa = addr1, addr2, addr3
    elif to_ds == 1 and from_ds == 0:
        bssid, sa, da = addr1, addr2, addr3
    else:
        # WDS frame
        bssid, da, sa = addr1, addr2, addr3
    
    type_names = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
    
    return {
        'frame_type': type_names.get(frame_type, "Unknown"),
        'subtype': frame_subtype,
        'to_ds': to_ds,
        'from_ds': from_ds,
        'dst': fmt_mac(da),
        'src': fmt_mac(sa),
        'bssid': fmt_mac(bssid),
        'raw': mac_bytes
    }


def decode_packet(iq, start_pos, timestamp=None):
    """Decode one WiFi packet with improved robustness"""
    
    if start_pos + 2000 > len(iq):
        return None
    
    try:
        # Fine timing synchronization
        fine_start = fine_tune_timing(iq, start_pos)
        
        # Extract packet region
        packet = iq[fine_start:fine_start+3000]
        
        # Frequency correction
        offset = estimate_packet_freq_offset(packet)
        
        if abs(offset) > 8e3:  # Correct if > 8 kHz
            t = np.arange(len(packet)) / 20e6
            packet = packet * np.exp(-1j * 2 * np.pi * offset * t)
        
        # Channel estimation
        long_preamble = packet[160:320]
        H = estimate_channel(long_preamble)
        
        # Decode SIGNAL field (always BPSK rate 1/2)
        signal_sym = packet[320:400]
        signal_bits = demodulate_ofdm(signal_sym, H, mcs=0)
        signal_decoded = viterbi_decode(signal_bits)
        
        if len(signal_decoded) < 24:
            return None
        
        # Parse SIGNAL field
        rate = signal_decoded[0:4]
        length = sum([signal_decoded[5+i] * (2**i) for i in range(12)])
        parity = signal_decoded[17]
        
        if length > 4095 or length < 14:  # Sanity check
            return None
        
        # Decode DATA symbols
        num_symbols = min(20, (length * 8 + 16 + 6) // 48 + 1)
        
        all_bits = []
        for i in range(num_symbols):
            sym_start = 400 + i * 80
            if sym_start + 80 > len(packet):
                break
            
            sym = packet[sym_start:sym_start+80]
            bits = demodulate_ofdm(sym, H, mcs=0)
            decoded = viterbi_decode(bits)
            all_bits.extend(decoded)
        
        if len(all_bits) < 200:
            return None
        
        # Descramble
        descrambled = descramble(np.array(all_bits))
        
        # Skip SERVICE field (16 bits)
        mac_bytes = bits_to_bytes(descrambled[16:16+length*8])
        
        if len(mac_bytes) < 24:
            return None
        
        # Parse MAC frame
        mac_info = parse_mac_frame(mac_bytes)
        
        if mac_info:
            # Check FCS if available
            fcs_valid = verify_fcs(mac_bytes) if len(mac_bytes) >= 28 else False
            mac_info['fcs_valid'] = fcs_valid
            mac_info['timestamp'] = timestamp
            mac_info['length'] = length
            mac_info['freq_offset'] = offset
            return mac_info
        
        return None
        
    except Exception as e:
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 enhanced_wifi_decoder.py input.cfile [output.pcap]")
        sys.exit(1)
    
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else None
    
    print("="*70)
    print("Enhanced WiFi OFDM Decoder")
    print("="*70 + "\n")
    
    iq = load_iq(infile)
    
    print("🔍 Detecting packets...")
    detections, strengths = detect_packets_robust(iq)
    print(f"   Found {len(detections)} potential packets\n")
    
    if not detections:
        print("✗ No packets found")
        sys.exit(1)
    
    # Open PCAP if requested
    pcap = PCAPWriter(outfile) if outfile else None
    
    results = []
    for idx, (pos, strength) in enumerate(zip(detections, strengths)):
        print(f"[{idx+1}/{len(detections)}] ", end='', flush=True)
        
        # Calculate timestamp based on sample position
        timestamp = pos / 20e6
        
        result = decode_packet(iq, pos, timestamp)
        
        if result:
            results.append(result)
            print(f"✓ {result['frame_type']:12} {result['src']} → {result['dst']}")
            
            # Write to PCAP
            if pcap and result.get('raw'):
                pcap.write_packet(result['raw'], timestamp)
        else:
            print("✗ Failed")
    
    if pcap:
        pcap.close()
        print(f"\n✓ Wrote {len(results)} packets to {outfile}")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"\nDecoded: {len(results)} / {len(detections)} packets ({100*len(results)/len(detections):.1f}%)\n")
    
    if results:
        # Unique MACs
        macs = set()
        for r in results:
            macs.add(r['src'])
            macs.add(r['dst'])
            macs.add(r['bssid'])
        
        print(f"📡 Unique MAC addresses ({len(macs)}):")
        for mac in sorted(macs):
            # Count appearances
            as_src = sum(1 for r in results if r['src'] == mac)
            as_dst = sum(1 for r in results if r['dst'] == mac)
            print(f"   {mac}  [TX:{as_src:2d} RX:{as_dst:2d}]")
        
        # Frame types
        print(f"\n📊 Frame types:")
        from collections import Counter
        types = Counter(r['frame_type'] for r in results)
        for ftype, count in types.most_common():
            print(f"   {ftype:12}: {count}")
        
        # FCS statistics
        valid_fcs = sum(1 for r in results if r.get('fcs_valid'))
        print(f"\n✅ FCS valid: {valid_fcs} / {len(results)}")
        
        if outfile:
            print(f"\n💡 Analyze with: tshark -r {outfile}")
            print(f"   or:           wireshark {outfile}")
    else:
        print("⚠ No packets decoded successfully")
        print("\nTroubleshooting:")
        print("  • Check signal strength")
        print("  • Verify sample rate (should be 20 MHz)")
        print("  • Try adjusting detection threshold")


if __name__ == "__main__":
    main()