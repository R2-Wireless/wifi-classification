#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gr-ieee802-11 WiFi Receiver with PCAP output and Debug Files
Captures decoded MAC frames and writes them to PCAP format
Optionally writes intermediate signal processing steps to debug files
"""

from gnuradio import blocks, fft, gr
from gnuradio.fft import window
import sys
import signal
import struct
import time
import os
from argparse import ArgumentParser
from datetime import datetime
import ieee802_11
import pmt

class PCAPWriter:
    """Write 802.11 frames to PCAP format"""
    
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
        self.packet_count = 0
    
    def write_packet(self, data, timestamp=None):
        """Write a packet to PCAP"""
        if timestamp is None:
            timestamp = time.time()
        
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
        self.f.flush()
        self.packet_count += 1
    
    def close(self):
        self.f.close()


class message_handler(gr.sync_block):
    """Custom block to handle messages and write to PCAP"""
    
    def __init__(self, pcap_writer):
        gr.sync_block.__init__(
            self,
            name="message_handler",
            in_sig=None,
            out_sig=None
        )
        self.pcap = pcap_writer
        self.message_port_register_in(pmt.intern('in'))
        self.set_msg_handler(pmt.intern('in'), self.handle_msg)
        self.packet_count = 0
    
    def handle_msg(self, msg):
        """Handle incoming MAC frame messages"""
        try:
            # Extract metadata and frame bytes
            meta = pmt.car(msg)
            frame_bytes = pmt.cdr(msg)
            
            # Convert PMT to bytes
            if pmt.is_u8vector(frame_bytes):
                data = bytes(pmt.u8vector_elements(frame_bytes))
            else:
                return
            
            # Extract metadata
            snr = pmt.dict_ref(meta, pmt.intern('snr'), pmt.from_double(0))
            freq_offset = pmt.dict_ref(meta, pmt.intern('frequency offset'), pmt.from_double(0))
            cfo_short = pmt.dict_ref(meta, pmt.intern('cfo short'), pmt.from_double(0))
            cfo_long = pmt.dict_ref(meta, pmt.intern('cfo long'), pmt.from_double(0))
            
            # Parse basic MAC info
            if len(data) >= 24:
                frame_control = struct.unpack('<H', data[0:2])[0]
                frame_type = (frame_control >> 2) & 0x3
                frame_subtype = (frame_control >> 4) & 0xF
                
                def fmt_mac(b):
                    return ':'.join([f'{x:02x}' for x in b])
                
                addr1 = data[4:10]
                addr2 = data[10:16]
                addr3 = data[16:22]
                
                type_names = {0: "Mgmt", 1: "Ctrl", 2: "Data"}
                
                self.packet_count += 1
                print(f"[{self.packet_count:3d}] {type_names.get(frame_type, 'Unk'):4} "
                      f"{fmt_mac(addr2)} → {fmt_mac(addr1)}  "
                      f"SNR:{pmt.to_double(snr):5.1f}dB  "
                      f"CFOd:{pmt.to_double(freq_offset)/1e3:+6.1f}kHz  "
                      f"CFOs:{pmt.to_double(cfo_short)/1e3:+6.1f}kHz  "
                      f"CFOl:{pmt.to_double(cfo_long)/1e3:+6.1f}kHz  "
                      f"{len(data):4d}B")
                
                # Write to PCAP
                self.pcap.write_packet(data)
            
        except Exception as e:
            print(f"Error handling message: {e}")
            import traceback
            traceback.print_exc()


class wifi_rx_file(gr.top_block):

    def __init__(self, filename, output_pcap, freq_offset=0, enable_debug=False):
        gr.top_block.__init__(self, "WiFi RX from File")

        ##################################################
        # Variables
        ##################################################
        self.window_size = window_size = 48
        self.sync_length = sync_length = 320
        self.samp_rate = samp_rate = 20e6
        self.freq = freq = 5.89e9
        self.chan_est = chan_est = ieee802_11.LS
        self.enable_debug = enable_debug

        ##################################################
        # Blocks
        ##################################################
        
        # PCAP writer
        self.pcap = PCAPWriter(output_pcap)
        self.msg_handler = message_handler(self.pcap)
        
        # File source - repeat so it processes multiple times
        self.blocks_file_source_0 = blocks.file_source(
            gr.sizeof_gr_complex*1, filename, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        
        # ====== SIGNAL SCALING (CRITICAL FIX) ======
        # Normalize the signal amplitude to reasonable levels
        # Expected power: ~0.1, observed: ~32,800,456
        # Scale factor: 1/6000 brings power to ~0.91
        self.blocks_multiply_const = blocks.multiply_const_cc(1.0/6000.0)
        print(f"Applying signal scaling: 1/6000 (observed power was very high)")
        # ===========================================
        
        # Throttle to process at realistic speed
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate, True)
        
        # Frequency offset correction
        if freq_offset != 0:
            self.blocks_rotator = blocks.rotator_cc(
                -2.0 * 3.14159 * freq_offset / samp_rate)
        
        # Short preamble correlation
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, 16)
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_moving_average_xx_1 = blocks.moving_average_cc(window_size, 1, 4000, 1)
        self.blocks_complex_to_mag_0 = blocks.complex_to_mag(1)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_moving_average_xx_0 = blocks.moving_average_ff(window_size, 1, 4000, 1)
        self.blocks_divide_xx_0 = blocks.divide_ff(1)
        
        # WiFi sync
        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 2, False, False)
        self.tagdbg = blocks.tag_debug(gr.sizeof_gr_complex, "after_short", "")
        self.connect((self.ieee802_11_sync_short_0, 0), (self.tagdbg, 0))

        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, sync_length)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(sync_length, True, True)
        
        self.tagdbg_long = blocks.tag_debug(gr.sizeof_gr_complex, "after_long", "")
        self.connect((self.ieee802_11_sync_long_0, 0), (self.tagdbg_long, 0))

        
        # FFT
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 64)
        self.fft_vxx_0 = fft.fft_vcc(64, True, window.rectangular(64), True, 1)
        
        # Force tag propagation through vectorization + FFT
        self.blocks_stream_to_vector_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)
        self.fft_vxx_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)
        
        # Equalizer and decoder
        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(
            ieee802_11.Equalizer(chan_est), freq, samp_rate, True, True)
        #self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(False, False)
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, True)

        ##################################################
        # Debug File Sinks (if enabled)
        ##################################################
        if self.enable_debug:
            # Ensure output folder exists
            os.makedirs("debug_steps", exist_ok=True)
            
            print("Debug mode enabled - creating debug output files...")
            
            # 0) Raw input (after throttle, before any processing)
            self.file_sink_raw = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_0_raw_input.bin")
            self.file_sink_raw.set_unbuffered(True)
            
            # 1) After frequency correction (if applied)
            if freq_offset != 0:
                self.file_sink_freq_corr = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_1_freq_corrected.bin")
                self.file_sink_freq_corr.set_unbuffered(True)
            
            # 2) Delayed IQ (for correlation)
            self.file_sink_delay = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_2_delayed_iq.bin")
            self.file_sink_delay.set_unbuffered(True)
            
            # 3) Conjugated delayed IQ
            self.file_sink_conj = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_3_conjugate.bin")
            self.file_sink_conj.set_unbuffered(True)
            
            # 4) Multiply: current IQ * delayed conjugate
            self.file_sink_mult = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_4_multiply.bin")
            self.file_sink_mult.set_unbuffered(True)
            
            # 5) Moving average (complex correlation)
            self.file_sink_mavg = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_5_moving_avg_complex.bin")
            self.file_sink_mavg.set_unbuffered(True)
            
            # 6) Correlation magnitude (in_cor)
            self.file_sink_in_cor = blocks.file_sink(gr.sizeof_float*1, "debug_steps/step_6_correlation_mag.bin")
            self.file_sink_in_cor.set_unbuffered(True)
            
            # 7) Mag squared (for normalization)
            self.file_sink_mag_sq = blocks.file_sink(gr.sizeof_float*1, "debug_steps/step_7_mag_squared.bin")
            self.file_sink_mag_sq.set_unbuffered(True)
            
            # 8) Moving average of mag squared
            self.file_sink_mavg_norm = blocks.file_sink(gr.sizeof_float*1, "debug_steps/step_8_mavg_norm.bin")
            self.file_sink_mavg_norm.set_unbuffered(True)
            
            # 9) Normalized correlation (divide result)
            self.file_sink_norm_cor = blocks.file_sink(gr.sizeof_float*1, "debug_steps/step_9_normalized_correlation.bin")
            self.file_sink_norm_cor.set_unbuffered(True)
            
            # 10) After short sync
            self.file_sink_short_sync = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_10_after_short_sync.bin")
            self.file_sink_short_sync.set_unbuffered(True)
            
            # 11) After long sync
            self.file_sink_long_sync = blocks.file_sink(gr.sizeof_gr_complex*1, "debug_steps/step_11_after_long_sync.bin")
            self.file_sink_long_sync.set_unbuffered(True)
            
            # 12) After FFT (64 complex samples per vector = 512 bytes)
            # FFT outputs vectors, save raw vector output
            self.file_sink_fft = blocks.file_sink(gr.sizeof_gr_complex*64, "debug_steps/step_12_after_fft.bin")
            self.file_sink_fft.set_unbuffered(True)
            
            # 13) After equalizer 
            # The equalizer outputs are already in a special format (48 bytes per item)
            # We'll just save the raw output without conversion
            self.file_sink_eq = blocks.file_sink(48, "debug_steps/step_13_after_equalizer.bin")
            self.file_sink_eq.set_unbuffered(True)

        ##################################################
        # Connections
        ##################################################
        
         # Input chain with scaling
        if freq_offset != 0:
            self.connect((self.blocks_file_source_0, 0), (self.blocks_multiply_const, 0))
            self.connect((self.blocks_multiply_const, 0), (self.blocks_throttle_0, 0))
            if self.enable_debug:
                self.connect((self.blocks_throttle_0, 0), (self.file_sink_raw, 0))
            self.connect((self.blocks_throttle_0, 0), (self.blocks_rotator, 0))
            if self.enable_debug:
                self.connect((self.blocks_rotator, 0), (self.file_sink_freq_corr, 0))
            self.connect((self.blocks_rotator, 0), (self.blocks_complex_to_mag_squared_0, 0))
            self.connect((self.blocks_rotator, 0), (self.blocks_delay_0_0, 0))
            self.connect((self.blocks_rotator, 0), (self.blocks_multiply_xx_0, 0))
        else:
            self.connect((self.blocks_file_source_0, 0), (self.blocks_multiply_const, 0))
            self.connect((self.blocks_multiply_const, 0), (self.blocks_throttle_0, 0))
            if self.enable_debug:
                self.connect((self.blocks_throttle_0, 0), (self.file_sink_raw, 0))
            self.connect((self.blocks_throttle_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
            self.connect((self.blocks_throttle_0, 0), (self.blocks_delay_0_0, 0))
            self.connect((self.blocks_throttle_0, 0), (self.blocks_multiply_xx_0, 0))
        
        # Short preamble detection
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
        
        # Debug connections for correlation chain
        if self.enable_debug:
            self.connect((self.blocks_delay_0_0, 0), (self.file_sink_delay, 0))
            self.connect((self.blocks_conjugate_cc_0, 0), (self.file_sink_conj, 0))
            self.connect((self.blocks_multiply_xx_0, 0), (self.file_sink_mult, 0))
            self.connect((self.blocks_moving_average_xx_1, 0), (self.file_sink_mavg, 0))
            self.connect((self.blocks_complex_to_mag_0, 0), (self.file_sink_in_cor, 0))
            self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.file_sink_mag_sq, 0))
            self.connect((self.blocks_moving_average_xx_0, 0), (self.file_sink_mavg_norm, 0))
            self.connect((self.blocks_divide_xx_0, 0), (self.file_sink_norm_cor, 0))
        
        
        #====================================================================================================
    
        # Long preamble and FFT
        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_long_0, 1))
        
        if self.enable_debug:
            self.connect((self.ieee802_11_sync_short_0, 0), (self.file_sink_short_sync, 0))
        
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        
        if self.enable_debug:
            self.connect((self.ieee802_11_sync_long_0, 0), (self.file_sink_long_sync, 0))
        

        #----------------------------------------------------
        
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))
        
        if self.enable_debug:
            self.connect((self.fft_vxx_0, 0), (self.file_sink_fft, 0))
        
        # Equalization and decoding
        self.connect((self.fft_vxx_0, 0), (self.ieee802_11_frame_equalizer_0, 0))
        
        if self.enable_debug:
            self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.file_sink_eq, 0))
        
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))
        
        # Message connection to our handler
        self.msg_connect((self.ieee802_11_decode_mac_0, 'out'), (self.msg_handler, 'in'))
    
        #===========================================================================================================
        """
	# Long preamble and FFT
	self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0, 0))
	self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
	self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_long_0, 1))

	if self.enable_debug:
	    self.connect((self.ieee802_11_sync_short_0, 0), (self.file_sink_short_sync, 0))

	# --- Tag debug BEFORE stream_to_vector ---
	self.tag_debug_pre = blocks.tag_debug(gr.sizeof_gr_complex, "pre_s2v", "")
	self.connect((self.ieee802_11_sync_long_0, 0), (self.tag_debug_pre, 0))

	if self.enable_debug:
	    # tap the same stream (after sync_long) for file debug
	    self.connect((self.tag_debug_pre, 0), (self.file_sink_long_sync, 0))

	# stream_to_vector
	self.connect((self.tag_debug_pre, 0), (self.blocks_stream_to_vector_0, 0))

	# IMPORTANT: force tag propagation through vectorization + FFT
	self.blocks_stream_to_vector_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)
	self.fft_vxx_0.set_tag_propagation_policy(gr.TPP_ALL_TO_ALL)

	# FFT
	self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))

	# --- Tag debug AFTER stream_to_vector / FFT ---
	# (Note: after stream_to_vector, items are vectors; tag_debug can still print tags)
	self.tag_debug_post = blocks.tag_debug(gr.sizeof_gr_complex*64, "post_fft", "")
	self.connect((self.fft_vxx_0, 0), (self.tag_debug_post, 0))

	if self.enable_debug:
	    self.connect((self.tag_debug_post, 0), (self.file_sink_fft, 0))

	# Equalization and decoding
	self.connect((self.tag_debug_post, 0), (self.ieee802_11_frame_equalizer_0, 0))

	if self.enable_debug:
	    self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.file_sink_eq, 0))

	self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))

	# Message connection to our handler
	self.msg_connect((self.ieee802_11_decode_mac_0, 'out'), (self.msg_handler, 'in'))
        """      
        #============================================================================================================


def argument_parser():
    parser = ArgumentParser()
    parser.add_argument("input_file", help="Input IQ file (.cfile format)")
    parser.add_argument("output_pcap", nargs='?', default='/tmp/wifi_output.pcap',
                       help="Output PCAP file")
    parser.add_argument("--freq-offset", dest="freq_offset", type=float, default=0.0,
                       help="Frequency offset in Hz")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug output files in debug_steps/ folder")
    return parser


def main(top_block_cls=wifi_rx_file, options=None):
    if options is None:
        options = argument_parser().parse_args()
    
    print("="*70)
    print("gr-ieee802-11 WiFi Receiver with PCAP Output")
    print("="*70)
    print(f"Input:  {options.input_file}")
    print(f"Output: {options.output_pcap}")
    if options.freq_offset != 0:
        print(f"Freq offset: {options.freq_offset} Hz")
    if options.debug:
        print(f"Debug mode: ENABLED (output to debug_steps/)")
    print("="*70)
    print()
    
    tb = top_block_cls(
        filename=options.input_file,
        output_pcap=options.output_pcap,
        freq_offset=float(options.freq_offset),
        enable_debug=options.debug
    )

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    
    print("Processing file (will run for a few seconds)...\n")
    
    # Let it run for enough time to process the file
    # At 20 MHz, 1M samples = 0.05 seconds, so give it time
    try:
        # Run for 3-5 seconds to ensure all packets are captured
        time.sleep(5)
        
        # Check if still getting packets
        last_count = tb.msg_handler.packet_count
        time.sleep(2)
        if tb.msg_handler.packet_count > last_count:
            # Still decoding, wait a bit more
            time.sleep(3)
    except KeyboardInterrupt:
        pass
    
    tb.stop()
    tb.wait()
    tb.pcap.close()
    
    print()
    print("="*70)
    print(f"✓ Processing complete!")
    print(f"✓ Decoded {tb.msg_handler.packet_count} packets")
    print(f"✓ Written to: {options.output_pcap}")
    if options.debug:
        print(f"✓ Debug files written to: debug_steps/")
    print("="*70)
    print(f"\nAnalyze with:")
    print(f"  tshark -r {options.output_pcap}")
    print(f"  tshark -r {options.output_pcap} -T fields -e wlan.sa -e wlan.da -e wlan.bssid")
    print(f"  wireshark {options.output_pcap}")
    
    if options.debug:
        print(f"\nDebug files can be analyzed with:")
        print(f"  # Normalized correlation (key metric for preamble detection):")
        print(f"  python3 -c 'import numpy as np; d=np.fromfile(\"debug_steps/step_9_normalized_correlation.bin\", np.float32); print(\"Max:\", d.max(), \"Mean:\", d.mean())'")
        print(f"  ")
        print(f"  # Complex IQ samples:")
        print(f"  python3 -c 'import numpy as np; d=np.fromfile(\"debug_steps/step_0_raw_input.bin\", np.complex64); print(d[:10])'")
        print(f"  ")
        print(f"  # FFT output (64 subcarriers per OFDM symbol):")
        print(f"  python3 -c 'import numpy as np; d=np.fromfile(\"debug_steps/step_12_after_fft.bin\", np.complex64); print(\"Samples:\", len(d), \"Symbols:\", len(d)//64)'")
        print(f"  ")
        print(f"  # Or use GNU Radio Companion / MATLAB / Octave to visualize")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        sys.argv += ["Anafi_20mhz_SNR_300_dB.cfile", "output_spyder.pcap", "--debug"]
    main()    
