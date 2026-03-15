from sync_long_capture_probe import load_sync_long_capture
import numpy as np

cap = load_sync_long_capture("/tmp/sync_long_capture.npz")

print(f"Total samples: {len(cap['samples']):,}")
print(f"Frames detected: {len(cap['frames'])}")

f = cap['frames'][0]
print(f"Frame 0 starts at sample {f['start_offset']}")
print(f"  wifi_start (CFO residual):   {f['wifi_start']:.6f} rad/sample")
print(f"  cfo_short:                   {f['cfo_short_rad_per_samp']:.6f} rad/sample")
print(f"  cfo_long:                    {f['cfo_long_rad_per_samp']:.6f} rad/sample")
print(f"  frame_id:                    {f['frame_id']}")
print(f"  LTS1 shape:                  {f['lts1'].shape}")     # (64,)
print(f"  LTS2 shape:                  {f['lts2'].shape}")     # (64,)
print(f"  data_symbols shape:          {f['data_symbols'].shape}")  # (K, 64)
# row 0 of data_symbols = SIGNAL field (time domain, CP stripped)
# rows 1..K-1 = data OFDM symbols (time domain, CP stripped)
# All of these still need FFT before equalization — that's what fft_vcc does downstream
