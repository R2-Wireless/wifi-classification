import numpy as np
d1 = np.load('cap.npz', allow_pickle=True)
d2 = np.load('/tmp/sync_long_capture.npz', allow_pickle=True)
print("cap.npz samples:", len(d1['samples']))
print("live capture samples:", len(d2['samples']))
print("cap.npz tags:", len(d1['tag_offsets']))
print("live capture tags:", len(d2['tag_offsets']))
# Compare the CFO values baked into wifi_start tags:
for i,k in enumerate(d1['tag_keys']):
    if k == 'wifi_start':
        print(f"cap.npz  wifi_start offset={d1['tag_offsets'][i]}  cfo={d1['tag_values_f64'][i]:.2f}")
for i,k in enumerate(d2['tag_keys']):
    if k == 'wifi_start':
        print(f"live     wifi_start offset={d2['tag_offsets'][i]}  cfo={d2['tag_values_f64'][i]:.2f}")