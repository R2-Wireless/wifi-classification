import numpy as np
samples = np.fromfile("/mnt/c/Users/Public/Documents/Wify/Py_script/cfiles/Neo2_19_02/Neo2-Wifi-5180MHz-02-19-26-15h57m06s639_0001_20mhz_SNR_Both_dB.cfile", dtype=np.complex64)
power_db = 10 * np.log10(np.mean(np.abs(samples)**2))
print(f"Average signal power: {power_db:.1f} dB")
# Also check peak vs average
peak_db = 10 * np.log10(np.max(np.abs(samples)**2))
print(f"Peak power: {peak_db:.1f} dB")