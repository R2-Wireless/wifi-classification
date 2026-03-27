function plot_sync_long_only_debug(mat_path)
% Plot sync-long-only long correlation debug data exported by main_script_14.py
%
% Usage:
%   plot_sync_long_only_debug
%   plot_sync_long_only_debug('/tmp/sync_long_only_debug.mat')

if nargin < 1 || isempty(mat_path)
    mat_path = "\\wsl.localhost\Ubuntu-22.04\tmp\sync_long_only_debug.mat";
end

d = load(mat_path);

corr_long = get_field_or(d, 'corr_long', []);
sorted_peaks = get_field_or(d, 'sorted_peaks', []);
peak_pairs = get_field_or(d, 'peak_pairs', []);
frame_ids = get_field_or(d, 'frame_ids', []);
iq_abs = get_field_or(d, 'iq_abs', []);
threshold = get_scalar_or(d, 'threshold', NaN);
best_freq_hz = get_scalar_or(d, 'best_freq_hz', NaN);
lts_snr_db = get_field_or(d, 'lts_snr_db', []);

% Exported indices come from Python and are therefore 0-based.
sorted_peaks = double(sorted_peaks(:)) + 1;
peak_pairs = double(peak_pairs) + 1;
frame_ids = double(frame_ids(:));

figure('Name', 'sync-long-only debug', 'Color', 'w');
tiledlayout(2, 1, 'TileSpacing', 'compact', 'Padding', 'compact');

ax1 = nexttile;
if ~isempty(iq_abs)
    plot(iq_abs, 'b-');
    grid on;
    ylabel('|IQ|');
    title('Input magnitude');
else
    text(0.5, 0.5, 'iq_abs not available', 'HorizontalAlignment', 'center');
    axis off;
end

ax2 = nexttile;
plot(corr_long, 'k-', 'LineWidth', 0.8);
grid on; hold on;
xlabel('Sample index');
ylabel('|corr|');
title(sprintf('Long correlation  threshold=%.3f  best freq=%.1f Hz', threshold, best_freq_hz));

if ~isempty(sorted_peaks)
    plot(sorted_peaks, corr_long(sorted_peaks), 'ro', 'MarkerSize', 6, 'LineWidth', 1.0);
end

for k = 1:size(peak_pairs, 1)
    p1 = peak_pairs(k, 1);
    p2 = peak_pairs(k, 2);
    xline(p1, '--', 'Color', [0.2 0.6 1.0 0.3]);
    xline(p2, '--', 'Color', [1.0 0.4 0.2 0.3]);
    if k <= numel(frame_ids)
        label = sprintf('F%d', frame_ids(k));
        if k <= numel(lts_snr_db) && ~isnan(lts_snr_db(k))
            label = sprintf('%s  LTS SNR %.1f dB', label, lts_snr_db(k));
        end
        text(double(p1), double(corr_long(p1)), [' ' label], ...
            'VerticalAlignment', 'bottom', 'FontSize', 9, 'Color', [0.1 0.1 0.7]);
    end
end

if ~isnan(threshold)
    yline(threshold, 'm--', 'Threshold');
end
hold off;

linkaxes([ax1, ax2], 'x');

end

function value = get_field_or(s, name, default_value)
if isfield(s, name)
    value = s.(name);
else
    value = default_value;
end
end

function value = get_scalar_or(s, name, default_value)
if isfield(s, name)
    raw = s.(name);
    value = raw(1);
else
    value = default_value;
end
end
