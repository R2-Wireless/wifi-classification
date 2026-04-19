function plot_sync_long_dump(dump_dir, prefix)
% Plot sync_long binary dumps produced by run_main_17.py or sync_long.cc.
%
% Usage:
%   plot_sync_long_dump
%   plot_sync_long_dump('/tmp')
%   plot_sync_long_dump('/tmp', 'sync')
%
% Files used:
%   <prefix>_long_mag.bin or sync_long_cor_mag.bin
%   <prefix>_long_det.bin or sync_long_det.bin
%   <prefix>_long_det_meta.bin or sync_long_det_meta.bin
%   <prefix>_long_cplx.bin or sync_long_cor_cplx.bin

if nargin < 1 || isempty(dump_dir)
    dump_dir = "\\wsl.localhost\Ubuntu-22.04\tmp";
end

if nargin < 2
    prefix = "";
end

dump_dir = char(dump_dir);
prefix = char(prefix);

mag_path = pick_path(dump_dir, prefix, "_long_mag.bin", "sync_long_cor_mag.bin");
det_path = pick_path(dump_dir, prefix, "_long_det.bin", "sync_long_det.bin");
det_meta_path = pick_path(dump_dir, prefix, "_long_det_meta.bin", "sync_long_det_meta.bin");
cplx_path = pick_path(dump_dir, prefix, "_long_cplx.bin", "sync_long_cor_cplx.bin");

corr_long = read_f32(mag_path);
peak_pairs = read_u64_pairs(det_path);
det_meta = read_u64_triples(det_meta_path);
corr_cplx = read_c64(cplx_path);

frame_ids = [];
if ~isempty(det_meta)
    frame_ids = double(det_meta(:, 1));
end

figure('Name', 'sync_long dump', 'Color', 'w');
tiledlayout(2, 1, 'TileSpacing', 'compact', 'Padding', 'compact');

% ax1 = nexttile;
plot(corr_long, 'k-', 'LineWidth', 0.8);
grid on; hold on;
xlabel('Sample index');
ylabel('|corr|');
title(sprintf('sync_long magnitude  (%s)', mag_path), 'Interpreter', 'none');

for k = 1:size(peak_pairs, 1)
    p1 = double(peak_pairs(k, 1)) + 1;
    p2 = double(peak_pairs(k, 2)) + 1;
    if p1 >= 1 && p1 <= numel(corr_long)
        plot(p1, corr_long(p1), 'ro', 'MarkerSize', 6, 'LineWidth', 1.0);
        xline(p1, '--', 'Color', [0.2 0.6 1.0 0.3]);
    end
    if p2 >= 1 && p2 <= numel(corr_long)
        plot(p2, corr_long(p2), 'bo', 'MarkerSize', 6, 'LineWidth', 1.0);
        xline(p2, '--', 'Color', [1.0 0.4 0.2 0.3]);
    end
    if k <= numel(frame_ids) && p1 >= 1 && p1 <= numel(corr_long)
        text(p1, corr_long(p1), sprintf(' F%d', frame_ids(k)), ...
            'VerticalAlignment', 'bottom', 'FontSize', 9, 'Color', [0.1 0.1 0.7]);
    end
end
% hold off;

% ax2 = nexttile;
% if isempty(corr_cplx)
%     text(0.5, 0.5, 'complex correlation dump not available', ...
%         'HorizontalAlignment', 'center');
%     axis off;
% else
%     yyaxis left;
%     plot(angle(corr_cplx), 'b-');
%     ylabel('phase (rad)');
%     yyaxis right;
%     plot(abs(corr_cplx), 'Color', [0.1 0.1 0.1 0.5]);
%     ylabel('|corr cplx|');
%     grid on;
%     xlabel('Sample index');
%     title(sprintf('sync_long complex correlation  (%s)', cplx_path), 'Interpreter', 'none');
% end
% 
% linkaxes([ax1, ax2], 'x');

end

function path = pick_path(dump_dir, prefix, suffix_name, fallback_name)
if strlength(string(prefix)) > 0
    candidate = fullfile(dump_dir, [prefix suffix_name]);
    if isfile(candidate)
        path = candidate;
        return;
    end
end

candidate = fullfile(dump_dir, fallback_name);
if isfile(candidate)
    path = candidate;
    return;
end

error('Dump file not found. Tried: %s and %s', ...
      fullfile(dump_dir, [prefix suffix_name]), candidate);
end

function out = read_f32(path)
fid = fopen(path, 'rb');
assert(fid >= 0, 'Cannot open %s', path);
cleanup = onCleanup(@() fclose(fid));
out = fread(fid, inf, 'float32=>single');
end

function out = read_u64_pairs(path)
fid = fopen(path, 'rb');
assert(fid >= 0, 'Cannot open %s', path);
cleanup = onCleanup(@() fclose(fid));
raw = fread(fid, inf, 'uint64=>uint64');
if isempty(raw)
    out = zeros(0, 2, 'uint64');
else
    out = reshape(raw, 2, []).';
end
end

function out = read_u64_triples(path)
if ~isfile(path)
    out = zeros(0, 3, 'uint64');
    return;
end
fid = fopen(path, 'rb');
assert(fid >= 0, 'Cannot open %s', path);
cleanup = onCleanup(@() fclose(fid));
raw = fread(fid, inf, 'uint64=>uint64');
if isempty(raw)
    out = zeros(0, 3, 'uint64');
else
    out = reshape(raw, 3, []).';
end
end

function out = read_c64(path)
if ~isfile(path)
    out = complex([], []);
    return;
end
fid = fopen(path, 'rb');
assert(fid >= 0, 'Cannot open %s', path);
cleanup = onCleanup(@() fclose(fid));
raw = fread(fid, inf, 'float32=>single');
if isempty(raw)
    out = complex([], []);
else
    out = complex(raw(1:2:end), raw(2:2:end));
end
end
