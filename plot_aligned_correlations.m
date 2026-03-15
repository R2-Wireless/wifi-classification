function plot_aligned_correlations(dump_dir, prefix)
% Align sync_long correlation samples to sync_short absolute input axis.
%
% Required files (from dump folder):
%   <prefix>_short_cor.bin         float32
%   <prefix>_short_det_meta.bin    records:
%      old: uint64 idx, float metric, float threshold, uint8 state, uint32 copied, uint64 frame_id
%      new: old + uint64 tag_output_idx
%   <prefix>_long_mag_abs.bin      records: uint64 sl_idx, float mag
%
% Mapping per long sample L:
%   anchor = latest det_meta row where tag_output_idx <= L
%   abs_x  = anchor.idx + (L - anchor.tag_output_idx)
%
% Usage:
%   plot_aligned_correlations()
%   plot_aligned_correlations('/tmp')
%   plot_aligned_correlations('/tmp', 'capture01')

if nargin < 1 || isempty(dump_dir)
    dump_dir = '/tmp';
end
if nargin < 2 || isempty(prefix)
    prefix = auto_detect_prefix(dump_dir);
end

short_cor_path = fullfile(dump_dir, [prefix '_short_cor.bin']);
det_meta_path = fullfile(dump_dir, [prefix '_short_det_meta.bin']);
long_mag_abs_path = fullfile(dump_dir, [prefix '_long_mag_abs.bin']);

short_cor = read_f32(short_cor_path);
det = read_short_det_meta(det_meta_path);
long_abs = read_long_mag_abs(long_mag_abs_path);

if isempty(det.idx) || isempty(det.tag_output_idx)
    error(['det_meta does not contain tag_output_idx (new 37-byte record required): ' ...
           '%s'], det_meta_path);
end
if isempty(long_abs.sl_idx)
    error('No long_mag_abs records found: %s', long_mag_abs_path);
end

% Ensure anchors sorted by tag_output_idx.
[tag_out, aord] = sort(double(det.tag_output_idx(:)));
anchor_abs_in = double(det.idx(aord));

sl_idx = double(long_abs.sl_idx(:));
mag = double(long_abs.mag(:));

% For each long index, find most recent anchor with tag_out <= sl_idx.
anchor_idx = zeros(size(sl_idx));
p = 1;
for i = 1:numel(sl_idx)
    while (p < numel(tag_out)) && (tag_out(p + 1) <= sl_idx(i))
        p = p + 1;
    end
    if ~isempty(tag_out) && (tag_out(1) <= sl_idx(i))
        anchor_idx(i) = p;
    else
        anchor_idx(i) = 0;
    end
end

valid = anchor_idx > 0;
mapped_x = nan(size(sl_idx));
mapped_x(valid) = anchor_abs_in(anchor_idx(valid)) + (sl_idx(valid) - tag_out(anchor_idx(valid)));

fig = figure('Name', ['Aligned correlations: ' prefix], ...
             'Color', 'w', 'Units', 'normalized', 'Position', [0.06 0.08 0.88 0.84]);
ax1 = subplot(2, 1, 1);
ax2 = subplot(2, 1, 2);

% Top: short correlation in absolute sample axis.
axes(ax1);
x_short = (0:numel(short_cor)-1).';
if ~isempty(short_cor)
    plot(x_short, short_cor, 'b-', 'LineWidth', 0.7); hold on;
else
    plot(nan, nan, 'b-'); hold on;
end
if ~isempty(det.idx)
    % Plot detection metric at absolute input index.
    plot(double(det.idx), double(det.metric), 'ro', 'MarkerSize', 5, 'LineWidth', 1.0);
end
grid on;
xlabel('absolute input sample index');
ylabel('short corr metric');
title(['sync\_short (prefix: ' prefix ')']);
legend({'short corr', 'detections'}, 'Location', 'best', 'Interpreter', 'none');

% Bottom: sync_long magnitude mapped into same absolute axis.
axes(ax2);
if any(valid)
    [mx, mord] = sort(mapped_x(valid));
    mm = mag(valid);
    mm = mm(mord);
    plot(mx, mm, '-', 'Color', [0 0.5 0], 'LineWidth', 0.8); hold on;
    plot(mx, mm, 'o', 'Color', [0 0.5 0], 'MarkerSize', 3, 'LineWidth', 0.8);
else
    plot(nan, nan, '-', 'Color', [0 0.5 0]); hold on;
end
grid on;
xlabel('absolute input sample index');
ylabel('|long corr|');
title('sync\_long correlation mapped to absolute axis');
legend({'mapped long corr', 'mapped points'}, 'Location', 'best');

linkaxes([ax1 ax2], 'x');

fprintf('Prefix: %s\n', prefix);
fprintf('short_cor samples       : %d\n', numel(short_cor));
fprintf('det_meta anchors        : %d\n', numel(det.idx));
fprintf('long_mag_abs samples    : %d\n', numel(sl_idx));
fprintf('mapped samples (valid)  : %d\n', nnz(valid));
end


function prefix = auto_detect_prefix(dump_dir)
f = dir(fullfile(dump_dir, '*_long_mag_abs.bin'));
if isempty(f)
    error('No *_long_mag_abs.bin files found in %s', dump_dir);
end
if numel(f) > 1
    error(['Multiple prefixes found. Pass prefix explicitly. First few: %s, %s'], ...
          strip_suffix(f(1).name, '_long_mag_abs.bin'), ...
          strip_suffix(f(2).name, '_long_mag_abs.bin'));
end
prefix = strip_suffix(f(1).name, '_long_mag_abs.bin');
end


function v = read_f32(path)
fid = fopen(path, 'rb');
if fid < 0
    v = [];
    return;
end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
v = fread(fid, inf, 'single=>single');
end


function det = read_short_det_meta(path)
det.idx = [];
det.metric = [];
det.threshold = [];
det.state = [];
det.copied = [];
det.frame_id = [];
det.tag_output_idx = [];

fid = fopen(path, 'rb');
if fid < 0
    return;
end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>

info = dir(path);
has_tag_output_idx = false;
if ~isempty(info)
    if mod(info.bytes, 37) == 0
        has_tag_output_idx = true;
    elseif mod(info.bytes, 29) ~= 0
        warning('Unexpected det_meta size (%d bytes): %s', info.bytes, path);
    end
end

while true
    idx = fread(fid, 1, 'uint64=>uint64');
    if isempty(idx), break; end
    metric = fread(fid, 1, 'single=>single');
    thr = fread(fid, 1, 'single=>single');
    state = fread(fid, 1, 'uint8=>uint8');
    copied = fread(fid, 1, 'uint32=>uint32');
    frame_id = fread(fid, 1, 'uint64=>uint64');
    if has_tag_output_idx
        tag_out = fread(fid, 1, 'uint64=>uint64');
    else
        tag_out = uint64(0);
    end

    if isempty(metric) || isempty(thr) || isempty(state) || isempty(copied) || ...
            isempty(frame_id) || isempty(tag_out)
        break;
    end

    det.idx(end + 1, 1) = idx; %#ok<AGROW>
    det.metric(end + 1, 1) = metric; %#ok<AGROW>
    det.threshold(end + 1, 1) = thr; %#ok<AGROW>
    det.state(end + 1, 1) = state; %#ok<AGROW>
    det.copied(end + 1, 1) = copied; %#ok<AGROW>
    det.frame_id(end + 1, 1) = frame_id; %#ok<AGROW>
    det.tag_output_idx(end + 1, 1) = tag_out; %#ok<AGROW>
end
end


function out = read_long_mag_abs(path)
out.sl_idx = [];
out.mag = [];

fid = fopen(path, 'rb');
if fid < 0
    return;
end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>

while true
    sl_idx = fread(fid, 1, 'uint64=>uint64');
    if isempty(sl_idx), break; end
    mag = fread(fid, 1, 'single=>single');
    if isempty(mag), break; end
    out.sl_idx(end + 1, 1) = sl_idx; %#ok<AGROW>
    out.mag(end + 1, 1) = mag; %#ok<AGROW>
end
end


function s = strip_suffix(name, suffix)
if endsWith(name, suffix)
    s = extractBefore(name, strlength(name) - strlength(suffix) + 1);
else
    s = name;
end
end
