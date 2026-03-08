function plot_sync_short_debug_3(short_cor_path, det_meta_path, copy_regions_path, long_mag_path, long_det_path, long_det_meta_path)
% Plot sync_short correlation with detection markers and shaded COPY regions.
%
% Binary inputs are produced by sync_short.cc when WIFI_DUMP_CORR=1:
%   short_cor_path: float32 correlation array (default /tmp/sync_short_cor.bin)
%   det_meta_path: records of:
%       uint64 idx, float32 metric, float32 threshold, uint8 state, uint32 copied
%       (default /tmp/sync_short_det_meta.bin)
%   copy_regions_path: repeated pairs uint64 [start end_exclusive]
%       (default /tmp/sync_short_copy_regions.bin)
%
% State values:
%   0 = SEARCH trigger
%   1 = COPY retrigger

if nargin < 1 || isempty(short_cor_path)
    short_cor_path = '/tmp/sync_short_cor.bin';
end
if nargin < 2 || isempty(det_meta_path)
    det_meta_path = '/tmp/sync_short_det_meta.bin';
end
if nargin < 3 || isempty(copy_regions_path)
    copy_regions_path = '/tmp/sync_short_copy_regions.bin';
end
if nargin < 4 || isempty(long_mag_path)
    long_mag_path = '/tmp/sync_long_cor_mag.bin';
end
if nargin < 5 || isempty(long_det_path)
    long_det_path = '/tmp/sync_long_det.bin';
end
if nargin < 6 || isempty(long_det_meta_path)
    long_det_meta_path = '/tmp/sync_long_det_meta.bin';
end

cor = read_f32(short_cor_path);
x = (0:numel(cor)-1).';

det = load_det_meta(det_meta_path);
regions = load_copy_regions(copy_regions_path);
long_cor = read_f32(long_mag_path);
long_x = (0:numel(long_cor)-1).';
long_det = load_u64(long_det_path);
long_meta = load_long_det_meta(long_det_meta_path);
if ~isempty(long_meta.frame_id)
    long_regions = [min(long_meta.peak1, long_meta.peak2), ...
                    max(long_meta.peak1, long_meta.peak2)];
    long_region_frame_id = long_meta.frame_id;
else
    long_regions = build_long_regions(long_det);
    long_region_frame_id = nan(size(long_regions, 1), 1);
end

[short_region_frame_id, short_region_state] = map_short_regions_to_det(regions, det);

figure('Name', 'sync_short/sync_long correlation + detections', 'Color', 'w');
tiledlayout(2, 1, 'TileSpacing', 'compact', 'Padding', 'compact');

nexttile;
h_corr = plot(x, cor, 'b-');
grid on;
hold on;
xlabel('sample index');
ylabel('metric');
title('sync\_short correlation + detections + COPY regions');

if ~isempty(cor)
    y_min = min(cor);
    y_max = max(cor);
    if y_min == y_max
        y_min = y_min - 1;
        y_max = y_max + 1;
    end
else
    y_min = -1;
    y_max = 1;
end

[h_search_region, h_copy_region] = shade_regions_by_state(regions, det, y_min, y_max);

if ~isempty(det.idx)
    idx_in_range = det.idx >= 0 & det.idx <= (numel(cor)-1);
    idx = det.idx(idx_in_range);
    metric = det.metric(idx_in_range);
    threshold = det.threshold(idx_in_range);
    state = det.state(idx_in_range);

    valid = metric >= threshold;
    invalid = ~valid;

    search_valid = valid & (state == 0);
    copy_valid = valid & (state == 1);

    h_search_det = plot(idx(search_valid), metric(search_valid), 'ro', 'MarkerSize', 7, 'LineWidth', 1.0);
    h_copy_det = plot(idx(copy_valid), metric(copy_valid), 'mo', 'MarkerSize', 7, 'LineWidth', 1.0);
    h_invalid = plot(idx(invalid), metric(invalid), 'ko', 'MarkerSize', 6, 'LineWidth', 1.0);

    legend([h_corr h_search_region h_copy_region h_search_det h_copy_det h_invalid], ...
           {'corr', 'SEARCH-start region', 'COPY-retrigger region', ...
            'SEARCH det valid', 'COPY det valid', 'det invalid'}, ...
           'Location', 'best');
else
    legend([h_corr h_search_region h_copy_region], ...
           {'corr', 'SEARCH-start region', 'COPY-retrigger region'}, ...
           'Location', 'best');
end

hold off;

nexttile;
h_long = plot(long_x, long_cor, 'k-');
grid on;
hold on;
xlabel('correlation-sample index');
ylabel('|corr|');
title('sync\_long |corr| + detected peaks');

if ~isempty(long_cor)
    ly_min = min(long_cor);
    ly_max = max(long_cor);
    if ly_min == ly_max
        ly_min = ly_min - 1;
        ly_max = ly_max + 1;
    end
else
    ly_min = -1;
    ly_max = 1;
end

h_long_region_a = [];
h_long_region_b = [];
long_to_short_region = nan(size(long_regions, 1), 1);
for k = 1:size(long_regions, 1)
    x1 = long_regions(k, 1);
    x2 = long_regions(k, 2);
    if x2 < x1
        continue;
    end
    mapped_short_idx = nan;
    if ~isnan(long_region_frame_id(k))
        m = find(short_region_frame_id == long_region_frame_id(k), 1, 'first');
        if ~isempty(m)
            mapped_short_idx = m;
        end
    end
    long_to_short_region(k) = mapped_short_idx;

    if ~isnan(mapped_short_idx) && short_region_state(mapped_short_idx) == 0
        c = [0.76 0.88 1.00];  % same SEARCH color as short panel
        a = 0.22;
    elseif mod(k, 2) == 1
        c = [0.86 0.86 0.86];  % same COPY alternating shades as short panel
        a = 0.20;
    else
        c = [0.78 0.78 0.78];
        a = 0.20;
    end
    h = patch([x1 x2 x2 x1], [ly_min ly_min ly_max ly_max], c, ...
              'FaceAlpha', a, 'EdgeColor', 'none');
    if mod(k, 2) == 1 && isempty(h_long_region_a)
        h_long_region_a = h;
    elseif mod(k, 2) == 0 && isempty(h_long_region_b)
        h_long_region_b = h;
    end
end
if isempty(h_long_region_a)
    h_long_region_a = plot(nan, nan, 's', 'MarkerFaceColor', [0.86 0.86 0.86], ...
                           'MarkerEdgeColor', [0.86 0.86 0.86]);
end
if isempty(h_long_region_b)
    h_long_region_b = plot(nan, nan, 's', 'MarkerFaceColor', [0.78 0.78 0.78], ...
                           'MarkerEdgeColor', [0.78 0.78 0.78]);
end

if ~isempty(long_det)
    in_range = long_det >= 0 & long_det <= (numel(long_cor)-1);
    long_det_in = long_det(in_range);
    h_long_det = plot(long_det_in, long_cor(long_det_in + 1), 'mo', ...
                      'MarkerSize', 6, 'LineWidth', 1.0);
else
    h_long_det = plot(nan, nan, 'mo', 'MarkerSize', 6, 'LineWidth', 1.0);
end

legend([h_long h_long_region_a h_long_region_b h_long_det], ...
       {'|corr|', 'SEARCH-mapped region', 'COPY-mapped region', 'detected peaks'}, ...
       'Location', 'best');
hold off;

fprintf('Loaded %d correlation samples\n', numel(cor));
fprintf('Loaded %d detection records\n', numel(det.idx));
if ~isempty(det.idx)
    n_valid = nnz(det.metric >= det.threshold);
    fprintf('  valid detections: %d\n', n_valid);
    fprintf('  invalid detections: %d\n', numel(det.idx) - n_valid);
end
fprintf('Loaded %d COPY regions\n', size(regions, 1));
fprintf('Loaded %d sync_long correlation samples\n', numel(long_cor));
fprintf('Loaded %d sync_long detected peaks (%d regions)\n', ...
        numel(long_det), size(long_regions, 1));
fprintf('\nLong region classification vs sync_short COPY regions:\n');
fprintf('  long_region  frame_id  [peak1 peak2]  -> short_region  short_state\n');
for k = 1:size(long_regions, 1)
    if k <= numel(long_region_frame_id)
        fid = long_region_frame_id(k);
    else
        fid = nan;
    end
    sidx = long_to_short_region(k);
    if ~isnan(sidx)
        sstate = short_region_state(sidx);
        fprintf('  %10d  %8g  [%6d %6d]  -> %11d  %d\n', ...
                k, fid, round(long_regions(k, 1)), round(long_regions(k, 2)), sidx, sstate);
    else
        fprintf('  %10d  %8g  [%6d %6d]  -> %11s  %s\n', ...
                k, fid, round(long_regions(k, 1)), round(long_regions(k, 2)), 'N/A', 'N/A');
    end
end

end

function v = read_f32(path)
fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    v = [];
    return;
end
cleanup = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'single=>double');
end

function det = load_det_meta(path)
det.idx = [];
det.metric = [];
det.threshold = [];
det.state = [];
det.copied = [];
det.frame_id = [];

fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    return;
end
cleanup = onCleanup(@() fclose(fid));

fseek(fid, 0, 'eof');
nbytes = ftell(fid);
fseek(fid, 0, 'bof');

rec_v2 = 29;  % uint64 idx, float metric, float threshold, uint8 state, uint32 copied, uint64 frame_id
rec_v1 = 21;  % uint64 idx, float metric, float threshold, uint8 state, uint32 copied
has_frame_id = false;
if mod(nbytes, rec_v2) == 0
    rec_bytes = rec_v2;
    has_frame_id = true;
elseif mod(nbytes, rec_v1) == 0
    rec_bytes = rec_v1;
else
    warning('Unexpected short det meta size (%d bytes), attempting v1 parsing.', nbytes);
    rec_bytes = rec_v1;
end

nrec = floor(nbytes / rec_bytes);
idx = zeros(nrec, 1);
metric = zeros(nrec, 1);
threshold = zeros(nrec, 1);
state = zeros(nrec, 1);
copied = zeros(nrec, 1);
frame_id = nan(nrec, 1);
for k = 1:nrec
    idx(k) = fread(fid, 1, 'uint64=>double');
    metric(k) = fread(fid, 1, 'single=>double');
    threshold(k) = fread(fid, 1, 'single=>double');
    state(k) = fread(fid, 1, 'uint8=>double');
    copied(k) = fread(fid, 1, 'uint32=>double');
    if has_frame_id
        frame_id(k) = fread(fid, 1, 'uint64=>double');
    end
end

det.idx = idx;
det.metric = metric;
det.threshold = threshold;
det.state = state;
det.copied = copied;
det.frame_id = frame_id;
end

function regions = load_copy_regions(path)
fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    regions = zeros(0, 2);
    return;
end
cleanup = onCleanup(@() fclose(fid));

r = fread(fid, [2 inf], 'uint64=>double').';
if isempty(r)
    regions = zeros(0, 2);
    return;
end
regions = r;
end

function v = load_u64(path)
fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    v = [];
    return;
end
cleanup = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'uint64=>double');
end

function regions = build_long_regions(long_det)
if isempty(long_det)
    regions = zeros(0, 2);
    return;
end
n = floor(numel(long_det) / 2);
regions = zeros(n, 2);
for i = 1:n
    a = long_det(2*i - 1);
    b = long_det(2*i);
    regions(i, :) = [min(a, b), max(a, b)];
end
end

function meta = load_long_det_meta(path)
meta.frame_id = [];
meta.peak1 = [];
meta.peak2 = [];

fid = fopen(path, 'rb');
if fid < 0
    return;
end
cleanup = onCleanup(@() fclose(fid));
raw = fread(fid, inf, 'uint64=>double');
if isempty(raw)
    return;
end
n = floor(numel(raw) / 3);
if n < 1
    return;
end
raw = raw(1:(3 * n));
raw = reshape(raw, 3, n).';
meta.frame_id = raw(:, 1);
meta.peak1 = raw(:, 2);
meta.peak2 = raw(:, 3);
end

function [region_frame_id, region_state] = map_short_regions_to_det(regions, det)
region_frame_id = nan(size(regions, 1), 1);
region_state = nan(size(regions, 1), 1);
if isempty(regions) || isempty(det.idx)
    return;
end
[tf, loc] = ismember(regions(:, 1), det.idx);
if any(tf)
    if isfield(det, 'frame_id') && ~isempty(det.frame_id)
        region_frame_id(tf) = det.frame_id(loc(tf));
    end
    region_state(tf) = det.state(loc(tf));
end
end

function [h_search_legend, h_copy_legend] = shade_regions_by_state(regions, det, y_min, y_max)
h_search_legend = [];
h_copy_legend = [];
if isempty(regions)
    h_search_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.76 0.88 1.00], ...
                           'MarkerEdgeColor', [0.76 0.88 1.00]);
    h_copy_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.82 0.82 0.82], ...
                         'MarkerEdgeColor', [0.82 0.82 0.82]);
    return;
end

state_by_start = nan(size(regions, 1), 1);
if ~isempty(det.idx)
    [tf, loc] = ismember(regions(:, 1), det.idx);
    state_by_start(tf) = det.state(loc(tf));
end

copy_count = 0;
search_seen = false;
copy_seen = false;

for k = 1:size(regions, 1)
    x1 = regions(k, 1);
    x2 = regions(k, 2) - 1;
    if x2 < x1
        continue;
    end

    st = state_by_start(k);
    if st == 0
        color_rgb = [0.76 0.88 1.00];  % SEARCH-start
        alpha = 0.22;
        search_seen = true;
    elseif st == 1
        copy_count = copy_count + 1;
        if mod(copy_count, 2) == 1
            color_rgb = [0.86 0.86 0.86];
        else
            color_rgb = [0.78 0.78 0.78];
        end
        alpha = 0.20;
        copy_seen = true;
    else
        color_rgb = [0.90 0.90 0.90];
        alpha = 0.15;
    end

    h = patch([x1 x2 x2 x1], [y_min y_min y_max y_max], color_rgb, ...
              'FaceAlpha', alpha, 'EdgeColor', 'none');
    if st == 0 && isempty(h_search_legend)
        h_search_legend = h;
    elseif st == 1 && isempty(h_copy_legend)
        h_copy_legend = h;
    end
end

if isempty(h_search_legend)
    if search_seen
        h_search_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.76 0.88 1.00], ...
                               'MarkerEdgeColor', [0.76 0.88 1.00]);
    else
        h_search_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.85 0.85 0.85], ...
                               'MarkerEdgeColor', [0.85 0.85 0.85]);
    end
end
if isempty(h_copy_legend)
    if copy_seen
        h_copy_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.82 0.82 0.82], ...
                             'MarkerEdgeColor', [0.82 0.82 0.82]);
    else
        h_copy_legend = plot(nan, nan, 's', 'MarkerFaceColor', [0.85 0.85 0.85], ...
                             'MarkerEdgeColor', [0.85 0.85 0.85]);
    end
end
end
