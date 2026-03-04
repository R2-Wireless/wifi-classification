function plot_sync_short_debug(short_cor_path, det_meta_path, copy_regions_path)
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

cor = read_f32(short_cor_path);
x = (0:numel(cor)-1).';

det = load_det_meta(det_meta_path);
regions = load_copy_regions(copy_regions_path);

figure('Name', 'sync_short correlation + detections + COPY regions', 'Color', 'w');
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

fprintf('Loaded %d correlation samples\n', numel(cor));
fprintf('Loaded %d detection records\n', numel(det.idx));
if ~isempty(det.idx)
    n_valid = nnz(det.metric >= det.threshold);
    fprintf('  valid detections: %d\n', n_valid);
    fprintf('  invalid detections: %d\n', numel(det.idx) - n_valid);
end
fprintf('Loaded %d COPY regions\n', size(regions, 1));

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

fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    return;
end
cleanup = onCleanup(@() fclose(fid));

idx = [];
metric = [];
threshold = [];
state = [];
copied = [];

while true
    a = fread(fid, 1, 'uint64=>double');
    if isempty(a), break; end
    b = fread(fid, 1, 'single=>double');
    c = fread(fid, 1, 'single=>double');
    d = fread(fid, 1, 'uint8=>double');
    e = fread(fid, 1, 'uint32=>double');
    if isempty(b) || isempty(c) || isempty(d) || isempty(e)
        break;
    end
    idx(end+1, 1) = a; %#ok<AGROW>
    metric(end+1, 1) = b; %#ok<AGROW>
    threshold(end+1, 1) = c; %#ok<AGROW>
    state(end+1, 1) = d; %#ok<AGROW>
    copied(end+1, 1) = e; %#ok<AGROW>
end

det.idx = idx;
det.metric = metric;
det.threshold = threshold;
det.state = state;
det.copied = copied;
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
