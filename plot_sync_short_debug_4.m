function plot_sync_short_debug_4(short_cor_path, det_meta_path, copy_regions_path, ...
                                  long_mag_path, long_det_path)
% Plot sync_short AND sync_long correlations with matching shading.
%
% ── sync_short inputs (produced by sync_short.cc when WIFI_DUMP_CORR=1) ─────
%   short_cor_path    : float32 correlation array
%                       default: \\wsl.localhost\Ubuntu-22.04\tmp\sync_short_cor.bin
%   det_meta_path     : detection records
%                         { uint64 idx, float32 metric, float32 threshold,
%                           uint8 state, uint32 copied }
%                       default: \\wsl.localhost\Ubuntu-22.04\tmp\sync_short_det_meta.bin
%   copy_regions_path : repeated pairs uint64 [start end_exclusive]
%                       default: \\wsl.localhost\Ubuntu-22.04\tmp\sync_short_copy_regions.bin
%
% ── sync_long inputs (produced by sync_long.cc when WIFI_DUMP_CORR=1) ───────
%   long_mag_path     : float32 magnitude of LTS cross-correlation
%                       (written only during SYNC windows → segmented series)
%                       default: \\wsl.localhost\Ubuntu-22.04\tmp\sync_long_cor_mag.bin
%   long_det_path     : repeated pairs uint64 [peak1 peak2]  (peak2 = peak1+64)
%                       indices are in sync_long INPUT sample space
%                       default: \\wsl.localhost\Ubuntu-22.04\tmp\sync_long_det.bin
%
% ── Coordinate spaces ───────────────────────────────────────────────────────
%   sync_short x-axis : absolute input sample index (from the SDR)
%   sync_long  x-axis : sync_long input sample index  (= sync_short OUTPUT)
%                       These are DIFFERENT spaces; the two subplots share no
%                       common x-axis but use identical visual shading so that
%                       corresponding frames line up by colour.
%
% ── State values ─────────────────────────────────────────────────────────────
%   0 = SEARCH trigger
%   1 = COPY   retrigger

% ── Default paths ────────────────────────────────────────────────────────────
WSL = '\\wsl.localhost\Ubuntu-22.04\tmp\';
if nargin < 1 || isempty(short_cor_path)
    short_cor_path    = [WSL 'sync_short_cor.bin'];
end
if nargin < 2 || isempty(det_meta_path)
    det_meta_path     = [WSL 'sync_short_det_meta.bin'];
end
if nargin < 3 || isempty(copy_regions_path)
    copy_regions_path = [WSL 'sync_short_copy_regions.bin'];
end
if nargin < 4 || isempty(long_mag_path)
    long_mag_path     = [WSL 'sync_long_cor_mag.bin'];
end
if nargin < 5 || isempty(long_det_path)
    long_det_path     = [WSL 'sync_long_det.bin'];
end

% ── Load data ────────────────────────────────────────────────────────────────
cor_short  = read_f32(short_cor_path);
det        = load_det_meta(det_meta_path);
regions    = load_copy_regions(copy_regions_path);
cor_long   = read_f32(long_mag_path);
long_peaks = load_long_det(long_det_path);  % Nx2 [peak1 peak2]

% ── Figure with two vertically stacked subplots ──────────────────────────────
fig = figure('Name', 'sync_short + sync_long correlation / detections', ...
             'Color', 'w', 'Units', 'normalized', 'Position', [0.05 0.05 0.90 0.88]);

ax1 = subplot(2, 1, 1);   % sync_short  (top)
ax2 = subplot(2, 1, 2);   % sync_long   (bottom)

% ════════════════════════════════════════════════════════════════════════════
%  TOP PANEL – sync_short
% ════════════════════════════════════════════════════════════════════════════
axes(ax1);
x_short = (0 : numel(cor_short) - 1).';

if ~isempty(cor_short)
    h_corr_s = plot(x_short, cor_short, 'b-', 'LineWidth', 0.6);
else
    h_corr_s = plot(nan, nan, 'b-');
end
grid on;  hold on;
xlabel('sample index  (sync\_short input)');
ylabel('metric');
title('sync\_short  –  correlation + detections + COPY regions');

[y_min_s, y_max_s] = safe_ylim(cor_short);

[h_search_region_s, h_copy_region_s] = ...
    shade_regions_by_state(regions, det, y_min_s, y_max_s);

if ~isempty(det.idx)
    in_range = det.idx >= 0 & det.idx <= (numel(cor_short) - 1);
    idx_p    = det.idx(in_range);
    met_p    = det.metric(in_range);
    thr_p    = det.threshold(in_range);
    st_p     = det.state(in_range);

    valid         = met_p >= thr_p;
    search_valid  = valid & (st_p == 0);
    copy_valid    = valid & (st_p == 1);
    invalid       = ~valid;

    h_sd  = plot(idx_p(search_valid), met_p(search_valid), ...
                 'ro', 'MarkerSize', 7, 'LineWidth', 1.0);
    h_cd  = plot(idx_p(copy_valid),   met_p(copy_valid),   ...
                 'mo', 'MarkerSize', 7, 'LineWidth', 1.0);
    h_inv = plot(idx_p(invalid),      met_p(invalid),      ...
                 'ko', 'MarkerSize', 6, 'LineWidth', 1.0);

    legend(ax1, [h_corr_s h_search_region_s h_copy_region_s h_sd h_cd h_inv], ...
           {'corr', 'SEARCH-start region', 'COPY-retrigger region', ...
            'SEARCH det valid', 'COPY det valid', 'det invalid'}, ...
           'Location', 'best', 'FontSize', 8);
else
    legend(ax1, [h_corr_s h_search_region_s h_copy_region_s], ...
           {'corr', 'SEARCH-start region', 'COPY-retrigger region'}, ...
           'Location', 'best', 'FontSize', 8);
end
hold off;
ylim(ax1, [y_min_s, y_max_s]);

% ════════════════════════════════════════════════════════════════════════════
%  BOTTOM PANEL – sync_long
% ════════════════════════════════════════════════════════════════════════════
axes(ax2);
x_long = (0 : numel(cor_long) - 1).';

if ~isempty(cor_long)
    h_corr_l = plot(x_long, cor_long, 'Color', [0.13 0.55 0.13], 'LineWidth', 0.6);
else
    h_corr_l = plot(nan, nan, 'Color', [0.13 0.55 0.13]);
end
grid on;  hold on;
xlabel('sample index  (sync\_long input = sync\_short output)');
ylabel('|LTS corr|');
title('sync\_long  –  LTS cross-correlation magnitude + LTS peak detections');

[y_min_l, y_max_l] = safe_ylim(cor_long);

% ── Replicate the same region shading from sync_short (same colours/alpha) ──
% We shade by the COPY-region index: each COPY region corresponds to one
% frame handed to sync_long.  We shade bands of equal width (SYNC_LENGTH
% samples each) alternating grey/grey to match the top panel visually.
% If regions data is available we use frame ordering to keep colours in sync.
[h_search_region_l, h_copy_region_l] = ...
    shade_long_by_short_regions(regions, det, numel(cor_long), y_min_l, y_max_l);

% ── LTS peak markers ─────────────────────────────────────────────────────────
h_lts1 = [];
h_lts2 = [];
h_span = [];
if ~isempty(long_peaks)
    for k = 1 : size(long_peaks, 1)
        p1 = long_peaks(k, 1);
        p2 = long_peaks(k, 2);

        % Vertical lines at each peak
        lp1 = xline(p1, '--', 'Color', [0.0  0.65 0.0],  'LineWidth', 1.4, ...
                    'HandleVisibility', 'off');
        lp2 = xline(p2, '-',  'Color', [0.0  0.35 0.0],  'LineWidth', 1.4, ...
                    'HandleVisibility', 'off');

        % Horizontal bracket between peak1 and peak2
        mid_y = y_min_l + 0.92 * (y_max_l - y_min_l);
        bh = plot([p1 p2], [mid_y mid_y], '-', ...
                  'Color', [0.0 0.50 0.0], 'LineWidth', 1.8, ...
                  'HandleVisibility', 'off');

        % Tick marks at bracket ends
        tick_h = 0.025 * (y_max_l - y_min_l);
        plot([p1 p1], [mid_y - tick_h, mid_y + tick_h], '-', ...
             'Color', [0.0 0.50 0.0], 'LineWidth', 1.8, 'HandleVisibility', 'off');
        plot([p2 p2], [mid_y - tick_h, mid_y + tick_h], '-', ...
             'Color', [0.0 0.50 0.0], 'LineWidth', 1.8, 'HandleVisibility', 'off');

        % Label "64" above the bracket
        text((p1 + p2) / 2, mid_y + 2.5 * tick_h, '64', ...
             'HorizontalAlignment', 'center', 'FontSize', 7, ...
             'Color', [0.0 0.35 0.0]);

        % Keep one handle per series for legend
        if isempty(h_lts1),  h_lts1 = lp1;  end
        if isempty(h_lts2),  h_lts2 = lp2;  end
        if isempty(h_span),  h_span  = bh;   end
    end
end

% Build legend entries
leg_handles = h_corr_l;
leg_labels  = {'|LTS corr|'};
if ~isempty(h_search_region_l)
    leg_handles = [leg_handles, h_search_region_l];
    leg_labels{end+1} = 'SEARCH-start region';
end
if ~isempty(h_copy_region_l)
    leg_handles = [leg_handles, h_copy_region_l];
    leg_labels{end+1} = 'COPY-retrigger region';
end
if ~isempty(h_lts1)
    leg_handles = [leg_handles, h_lts1];
    leg_labels{end+1} = 'LTS peak 1';
end
if ~isempty(h_lts2)
    leg_handles = [leg_handles, h_lts2];
    leg_labels{end+1} = 'LTS peak 2';
end
legend(ax2, leg_handles, leg_labels, 'Location', 'best', 'FontSize', 8);

hold off;
ylim(ax2, [y_min_l, y_max_l]);

% ── Summary to console ───────────────────────────────────────────────────────
fprintf('\n── sync_short ──────────────────────────────────────────\n');
fprintf('  Correlation samples : %d\n', numel(cor_short));
fprintf('  Detection records   : %d\n', numel(det.idx));
if ~isempty(det.idx)
    n_valid = nnz(det.metric >= det.threshold);
    fprintf('    valid   : %d\n', n_valid);
    fprintf('    invalid : %d\n', numel(det.idx) - n_valid);
end
fprintf('  COPY regions        : %d\n', size(regions, 1));
fprintf('\n── sync_long ───────────────────────────────────────────\n');
fprintf('  Correlation samples : %d\n', numel(cor_long));
fprintf('  LTS peak pairs      : %d\n', size(long_peaks, 1));
if ~isempty(long_peaks)
    for k = 1 : size(long_peaks, 1)
        fprintf('    [%d]  peak1=%llu  peak2=%llu  diff=%d\n', ...
                k, long_peaks(k,1), long_peaks(k,2), ...
                long_peaks(k,2) - long_peaks(k,1));
    end
end
fprintf('\n');

end % ── main function ──────────────────────────────────────────────────────


% ═══════════════════════════════════════════════════════════════════════════
%  HELPER: shade_long_by_short_regions
%  Draws region shading on the sync_long axes that matches the colour scheme
%  used on the sync_short axes.  The sync_long correlation is segmented
%  (only written during SYNC windows), so we shade the full x-extent in
%  bands, one band per COPY region from sync_short (same colour order).
% ═══════════════════════════════════════════════════════════════════════════
function [h_search_legend, h_copy_legend] = ...
    shade_long_by_short_regions(regions, det, n_long_samples, y_min, y_max)

h_search_legend = [];
h_copy_legend   = [];

% Sentinel legend patches (drawn even if no data)
sentinel_search = plot(nan, nan, 's', ...
    'MarkerFaceColor', [0.76 0.88 1.00], 'MarkerEdgeColor', [0.76 0.88 1.00]);
sentinel_copy   = plot(nan, nan, 's', ...
    'MarkerFaceColor', [0.82 0.82 0.82], 'MarkerEdgeColor', [0.82 0.82 0.82]);

if isempty(regions) || n_long_samples == 0
    h_search_legend = sentinel_search;
    h_copy_legend   = sentinel_copy;
    return;
end

% Determine the state of each region (same logic as sync_short shading)
state_by_start = nan(size(regions, 1), 1);
if ~isempty(det.idx)
    [tf, loc] = ismember(regions(:, 1), det.idx);
    state_by_start(tf) = det.state(loc(tf));
end

% Count how many samples each region "owns" in the sync_short output.
% Approximation: each COPY region spans (end_excl - start) short-output
% samples (sync_short produces 1 output per consumed input in COPY state).
region_lengths = regions(:, 2) - regions(:, 1);   % in short-input samples
total_short    = sum(region_lengths);
if total_short == 0
    h_search_legend = sentinel_search;
    h_copy_legend   = sentinel_copy;
    return;
end

% Map region extents onto the sync_long x-axis proportionally.
long_x = 0;
copy_count   = 0;
search_seen  = false;
copy_seen    = false;

for k = 1 : size(regions, 1)
    frac   = region_lengths(k) / total_short;
    band_w = frac * n_long_samples;
    x1     = long_x;
    x2     = long_x + band_w;
    long_x = x2;

    st = state_by_start(k);
    if st == 0
        color_rgb = [0.76 0.88 1.00];
        alpha      = 0.22;
        search_seen = true;
    elseif st == 1
        copy_count = copy_count + 1;
        if mod(copy_count, 2) == 1
            color_rgb = [0.86 0.86 0.86];
        else
            color_rgb = [0.78 0.78 0.78];
        end
        alpha    = 0.20;
        copy_seen = true;
    else
        color_rgb = [0.90 0.90 0.90];
        alpha     = 0.15;
    end

    h = patch([x1 x2 x2 x1], [y_min y_min y_max y_max], color_rgb, ...
              'FaceAlpha', alpha, 'EdgeColor', 'none');

    if st == 0 && isempty(h_search_legend)
        h_search_legend = h;
        delete(sentinel_search);
        sentinel_search = [];
    elseif st == 1 && isempty(h_copy_legend)
        h_copy_legend = h;
        delete(sentinel_copy);
        sentinel_copy = [];
    end
end

% Fall back to sentinels if we never saw a matching state
if isempty(h_search_legend)
    h_search_legend = sentinel_search;
    if ~search_seen && ~isempty(sentinel_search)
        % grey sentinel  (state never seen)
        set(sentinel_search, 'MarkerFaceColor', [0.85 0.85 0.85], ...
                              'MarkerEdgeColor', [0.85 0.85 0.85]);
    end
else
    if ~isempty(sentinel_search), delete(sentinel_search); end
end
if isempty(h_copy_legend)
    h_copy_legend = sentinel_copy;
    if ~copy_seen && ~isempty(sentinel_copy)
        set(sentinel_copy, 'MarkerFaceColor', [0.85 0.85 0.85], ...
                            'MarkerEdgeColor', [0.85 0.85 0.85]);
    end
else
    if ~isempty(sentinel_copy), delete(sentinel_copy); end
end
end


% ═══════════════════════════════════════════════════════════════════════════
%  HELPER: shade_regions_by_state  (sync_short panel – unchanged from v3)
% ═══════════════════════════════════════════════════════════════════════════
function [h_search_legend, h_copy_legend] = ...
    shade_regions_by_state(regions, det, y_min, y_max)

h_search_legend = [];
h_copy_legend   = [];

if isempty(regions)
    h_search_legend = plot(nan, nan, 's', ...
        'MarkerFaceColor', [0.76 0.88 1.00], 'MarkerEdgeColor', [0.76 0.88 1.00]);
    h_copy_legend   = plot(nan, nan, 's', ...
        'MarkerFaceColor', [0.82 0.82 0.82], 'MarkerEdgeColor', [0.82 0.82 0.82]);
    return;
end

state_by_start = nan(size(regions, 1), 1);
if ~isempty(det.idx)
    [tf, loc] = ismember(regions(:, 1), det.idx);
    state_by_start(tf) = det.state(loc(tf));
end

copy_count  = 0;
search_seen = false;
copy_seen   = false;

for k = 1 : size(regions, 1)
    x1 = regions(k, 1);
    x2 = regions(k, 2) - 1;
    if x2 < x1, continue; end

    st = state_by_start(k);
    if st == 0
        color_rgb   = [0.76 0.88 1.00];
        alpha        = 0.22;
        search_seen  = true;
    elseif st == 1
        copy_count   = copy_count + 1;
        color_rgb    = [0.86 0.86 0.86] - mod(copy_count+1,2)*[0.08 0.08 0.08];
        alpha        = 0.20;
        copy_seen    = true;
    else
        color_rgb    = [0.90 0.90 0.90];
        alpha        = 0.15;
    end

    h = patch([x1 x2 x2 x1], [y_min y_min y_max y_max], color_rgb, ...
              'FaceAlpha', alpha, 'EdgeColor', 'none');

    if st == 0 && isempty(h_search_legend),  h_search_legend = h;  end
    if st == 1 && isempty(h_copy_legend),    h_copy_legend   = h;  end
end

if isempty(h_search_legend)
    c = [0.76 0.88 1.00]; if ~search_seen, c = [0.85 0.85 0.85]; end
    h_search_legend = plot(nan, nan, 's', 'MarkerFaceColor', c, 'MarkerEdgeColor', c);
end
if isempty(h_copy_legend)
    c = [0.82 0.82 0.82]; if ~copy_seen,   c = [0.85 0.85 0.85]; end
    h_copy_legend   = plot(nan, nan, 's', 'MarkerFaceColor', c, 'MarkerEdgeColor', c);
end
end


% ═══════════════════════════════════════════════════════════════════════════
%  I/O HELPERS
% ═══════════════════════════════════════════════════════════════════════════
function v = read_f32(path)
fid = fopen(path, 'rb');
if fid < 0
    warning('Could not open %s', path);
    v = [];
    return;
end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
v = fread(fid, inf, 'single=>double');
end

function det = load_det_meta(path)
det.idx = []; det.metric = []; det.threshold = []; det.state = []; det.copied = [];
fid = fopen(path, 'rb');
if fid < 0, warning('Could not open %s', path); return; end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
idx=[]; metric=[]; threshold=[]; state=[]; copied=[];
while true
    a = fread(fid, 1, 'uint64=>double'); if isempty(a), break; end
    b = fread(fid, 1, 'single=>double');
    c = fread(fid, 1, 'single=>double');
    d = fread(fid, 1, 'uint8=>double');
    e = fread(fid, 1, 'uint32=>double');
    if isempty(b)||isempty(c)||isempty(d)||isempty(e), break; end
    idx(end+1,1)=a; metric(end+1,1)=b; threshold(end+1,1)=c; %#ok<AGROW>
    state(end+1,1)=d; copied(end+1,1)=e; %#ok<AGROW>
end
det.idx=idx; det.metric=metric; det.threshold=threshold;
det.state=state; det.copied=copied;
end

function regions = load_copy_regions(path)
fid = fopen(path, 'rb');
if fid < 0, warning('Could not open %s', path); regions=zeros(0,2); return; end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
r = fread(fid, [2 inf], 'uint64=>double').';
if isempty(r), regions=zeros(0,2); return; end
regions = r;
end

function peaks = load_long_det(path)
% Returns Nx2 matrix of [peak1 peak2] uint64 pairs.
fid = fopen(path, 'rb');
if fid < 0, warning('Could not open %s', path); peaks=zeros(0,2); return; end
cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
r = fread(fid, [2 inf], 'uint64=>double').';
if isempty(r), peaks=zeros(0,2); return; end
peaks = r;
end

function [y_min, y_max] = safe_ylim(v)
if isempty(v)
    y_min = -1; y_max = 1; return;
end
y_min = min(v);
y_max = max(v);
if y_min == y_max
    y_min = y_min - 1;
    y_max = y_max + 1;
end
% Add 5% headroom at top for bracket labels
y_max = y_max + 0.08 * (y_max - y_min);
end