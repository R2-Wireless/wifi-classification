function plot_snr_comparison_old_2(dump_dir, options)
% PLOT_SNR_COMPARISON  Plot sync_short + sync_long dumps for ALL cfile recordings
%   overlaid or stacked, colour-coded by SNR, to visualise the SNR impact.
%
% Usage:
%   plot_snr_comparison(dump_dir)
%   plot_snr_comparison(dump_dir, options)
%
% Arguments:
%   dump_dir  - path to the dump folder produced by enhanced_frame_analyzer_v3.py
%               with --dump-bin  (default: '/tmp')
%
% Options struct fields (all optional):
%   .overlay          true  = all files in ONE axes (default)
%                     false = one subplot row per file (stacked)
%   .alpha            line alpha for overlay mode  (default 0.55)
%   .sort_by_snr      sort legend / colour map by SNR  (default true)
%   .show_detections  mark detection points           (default true)
%   .show_regions     shade COPY regions              (default true)
%   .show_long        also plot sync_long panel       (default true)
%   .snr_source       'filename'  – parse SNR from filename token snrXXdB
%                     'detmeta'   – estimate from correlation peak heights (default)
%   .colormap         any valid MATLAB colormap name   (default 'turbo')
%   .file_filter      glob pattern applied to prefix names (default '*')
%
% File naming expected (produced by enhanced_frame_analyzer_v3.py):
%   {prefix}_short_cor.bin          float32  correlation metric
%   {prefix}_short_det_meta.bin     struct   {uint64 idx, float metric,
%                                             float thr, uint8 state,
%                                             uint32 copied, uint64 frame_id}
%   {prefix}_short_copy_regions.txt binary   pairs {uint64 start, uint64 end}
%   {prefix}_long_mag.bin           float32  |correlation| samples
%   {prefix}_long_det.bin           uint64   detected peak indices
%   {prefix}_long_det_meta.bin      uint64[] triplets {frame_id, peak1, peak2}

% -------------------------------------------------------------------------
% Defaults
% -------------------------------------------------------------------------
if nargin < 1 || isempty(dump_dir)
    dump_dir = 'C:\Users\Public\Documents\Wify\Py_script\cfiles\snr_test\dumps\';
end
if nargin < 2 || isempty(options)
    options = struct();
end

opt = parse_options(options);

% Force char so fullfile/[] concatenation never produces a 1×2 string array
% (happens when caller passes a double-quoted string literal).
dump_dir = char(dump_dir);

% -------------------------------------------------------------------------
% Discover file prefixes
% -------------------------------------------------------------------------
listing = dir(fullfile(dump_dir, '*_short_cor.bin'));
if isempty(listing)
    error('No *_short_cor.bin files found in: %s', dump_dir);
end

prefixes = cell(numel(listing), 1);
for k = 1:numel(listing)
    fname = listing(k).name;
    prefixes{k} = fname(1:end - length('_short_cor.bin'));
end

% Apply optional filter
if ~strcmp(opt.file_filter, '*')
    keep = cellfun(@(p) ~isempty(regexp(p, glob2regexp(opt.file_filter), 'once')), prefixes);
    prefixes = prefixes(keep);
end

if isempty(prefixes)
    error('No files matched filter "%s" in %s', opt.file_filter, dump_dir);
end

n_files = numel(prefixes);
fprintf('Found %d file set(s) in %s\n', n_files, dump_dir);

% -------------------------------------------------------------------------
% Load all datasets
% -------------------------------------------------------------------------
datasets = cell(n_files, 1);
for k = 1:n_files
    datasets{k} = load_dataset(dump_dir, prefixes{k}, opt);
    fprintf('  [%d/%d] %s  est_snr=%.1f dB  detections=%d\n', ...
            k, n_files, prefixes{k}, datasets{k}.snr_db, datasets{k}.n_det);
end

% Sort by SNR if requested
if opt.sort_by_snr
    snrs = cellfun(@(d) d.snr_db, datasets);
    [~, idx] = sort(snrs);
    datasets = datasets(idx);
    prefixes = prefixes(idx);
end

% -------------------------------------------------------------------------
% Build colour map: low SNR -> red/orange, high SNR -> green/blue
% -------------------------------------------------------------------------
cmap = feval(opt.colormap, max(n_files, 2));
% map index 1 = lowest SNR, index end = highest SNR
colors = cmap;  % already in SNR order after sorting

% -------------------------------------------------------------------------
% Plot
% -------------------------------------------------------------------------
if opt.overlay
    plot_overlay(datasets, prefixes, colors, opt);
else
    plot_stacked(datasets, prefixes, colors, opt);
end

end % main function

% =========================================================================
%  PLOT OVERLAY MODE
% =========================================================================
function plot_overlay(datasets, prefixes, colors, opt)

n_files = numel(datasets);
n_panels = 1 + opt.show_long;

fig = figure('Name', 'SNR comparison – sync correlation (overlay)', ...
             'Color', 'w');%, 'Position', [60 60 1400 600 * n_panels]);
tl = tiledlayout(n_panels, 1, 'TileSpacing', 'compact', 'Padding', 'compact');
title(tl, ['sync\_short/sync\_long correlation – ' num2str(n_files) ' files overlaid, colour = SNR'], ...
      'FontSize', 13);

ax_short = nexttile(tl);
hold(ax_short, 'on');
grid(ax_short, 'on');
xlabel(ax_short, 'sample index');
ylabel(ax_short, 'short correlation metric');
title(ax_short, 'sync\_short – all files overlaid');

if opt.show_long
    ax_long = nexttile(tl);
    hold(ax_long, 'on');
    grid(ax_long, 'on');
    xlabel(ax_long, 'sample index');
    ylabel(ax_long, '|sync\_long correlation|');
    title(ax_long, 'sync\_long – all files overlaid');
end

legend_handles = gobjects(n_files, 1);
legend_labels  = cell(n_files, 1);

for k = 1:n_files
    ds   = datasets{k};
    col  = colors(k, :);
    alp  = opt.alpha;
    lbl  = sprintf('%s  (%.1f dB)', shorten_prefix(prefixes{k}), ds.snr_db);

    % ---- short correlation ----
    if ~isempty(ds.cor)
        x = (0:numel(ds.cor)-1).';
        h = plot(ax_short, x, ds.cor, '-', 'Color', [col alp], 'LineWidth', 1.0);
        legend_handles(k) = h;
        legend_labels{k}  = lbl;
    end

    % ---- detection markers (short) ----
    if opt.show_detections && ~isempty(ds.det.idx)
        valid = ds.det.metric >= ds.det.threshold;
        plot(ax_short, ds.det.idx(valid), ds.det.metric(valid), ...
             'o', 'Color', col, 'MarkerSize', 5, 'LineWidth', 1.0, ...
             'MarkerFaceColor', col);
        if any(~valid)
            plot(ax_short, ds.det.idx(~valid), ds.det.metric(~valid), ...
                 'x', 'Color', col * 0.6, 'MarkerSize', 5, 'LineWidth', 1.0);
        end
    end

    % ---- shade COPY regions (short) ----
    if opt.show_regions && ~isempty(ds.regions) && ~isempty(ds.cor)
        y_lim = [min(ds.cor(:)), max(ds.cor(:))];
        if y_lim(1) == y_lim(2), y_lim = y_lim + [-1 1]; end
        shade_regions(ax_short, ds.regions, y_lim, col, 0.08);
    end

    % ---- sync_long ----
    if opt.show_long && ~isempty(ds.long_cor)
        xl = (0:numel(ds.long_cor)-1).';
        plot(ax_long, xl, ds.long_cor, '-', 'Color', [col alp], 'LineWidth', 1.0);

        if opt.show_detections && ~isempty(ds.long_det)
            valid_idx = ds.long_det(ds.long_det >= 0 & ds.long_det < numel(ds.long_cor)) + 1;
            if ~isempty(valid_idx)
                plot(ax_long, valid_idx - 1, ds.long_cor(valid_idx), ...
                     'o', 'Color', col, 'MarkerSize', 5, 'LineWidth', 1.0, ...
                     'MarkerFaceColor', col);
            end
        end
    end
end

% Threshold reference line on short panel (use first dataset)
if ~isempty(datasets) && ~isempty(datasets{1}.det.threshold)
    thr_val = mean(datasets{1}.det.threshold);
    yline(ax_short, thr_val, '--k', sprintf('thr=%.3f', thr_val), ...
          'LabelVerticalAlignment', 'bottom', 'LineWidth', 1.2);
end

% Legend
valid_h = legend_handles(arrayfun(@(h) ishandle(h) && h ~= 0, legend_handles));
valid_l = legend_labels(arrayfun(@(h) ishandle(h) && h ~= 0, legend_handles));
if ~isempty(valid_h)
    legend(ax_short, valid_h, valid_l, 'Location', 'best', 'FontSize', 7, ...
           'Interpreter', 'none');
end

% Colourbar as SNR scale
add_snr_colorbar(fig, datasets, opt.colormap);

fprintf('\nOverlay plot complete.  %d file sets shown.\n', n_files);

end % plot_overlay

% =========================================================================
%  PLOT STACKED (one row per file)
% =========================================================================
function plot_stacked(datasets, prefixes, colors, opt)

n_files = numel(datasets);
n_panels_per_file = 1 + opt.show_long;
n_rows = n_files * n_panels_per_file;

fig = figure('Name', 'SNR comparison – sync correlation (stacked)', ...
             'Color', 'w', ...
             'Position', [60 60 1400 max(300, 220 * n_rows)]);
tl = tiledlayout(n_rows, 1, 'TileSpacing', 'compact', 'Padding', 'compact');
title(tl, 'sync\_short/sync\_long – one row per file, sorted by SNR (low→high)', ...
      'FontSize', 12);

for k = 1:n_files
    ds  = datasets{k};
    col = colors(k, :);
    ttl = sprintf('%s  |  SNR ≈ %.1f dB  |  dets=%d', ...
                  shorten_prefix(prefixes{k}), ds.snr_db, ds.n_det);

    % --- short panel ---
    ax = nexttile(tl);
    hold(ax, 'on'); grid(ax, 'on');
    ylabel(ax, 'metric');
    title(ax, ['short: ' ttl], 'Interpreter', 'none', 'FontSize', 8);

    if ~isempty(ds.cor)
        x = (0:numel(ds.cor)-1).';
        plot(ax, x, ds.cor, '-', 'Color', col, 'LineWidth', 0.8);

        if opt.show_regions && ~isempty(ds.regions)
            y_lim = [min(ds.cor), max(ds.cor)];
            if y_lim(1) == y_lim(2), y_lim = y_lim + [-1 1]; end
            shade_regions(ax, ds.regions, y_lim, col, 0.15);
        end

        if opt.show_detections && ~isempty(ds.det.idx)
            valid = ds.det.metric >= ds.det.threshold;
            plot(ax, ds.det.idx(valid), ds.det.metric(valid), 'o', ...
                 'Color', col, 'MarkerSize', 4, 'MarkerFaceColor', col);
            if any(~valid)
                plot(ax, ds.det.idx(~valid), ds.det.metric(~valid), 'x', ...
                     'Color', col * 0.5, 'MarkerSize', 4);
            end
        end

        if ~isempty(ds.det.threshold)
            yline(ax, mean(ds.det.threshold), '--k', 'LineWidth', 0.9);
        end
    end

    if k == n_files, xlabel(ax, 'sample index'); end

    % --- long panel ---
    if opt.show_long
        axl = nexttile(tl);
        hold(axl, 'on'); grid(axl, 'on');
        ylabel(axl, '|corr|');
        title(axl, ['long: ' ttl], 'Interpreter', 'none', 'FontSize', 8);

        if ~isempty(ds.long_cor)
            xl = (0:numel(ds.long_cor)-1).';
            plot(axl, xl, ds.long_cor, '-', 'Color', col, 'LineWidth', 0.8);

            if opt.show_detections && ~isempty(ds.long_det)
                vi = ds.long_det(ds.long_det >= 0 & ds.long_det < numel(ds.long_cor)) + 1;
                if ~isempty(vi)
                    plot(axl, vi - 1, ds.long_cor(vi), 'o', ...
                         'Color', col, 'MarkerSize', 4, 'MarkerFaceColor', col);
                end
            end
        end

        if k == n_files, xlabel(axl, 'sample index'); end
    end
end

add_snr_colorbar(fig, datasets, opt.colormap);
fprintf('\nStacked plot complete.  %d file sets shown.\n', n_files);

end % plot_stacked

% =========================================================================
%  LOAD ONE DATASET
% =========================================================================
function ds = load_dataset(dump_dir, prefix, opt)

% Force char so that [] concatenation below always produces a single
% string, not a 1×2 string array (which happens when fullfile() returns
% a MATLAB string type instead of char).
base = char(fullfile(char(dump_dir), char(prefix)));

ds.prefix   = prefix;
ds.cor      = read_f32([base '_short_cor.bin']);
ds.det      = load_det_meta([base '_short_det_meta.bin']);
ds.regions  = load_copy_regions([base '_short_copy_regions.txt']);
ds.long_cor = read_f32([base '_long_mag.bin']);
ds.long_det = load_u64([base '_long_det.bin']);
ds.n_det    = numel(ds.det.idx);

% ---- Estimate SNR --------------------------------------------------------
if strcmp(opt.snr_source, 'filename')
    ds.snr_db = parse_snr_from_name(prefix);
else
    ds.snr_db = estimate_snr_from_peaks(ds);
end

end

% =========================================================================
%  SNR ESTIMATION helpers
% =========================================================================
function snr = parse_snr_from_name(prefix)
% Try to find token like snr10dB, snr-5dB, snr+3dB, snr10 in prefix
m = regexp(prefix, 'snr([+-]?\d+(?:\.\d+)?)', 'tokens', 'ignorecase', 'once');
if ~isempty(m)
    snr = str2double(m{1});
else
    % fallback: extract any trailing number
    m2 = regexp(prefix, '(\d+(?:\.\d+)?)(?:db)?$', 'tokens', 'ignorecase', 'once');
    if ~isempty(m2)
        snr = str2double(m2{1});
    else
        snr = NaN;
    end
end
if isnan(snr)
    snr = 0;
    warning('Could not parse SNR from prefix: %s  (using 0 dB)', prefix);
end
end

function snr = estimate_snr_from_peaks(ds)
% Heuristic: use the 90th percentile of valid detection metric values
% as a rough proxy for "signal strength". In practice correlation peaks
% grow with SNR, so sorting files by this value gives a meaningful order.
if ~isempty(ds.det.metric) && ~isempty(ds.det.threshold)
    valid = ds.det.metric >= ds.det.threshold;
    if any(valid)
        snr = prctile(ds.det.metric(valid), 90);
        return;
    end
end
% Fallback: 90th percentile of full short correlation
if ~isempty(ds.cor)
    snr = prctile(ds.cor, 90);
    return;
end
snr = 0;
end

% =========================================================================
%  PLOTTING helpers
% =========================================================================
function shade_regions(ax, regions, y_lim, color, alpha)
for k = 1:size(regions, 1)
    x1 = regions(k, 1);
    x2 = regions(k, 2) - 1;
    if x2 < x1, continue; end
    patch(ax, [x1 x2 x2 x1], [y_lim(1) y_lim(1) y_lim(2) y_lim(2)], ...
          color, 'FaceAlpha', alpha, 'EdgeColor', 'none');
end
end

function add_snr_colorbar(fig, datasets, cmap_name)
% Add a fake axes with a colourbar to show the SNR → colour mapping.
snrs = cellfun(@(d) d.snr_db, datasets);
if numel(unique(snrs)) < 2, return; end

ax_cb = axes(fig, 'Visible', 'off', 'Position', [0.93 0.1 0.01 0.8]);
cmap  = feval(cmap_name, 256);
colormap(ax_cb, cmap);
cb = colorbar(ax_cb, 'Location', 'eastoutside');
clim(ax_cb, [min(snrs) max(snrs)]);
cb.Label.String = 'Estimated SNR (dB)';
cb.Label.FontSize = 10;
end

function s = shorten_prefix(p)
% Keep last two underscore-separated tokens to avoid huge legend text
parts = strsplit(p, '__');
if numel(parts) >= 2
    s = strjoin(parts(end-1:end), '__');
else
    s = p;
end
if numel(s) > 40
    s = ['…' s(end-38:end)];
end
end

% =========================================================================
%  BINARY FILE READERS  (same logic as plot_sync_short_debug_3.m)
% =========================================================================
function v = read_f32(path)
path = char(path);   % guard: char() collapses a 1×2 string array to a proper path
fid = fopen(path, 'rb');
if fid < 0
    v = [];
    return;
end
cleanup = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'single=>double');
end

function det = load_det_meta(path)
det.idx = []; det.metric = []; det.threshold = [];
det.state = []; det.copied = []; det.frame_id = [];
det.tag_output_idx = []; det.has_tag_output_idx = false;

path = char(path);
fid = fopen(path, 'rb');
if fid < 0, return; end
cleanup = onCleanup(@() fclose(fid));

fseek(fid, 0, 'eof');
nbytes = ftell(fid);
fseek(fid, 0, 'bof');

rec_v3 = 37;  % v2 + uint64 tag_output_idx
rec_v2 = 29;  % uint64 + float + float + uint8 + uint32 + uint64
rec_v1 = 21;  % uint64 + float + float + uint8 + uint32
if mod(nbytes, rec_v3) == 0 && nbytes > 0
    rec_bytes = rec_v3; has_fid = true; has_tag_output_idx = true;
elseif mod(nbytes, rec_v2) == 0 && nbytes > 0
    rec_bytes = rec_v2; has_fid = true; has_tag_output_idx = false;
elseif mod(nbytes, rec_v1) == 0 && nbytes > 0
    rec_bytes = rec_v1; has_fid = false; has_tag_output_idx = false;
else
    rec_bytes = rec_v1; has_fid = false; has_tag_output_idx = false;
end

nrec = floor(nbytes / rec_bytes);
if nrec == 0, return; end

idx = zeros(nrec,1); metric = zeros(nrec,1);
threshold = zeros(nrec,1); state = zeros(nrec,1);
copied = zeros(nrec,1); frame_id = nan(nrec,1); tag_output_idx = nan(nrec,1);

for k = 1:nrec
    idx(k)       = fread(fid, 1, 'uint64=>double');
    metric(k)    = fread(fid, 1, 'single=>double');
    threshold(k) = fread(fid, 1, 'single=>double');
    state(k)     = fread(fid, 1, 'uint8=>double');
    copied(k)    = fread(fid, 1, 'uint32=>double');
    if has_fid
        frame_id(k) = fread(fid, 1, 'uint64=>double');
    end
    if has_tag_output_idx
        tag_output_idx(k) = fread(fid, 1, 'uint64=>double');
    end
end

det.idx = idx; det.metric = metric; det.threshold = threshold;
det.state = state; det.copied = copied; det.frame_id = frame_id;
det.tag_output_idx = tag_output_idx;
det.has_tag_output_idx = has_tag_output_idx;
end

function regions = load_copy_regions(path)
% Note: the file uses extension .txt but contains raw binary uint64 pairs.
path = char(path);
fid = fopen(path, 'rb');
if fid < 0
    regions = zeros(0, 2);
    return;
end
cleanup = onCleanup(@() fclose(fid));
r = fread(fid, [2 inf], 'uint64=>double').';
if isempty(r)
    regions = zeros(0, 2);
else
    regions = r;
end
end

function v = load_u64(path)
path = char(path);
fid = fopen(path, 'rb');
if fid < 0, v = []; return; end
cleanup = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'uint64=>double');
end

% =========================================================================
%  OPTIONS PARSER
% =========================================================================
function opt = parse_options(s)
opt.overlay         = getfield_default(s, 'overlay',         true);
opt.alpha           = getfield_default(s, 'alpha',           0.55);
opt.sort_by_snr     = getfield_default(s, 'sort_by_snr',     true);
opt.show_detections = getfield_default(s, 'show_detections', true);
opt.show_regions    = getfield_default(s, 'show_regions',    true);
opt.show_long       = getfield_default(s, 'show_long',       true);
opt.snr_source      = getfield_default(s, 'snr_source',      'detmeta');
opt.colormap        = getfield_default(s, 'colormap',        'turbo');
opt.file_filter     = getfield_default(s, 'file_filter',     '*');
end

function v = getfield_default(s, field, default)
if isfield(s, field)
    v = s.(field);
else
    v = default;
end
end

% =========================================================================
%  GLOB → REGEXP  (simple: * → .*)
% =========================================================================
function r = glob2regexp(g)
r = ['^' strrep(strrep(regexprep(g, '\.', '\\.'), '*', '.*'), '?', '.') '$'];
end
