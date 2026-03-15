function plot_snr_comparison_old(dump_dir, options)
% PLOT_SNR_COMPARISON  Plot sync_short + sync_long dumps for ALL cfile recordings
%   overlaid or stacked, colour-coded by SNR, with BOTH panels sharing the
%   same absolute input-sample x-axis.
%
% Usage:
%   plot_snr_comparison(dump_dir)
%   plot_snr_comparison(dump_dir, options)
%
% Arguments:
%   dump_dir  - path to the dump folder produced by enhanced_frame_analyzer_v3.py
%               with --dump-bin  (default: current dir)
%
% Options struct fields (all optional):
%   .overlay          true  = all files in ONE axes (default)
%                     false = one subplot row per file (stacked)
%   .alpha            line alpha for overlay mode  (default 0.55)
%   .sort_by_snr      sort legend / colour map by SNR  (default true)
%   .show_detections  mark detection points           (default true)
%   .show_regions     shade COPY regions              (default true)
%   .show_long        also plot sync_long panel       (default true)
%   .snr_source       'filename'  - parse SNR from filename token SNR_XX_dB
%                     'detmeta'   - estimate from correlation peak heights
%                     'auto'      - try filename first, fall back to detmeta (DEFAULT)
%   .colormap         any valid MATLAB colormap name  (default 'turbo')
%   .file_filter      glob pattern applied to prefix names (default '*')
%
% ALIGNED X-AXIS (sync_long)
% --------------------------
% If the modified sync_long.cc is used (dumps _long_mag_abs.bin with
% {uint64 sl_idx, float32 mag} records) AND the modified sync_short.cc
% is used (det_meta v3 with tag_output_idx field), the sync_long panel
% is mapped to the same absolute sample index as sync_short so both
% panels share a common x-axis and linkaxes() zoom stays in sync.
%
% If only the old _long_mag.bin exists (float32 only), the sync_long
% panel falls back to its local correlation-output counter x-axis with
% a warning label (old behaviour).
%
% New dump files (produced when WIFI_DUMP_CORR=1 with modified C++):
%   {prefix}_long_mag_abs.bin   repeated { uint64 sl_idx, float32 mag }
%
% Existing files (unchanged):
%   {prefix}_short_cor.bin          float32  correlation metric
%   {prefix}_short_det_meta.bin     v3 struct (37 bytes each):
%                                     uint64 abs_input_idx
%                                     float32 metric, float32 threshold
%                                     uint8 state, uint32 copied
%                                     uint64 frame_id, uint64 tag_output_idx  <- NEW
%   {prefix}_short_copy_regions.txt binary pairs {uint64 start, uint64 end}
%   {prefix}_long_mag.bin           float32 fallback (old format)
%   {prefix}_long_det.bin           uint64 detected peak indices

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

% Force char so fullfile/[] never produces a 1x2 string array
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
    fname       = listing(k).name;
    prefixes{k} = fname(1:end - length('_short_cor.bin'));
end

% Apply optional glob filter
if ~strcmp(opt.file_filter, '*')
    keep     = cellfun(@(p) ~isempty(regexp(p, glob2regexp(opt.file_filter), 'once')), prefixes);
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
    fprintf('  [%d/%d] %-55s  SNR=%+.1f dB  dets=%d  long_aligned=%s\n', ...
            k, n_files, prefixes{k}, datasets{k}.snr_db, datasets{k}.n_det, ...
            string(datasets{k}.long_aligned));
end

% -------------------------------------------------------------------------
% Sort by SNR (ascending: lowest SNR first = index 1 in colourmap)
% -------------------------------------------------------------------------
if opt.sort_by_snr
    snrs     = cellfun(@(d) d.snr_db, datasets);
    [~, idx] = sort(snrs);
    datasets = datasets(idx);
    prefixes = prefixes(idx);
end

% -------------------------------------------------------------------------
% Build colour map
% -------------------------------------------------------------------------
cmap   = feval(opt.colormap, max(n_files, 2));
colors = cmap;

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

n_files  = numel(datasets);
n_panels = 1 + opt.show_long;

fig = figure('Name', 'SNR comparison - sync correlation (overlay)', ...
             'Color', 'w');
tl = tiledlayout(n_panels, 1, 'TileSpacing', 'compact', 'Padding', 'compact');
title(tl, ['sync\_short + sync\_long — ' num2str(n_files) ...
           ' files overlaid, colour = SNR'], 'FontSize', 13);

% Check whether ANY dataset has aligned long data
any_aligned = any(cellfun(@(d) d.long_aligned, datasets));

% ---- sync_short panel ---------------------------------------------------
ax_short = nexttile(tl);
hold(ax_short, 'on');  grid(ax_short, 'on');
xlabel(ax_short, 'absolute input sample index');
ylabel(ax_short, 'short correlation metric');
title(ax_short, 'sync\_short  —  all files overlaid');

% ---- sync_long panel (optional) -----------------------------------------
if opt.show_long
    ax_long = nexttile(tl);
    hold(ax_long, 'on');  grid(ax_long, 'on');
    xlabel(ax_long, 'absolute input sample index');
    ylabel(ax_long, '|sync\_long correlation|');
    if any_aligned
        title(ax_long, 'sync\_long  —  aligned to absolute sample index');
    else
        title(ax_long, ['sync\_long  —  local correlation-output index  ' ...
                        '(recompile sync\_long.cc for alignment)']);
    end
end

legend_handles = gobjects(n_files, 1);
legend_labels  = cell(n_files, 1);

for k = 1:n_files
    ds  = datasets{k};
    col = colors(k, :);
    alp = opt.alpha;
    lbl = make_legend_label(prefixes{k}, ds.snr_db);

    % ---- short correlation line ----
    if ~isempty(ds.cor)
        x = (0:numel(ds.cor)-1).';
        h = plot(ax_short, x, ds.cor, '-', 'Color', [col alp], 'LineWidth', 1.0);
        legend_handles(k) = h;
        legend_labels{k}  = lbl;
    end

    % ---- detection markers (short) ----
    if opt.show_detections && ~isempty(ds.det.idx)
        valid = ds.det.metric >= ds.det.threshold;
        if any(valid)
            plot(ax_short, ds.det.idx(valid), ds.det.metric(valid), ...
                 'o', 'Color', col, 'MarkerSize', 5, 'LineWidth', 1.0, ...
                 'MarkerFaceColor', col);
        end
        if any(~valid)
            plot(ax_short, ds.det.idx(~valid), ds.det.metric(~valid), ...
                 'x', 'Color', col * 0.6, 'MarkerSize', 5, 'LineWidth', 1.0);
        end
    end

    % ---- shade COPY regions (short) ----
    if opt.show_regions && ~isempty(ds.regions) && ~isempty(ds.cor)
        yl = [safe_min(ds.cor), safe_max(ds.cor)];
        if yl(1) == yl(2), yl = yl + [-1 1]; end
        shade_regions(ax_short, ds.regions, yl, col, 0.08);
    end

    % ---- sync_long ----
    if opt.show_long
        if ds.long_aligned && ~isempty(ds.long_abs_x)
            % ── ALIGNED: plot at absolute sample positions ──────────────
            valid_pts = ~isnan(ds.long_abs_x);
            if any(valid_pts)
                plot(ax_long, ds.long_abs_x(valid_pts), ds.long_mag(valid_pts), ...
                     '-', 'Color', [col alp], 'LineWidth', 1.0);
            end
            if opt.show_detections
                mark_long_peaks_abs(ax_long, ds, col);
            end
        elseif ~isempty(ds.long_cor)
            % ── FALLBACK: local counter x-axis ──────────────────────────
            xl = (0:numel(ds.long_cor)-1).';
            plot(ax_long, xl, ds.long_cor, '-', 'Color', [col alp], ...
                 'LineWidth', 1.0, 'LineStyle', '--');  % dashed = unaligned

            if opt.show_detections && ~isempty(ds.long_det)
                n_lc = numel(ds.long_cor);
                vi   = ds.long_det(ds.long_det >= 0 & ds.long_det < n_lc) + 1;
                if ~isempty(vi)
                    plot(ax_long, vi - 1, ds.long_cor(vi), ...
                         'o', 'Color', col, 'MarkerSize', 5, 'LineWidth', 1.0, ...
                         'MarkerFaceColor', col);
                end
            end
        end
    end
end

% Threshold reference line(s)
all_thr    = cellfun(@(d) mean_or_nan(d.det.threshold), datasets);
unique_thr = unique(all_thr(~isnan(all_thr)));
for t = unique_thr(:).'
    yline(ax_short, t, '--k', sprintf('thr=%.3f', t), ...
          'LabelVerticalAlignment', 'bottom', 'LineWidth', 1.2);
end

% Legend
valid_mask = arrayfun(@(h) ishandle(h) && h ~= 0, legend_handles);
if any(valid_mask)
    legend(ax_short, legend_handles(valid_mask), legend_labels(valid_mask), ...
           'Location', 'northeast', 'FontSize', 7, 'Interpreter', 'none');
end

% Link x-axes when long panel is aligned so zoom stays synchronised
if opt.show_long && any_aligned
    linkaxes([ax_short ax_long], 'x');
    fprintf('  [info] Axes linked — zoom/pan on either panel moves both.\n');
end

add_snr_colorbar(fig, datasets, opt.colormap);
fprintf('\nOverlay plot complete.  %d file sets shown.\n', n_files);

end % plot_overlay


% =========================================================================
%  PLOT STACKED (one row per file, sorted low->high SNR)
% =========================================================================
function plot_stacked(datasets, prefixes, colors, opt)

n_files           = numel(datasets);
n_panels_per_file = 1 + opt.show_long;
n_rows            = n_files * n_panels_per_file;

fig = figure('Name', 'SNR comparison - sync correlation (stacked)', ...
             'Color', 'w', 'Position', [60 60 1400 max(300, 220 * n_rows)]);
tl = tiledlayout(n_rows, 1, 'TileSpacing', 'compact', 'Padding', 'compact');
title(tl, 'sync\_short + sync\_long — one row per file, sorted by SNR (low to high)', ...
      'FontSize', 12);

for k = 1:n_files
    ds  = datasets{k};
    col = colors(k, :);
    ttl = sprintf('%s  |  SNR = %+.1f dB  |  dets=%d', ...
                  make_display_name(prefixes{k}), ds.snr_db, ds.n_det);

    % --- short panel ---
    ax = nexttile(tl);
    hold(ax, 'on'); grid(ax, 'on');
    ylabel(ax, 'metric');
    title(ax, ['short: ' ttl], 'Interpreter', 'none', 'FontSize', 8);
    xlabel(ax, 'absolute input sample index');

    if ~isempty(ds.cor)
        x = (0:numel(ds.cor)-1).';
        plot(ax, x, ds.cor, '-', 'Color', col, 'LineWidth', 0.8);

        if opt.show_regions && ~isempty(ds.regions)
            yl = [safe_min(ds.cor), safe_max(ds.cor)];
            if yl(1) == yl(2), yl = yl + [-1 1]; end
            shade_regions(ax, ds.regions, yl, col, 0.15);
        end

        if opt.show_detections && ~isempty(ds.det.idx)
            valid = ds.det.metric >= ds.det.threshold;
            if any(valid)
                plot(ax, ds.det.idx(valid), ds.det.metric(valid), 'o', ...
                     'Color', col, 'MarkerSize', 4, 'MarkerFaceColor', col);
            end
            if any(~valid)
                plot(ax, ds.det.idx(~valid), ds.det.metric(~valid), 'x', ...
                     'Color', col * 0.5, 'MarkerSize', 4);
            end
        end

        if ~isempty(ds.det.threshold)
            yline(ax, mean(ds.det.threshold), '--k', 'LineWidth', 0.9);
        end
    end

    % --- long panel ---
    if opt.show_long
        axl = nexttile(tl);
        hold(axl, 'on'); grid(axl, 'on');
        ylabel(axl, '|corr|');

        if ds.long_aligned
            title(axl, ['long (aligned): ' ttl], 'Interpreter', 'none', 'FontSize', 8);
            xlabel(axl, 'absolute input sample index');
        else
            title(axl, ['long (unaligned): ' ttl], 'Interpreter', 'none', 'FontSize', 8);
            xlabel(axl, 'local correlation-output index');
        end

        if ds.long_aligned && ~isempty(ds.long_abs_x)
            valid_pts = ~isnan(ds.long_abs_x);
            if any(valid_pts)
                plot(axl, ds.long_abs_x(valid_pts), ds.long_mag(valid_pts), ...
                     '-', 'Color', col, 'LineWidth', 0.8);
            end
            if opt.show_detections
                mark_long_peaks_abs(axl, ds, col);
            end
        elseif ~isempty(ds.long_cor)
            xl = (0:numel(ds.long_cor)-1).';
            plot(axl, xl, ds.long_cor, '--', 'Color', col, 'LineWidth', 0.8);

            if opt.show_detections && ~isempty(ds.long_det)
                n_lc = numel(ds.long_cor);
                vi   = ds.long_det(ds.long_det >= 0 & ds.long_det < n_lc) + 1;
                if ~isempty(vi)
                    plot(axl, vi - 1, ds.long_cor(vi), 'o', ...
                         'Color', col, 'MarkerSize', 4, 'MarkerFaceColor', col);
                end
            end
        end

        % Link axes for this file pair when aligned
        if ds.long_aligned
            linkaxes([ax axl], 'x');
        end
    end
end

add_snr_colorbar(fig, datasets, opt.colormap);
fprintf('\nStacked plot complete.  %d file sets shown.\n', n_files);

end % plot_stacked


% =========================================================================
%  LOAD ONE DATASET
% =========================================================================
function ds = load_dataset(dump_dir, prefix, opt)

base = char(fullfile(char(dump_dir), char(prefix)));

ds.prefix   = prefix;
ds.cor      = read_f32([base '_short_cor.bin']);
ds.det      = load_det_meta([base '_short_det_meta.bin']);
ds.regions  = load_copy_regions([base '_short_copy_regions.txt']);
ds.n_det    = numel(ds.det.idx);

% Try new aligned long file first, fall back to old float32-only file
[ds.long_abs_x, ds.long_mag, ds.long_aligned] = ...
    load_long_aligned(base, ds.det);

% Always load old long_cor for fallback rendering (and long_det for markers)
ds.long_cor = read_f32([base '_long_mag.bin']);
ds.long_det = load_u64([base '_long_det.bin']);

% ---- SNR estimation -------------------------------------------------------
switch opt.snr_source
    case 'filename'
        ds.snr_db = parse_snr_from_name(prefix);
    case 'detmeta'
        ds.snr_db = estimate_snr_from_peaks(ds);
    otherwise  % 'auto'
        ds.snr_db = parse_snr_from_name(prefix);
        if isnan(ds.snr_db)
            ds.snr_db = estimate_snr_from_peaks(ds);
            fprintf('    (no SNR token in filename - using peak heuristic: %.3f)\n', ds.snr_db);
        end
end

end


% =========================================================================
%  ALIGNED LONG CORRELATION LOADER + MAPPER
% =========================================================================
function [abs_x, mag, aligned] = load_long_aligned(base, det)
% Returns:
%   abs_x   — absolute input sample index for each long correlation sample
%   mag     — |correlation| values
%   aligned — true if new-format _long_mag_abs.bin was found and mapped

abs_x   = [];
mag     = [];
aligned = false;

% ---- Try new indexed file first ----------------------------------------
[sl_idx, mag_raw] = load_long_mag_abs([base '_long_mag_abs.bin']);
if isempty(sl_idx)
    return;
end

% ---- Map sl_idx → absolute sample index using det_meta v3 anchors ------
if ~det.has_tag_output_idx || isempty(det.tag_output_idx)
    % det_meta is old format — can't align
    fprintf('    [warn] _long_mag_abs.bin found but det_meta has no tag_output_idx.\n');
    fprintf('          Recompile sync_short.cc for full alignment.\n');
    return;
end

abs_x_mapped = map_long_to_abs(sl_idx, det);

% Accept alignment if at least 50% of samples mapped (not NaN)
frac_mapped = nnz(~isnan(abs_x_mapped)) / numel(abs_x_mapped);
if frac_mapped < 0.5
    fprintf('    [warn] Only %.0f%% of long samples could be mapped — falling back.\n', ...
            frac_mapped * 100);
    return;
end

abs_x   = abs_x_mapped;
mag     = mag_raw;
aligned = true;
end


function abs_x = map_long_to_abs(sl_idx, det)
% For each sync_long correlation sample identified by sl_idx (= sync_long's
% input item counter = sync_short's output item counter), find the most
% recent wifi_start tag anchor where tag_output_idx <= sl_idx, then:
%
%   abs_x = anchor.abs_input_idx + (sl_idx - anchor.tag_output_idx)
%
% This is valid because in a COPY window sync_short produces one output
% sample per input sample consumed (1:1 mapping).

abs_x = nan(numel(sl_idx), 1);
if isempty(sl_idx), return; end

% Sort anchors by tag_output_idx ascending
[sorted_out, order] = sort(det.tag_output_idx);
sorted_abs          = det.idx(order);

% Vectorised search: for each sl_idx find last anchor with out_idx <= sl_idx
for k = 1:numel(sl_idx)
    L   = sl_idx(k);
    idx = find(sorted_out <= L, 1, 'last');
    if ~isempty(idx)
        abs_x(k) = sorted_abs(idx) + (L - sorted_out(idx));
    end
    % sl_idx before first anchor → stays NaN (pre-trigger startup artefact)
end
end


% =========================================================================
%  MARK DETECTED LTS PEAKS AT ABSOLUTE POSITIONS
% =========================================================================
function mark_long_peaks_abs(ax, ds, col)
% Mark LTS peak pairs using the long_det indices (which are in sl_idx space)
% converted to absolute positions via the same anchor mapping.

if isempty(ds.long_det) || isempty(ds.long_abs_x) || ...
   ~ds.long_aligned || ~ds.det.has_tag_output_idx
    return;
end

% long_det contains sl_idx values for detected peaks
peak_abs = map_long_to_abs(ds.long_det, ds.det);
valid    = ~isnan(peak_abs);
if ~any(valid), return; end

% Find corresponding magnitudes by looking up nearest sample in long_abs_x
abs_peaks = peak_abs(valid);
[~, nearest] = arrayfun(@(p) min(abs(ds.long_abs_x - p)), abs_peaks, ...
                        'UniformOutput', true);
mag_at_peaks = ds.long_mag(nearest);

plot(ax, abs_peaks, mag_at_peaks, '^', ...
     'Color', col, 'MarkerSize', 7, 'LineWidth', 1.5, ...
     'MarkerFaceColor', col);

% Annotate pairs 64 samples apart (LTS double-peak signature)
for j = 1:numel(abs_peaks)-1
    d = abs_peaks(j+1) - abs_peaks(j);
    if abs(d - 64) <= 2
        mid_x = (abs_peaks(j) + abs_peaks(j+1)) / 2;
        mid_y = max(mag_at_peaks(j), mag_at_peaks(j+1));
        text(ax, mid_x, mid_y * 1.06, sprintf('\\Delta=%d', round(d)), ...
             'HorizontalAlignment', 'center', 'FontSize', 8, 'Color', col);
    end
end
end


% =========================================================================
%  SNR ESTIMATION
% =========================================================================
function snr = parse_snr_from_name(prefix)
% Pattern 1: SNR_<value>_dB
m = regexp(prefix, '[Ss][Nn][Rr]_([+-]?\d+(?:\.\d+)?)_[Dd][Bb]', 'tokens', 'once');
if ~isempty(m), snr = str2double(m{1}); return; end

% Pattern 2: SNR<value>dB or SNR<value>
m = regexp(prefix, '[Ss][Nn][Rr]([+-]?\d+(?:\.\d+)?)(?:[Dd][Bb])?(?:\b|_)', 'tokens', 'once');
if ~isempty(m), snr = str2double(m{1}); return; end

snr = NaN;
end

function snr = estimate_snr_from_peaks(ds)
if ~isempty(ds.det.metric) && ~isempty(ds.det.threshold)
    valid = ds.det.metric >= ds.det.threshold;
    if any(valid)
        snr = prctile(ds.det.metric(valid), 90);
        return;
    end
end
if ~isempty(ds.cor)
    snr = prctile(ds.cor, 90);
    return;
end
snr = 0;
end


% =========================================================================
%  PLOTTING UTILITIES
% =========================================================================
function shade_regions(ax, regions, y_lim, color, alpha_val)
for k = 1:size(regions, 1)
    x1 = regions(k, 1);
    x2 = regions(k, 2) - 1;
    if x2 < x1, continue; end
    patch(ax, [x1 x2 x2 x1], [y_lim(1) y_lim(1) y_lim(2) y_lim(2)], ...
          color, 'FaceAlpha', alpha_val, 'EdgeColor', 'none', ...
          'HandleVisibility', 'off');
end
end

function add_snr_colorbar(fig, datasets, cmap_name)
snrs = cellfun(@(d) d.snr_db, datasets);
if numel(unique(snrs)) < 2, return; end

ax_cb = axes(fig, 'Visible', 'off', 'Position', [0.92 0.08 0.01 0.84]);
colormap(ax_cb, feval(cmap_name, 256));
cb = colorbar(ax_cb, 'Location', 'eastoutside');
clim(ax_cb, [min(snrs) max(snrs)]);

snr_range = max(snrs) - min(snrs);
if snr_range >= 1 && min(snrs) >= -40 && max(snrs) <= 60
    cb.Label.String = 'SNR (dB)';
else
    cb.Label.String = 'Relative signal strength (correlation metric)';
end
cb.Label.FontSize = 9;
end

function lbl = make_legend_label(prefix, snr_db)
name = make_display_name(prefix);
if ~isnan(snr_db)
    lbl = sprintf('%s  (%+.1f dB)', name, snr_db);
else
    lbl = name;
end
end

function s = make_display_name(p)
m = regexp(p, '[Ss][Nn][Rr].+$', 'match', 'once');
if ~isempty(m)
    s = strrep(m, '_', ' ');
else
    parts = strsplit(p, '__');
    s = parts{end};
    if numel(s) > 42
        s = ['...' s(end-39:end)];
    end
end
end

function v = safe_min(x), v = min(x(:)); end
function v = safe_max(x), v = max(x(:)); end
function v = mean_or_nan(x)
if isempty(x), v = NaN; else, v = mean(x); end
end


% =========================================================================
%  BINARY FILE READERS
% =========================================================================
function v = read_f32(path)
path = char(path);
fid  = fopen(path, 'rb');
if fid < 0, v = []; return; end
c = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'single=>double');
end

function [sl_idx, mag] = load_long_mag_abs(path)
% New format: repeated { uint64 sl_idx, float32 mag } = 12 bytes/record
sl_idx = []; mag = [];
path = char(path);
fid  = fopen(path, 'rb');
if fid < 0, return; end
c = onCleanup(@() fclose(fid));
fseek(fid, 0, 'eof'); nb = ftell(fid); fseek(fid, 0, 'bof');
if nb == 0 || mod(nb, 12) ~= 0, return; end
n = nb / 12;
sl_idx = zeros(n, 1);
mag    = zeros(n, 1);
for k = 1:n
    sl_idx(k) = fread(fid, 1, 'uint64=>double');
    mag(k)    = fread(fid, 1, 'single=>double');
end
end

function det = load_det_meta(path)
% Supports v1 (21 bytes), v2 (29 bytes), v3 (37 bytes)
% v3 adds tag_output_idx field needed for long correlation alignment.
det = struct('idx',[],'metric',[],'threshold',[],'state',[],'copied',[], ...
             'frame_id',[],'tag_output_idx',[],'has_tag_output_idx',false);

path = char(path);
fid  = fopen(path, 'rb');
if fid < 0, return; end
c = onCleanup(@() fclose(fid));

fseek(fid, 0, 'eof'); nb = ftell(fid); fseek(fid, 0, 'bof');
if nb == 0, return; end

rec_v3 = 37;  rec_v2 = 29;  rec_v1 = 21;

if     mod(nb, rec_v3) == 0,  rec = rec_v3; ver = 3;
elseif mod(nb, rec_v2) == 0,  rec = rec_v2; ver = 2;
elseif mod(nb, rec_v1) == 0,  rec = rec_v1; ver = 1;
else,                          rec = rec_v2; ver = 2;
end

nrec = floor(nb / rec);
idx_v = zeros(nrec,1); me_v = zeros(nrec,1); th_v = zeros(nrec,1);
st_v  = zeros(nrec,1); cp_v = zeros(nrec,1);
fi_v  = nan(nrec,1);   to_v = nan(nrec,1);

for k = 1:nrec
    idx_v(k) = fread(fid, 1, 'uint64=>double');
    me_v(k)  = fread(fid, 1, 'single=>double');
    th_v(k)  = fread(fid, 1, 'single=>double');
    st_v(k)  = fread(fid, 1, 'uint8=>double');
    cp_v(k)  = fread(fid, 1, 'uint32=>double');
    if ver >= 2, fi_v(k) = fread(fid, 1, 'uint64=>double'); end
    if ver >= 3, to_v(k) = fread(fid, 1, 'uint64=>double'); end
end

det.idx               = idx_v;
det.metric            = me_v;
det.threshold         = th_v;
det.state             = st_v;
det.copied            = cp_v;
det.frame_id          = fi_v;
det.tag_output_idx    = to_v;
det.has_tag_output_idx = (ver >= 3);
end

function regions = load_copy_regions(path)
path = char(path);
fid  = fopen(path, 'rb');
if fid < 0, regions = zeros(0,2); return; end
c = onCleanup(@() fclose(fid));
r = fread(fid, [2 inf], 'uint64=>double').';
if isempty(r), regions = zeros(0,2); else, regions = r; end
end

function v = load_u64(path)
path = char(path);
fid  = fopen(path, 'rb');
if fid < 0, v = []; return; end
c = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'uint64=>double');
end


% =========================================================================
%  OPTIONS PARSER
% =========================================================================
function opt = parse_options(s)
opt.overlay         = getf(s, 'overlay',         true);
opt.alpha           = getf(s, 'alpha',            0.55);
opt.sort_by_snr     = getf(s, 'sort_by_snr',      true);
opt.show_detections = getf(s, 'show_detections',  true);
opt.show_regions    = getf(s, 'show_regions',      true);
opt.show_long       = getf(s, 'show_long',         true);
opt.snr_source      = getf(s, 'snr_source',       'auto');
opt.colormap        = getf(s, 'colormap',         'turbo');
opt.file_filter     = getf(s, 'file_filter',      '*');
end

function v = getf(s, field, default)
if isfield(s, field), v = s.(field); else, v = default; end
end

function r = glob2regexp(g)
r = ['^' strrep(strrep(regexprep(g,'\.','\\.'),'*','.*'),'?','.') '$'];
end