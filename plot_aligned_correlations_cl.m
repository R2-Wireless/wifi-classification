function plot_aligned_correlations_cl(short_cor_path, det_meta_path, copy_regions_path, long_mag_abs_path)
% Plot sync_short and sync_long correlations on the SAME absolute sample index x-axis.
%
% Requires the new binary dumps produced by the modified sync_short.cc / sync_long.cc:
%
%   short_cor_path    : float32 array  — sync_short correlation metric per input sample
%                       (default /tmp/sync_short_cor.bin)
%
%   det_meta_path     : v3 records — struct per wifi_start tag:
%                         uint64  abs_input_idx      (= nitems_read(0)+i in sync_short)
%                         float32 metric
%                         float32 threshold
%                         uint8   state
%                         uint32  copied_in_state
%                         uint64  frame_id
%                         uint64  tag_output_idx     ← NEW field (= nitems_written(0),
%                                                       the sync_long input index at
%                                                       which the wifi_start tag arrives)
%                       (default /tmp/sync_short_det_meta.bin)
%
%   copy_regions_path : repeated uint64 pairs {start, end_exclusive}
%                       (default /tmp/sync_short_copy_regions.bin)
%
%   long_mag_abs_path : NEW file — repeated pairs { uint64 sl_idx, float32 mag }
%                       sl_idx = nitems_read(0)+i inside sync_long work(), which equals
%                       the sync_short output item counter at that point.
%                       (default /tmp/sync_long_cor_mag_abs.bin)
%
% HOW THE ALIGNMENT WORKS
% -----------------------
% sync_short dumps float32 values indexed by absolute input sample index (0-based).
% sync_long dumps {sl_idx, mag} pairs where sl_idx is sync_long's input item counter,
% which equals sync_short's output item counter at that moment.
%
% The det_meta record for each wifi_start tag stores BOTH:
%   abs_input_idx   — absolute position in sync_short's INPUT stream
%   tag_output_idx  — position in sync_short's OUTPUT stream (= sl_idx when the tag
%                     arrives at sync_long)
%
% So for each long correlation sample with sl_idx L:
%   Find the det_meta record whose tag_output_idx <= L (the tag that started this
%   COPY/SYNC window), call it anchor.
%   abs_sample_idx = anchor.abs_input_idx + (L - anchor.tag_output_idx)
%
% This reconstructs the absolute sample axis for every long correlation sample.

if nargin < 1 || isempty(short_cor_path),   short_cor_path   = '/tmp/sync_short_cor.bin';          end
if nargin < 2 || isempty(det_meta_path),    det_meta_path    = '/tmp/sync_short_det_meta.bin';     end
if nargin < 3 || isempty(copy_regions_path),copy_regions_path= '/tmp/sync_short_copy_regions.bin'; end
if nargin < 4 || isempty(long_mag_abs_path),long_mag_abs_path= '/tmp/sync_long_cor_mag_abs.bin';   end

% ── load data ───────────────────────────────────────────────────────────────
short_cor   = read_f32(short_cor_path);
det         = load_det_meta_v3(det_meta_path);
regions     = load_copy_regions(copy_regions_path);
[sl_idx, long_mag] = load_long_mag_abs(long_mag_abs_path);

if isempty(short_cor)
    error('Could not load sync_short correlation from %s', short_cor_path);
end

short_x = (0 : numel(short_cor)-1).';

% ── map sync_long sl_idx → absolute sample index ────────────────────────────
long_abs_x = map_long_to_abs(sl_idx, det);

% ── detect threshold line ───────────────────────────────────────────────────
if ~isempty(det.threshold)
    thr_vals = unique(det.threshold);
else
    thr_vals = 0.7;  % default
end

% ── figure ──────────────────────────────────────────────────────────────────
figure('Name','sync\_short + sync\_long — aligned on absolute sample index', ...
       'Color','w','Units','normalized','Position',[0.05 0.1 0.9 0.8]);

tiledlayout(2, 1, 'TileSpacing','compact','Padding','compact');

% ── TOP: sync_short ──────────────────────────────────────────────────────────
ax1 = nexttile;
hold on; grid on;

% shade COPY regions
shade_regions(regions, short_cor);

% threshold line(s)
for t = thr_vals(:).'
    yline(t, 'r--', sprintf('thr=%.2f', t), 'LineWidth', 1.2, ...
          'LabelHorizontalAlignment','left');
end

% correlation trace
plot(short_x, short_cor, 'b-', 'LineWidth', 0.5, 'DisplayName', 'sync\_short metric');

% detection markers
if ~isempty(det.abs_input_idx)
    valid   = det.metric >= det.threshold;
    s_det   = valid & (det.state == 0);
    c_det   = valid & (det.state == 1);
    invalid = ~valid;
    if any(s_det)
        plot(det.abs_input_idx(s_det), det.metric(s_det), 'ro', ...
             'MarkerSize',7,'LineWidth',1.2,'DisplayName','SEARCH det');
    end
    if any(c_det)
        plot(det.abs_input_idx(c_det), det.metric(c_det), 'mo', ...
             'MarkerSize',7,'LineWidth',1.2,'DisplayName','COPY det');
    end
    if any(invalid)
        plot(det.abs_input_idx(invalid), det.metric(invalid), 'ko', ...
             'MarkerSize',5,'LineWidth',1.0,'DisplayName','det invalid');
    end
end

xlabel('absolute input sample index');
ylabel('metric (normalised)');
title('sync\_short correlation metric');
legend('Location','best');
hold off;

% ── BOTTOM: sync_long (aligned) ──────────────────────────────────────────────
ax2 = nexttile;
hold on; grid on;

if ~isempty(long_abs_x) && ~isempty(long_mag)
    % shade same COPY regions for visual reference
    shade_regions(regions, long_mag, 'alpha', 0.12);

    % long correlation trace — plotted at absolute sample positions
    plot(long_abs_x, long_mag, 'k-', 'LineWidth', 0.6, 'DisplayName', 'sync\_long |corr|');

    % mark the LTS peak positions (derived from det_meta peak1/peak2 if present,
    % otherwise from local maxima)
    mark_long_peaks(long_abs_x, long_mag, det);
else
    text(0.5, 0.5, sprintf('No sync\_long data found.\nCheck %s', long_mag_abs_path), ...
         'Units','normalized','HorizontalAlignment','center','FontSize',11,'Color','r');
end

xlabel('absolute input sample index');
ylabel('|correlation|');
title('sync\_long |corr| — mapped to absolute sample index');
legend('Location','best');
hold off;

% link x-axes so zoom/pan stays synchronised
linkaxes([ax1 ax2], 'x');

% ── summary ──────────────────────────────────────────────────────────────────
fprintf('\n--- plot_aligned_correlations summary ---\n');
fprintf('sync_short: %d samples  (x: 0 .. %d)\n', numel(short_cor), numel(short_cor)-1);
fprintf('det_meta:   %d records  (v3=%s)\n', numel(det.abs_input_idx), ...
        string(det.has_tag_output_idx));
fprintf('COPY regions: %d\n', size(regions,1));
if ~isempty(long_abs_x)
    fprintf('sync_long:  %d samples  mapped to abs x: %d .. %d\n', ...
            numel(long_mag), round(min(long_abs_x)), round(max(long_abs_x)));
    n_mapped = nnz(~isnan(long_abs_x));
    n_unmapped = nnz(isnan(long_abs_x));
    fprintf('  mapped:   %d  unmapped (NaN): %d\n', n_mapped, n_unmapped);
else
    fprintf('sync_long:  no data\n');
end
end

% ════════════════════════════════════════════════════════════════════════════
%  MAPPING: sl_idx  →  absolute sample index
% ════════════════════════════════════════════════════════════════════════════
function abs_x = map_long_to_abs(sl_idx, det)
% For each sync_long correlation sample (identified by sl_idx = sync_long's
% input item counter), find the most recent det_meta anchor whose
% tag_output_idx <= sl_idx, then:
%   abs_x = anchor.abs_input_idx + (sl_idx - anchor.tag_output_idx)
%
% This works because within a COPY window the relationship between
% sync_short's input and output is 1:1 (one input sample → one output sample).

abs_x = nan(numel(sl_idx), 1);

if isempty(sl_idx)
    return;
end

if ~det.has_tag_output_idx || isempty(det.tag_output_idx)
    warning(['det_meta does not contain tag_output_idx (old format). ' ...
             'Cannot align sync_long. Recompile sync_short.cc with the new field.']);
    return;
end

% Sort anchors by tag_output_idx ascending
[sorted_out, order] = sort(det.tag_output_idx);
sorted_abs          = det.abs_input_idx(order);

% For each sl_idx, find the last anchor with tag_output_idx <= sl_idx
for k = 1:numel(sl_idx)
    L = sl_idx(k);
    idx = find(sorted_out <= L, 1, 'last');
    if ~isempty(idx)
        abs_x(k) = sorted_abs(idx) + (L - sorted_out(idx));
    end
    % If no anchor found (sl_idx before first tag) we leave NaN — these are
    % the pre-trigger startup samples discussed previously.
end
end

% ════════════════════════════════════════════════════════════════════════════
%  HELPERS
% ════════════════════════════════════════════════════════════════════════════
function v = read_f32(path)
fid = fopen(path, 'rb');
if fid < 0, warning('Cannot open %s', path); v = []; return; end
c = onCleanup(@() fclose(fid));
v = fread(fid, inf, 'single=>double');
end

function [sl_idx, mag] = load_long_mag_abs(path)
% File format: repeated { uint64 sl_idx, float32 mag } = 12 bytes/record
sl_idx = [];
mag    = [];
fid = fopen(path, 'rb');
if fid < 0, warning('Cannot open %s', path); return; end
c = onCleanup(@() fclose(fid));
fseek(fid, 0, 'eof'); nb = ftell(fid); fseek(fid, 0, 'bof');
if mod(nb, 12) ~= 0
    warning('sync_long mag_abs file size %d is not a multiple of 12', nb);
end
n = floor(nb / 12);
if n == 0, return; end
sl_idx = zeros(n,1);
mag    = zeros(n,1);
for k = 1:n
    sl_idx(k) = fread(fid, 1, 'uint64=>double');
    mag(k)    = fread(fid, 1, 'single=>double');
end
end

function det = load_det_meta_v3(path)
% v3 record (37 bytes):
%   uint64 abs_input_idx, float32 metric, float32 threshold,
%   uint8 state, uint32 copied, uint64 frame_id, uint64 tag_output_idx
% v2 record (29 bytes): same minus tag_output_idx
% v1 record (21 bytes): same minus frame_id and tag_output_idx
det = struct('abs_input_idx',[],'metric',[],'threshold',[],'state',[], ...
             'copied',[],'frame_id',[],'tag_output_idx',[],'has_tag_output_idx',false);
fid = fopen(path, 'rb');
if fid < 0, warning('Cannot open %s', path); return; end
c = onCleanup(@() fclose(fid));
fseek(fid, 0, 'eof'); nb = ftell(fid); fseek(fid, 0, 'bof');

rec_v3 = 37;  % with tag_output_idx
rec_v2 = 29;  % with frame_id
rec_v1 = 21;  % original

if     mod(nb, rec_v3) == 0,  rec = rec_v3; ver = 3;
elseif mod(nb, rec_v2) == 0,  rec = rec_v2; ver = 2;
elseif mod(nb, rec_v1) == 0,  rec = rec_v1; ver = 1;
else
    warning('det_meta size %d bytes not divisible by 37, 29, or 21. Trying v2.', nb);
    rec = rec_v2; ver = 2;
end

n = floor(nb / rec);
if n == 0, return; end

ai  = zeros(n,1); me = zeros(n,1); th = zeros(n,1);
st  = zeros(n,1); cp = zeros(n,1); fi = nan(n,1); to = nan(n,1);

for k = 1:n
    ai(k) = fread(fid,1,'uint64=>double');
    me(k) = fread(fid,1,'single=>double');
    th(k) = fread(fid,1,'single=>double');
    st(k) = fread(fid,1,'uint8=>double');
    cp(k) = fread(fid,1,'uint32=>double');
    if ver >= 2, fi(k) = fread(fid,1,'uint64=>double'); end
    if ver >= 3, to(k) = fread(fid,1,'uint64=>double'); end
end

det.abs_input_idx    = ai;
det.metric           = me;
det.threshold        = th;
det.state            = st;
det.copied           = cp;
det.frame_id         = fi;
det.tag_output_idx   = to;
det.has_tag_output_idx = (ver >= 3);
end

function regions = load_copy_regions(path)
regions = zeros(0,2);
fid = fopen(path, 'rb');
if fid < 0, warning('Cannot open %s', path); return; end
c = onCleanup(@() fclose(fid));
r = fread(fid, [2 inf], 'uint64=>double').';
if ~isempty(r), regions = r; end
end

function shade_regions(regions, ref_signal, varargin)
% Shade COPY regions on the current axes.
p = inputParser;
addParameter(p, 'alpha', 0.18, @isnumeric);
parse(p, varargin{:});
alpha = p.Results.alpha;

if isempty(regions) || isempty(ref_signal), return; end
y_min = min(ref_signal);
y_max = max(ref_signal);
if y_min == y_max, y_min = y_min - 1; y_max = y_max + 1; end

colors = {[0.76 0.88 1.00], [0.86 0.86 0.86], [0.78 0.78 0.78]};
for k = 1:size(regions,1)
    x1 = regions(k,1);
    x2 = regions(k,2) - 1;
    if x2 < x1, continue; end
    cidx = mod(k-1, numel(colors)) + 1;
    patch([x1 x2 x2 x1],[y_min y_min y_max y_max], colors{cidx}, ...
          'FaceAlpha', alpha, 'EdgeColor','none', 'HandleVisibility','off');
end
end

function mark_long_peaks(long_abs_x, long_mag, det)
% Mark detected LTS peak pairs on the sync_long panel.
% Uses tag_output_idx + frame start offset when available.
% Falls back to simple local-max search otherwise.

if isempty(long_abs_x) || isempty(long_mag), return; end

valid = ~isnan(long_abs_x);
if ~any(valid), return; end

x_v = long_abs_x(valid);
m_v = long_mag(valid);

% Simple approach: find peaks significantly above local median
med_val = median(m_v);
prom_thr = med_val * 3;  % peak must be 3× median

[~, locs] = findpeaks(m_v, 'MinPeakProminence', prom_thr, 'MinPeakDistance', 30);

if ~isempty(locs)
    plot(x_v(locs), m_v(locs), 'r^', 'MarkerSize', 8, 'LineWidth', 1.5, ...
         'MarkerFaceColor','r', 'DisplayName', 'LTS peaks');
    % annotate peak pairs that are 64 samples apart
    for j = 1:numel(locs)-1
        diff_x = x_v(locs(j+1)) - x_v(locs(j));
        if abs(diff_x - 64) <= 2
            mid_x = (x_v(locs(j)) + x_v(locs(j+1))) / 2;
            mid_y = max(m_v(locs(j)), m_v(locs(j+1)));
            text(mid_x, mid_y * 1.05, sprintf('\\Delta=%d', round(diff_x)), ...
                 'HorizontalAlignment','center','FontSize',8,'Color','r');
        end
    end
end
end