function plot_sync_short_debug_3_aligned(short_cor_path, det_meta_path, copy_regions_path, ...
                                  long_mag_path, long_det_path, long_det_meta_path, ...
                                  long_mag_abs_path)
% Plot sync_short and sync_long correlations with CORRECTLY ALIGNED x-axes.
%
% ALIGNMENT
% ---------
% sync_short det_meta v3 stores per detection:
%   idx            = nitems_read(0)+i  inside sync_short  -> raw ADC input space
%   tag_output_idx = nitems_written(0) inside sync_short  -> sync_long input space
%
% sync_long long_mag_abs stores per correlation sample:
%   uint64 nread_i = nitems_read(0)+i  inside sync_long   -> sync_long input space
%
% Mapping: raw_abs(nread_i) = T_in + (nread_i - T_out)
% where T_out/T_in are the tag anchors from the nearest-preceding detection.
%
% BOTTOM PANEL COLOURING
% ----------------------
% Each sync_long detection region (peak-pair) is drawn with a unique colour
% derived from its frame_id.  This makes every region visually distinct
% regardless of whether sync_short fired the tag from SEARCH or COPY state.
% The top panel still uses blue=SEARCH / grey=COPY to show sync_short state.

if nargin < 1 || isempty(short_cor_path),     short_cor_path     = '/tmp/sync_short_cor.bin';          end
if nargin < 2 || isempty(det_meta_path),      det_meta_path      = '/tmp/sync_short_det_meta.bin';     end
if nargin < 3 || isempty(copy_regions_path),  copy_regions_path  = '/tmp/sync_short_copy_regions.bin'; end
if nargin < 4 || isempty(long_mag_path),      long_mag_path      = '/tmp/sync_long_cor_mag.bin';       end
if nargin < 5 || isempty(long_det_path),      long_det_path      = '/tmp/sync_long_det.bin';           end
if nargin < 6 || isempty(long_det_meta_path), long_det_meta_path = '/tmp/sync_long_det_meta.bin';      end
if nargin < 7 || isempty(long_mag_abs_path),  long_mag_abs_path  = '/tmp/sync_long_cor_mag_abs.bin';   end

% ── load short data ───────────────────────────────────────────────────────
cor     = read_f32(short_cor_path);
short_x = (0:numel(cor)-1).';
det     = load_det_meta(det_meta_path);
regions = load_copy_regions(copy_regions_path);

% ── load long data ────────────────────────────────────────────────────────
[long_sl_x, long_sl_mag] = load_long_mag_abs(long_mag_abs_path);
long_det_raw = load_u64(long_det_path);
long_meta    = load_long_det_meta(long_det_meta_path);

% ── alignment prerequisites ───────────────────────────────────────────────
have_tag_out  = ~isempty(det.tag_output_idx) && ~all(isnan(det.tag_output_idx));
have_long_abs = ~isempty(long_sl_x);

if ~have_tag_out
    warning(['det_meta does not contain tag_output_idx (need v3, 37-byte records).\n' ...
             'Bottom panel x-axis will NOT be aligned.']);
end
if ~have_long_abs
    warning('long_mag_abs not available (%s).\nBottom panel x-axis will NOT be aligned.', ...
            long_mag_abs_path);
end

% ── per-frame affine remap table: [T_out, T_in] sorted by T_out ──────────
remap = [];
if have_tag_out && ~isempty(det.idx)
    valid = ~isnan(det.tag_output_idx);
    T_out = det.tag_output_idx(valid);
    T_in  = det.idx(valid);
    [T_out_s, si] = sort(T_out);
    remap = [T_out_s, T_in(si)];
end

% ── remap long_mag_abs to raw input space ────────────────────────────────
if have_long_abs && ~isempty(remap)
    long_abs_x   = remap_long_to_raw(long_sl_x, remap);
    long_abs_mag = long_sl_mag;
    have_aligned = true;
else
    long_abs_x   = (0:numel(long_sl_mag)-1).';
    long_abs_mag = long_sl_mag;
    have_aligned = false;
end

% ── remap long detection peaks to raw input space ────────────────────────
if ~isempty(long_meta.frame_id) && ~isempty(remap) && have_long_abs
    peak1_raw = remap_long_to_raw(safe_lookup(long_meta.peak1, long_sl_x), remap);
    peak2_raw = remap_long_to_raw(safe_lookup(long_meta.peak2, long_sl_x), remap);
    long_regions         = [min(peak1_raw,peak2_raw), max(peak1_raw,peak2_raw)];
    long_region_frame_id = long_meta.frame_id;
elseif ~isempty(long_meta.frame_id) && have_long_abs
    peak1_sl = safe_lookup(long_meta.peak1, long_sl_x);
    peak2_sl = safe_lookup(long_meta.peak2, long_sl_x);
    long_regions         = [min(peak1_sl,peak2_sl), max(peak1_sl,peak2_sl)];
    long_region_frame_id = long_meta.frame_id;
else
    raw_pairs            = build_long_regions(long_det_raw);
    long_regions         = raw_pairs;
    long_region_frame_id = nan(size(raw_pairs,1),1);
end

% ── individual peak circle positions ─────────────────────────────────────
if have_long_abs && ~isempty(remap) && ~isempty(long_det_raw)
    long_det_abs = remap_long_to_raw(safe_lookup(long_det_raw, long_sl_x), remap);
elseif have_long_abs && ~isempty(long_det_raw)
    long_det_abs = safe_lookup(long_det_raw, long_sl_x);
else
    long_det_abs = long_det_raw;
end

% ── cross-map short regions -> det for TOP panel shading colours ─────────
[short_region_frame_id, short_region_state] = map_short_regions_to_det(regions, det);

% ── per-frame colour palette for BOTTOM panel ────────────────────────────
% Each unique frame_id gets a distinct hue.  We use a fixed high-contrast
% palette that cycles if there are more than 8 frames.
FRAME_COLORS = [
    0.12  0.47  0.71;   % blue
    0.20  0.63  0.17;   % green
    0.89  0.10  0.11;   % red
    1.00  0.50  0.00;   % orange
    0.42  0.24  0.60;   % purple
    0.69  0.35  0.16;   % brown
    0.97  0.51  0.75;   % pink
    0.50  0.50  0.50;   % grey
];

% Build frame_id -> color index mapping from long_region_frame_id
unique_fids = unique(long_region_frame_id(~isnan(long_region_frame_id)));
frame_color_map = containers.Map('KeyType','double','ValueType','any');
for fi = 1:numel(unique_fids)
    idx = mod(fi-1, size(FRAME_COLORS,1)) + 1;
    frame_color_map(unique_fids(fi)) = FRAME_COLORS(idx,:);
end

% =========================================================================
%  FIGURE
% =========================================================================
figure('Name','sync_short / sync_long — aligned','Color','w');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');

% ── TOP: sync_short  (state-based colouring: blue=SEARCH, grey=COPY) ─────
ax1 = nexttile;
h_corr = plot(short_x, cor, 'b-');
grid on; hold on;
ylabel('metric');
title('sync\_short correlation + detections + COPY regions');

if ~isempty(cor)
    y_min = min(cor); y_max = max(cor);
    if y_min == y_max; y_min = y_min-1; y_max = y_max+1; end
else
    y_min = -1; y_max = 1;
end

[h_sr, h_cr] = shade_regions_by_state(regions, det, y_min, y_max);

% Build legend entries only for categories that have data points
leg_h = [h_corr, h_sr, h_cr];
leg_l = {'corr', 'SEARCH-start region', 'COPY-retrigger region'};

if ~isempty(det.idx)
    in_rng  = det.idx >= short_x(1) & det.idx <= short_x(end);
    di = det.idx(in_rng);  dm = det.metric(in_rng);
    dt = det.threshold(in_rng);  ds = det.state(in_rng);
    vld = dm >= dt;
    mask_sd = vld & ds==0;
    mask_cd = vld & ds==1;
    mask_iv = ~vld;
    if any(mask_sd)
        h = plot(di(mask_sd), dm(mask_sd), 'ro', 'MarkerSize',7, 'LineWidth',1);
        leg_h(end+1) = h;  leg_l{end+1} = 'SEARCH det valid';
    else
        plot(nan, nan, 'ro', 'MarkerSize',7, 'LineWidth',1);
    end
    if any(mask_cd)
        h = plot(di(mask_cd), dm(mask_cd), 'mo', 'MarkerSize',7, 'LineWidth',1);
        leg_h(end+1) = h;  leg_l{end+1} = 'COPY det valid';
    else
        plot(nan, nan, 'mo', 'MarkerSize',7, 'LineWidth',1);
    end
    if any(mask_iv)
        h = plot(di(mask_iv), dm(mask_iv), 'ko', 'MarkerSize',6, 'LineWidth',1);
        leg_h(end+1) = h;  leg_l{end+1} = 'det invalid';
    else
        plot(nan, nan, 'ko', 'MarkerSize',6, 'LineWidth',1);
    end
end
legend(leg_h, leg_l, 'Location','best');
hold off;

% ── BOTTOM: sync_long  (per-frame distinct colours) ───────────────────────
ax2 = nexttile;
h_long = plot(long_abs_x, long_abs_mag, 'k-');
grid on; hold on;
xlabel('absolute input sample index  (raw ADC stream, same as top panel)');
ylabel('|corr|');
if have_aligned
    title('sync\_long |corr| + detected peaks  (correctly aligned, each frame = distinct colour)');
else
    title('sync\_long |corr| + detected peaks  (NOT aligned — missing v3 det\_meta or long\_mag\_abs)');
end

if ~isempty(long_abs_mag)
    ly_min = min(long_abs_mag); ly_max = max(long_abs_mag);
    if ly_min == ly_max; ly_min = ly_min-1; ly_max = ly_max+1; end
else
    ly_min = -1; ly_max = 1;
end

% Draw one shaded patch per long region, coloured by frame_id.
% Also draw a thin vertical edge line at each boundary so adjacent
% same-hue regions are visually separated even when zoomed out.
long_to_short = nan(size(long_regions,1),1);
patch_handles = {};   % {handle, label} pairs for legend
seen_fids     = [];

for k = 1:size(long_regions,1)
    x1 = long_regions(k,1);  x2 = long_regions(k,2);
    if isnan(x1) || isnan(x2) || x2 < x1; continue; end

    fid = long_region_frame_id(k);

    % Map to short region for console output
    mapped = nan;
    if ~isnan(fid)
        m = find(short_region_frame_id == fid, 1);
        if ~isempty(m); mapped = m; end
    end
    long_to_short(k) = mapped;

    % Colour: unique per frame_id
    if ~isnan(fid) && isKey(frame_color_map, fid)
        c = frame_color_map(fid);
    else
        c = [0.7 0.7 0.7];
    end

    h = patch([x1 x2 x2 x1], [ly_min ly_min ly_max ly_max], c, ...
              'FaceAlpha', 0.25, 'EdgeColor', c, 'LineWidth', 1.0);

    % Add to legend once per unique frame_id
    if ~isnan(fid) && ~ismember(fid, seen_fids)
        seen_fids(end+1) = fid;
        patch_handles{end+1} = {h, sprintf('frame %g', fid)};
    end
end

% Peak circle markers coloured per frame_id
% long_det comes in pairs [peak1, peak2] per region; colour by region index
h_ld_added = false;
for k = 1:size(long_regions,1)
    fid = long_region_frame_id(k);
    if ~isnan(fid) && isKey(frame_color_map, fid)
        c = frame_color_map(fid);
    else
        c = [0.7 0.7 0.7];
    end
    % The two peak positions for this region
    p1 = long_regions(k,1);
    p2 = long_regions(k,2);
    for p = [p1, p2]
        if isnan(p); continue; end
        pm = lookup_mag(p, long_abs_x, long_abs_mag);
        if ~isnan(pm)
            h = plot(p, pm, 'o', 'Color', c, 'MarkerFaceColor', c, ...
                     'MarkerSize', 6, 'LineWidth', 1);
            if ~h_ld_added
                patch_handles{end+1} = {h, 'detected peaks'};
                h_ld_added = true;
            end
        end
    end
end
if ~h_ld_added
    h = plot(nan, nan, 'o', 'Color',[0.5 0.5 0.5], 'MarkerSize',6);
    patch_handles{end+1} = {h, 'detected peaks'};
end

% Assemble legend
leg_h2 = [h_long];
leg_l2 = {'|corr|'};
for i = 1:numel(patch_handles)
    leg_h2(end+1) = patch_handles{i}{1};
    leg_l2{end+1} = patch_handles{i}{2};
end
legend(leg_h2, leg_l2, 'Location','best');
hold off;

linkaxes([ax1 ax2], 'x');

% ── console summary ───────────────────────────────────────────────────────
fprintf('\nLoaded %d short correlation samples\n', numel(cor));
if ~isempty(det.idx)
    fprintf('Loaded %d detection records  (valid=%d  invalid=%d)\n', ...
            numel(det.idx), nnz(det.metric>=det.threshold), nnz(det.metric<det.threshold));
end
fprintf('have tag_output_idx (v3 det_meta): %d\n', have_tag_out);
fprintf('have long_mag_abs: %d\n', have_long_abs);
fprintf('alignment active: %d\n', have_aligned);
fprintf('Loaded %d COPY regions\n', size(regions,1));
fprintf('Loaded %d long mag_abs samples\n', numel(long_sl_mag));
fprintf('Loaded %d long peak pairs (%d regions)\n', numel(long_det_raw), size(long_regions,1));

fprintf('\n  k  frame_id  [raw_peak1   raw_peak2]  -> short_region  short_state\n');
for k = 1:size(long_regions,1)
    fid  = long_region_frame_id(k);
    sidx = long_to_short(k);
    if ~isnan(sidx)
        sstate = short_region_state(sidx);
        sstate_str = 'SEARCH';
        if sstate == 1; sstate_str = 'COPY-retrigger'; end
        fprintf('  %d  %8g  [%10.0f %10.0f]  -> short_region=%d  (%s)\n', ...
                k, fid, long_regions(k,1), long_regions(k,2), sidx, sstate_str);
    else
        fprintf('  %d  %8g  [%10.0f %10.0f]  ->  no matching short region\n', ...
                k, fid, long_regions(k,1), long_regions(k,2));
    end
end
fprintf('\nNote: "COPY-retrigger" means sync_short was already in COPY state\n');
fprintf('when it fired this tag. Each region is still a distinct independent frame.\n');
end

% =========================================================================
%  ALIGNMENT CORE
% =========================================================================

function raw_x = remap_long_to_raw(sl_x, remap)
raw_x = nan(size(sl_x));
if isempty(remap) || isempty(sl_x); return; end
T_out = remap(:,1);
T_in  = remap(:,2);
for k = 1:numel(sl_x)
    v = sl_x(k);
    if isnan(v); continue; end
    j = find(T_out <= v, 1, 'last');
    if ~isempty(j)
        raw_x(k) = T_in(j) + (v - T_out(j));
    end
end
end

% =========================================================================
%  HELPERS
% =========================================================================

function v = read_f32(path)
fid = fopen(path,'rb');
if fid<0; warning('Could not open %s',path); v=[]; return; end
c = onCleanup(@()fclose(fid));
v = fread(fid, inf, 'single=>double');
end

function [sl_x, mag] = load_long_mag_abs(path)
sl_x=[]; mag=[];
fid = fopen(path,'rb'); if fid<0; return; end
c = onCleanup(@()fclose(fid));
fseek(fid,0,'eof'); nb=ftell(fid); fseek(fid,0,'bof');
rec = 12;
if mod(nb,rec)~=0; warning('long_mag_abs: size %d not a multiple of 12',nb); end
nr = floor(nb/rec); if nr==0; return; end
sl_x = zeros(nr,1);  mag = zeros(nr,1);
for k = 1:nr
    sl_x(k) = fread(fid,1,'uint64=>double');
    mag(k)  = fread(fid,1,'single=>double');
end
end

function v = safe_lookup(corr_idx, sl_x)
v = nan(size(corr_idx));
if isempty(sl_x); return; end
n = numel(sl_x);
ok = corr_idx >= 0 & corr_idx < n;
v(ok) = sl_x(corr_idx(ok)+1);
end

function mag_out = lookup_mag(abs_pos, abs_x, mag)
mag_out = nan(size(abs_pos));
if isempty(abs_x); return; end
for k = 1:numel(abs_pos)
    if isnan(abs_pos(k)); continue; end
    [~,loc] = min(abs(abs_x - abs_pos(k)));
    if ~isempty(loc); mag_out(k) = mag(loc(1)); end
end
end

function det = load_det_meta(path)
det = struct('idx',[],'metric',[],'threshold',[],'state',[],'copied',[], ...
             'frame_id',[],'tag_output_idx',[]);
fid = fopen(path,'rb');
if fid<0; warning('Could not open %s',path); return; end
c = onCleanup(@()fclose(fid));
fseek(fid,0,'eof'); nb=ftell(fid); fseek(fid,0,'bof');
v3=37; v2=29; v1=21;
hfi=false; hto=false; rb=v1;
if     nb>0 && mod(nb,v3)==0; rb=v3; hfi=true; hto=true;
elseif nb>0 && mod(nb,v2)==0; rb=v2; hfi=true;
elseif nb>0 && mod(nb,v1)==0; rb=v1;
else
    warning('det_meta %d B not divisible by v3/v2/v1; trying v3.',nb);
    rb=v3; hfi=true; hto=true;
end
nr = floor(nb/rb);
idx=zeros(nr,1); met=zeros(nr,1); thr=zeros(nr,1);
st=zeros(nr,1);  cp=zeros(nr,1);  fi=nan(nr,1);  to=nan(nr,1);
for k = 1:nr
    idx(k) = fread(fid,1,'uint64=>double');
    met(k) = fread(fid,1,'single=>double');
    thr(k) = fread(fid,1,'single=>double');
    st(k)  = fread(fid,1,'uint8=>double');
    cp(k)  = fread(fid,1,'uint32=>double');
    if hfi; fi(k) = fread(fid,1,'uint64=>double'); end
    if hto; to(k) = fread(fid,1,'uint64=>double'); end
end
det.idx=idx; det.metric=met; det.threshold=thr;
det.state=st; det.copied=cp; det.frame_id=fi; det.tag_output_idx=to;
end

function regions = load_copy_regions(path)
fid = fopen(path,'rb');
if fid<0; warning('Could not open %s',path); regions=zeros(0,2); return; end
c = onCleanup(@()fclose(fid));
r = fread(fid,[2 inf],'uint64=>double').';
if isempty(r); regions=zeros(0,2); else; regions=r; end
end

function v = load_u64(path)
fid = fopen(path,'rb');
if fid<0; warning('Could not open %s',path); v=[]; return; end
c = onCleanup(@()fclose(fid));
v = fread(fid, inf, 'uint64=>double');
end

function regions = build_long_regions(long_det)
if isempty(long_det); regions=zeros(0,2); return; end
n = floor(numel(long_det)/2);  regions = zeros(n,2);
for i = 1:n
    a=long_det(2*i-1); b=long_det(2*i);
    regions(i,:) = [min(a,b), max(a,b)];
end
end

function meta = load_long_det_meta(path)
meta = struct('frame_id',[],'peak1',[],'peak2',[]);
fid = fopen(path,'rb'); if fid<0; return; end
c = onCleanup(@()fclose(fid));
raw = fread(fid, inf, 'uint64=>double');
if isempty(raw); return; end
n = floor(numel(raw)/3); if n<1; return; end
raw = reshape(raw(1:3*n), 3, n).';
meta.frame_id=raw(:,1); meta.peak1=raw(:,2); meta.peak2=raw(:,3);
end

function [rfid, rst] = map_short_regions_to_det(regions, det)
rfid=nan(size(regions,1),1); rst=nan(size(regions,1),1);
if isempty(regions) || isempty(det.idx); return; end
[tf,loc] = ismember(regions(:,1), det.idx);
if any(tf)
    if ~isempty(det.frame_id); rfid(tf) = det.frame_id(loc(tf)); end
    rst(tf) = det.state(loc(tf));
end
end

function [h_sl, h_cl] = shade_regions_by_state(regions, det, y_min, y_max)
mk = @(c) plot(nan,nan,'s','MarkerFaceColor',c,'MarkerEdgeColor',c);
h_sl=[]; h_cl=[];
if isempty(regions)
    h_sl=mk([0.76 0.88 1.00]); h_cl=mk([0.82 0.82 0.82]); return;
end
sbs = nan(size(regions,1),1);
if ~isempty(det.idx)
    [tf,loc] = ismember(regions(:,1), det.idx);
    sbs(tf) = det.state(loc(tf));
end
nc=0; ss=false; cs=false;
for k = 1:size(regions,1)
    x1=regions(k,1); x2=regions(k,2)-1;
    if x2<x1; continue; end
    st = sbs(k);
    if st==0
        c=[0.76 0.88 1.00]; a=0.22; ss=true;
    elseif st==1
        nc=nc+1; c=[0.86 0.86 0.86]-mod(nc,2)*[0.08 0.08 0.08]; a=0.20; cs=true;
    else
        c=[0.90 0.90 0.90]; a=0.15;
    end
    h = patch([x1 x2 x2 x1],[y_min y_min y_max y_max], c, 'FaceAlpha',a,'EdgeColor','none');
    if st==0 && isempty(h_sl); h_sl=h; end
    if st==1 && isempty(h_cl); h_cl=h; end
end
if isempty(h_sl); if ss; h_sl=mk([0.76 0.88 1.00]); else; h_sl=mk([0.85 0.85 0.85]); end; end
if isempty(h_cl); if cs; h_cl=mk([0.82 0.82 0.82]); else; h_cl=mk([0.85 0.85 0.85]); end; end
end