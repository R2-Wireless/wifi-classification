function plot_short_peaks_from_dump_dir(dump_dir, valid_only)
% Plot sync_short detected peaks from all files in a dump directory.
%
% Usage:
%   plot_short_peaks_from_dump_dir
%   plot_short_peaks_from_dump_dir('C:\path\to\dumps')
%   plot_short_peaks_from_dump_dir('C:\path\to\dumps', true)
%   dump_dir ="C:\Users\Public\Documents\Wify\Py_script\cfiles\snr_test\dumps"; plot_short_peaks_from_dump_dir(dump_dir)
%
% Inputs:
%   dump_dir   - folder containing per-file dumps produced by --dump-bin
%                expected files: *_short_det_meta.bin (preferred)
%                fallback:       *_short_det.bin
%   valid_only - when true and det_meta exists, keep only metric>=threshold
%                detections (default: true)

if nargin < 1 || isempty(dump_dir)
    dump_dir = pwd;
end
if nargin < 2 || isempty(valid_only)
    valid_only = true;
end

if ~isfolder(dump_dir)
    error('Dump directory not found: %s', dump_dir);
end

meta_files = dir(fullfile(dump_dir, '*_short_det_meta.bin'));
det_files  = dir(fullfile(dump_dir, '*_short_det.bin'));

if isempty(meta_files) && isempty(det_files)
    error(['No detection dump files found in %s. Expected *_short_det_meta.bin ' ...
           'or *_short_det.bin'], dump_dir);
end

fig = figure('Name', 'sync\_short detected peaks across files', ...
             'Color', 'w', 'Units', 'normalized', 'Position', [0.08 0.12 0.84 0.76]);
ax = axes(fig);
hold(ax, 'on');
grid(ax, 'on');

legend_handles = [];
legend_labels = {};

colors = lines(max(numel(meta_files), 1));
color_i = 1;

% Prefer richer meta files (idx + metric + threshold + state + copied + frame_id).
for k = 1:numel(meta_files)
    fpath = fullfile(meta_files(k).folder, meta_files(k).name);
    rec = read_short_det_meta(fpath);
    if isempty(rec.idx)
        continue;
    end

    if valid_only
        keep = rec.metric >= rec.threshold;
    else
        keep = true(size(rec.idx));
    end
    idx = double(rec.idx(keep));
    y   = double(rec.metric(keep)); % y-axis = detected peak value

    if isempty(idx)
        continue;
    end

    [idx, order] = sort(idx);
    y = y(order);

    h = plot(ax, idx, y, 'o-', ...
        'Color', colors(color_i, :), ...
        'MarkerSize', 4, ...
        'LineWidth', 1.0);
    legend_handles(end + 1) = h; %#ok<AGROW>
    legend_labels{end + 1} = strip_suffix(meta_files(k).name, '_short_det_meta.bin'); %#ok<AGROW>

    color_i = color_i + 1;
    if color_i > size(colors, 1)
        color_i = 1;
    end
end

% If no meta plotted, fallback to plain det files (idx only).
if isempty(legend_handles)
    colors = lines(max(numel(det_files), 1));
    for k = 1:numel(det_files)
        fpath = fullfile(det_files(k).folder, det_files(k).name);
        idx = read_short_det(fpath);
        if isempty(idx)
            continue;
        end

        idx = sort(double(idx));
        y = ones(size(idx)); % only indices exist in *_short_det.bin

        h = plot(ax, idx, y, 'o', ...
            'Color', colors(k, :), ...
            'MarkerSize', 5, ...
            'LineWidth', 1.0);
        legend_handles(end + 1) = h; %#ok<AGROW>
        legend_labels{end + 1} = strip_suffix(det_files(k).name, '_short_det.bin'); %#ok<AGROW>
    end
    ylabel(ax, 'detected peaks (index-only dumps)');
else
    ylabel(ax, 'detected peak value (short corr metric)');
end

xlabel(ax, 'sample index');
title(ax, 'sync\_short detected peaks per file');

if ~isempty(legend_handles)
    legend(ax, legend_handles, legend_labels, 'Interpreter', 'none', 'Location', 'best');
else
    warning('No readable detections found in dump files.');
end

hold(ax, 'off');

end


function out = read_short_det_meta(path)
% Record layout in bytes:
%   uint64 idx
%   float  metric
%   float  threshold
%   uint8  state
%   uint32 copied
%   uint64 frame_id
%   uint64 tag_output_idx (newer dumps)
% Total: 29 or 37 bytes/record (written field-by-field in C++).
out.idx = [];
out.metric = [];
out.threshold = [];
out.state = [];
out.copied = [];
out.frame_id = [];
out.tag_output_idx = [];

fid = fopen(path, 'rb');
if fid < 0
    return;
end
cleanup = onCleanup(@() fclose(fid));

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
    if isempty(idx)
        break;
    end

    metric = fread(fid, 1, 'single=>single');
    thr = fread(fid, 1, 'single=>single');
    state = fread(fid, 1, 'uint8=>uint8');
    copied = fread(fid, 1, 'uint32=>uint32');
    frame_id = fread(fid, 1, 'uint64=>uint64');
    if has_tag_output_idx
        tag_output_idx = fread(fid, 1, 'uint64=>uint64');
    else
        tag_output_idx = uint64(0);
    end

    if isempty(metric) || isempty(thr) || isempty(state) || isempty(copied) || ...
            isempty(frame_id) || isempty(tag_output_idx)
        break;
    end

    out.idx(end + 1, 1) = idx; %#ok<AGROW>
    out.metric(end + 1, 1) = metric; %#ok<AGROW>
    out.threshold(end + 1, 1) = thr; %#ok<AGROW>
    out.state(end + 1, 1) = state; %#ok<AGROW>
    out.copied(end + 1, 1) = copied; %#ok<AGROW>
    out.frame_id(end + 1, 1) = frame_id; %#ok<AGROW>
    out.tag_output_idx(end + 1, 1) = tag_output_idx; %#ok<AGROW>
end
end


function idx = read_short_det(path)
fid = fopen(path, 'rb');
if fid < 0
    idx = [];
    return;
end
cleanup = onCleanup(@() fclose(fid));
idx = fread(fid, inf, 'uint64=>uint64');
end


function s = strip_suffix(name, suffix)
if endsWith(name, suffix)
    s = extractBefore(name, strlength(name) - strlength(suffix) + 1);
else
    s = name;
end
end
