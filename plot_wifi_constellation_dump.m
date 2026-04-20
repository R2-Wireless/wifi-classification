function plot_wifi_constellation_dump(path, frame_id)
% Plot equalized constellation points from a dump file.
%
% Usage:
%   plot_wifi_constellation_dump
%   plot_wifi_constellation_dump('/tmp/wifi_constellation_eq.bin')
%   plot_wifi_constellation_dump('/tmp/wifi_constellation_eq.bin', 1)

if nargin < 1 || isempty(path)
    path = "\\wsl.localhost\Ubuntu-22.04\tmp\wifi_constellation_eq.bin";
end

recs = read_wifi_constellation_dump(path);
if isempty(recs)
    error('No constellation records found in %s', path);
end

if nargin < 2 || isempty(frame_id)
    frame_id = recs(1).frame_id;
end

sel = find([recs.frame_id] == frame_id);
if isempty(sel)
    error('No records found for frame_id=%d', frame_id);
end

Z = vertcat(recs(sel).z);

figure('Color', 'w', 'Name', sprintf('Constellation frame %d', frame_id));
plot(real(Z(:)), imag(Z(:)), '.', 'MarkerSize', 8);
axis equal;
grid on;
xlabel('I');
ylabel('Q');
title(sprintf('Equalized constellation, frame %d (%d OFDM data symbols)', ...
      frame_id, numel(sel)));
