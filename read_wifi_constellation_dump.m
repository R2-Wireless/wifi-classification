function recs = read_wifi_constellation_dump(path)
% Read equalized constellation dump records produced by frame_equalizer_impl.cc.
%
% Record layout:
%   uint64 frame_id
%   uint64 symbol_index   (0-based within payload/data symbols)
%   uint64 encoding
%   uint64 n_subcarriers  (currently 48)
%   n_subcarriers x complex64
%
% Usage:
%   recs = read_wifi_constellation_dump
%   recs = read_wifi_constellation_dump('/tmp/wifi_constellation_eq.bin')

if nargin < 1 || isempty(path)
    path = "\\wsl.localhost\Ubuntu-22.04\tmp\wifi_constellation_eq.bin";
end

fid = fopen(path, 'rb');
assert(fid >= 0, 'Cannot open file: %s', path);
cleanup = onCleanup(@() fclose(fid));

recs = struct('frame_id', {}, 'symbol_index', {}, 'encoding', {}, 'z', {});
k = 1;

while ~feof(fid)
    hdr = fread(fid, 4, 'uint64=>uint64');
    if numel(hdr) < 4
        break;
    end

    nsc = double(hdr(4));
    raw = fread(fid, 2 * nsc, 'float32=>single');
    if numel(raw) < 2 * nsc
        break;
    end

    z = complex(raw(1:2:end), raw(2:2:end));

    recs(k).frame_id = double(hdr(1));
    recs(k).symbol_index = double(hdr(2));
    recs(k).encoding = double(hdr(3));
    recs(k).z = z;
    k = k + 1;
end
