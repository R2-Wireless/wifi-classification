#!/usr/bin/env python3
import argparse
import re
import sys


INTERRUPT_RE = re.compile(
    r"\[sync_long\]\[interrupt\]\s+frame_id=(\d+)\s+copied=(\d+)\s+"
    r"left_for_signal=(\d+)\s+min_for_signal=(\d+)\s+signal_sufficient=(yes|NO)"
)

BUDGET_RE = re.compile(
    r"\[frame_equalizer\]\[budget\]\s+frame_id=(\d+)\s+bytes=(\d+)\s+n_sym=(\d+)\s+"
    r"needed_raw_samples=(\d+)\s+min_for_signal=(\d+)"
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize sync_long interruption vs frame_equalizer budget by frame_id."
    )
    parser.add_argument("logfile", nargs="?", default="ttt.log", help="Path to log file")
    args = parser.parse_args()

    rows = {}

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = INTERRUPT_RE.search(line)
                if m:
                    frame_id = int(m.group(1))
                    row = rows.setdefault(frame_id, {})
                    row["copied"] = int(m.group(2))
                    row["left_for_signal"] = int(m.group(3))
                    row["min_for_signal_intr"] = int(m.group(4))
                    row["signal_sufficient"] = m.group(5)
                    continue

                m = BUDGET_RE.search(line)
                if m:
                    frame_id = int(m.group(1))
                    row = rows.setdefault(frame_id, {})
                    row["bytes"] = int(m.group(2))
                    row["n_sym"] = int(m.group(3))
                    row["needed_raw_samples"] = int(m.group(4))
                    row["min_for_signal_budget"] = int(m.group(5))
    except FileNotFoundError:
        print(f"error: log file not found: {args.logfile}", file=sys.stderr)
        return 1

    if not rows:
        print("No [sync_long][interrupt] or [frame_equalizer][budget] lines found.")
        return 0

    header = (
        "frame_id copied needed_raw n_sym bytes signal_ok data_sufficient notes"
    )
    print(header)
    print("-" * len(header))

    both_count = 0
    for frame_id in sorted(rows.keys()):
        row = rows[frame_id]
        copied = row.get("copied")
        needed = row.get("needed_raw_samples")
        n_sym = row.get("n_sym")
        n_bytes = row.get("bytes")
        signal_ok = row.get("signal_sufficient")

        if copied is not None and needed is not None:
            both_count += 1
            data_ok = "yes" if copied >= needed else "NO"
            notes = "joined"
        elif copied is not None:
            data_ok = "-"
            notes = "no_budget"
        else:
            data_ok = "-"
            notes = "no_interrupt"

        print(
            f"{frame_id:8d} "
            f"{str(copied) if copied is not None else '-':>6} "
            f"{str(needed) if needed is not None else '-':>10} "
            f"{str(n_sym) if n_sym is not None else '-':>5} "
            f"{str(n_bytes) if n_bytes is not None else '-':>5} "
            f"{signal_ok if signal_ok is not None else '-':>8} "
            f"{data_ok:>15} "
            f"{notes}"
        )

    print(
        f"\nframes_total={len(rows)} joined={both_count} "
        f"interrupt_only={sum(1 for r in rows.values() if 'copied' in r and 'needed_raw_samples' not in r)} "
        f"budget_only={sum(1 for r in rows.values() if 'needed_raw_samples' in r and 'copied' not in r)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
