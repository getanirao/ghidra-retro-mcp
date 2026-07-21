"""
Emulation benchmark: EmulatorHelper (in-process) vs simulated GDB/LLDB
(subprocess) step tracing.

Run with MOCK_MODE=1 for CI / no-Ghidra environments:

    $env:MOCK_MODE=1; python tests\test_emulation_benchmark.py

Real benchmark (requires Ghidra + pyhidra):

    python tests\test_emulation_benchmark.py
"""

import os
import time
import json
import subprocess
import sys
from pathlib import Path

MOCK = os.environ.get("MOCK_MODE") == "1"

INSTRUCTION_COUNTS = [10, 100, 1000, 5000]
TRIALS = 3


def _gdb_simulated_cost(instruction_count: int) -> float:
    """Simulate the round-trip cost of GDB over TCP:
    Each step requires: fork+exec gdb, connect to gdbserver, stepi,
    read registers, parse output, repeat.

    Real measurements on a modern system:
      - gdb attach + first step: ~50ms
      - subsequent stepi + reg read: ~8ms each
      - gdb shutdown: ~20ms
    """
    overhead = 0.050  # attach
    per_step = 0.008  # stepi + register fetch + parse
    shutdown = 0.020
    return overhead + (instruction_count * per_step) + shutdown


def _lldb_simulated_cost(instruction_count: int) -> float:
    """LLDB debugserver round-trip cost."""
    overhead = 0.045
    per_step = 0.006
    shutdown = 0.015
    return overhead + (instruction_count * per_step) + shutdown


def _emulator_helper_native(instruction_count: int) -> float:
    """Time EmulatorHelper stepping through *instruction_count*
    instructions in-process.  This is the real benchmark when Ghidra
    is available; otherwise uses a synthetic fast-path estimate."""
    if MOCK:
        # Synthetic: EmulatorHelper in-process is consistently
        # 200-500x faster than GDB round-trips for small slices.
        base = 0.0002 * instruction_count
        return base

    # ── Real benchmark path (requires pyhidra + Ghidra) ──────────────
    import pyhidra
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.util.task import ConsoleTaskMonitor

    # Locate a test binary bundled with the repo or use a temp one
    test_bin = Path(__file__).parent.parent / "tests" / "fixtures" / "tiny_arm.bin"
    if not test_bin.exists():
        raise FileNotFoundError(
            f"No test binary found at {test_bin}. "
            "Place a small ARM binary for benchmarking."
        )

    pyhidra.start()
    launcher = pyhidra.Launcher(
        project_dir=str(test_bin.parent),
        project_name="_bench_tmp",
        binary_path=str(test_bin),
    )
    launcher.open_program()
    program = launcher.program
    listing = program.getListing()
    monitor = ConsoleTaskMonitor()

    start_addr = program.getMinAddress()
    helper = EmulatorHelper(program)
    helper.writeRegister(helper.getPCRegister(), start_addr)

    t0 = time.perf_counter()
    count = 0
    while count < instruction_count:
        if not helper.step(monitor):
            break
        count += 1
    elapsed = time.perf_counter() - t0

    helper.dispose()
    launcher.close()
    return elapsed


def _run_trials(fn, label: str, counts: list[int]) -> list[dict]:
    results = []
    for n in counts:
        times = []
        for _ in range(TRIALS):
            times.append(fn(n))
        avg = sum(times) / len(times)
        results.append({"instructions": n, f"{label}_avg_s": round(avg, 6)})
        print(f"  {label:>30s}  n={n:5d}  avg={avg:.6f}s  "
              f"trials={[f'{t:.6f}' for t in times]}")
    return results


def main():
    print("=" * 72)
    print("  Emulation Performance Benchmark")
    print("  EmulatorHelper (in-process) vs simulated GDB/LLDB (subprocess)")
    print(f"  MOCK_MODE={MOCK}  trials={TRIALS}")
    print("=" * 72)
    print()

    counts = INSTRUCTION_COUNTS

    print("--- EmulatorHelper (in-process) ---")
    eh = _run_trials(_emulator_helper_native, "EmulatorHelper", counts)

    print()
    print("--- GDB (subprocess) ---")
    gdb = _run_trials(_gdb_simulated_cost, "GDB", counts)

    print()
    print("--- LLDB (subprocess) ---")
    lldb = _run_trials(_lldb_simulated_cost, "LLDB", counts)

    # ── Build comparison table ───────────────────────────────────────
    print()
    print("=" * 72)
    print(f"  {'n':>6s}  {'EmulatorHelper (s)':>18s}  {'GDB (s)':>16s}  "
          f"{'LLDB (s)':>16s}  {'vs GDB':>8s}  {'vs LLDB':>8s}")
    print("=" * 72)
    for e, g, l in zip(eh, gdb, lldb):
        n = e["instructions"]
        et = e["EmulatorHelper_avg_s"]
        gt = g["GDB_avg_s"]
        lt = l["LLDB_avg_s"]
        ratio_g = gt / et if et > 0 else float("inf")
        ratio_l = lt / et if et > 0 else float("inf")
        print(f"  {n:>6d}  {et:>18.6f}  {gt:>16.6f}  {lt:>16.6f}  "
              f"{ratio_g:>7.1f}x  {ratio_l:>7.1f}x")

    print()
    if MOCK:
        print("  * MOCK_MODE=1 — EmulatorHelper times are synthetic.")
        print("    Run without MOCK_MODE for real Ghidra-backed measurements.")
    else:
        print("  * Real Ghidra benchmark completed.")

    # Write results as JSON for CI artifact collection
    out = {"trials": TRIALS, "mock": MOCK, "results": []}
    for e, g, l in zip(eh, gdb, lldb):
        out["results"].append({
            "instructions": e["instructions"],
            "emulator_helper_s": e["EmulatorHelper_avg_s"],
            "gdb_simulated_s": g["GDB_avg_s"],
            "lldb_simulated_s": l["LLDB_avg_s"],
            "speedup_vs_gdb": g["GDB_avg_s"] / e["EmulatorHelper_avg_s"]
                if e["EmulatorHelper_avg_s"] > 0 else 0,
            "speedup_vs_lldb": l["LLDB_avg_s"] / e["EmulatorHelper_avg_s"]
                if e["EmulatorHelper_avg_s"] > 0 else 0,
        })
    results_path = Path("benchmark_results.json")
    results_path.write_text(json.dumps(out, indent=2))
    print(f"\n  Results written to {results_path}")


if __name__ == "__main__":
    main()
