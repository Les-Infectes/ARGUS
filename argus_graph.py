#!/usr/bin/env python3
"""
Run all BloodHound Tier-based analysis modes automatically.
Generates JSON files for Tier 0, Tier 1, Tier 2 attack paths, and optionally a Global graph.
"""
import argparse
import subprocess
import sys
import os
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
GRAPH_BUILDER = SCRIPT_DIR / "argus_builder.py"


def run_mode(data_dir, start, mode, output_file, certipy_json=None):
    """Run argus_builder.py with specified mode."""
    cmd = [
        sys.executable,
        str(GRAPH_BUILDER),
        "--data-dir", data_dir,
        "--start", start,
        "--mode", str(mode),
        "--out", output_file,
    ]
    if certipy_json:
        cmd.extend(["--certipy-json", certipy_json])

    print(f"\n{'='*70}")
    print(f"Running Mode {mode}...")
    print(f"{'='*70}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=False, text=True)
        print(f"✓ Mode {mode} completed: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Mode {mode} failed with error code {e.returncode}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Run all BloodHound analysis modes and generate complete reports."
    )
    parser.add_argument(
        "--data-dir",
        required=True,
        help="Path to BloodHound JSON folder"
    )
    parser.add_argument(
        "--start",
        required=True,
        help="Start node identifier (e.g., 'user@domain.local')"
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Output directory for JSON files (default: results/)"
    )
    parser.add_argument(
        "--certipy-json",
        default=None,
        help="Path to certipy_data.json (ADCS certificate templates)"
    )
    parser.add_argument(
        "--all-starts",
        action="store_true",
        help="Include a global graph with paths from ALL possible entry points to Tier 0"
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Define output files for each tier
    outputs = {
        0: output_dir / "graph_tier0.json",
        1: output_dir / "graph_tier1.json",
        2: output_dir / "graph_tier2.json",
    }
    if args.all_starts:
        outputs[4] = output_dir / "graph_global.json"

    print("="*70)
    print("CartoAD - Tier-Based Attack Path Analysis")
    print("="*70)
    print(f"Data directory: {args.data_dir}")
    print(f"Start node: {args.start}")
    print(f"Output directory: {output_dir}")
    print(f"\nGenerating tier-based reports...")

    # Run all modes
    results = {}
    for mode, output_file in outputs.items():
        success = run_mode(args.data_dir, args.start, mode, str(output_file), args.certipy_json)
        results[mode] = success

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    mode_names = {
        0: "Mode 0 - Tier 0 (ALL paths to Domain/DCs/DA/Cert Publishers - Critical)",
        1: "Mode 1 - Tier 1 (30 paths, 1-7 hops from Tier 0)",
        2: "Mode 2 - Tier 2 (40 paths, ego-graph exploration)",
        4: "Mode 4 - Global (Paths from ALL entry points to Tier 0)",
    }

    for mode, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        output_file = outputs[mode]
        print(f"{status} - {mode_names[mode]}")
        if success:
            print(f"         → {output_file}")

    # Final status
    all_success = all(results.values())
    if all_success:
        print("\n✓ All tier analyses completed successfully!")
        print(f"\nGenerated files in: {output_dir}/")
        print("  - graph_tier0.json  (Tier 0: Domain control - ALL paths)")
        print("  - graph_tier1.json  (Tier 1: 1-7 hops - 30 paths)")
        print("  - graph_tier2.json  (Tier 2: ego-graph exploration - 40 paths)")
        if args.all_starts:
            print("  - graph_global.json (Global view: all entry points)")
        print("\nYou can now load these files in the UI (cartographie.html)")
        print("\nClassification v6:")
        print("  Tier 0: deterministic (SEED + CLOSURE + INDIRECT + MEMBERS)")
        print("  Tier 1: BFS distance 1-7 hops from Tier 0")
        print("  Tier 2: ego-graph exploration (8+ hops or unreachable)")
        return 0
    else:
        failed_modes = [mode for mode, success in results.items() if not success]
        print(f"\n✗ Some modes failed: {failed_modes}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
