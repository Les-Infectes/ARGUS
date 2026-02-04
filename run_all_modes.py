#!/usr/bin/env python3
"""
Run all BloodHound Tier-based analysis modes automatically.
Generates 3 JSON files for Tier 0, Tier 1, and Tier 2 attack paths.
"""
import argparse
import subprocess
import sys
import os
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
GRAPH_BUILDER = SCRIPT_DIR / "graph_builder.py"


def run_mode(data_dir, start, mode, output_file):
    """Run graph_builder.py with specified mode."""
    cmd = [
        sys.executable,
        str(GRAPH_BUILDER),
        "--data-dir", data_dir,
        "--start", start,
        "--mode", str(mode),
        "--out", output_file,
    ]

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

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Define output files for each tier
    outputs = {
        0: output_dir / "graph_tier0.json",
        1: output_dir / "graph_tier1.json",
        2: output_dir / "graph_tier2.json",
        3: output_dir / "graph_tier3.json",
    }

    print("="*70)
    print("CartoAD - Tier-Based Attack Path Analysis")
    print("="*70)
    print(f"Data directory: {args.data_dir}")
    print(f"Start node: {args.start}")
    print(f"Output directory: {output_dir}")
    print(f"\nGenerating {len(outputs)} tier-based reports...")

    # Run all modes
    results = {}
    for mode, output_file in outputs.items():
        success = run_mode(args.data_dir, args.start, mode, str(output_file))
        results[mode] = success

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    mode_names = {
        0: "Mode 0 - Tier 0 (10 paths to Domain/DCs/DA - Critical)",
        1: "Mode 1 - Tier 1 (20 paths to high-privilege accounts - 1-2 hops)",
        2: "Mode 2 - Tier 2 (30 paths to servers/workstations - 3-5 hops)",
        3: "Mode 3 - Tier 3 (40 paths to isolated/distant objects - 6+ hops)",
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
        print("  - graph_tier0.json  (Tier 0: Domain control - 10 paths)")
        print("  - graph_tier1.json  (Tier 1: High privileges - 20 paths)")
        print("  - graph_tier2.json  (Tier 2: Infrastructure - 30 paths)")
        print("  - graph_tier3.json  (Tier 3: Isolated/distant - 40 paths)")
        print("\nYou can now load these files in the UI (cartographie.html)")
        print("\nℹ Classification uses technical criteria:")
        print("  • SID-based detection (RID -500, -502, -512, -516, -518, -519, etc.)")
        print("  • userAccountControl flags (DC detection)")
        print("  • DCSync rights holders")
        print("  • Graph distance calculation (shortest path to Tier 0)")
        return 0
    else:
        failed_modes = [mode for mode, success in results.items() if not success]
        print(f"\n✗ Some modes failed: {failed_modes}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
