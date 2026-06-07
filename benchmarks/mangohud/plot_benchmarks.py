#!/usr/bin/env python3
"""Read MangoHUD benchmark CSV logs and generate comparative plots for thesis reporting."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Global default plot limits. Adjust these values directly in the code.
TIME_XLIM: tuple[float, float] | None = (0, 100)
FRAMETIME_YLIM: tuple[float, float] | None = (0, 20)
FPS_YLIM: tuple[float, float] | None = None
FRAMETIME_HIST_XLIM: tuple[float, float] | None = (0, 10)
LOAD_YLIM: tuple[float, float] | None = None
TEMP_YLIM: tuple[float, float] | None = None
POWER_RAM_YLIM: tuple[float, float] | None = None
HISTOGRAM_BINS: int = 100

plt.rcParams['svg.fonttype'] = 'none'


def parse_metadata(path: Path) -> Dict[str, str]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        line1 = handle.readline().strip()
        line2 = handle.readline().strip()

    if not line1 or not line2:
        raise ValueError(f"File {path} does not contain expected metadata header lines.")

    keys = [column.strip() for column in next(csv.reader([line1]))]
    values = [value.strip() for value in next(csv.reader([line2]))]
    return {key: values[idx] if idx < len(values) else "" for idx, key in enumerate(keys)}


def load_bench_csv(path: Path) -> Tuple[pd.DataFrame, Dict[str, str]]:
    meta = parse_metadata(path)
    df = pd.read_csv(path, skiprows=2)
    df = df.loc[:, df.columns.notna()]

    if df.empty:
        raise ValueError(f"No measurement rows found in {path}")

    df = df.reset_index(drop=True)
    df["sample_index"] = df.index

    if "elapsed" in df.columns:
        elapsed_seconds = df["elapsed"] / 1_000_000_000.0
        df["elapsed_s"] = elapsed_seconds - elapsed_seconds.iloc[0]
    else:
        df["elapsed_s"] = df["sample_index"]

    if "frametime" in df.columns:
        df["frametime_ms"] = df["frametime"]

    config = path.stem
    if "_cs2_" in config:
        config = config.split("_cs2_")[0]

    df["config"] = config
    df["source"] = str(path.name)
    df["driver"] = meta.get("driver", "")
    df["kernel"] = meta.get("kernel", "")
    df["cpu"] = meta.get("cpu", "")
    df["gpu"] = meta.get("gpu", "")
    df["os"] = meta.get("os", "")
    df["cpuscheduler"] = meta.get("cpuscheduler", "")

    return df, meta


def build_summary(df: pd.DataFrame) -> Dict[str, float]:
    summary: Dict[str, float] = {}
    if "fps" in df.columns:
        summary["fps_mean"] = float(df["fps"].mean())
        summary["fps_median"] = float(df["fps"].median())
        summary["fps_std"] = float(df["fps"].std())
    if "frametime_ms" in df.columns:
        summary["frametime_mean_ms"] = float(df["frametime_ms"].mean())
        summary["frametime_median_ms"] = float(df["frametime_ms"].median())
        summary["frametime_std_ms"] = float(df["frametime_ms"].std())
        summary["frametime_p99_ms"] = float(df["frametime_ms"].quantile(0.99))
        summary["frametime_p999_ms"] = float(df["frametime_ms"].quantile(0.999))
        summary["frametime_p95_ms"] = float(df["frametime_ms"].quantile(0.95))
    if "cpu_load" in df.columns:
        summary["cpu_load_mean"] = float(df["cpu_load"].mean())
        summary["gpu_load_mean"] = float(df["gpu_load"].mean())
    if "gpu_temp" in df.columns:
        summary["gpu_temp_mean_c"] = float(df["gpu_temp"].mean())
        summary["cpu_temp_mean_c"] = float(df["cpu_temp"].mean()) if "cpu_temp" in df.columns else float("nan")
    return summary


def plot_benchmarks(
    dfs: List[pd.DataFrame],
    output_dir: Path,
    limits: Dict[str, tuple[float, float] | None] | None = None,
) -> None:
    sns.set(style="whitegrid", font_scale=1.1)
    output_dir.mkdir(parents=True, exist_ok=True)
    limits = limits or {}

    colors = sns.color_palette("tab10", n_colors=len(dfs))
    labels = [df["config"].iloc[0] for df in dfs]

    fig, axes = plt.subplots(3, 2, figsize=(18, 18), sharex=False)
    axes = axes.flatten()

    # Frame time over time
    for idx, df in enumerate(dfs):
        if "frametime_ms" in df.columns:
            axes[0].plot(df["elapsed_s"], df["frametime_ms"], alpha=0.55, color=colors[idx], label=labels[idx])
            if len(df) > 50:
                window = min(200, max(10, len(df) // 10))
                axes[0].plot(df["elapsed_s"], df["frametime_ms"].rolling(window, min_periods=1).mean(),
                             color=colors[idx], linewidth=2.0, linestyle="-")
    axes[0].set_title("Frame Time Over Time")
    axes[0].set_xlabel("Elapsed Time (s)")
    axes[0].set_ylabel("Frame Time (ms)")
    if limits.get("time_xlim"):
        axes[0].set_xlim(limits["time_xlim"])
    if limits.get("frametime_ylim"):
        axes[0].set_ylim(limits["frametime_ylim"])
    axes[0].legend()
    axes[0].grid(True)

    # FPS over time
    for idx, df in enumerate(dfs):
        if "fps" in df.columns:
            axes[1].plot(df["elapsed_s"], df["fps"], color=colors[idx], alpha=0.75, label=labels[idx])
    axes[1].set_title("FPS Over Time")
    axes[1].set_xlabel("Elapsed Time (s)")
    axes[1].set_ylabel("Frames per Second")
    if limits.get("time_xlim"):
        axes[1].set_xlim(limits["time_xlim"])
    if limits.get("fps_ylim"):
        axes[1].set_ylim(limits["fps_ylim"])
    axes[1].legend()
    axes[1].grid(True)

    # Frame time histogram
    hist_range = limits.get("frametime_hist_xlim")
    for idx, df in enumerate(dfs):
        if "frametime_ms" in df.columns:
            axes[2].hist(
                df["frametime_ms"],
                bins=HISTOGRAM_BINS,
                range=hist_range,
                alpha=0.45,
                color=colors[idx],
                label=labels[idx],
            )
    axes[2].set_title("Frame Time Distribution")
    axes[2].set_xlabel("Frame Time (ms)")
    axes[2].set_ylabel("Count")
    if hist_range:
        axes[2].set_xlim(hist_range)
    axes[2].legend()

    # CPU/GPU load
    for idx, df in enumerate(dfs):
        if "cpu_load" in df.columns and "gpu_load" in df.columns:
            axes[3].plot(df["elapsed_s"], df["cpu_load"], color=colors[idx], alpha=0.55, linestyle="-", label=f"CPU {labels[idx]}")
            axes[3].plot(df["elapsed_s"], df["gpu_load"], color=colors[idx], alpha=0.55, linestyle="--", label=f"GPU {labels[idx]}")
    axes[3].set_title("CPU and GPU Load Over Time")
    axes[3].set_xlabel("Elapsed Time (s)")
    axes[3].set_ylabel("Load (%)")
    if limits.get("time_xlim"):
        axes[3].set_xlim(limits["time_xlim"])
    if limits.get("load_ylim"):
        axes[3].set_ylim(limits["load_ylim"])
    axes[3].legend(ncol=2)
    axes[3].grid(True)

    # Temperature trends
    for idx, df in enumerate(dfs):
        if "gpu_temp" in df.columns:
            axes[4].plot(df["elapsed_s"], df["gpu_temp"], color=colors[idx], alpha=0.75, label=f"GPU {labels[idx]}")
        if "cpu_temp" in df.columns:
            axes[4].plot(df["elapsed_s"], df["cpu_temp"], color=colors[idx], alpha=0.75, linestyle="--", label=f"CPU {labels[idx]}")
    axes[4].set_title("Temperature Over Time")
    axes[4].set_xlabel("Elapsed Time (s)")
    axes[4].set_ylabel("Temperature (°C)")
    if limits.get("time_xlim"):
        axes[4].set_xlim(limits["time_xlim"])
    if limits.get("temp_ylim"):
        axes[4].set_ylim(limits["temp_ylim"])
    axes[4].legend(ncol=2)
    axes[4].grid(True)

    # Power and memory usage
    for idx, df in enumerate(dfs):
        if "gpu_power" in df.columns:
            axes[5].plot(df["elapsed_s"], df["gpu_power"], color=colors[idx], alpha=0.75, linestyle="-", label=f"GPU Power {labels[idx]}")
        if "ram_used" in df.columns:
            axes[5].plot(df["elapsed_s"], df["ram_used"], color=colors[idx], alpha=0.75, linestyle="--", label=f"RAM Used {labels[idx]}")
    axes[5].set_title("GPU Power and RAM Usage Over Time")
    axes[5].set_xlabel("Elapsed Time (s)")
    axes[5].set_ylabel("Power (W) / RAM Used")
    if limits.get("time_xlim"):
        axes[5].set_xlim(limits["time_xlim"])
    if limits.get("power_ram_ylim"):
        axes[5].set_ylim(limits["power_ram_ylim"])
    axes[5].legend(ncol=2)
    axes[5].grid(True)

    fig.tight_layout(rect=[0, 0.03, 1, 0.97])
    fig.suptitle("MangoHUD Benchmark Overview", fontsize=20)
    figure_path = output_dir / "benchmark_overview.png"
    fig.savefig(figure_path, dpi=200)
    plt.close(fig)
    print(f"Saved combined overview plot to {figure_path}")

    for df in dfs:
        config = df["config"].iloc[0]
        plot_path = output_dir / f"benchmark_{config}.svg"
        fig, axs = plt.subplots(2, 2, figsize=(16, 12))
        axs = axs.flatten()

        if "frametime_ms" in df.columns:
            axs[0].plot(df["elapsed_s"], df["frametime_ms"], color="tab:blue", alpha=0.7)
            axs[0].set_title("Frame Time")
            axs[0].set_xlabel("Elapsed Time (s)")
            axs[0].set_ylabel("ms")
            if limits.get("time_xlim"):
                axs[0].set_xlim(limits["time_xlim"])
            if limits.get("frametime_ylim"):
                axs[0].set_ylim(limits["frametime_ylim"])
            axs[0].grid(True)

        if "fps" in df.columns:
            axs[1].plot(df["elapsed_s"], df["fps"], color="tab:green", alpha=0.7)
            axs[1].set_title("FPS")
            axs[1].set_xlabel("Elapsed Time (s)")
            axs[1].set_ylabel("fps")
            if limits.get("time_xlim"):
                axs[1].set_xlim(limits["time_xlim"])
            if limits.get("fps_ylim"):
                axs[1].set_ylim(limits["fps_ylim"])
            axs[1].grid(True)

        if "frametime_ms" in df.columns:
            axs[2].hist(
                df["frametime_ms"],
                bins=HISTOGRAM_BINS,
                range=limits.get("frametime_hist_xlim"),
                color="tab:orange",
                alpha=0.7,
            )
            axs[2].set_title("Frame Time Histogram")
            axs[2].set_xlabel("Frame Time (ms)")
            axs[2].set_ylabel("Count")
            if limits.get("frametime_hist_xlim"):
                axs[2].set_xlim(limits["frametime_hist_xlim"])

        if "cpu_load" in df.columns and "gpu_load" in df.columns:
            axs[3].plot(df["elapsed_s"], df["cpu_load"], label="CPU Load", color="tab:red", alpha=0.7)
            axs[3].plot(df["elapsed_s"], df["gpu_load"], label="GPU Load", color="tab:purple", alpha=0.7)
            axs[3].set_title("CPU/GPU Load")
            axs[3].set_xlabel("Elapsed Time (s)")
            axs[3].set_ylabel("Load (%)")
            if limits.get("time_xlim"):
                axs[3].set_xlim(limits["time_xlim"])
            if limits.get("load_ylim"):
                axs[3].set_ylim(limits["load_ylim"])
            axs[3].legend()
            axs[3].grid(True)

        fig.suptitle(f"Benchmark Report: {config}", fontsize=18)
        fig.tight_layout(rect=[0, 0.03, 1, 0.95])
        fig.savefig(plot_path, dpi=200)
        plt.close(fig)
        print(f"Saved detailed per-run plot to {plot_path}")


def write_summary(summary_rows: List[Dict[str, object]], output_dir: Path) -> None:
    summary_df = pd.DataFrame(summary_rows)
    summary_csv = output_dir / "benchmark_summary.csv"
    summary_df.to_csv(summary_csv, index=False)
    print(f"Saved summary CSV to {summary_csv}")

    text_path = output_dir / "benchmark_summary.txt"
    with text_path.open("w", encoding="utf-8") as handle:
        handle.write("Benchmark summary statistics\n")
        handle.write("============================\n\n")
        for _, row in summary_df.iterrows():
            handle.write(f"Config: {row['config']}\n")
            for key, value in row.items():
                if key == "config":
                    continue
                handle.write(f"  {key}: {value}\n")
            handle.write("\n")
    print(f"Saved summary text report to {text_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot MangoHUD benchmark data from raw CSV logs.")
    parser.add_argument("--directory", "-d", default=".", help="Directory containing MangoHUD CSV files.")
    parser.add_argument("--output", "-o", default="plots", help="Directory to save plots and summary files.")
    parser.add_argument("--show", action="store_true", help="Show the combined overview plot after generation.")
    parser.add_argument("--time-xlim", nargs=2, type=float, metavar=("START", "END"), help="Elapsed time x-axis limits for time-based plots.")
    parser.add_argument("--frametime-ylim", nargs=2, type=float, metavar=("MIN", "MAX"), help="Y-axis limits for frame time plots.")
    parser.add_argument("--fps-ylim", nargs=2, type=float, metavar=("MIN", "MAX"), help="Y-axis limits for FPS plots.")
    parser.add_argument("--frametime-hist-xlim", nargs=2, type=float, metavar=("MIN", "MAX"), help="X-axis limits for the frame time histogram.")
    parser.add_argument("--load-ylim", nargs=2, type=float, metavar=("MIN", "MAX"), help="Y-axis limits for CPU/GPU load plots.")
    parser.add_argument("--temp-ylim", nargs=2, type=float, metavar=("MIN", "MAX"), help="Y-axis limits for temperature plots.")
    parser.add_argument("--power-ram-ylim", nargs=2, type=float, metavar=("MIN", "MAX"), help="Y-axis limits for GPU power and RAM usage plots.")
    args = parser.parse_args()

    root = Path(args.directory).expanduser().resolve()
    output_dir = Path(args.output).expanduser().resolve()

    csv_paths = sorted([path for path in root.glob("*.csv") if not path.name.endswith("_summary.csv")])
    if not csv_paths:
        raise SystemExit(f"No benchmark CSV files found in {root}")

    dfs: List[pd.DataFrame] = []
    summaries: List[Dict[str, object]] = []
    for csv_path in csv_paths:
        df, meta = load_bench_csv(csv_path)
        df["file_metadata"] = str(meta)
        dfs.append(df)
        summary = build_summary(df)
        summary["config"] = df["config"].iloc[0]
        summary["source_file"] = csv_path.name
        summary.update({k: v for k, v in meta.items() if k not in summary})
        summaries.append(summary)

    limits = {
        "time_xlim": tuple(args.time_xlim) if args.time_xlim else TIME_XLIM,
        "frametime_ylim": tuple(args.frametime_ylim) if args.frametime_ylim else FRAMETIME_YLIM,
        "fps_ylim": tuple(args.fps_ylim) if args.fps_ylim else FPS_YLIM,
        "frametime_hist_xlim": tuple(args.frametime_hist_xlim) if args.frametime_hist_xlim else FRAMETIME_HIST_XLIM,
        "load_ylim": tuple(args.load_ylim) if args.load_ylim else LOAD_YLIM,
        "temp_ylim": tuple(args.temp_ylim) if args.temp_ylim else TEMP_YLIM,
        "power_ram_ylim": tuple(args.power_ram_ylim) if args.power_ram_ylim else POWER_RAM_YLIM,
    }

    plot_benchmarks(dfs, output_dir, limits=limits)
    write_summary(summaries, output_dir)

    if args.show:
        try:
            import matplotlib.image as mpimg
            img = mpimg.imread(output_dir / "benchmark_overview.png")
            plt.figure(figsize=(12, 8))
            plt.imshow(img)
            plt.axis("off")
            plt.show()
        except Exception as exc:  # pragma: no cover
            print(f"Unable to show the figure automatically: {exc}")

    print("Benchmark plotting complete.")


if __name__ == "__main__":
    main()
