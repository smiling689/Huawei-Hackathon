from __future__ import annotations

import math
import sys
import time
import random
import statistics
from typing import List, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import font_manager, ticker

sys.path.append(".")

from src.basic_shamir import BasicShamir as FastBasicShamir  # noqa: E402
from src.feldman_vss import FeldmanVSS as FastFeldmanVSS  # noqa: E402
from basic_task1 import BasicShamir as SlowBasicShamir  # noqa: E402
from basic_task2 import FeldmanVSS as SlowFeldmanVSS  # noqa: E402


def _setup_matplotlib_fonts() -> None:
    preferred_fonts = [
        "SimHei",
        "Microsoft YaHei",
        "Noto Sans CJK SC",
        "WenQuanYi Micro Hei",
    ]
    available = {f.name for f in font_manager.fontManager.ttflist}
    for font_name in preferred_fonts:
        if font_name in available:
            existing = list(plt.rcParams.get("font.sans-serif", []))
            plt.rcParams["font.sans-serif"] = [font_name, *existing]
            break
    plt.rcParams["axes.unicode_minus"] = False


def _format_power_of_ten(value: float, _: int) -> str:
    if value <= 0:
        return ""
    exponent = int(round(math.log10(value)))
    if math.isclose(value, 10 ** exponent, rel_tol=1e-9, abs_tol=1e-12):
        return f"10^{exponent}"
    return f"{value:.1g}"


def _apply_log_axis_style(axis: plt.Axes) -> None:
    axis.set_yscale("log")
    axis.yaxis.set_major_locator(ticker.LogLocator(base=10))
    axis.yaxis.set_minor_locator(ticker.NullLocator())
    axis.yaxis.set_major_formatter(ticker.FuncFormatter(_format_power_of_ten))


def _apply_axis_text_style(axis: plt.Axes, font_size: float | None) -> None:
    if font_size is None:
        return
    axis.title.set_fontsize(font_size)
    axis.xaxis.label.set_fontsize(font_size)
    axis.yaxis.label.set_fontsize(font_size)
    axis.tick_params(axis="both", labelsize=font_size)


_setup_matplotlib_fonts()


def _generate_sizes(block_size: int) -> List[int]:
    small_sizes = sorted(
        set(
            [
                1,
                max(2, block_size // 4),
                max(4, block_size // 2),
                max(2, block_size // 4) * 3,
                max(8, block_size - 1),
            ]
        )
    )
    large_sizes = [1024, 2048, 4096, 8192, 12288, 16384, 20480, 24586, 28582, 32768]
    combined = sorted(set(small_sizes + large_sizes))
    return combined


def bench_basic(shamir_cls, impl_key: str, size: int, prime_bits: int, rounds: int, n: int, t: int, seed: int) -> Tuple[float, float]:
    local_rng = random.Random(f"{seed}-{impl_key}-basic-{size}")
    split_times: List[float] = []
    recover_times: List[float] = []
    for _ in range(rounds):
        secret = bytes(local_rng.getrandbits(8) for _ in range(size))
        shamir = shamir_cls(prime_bits=prime_bits)
        start = time.perf_counter()
        shares = shamir.split_secret(secret, n=n, t=t)
        split_times.append(time.perf_counter() - start)
        if len(shares) < t:
            raise ValueError("生成的份额不足以恢复秘密")

        meta_shares = [s for s in shares if s[0] < 0]
        positive_shares = [s for s in shares if s[0] > 0]
        if meta_shares:
            if len(positive_shares) < t:
                raise ValueError("混合模式需要至少 t 个正编号份额")
            rec_input = meta_shares + local_rng.sample(positive_shares, t)
        else:
            rec_input = local_rng.sample(shares, t)
        start = time.perf_counter()
        recovered = shamir.recover_secret(rec_input)
        recover_times.append(time.perf_counter() - start)
        assert recovered == secret
    return statistics.mean(split_times), statistics.mean(recover_times)


def bench_feldman(vss_cls, impl_key: str, size: int, prime_bits: int, rounds: int, n: int, t: int, seed: int) -> Tuple[float, float, float]:
    local_rng = random.Random(f"{seed}-{impl_key}-feldman-{size}")
    share_times: List[float] = []
    verify_times: List[float] = []
    recover_times: List[float] = []
    for _ in range(rounds):
        secret = bytes(local_rng.getrandbits(8) for _ in range(size))
        vss = vss_cls(bits=prime_bits)
        start = time.perf_counter()
        shares, commits = vss.share_with_commitments(secret, n=n, t=t)
        share_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        ok = vss.batch_verification(shares, commits)
        verify_times.append(time.perf_counter() - start)
        assert all(ok)

        share_indices = local_rng.sample(range(len(shares)), t)
        rec_input = [shares[idx] for idx in share_indices]
        start = time.perf_counter()
        recovered = vss.recover_secret_from_shares(rec_input, commits)
        recover_times.append(time.perf_counter() - start)
        assert recovered == secret
    return (
        statistics.mean(share_times),
        statistics.mean(verify_times),
        statistics.mean(recover_times),
    )


def run_benchmark(
    prime_bits: int = 256,
    n: int = 10,
    t: int = 4,
    rounds: int = 100,
    sizes: List[int] | None = None,
    seed: int = 1337,
    font_size: float | None = None,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    reference = FastBasicShamir(prime_bits=prime_bits)
    block_size = reference.block_size
    sizes = sizes or _generate_sizes(block_size)

    basic_rows = []
    with ProcessPoolExecutor() as executor:
        futures = {}
        for impl_name, cls in (
            ("Our", FastBasicShamir),
            ("Naive", SlowBasicShamir),
        ):
            for sz in sizes:
                future = executor.submit(bench_basic, cls, impl_name, sz, prime_bits, rounds, n, t, seed)
                futures[future] = (impl_name, sz)
        for future in as_completed(futures):
            impl_name, sz = futures[future]
            split, recover = future.result()
            basic_rows.append(
                {
                    "Implementation": impl_name,
                    "Secret Size (bytes)": sz,
                    "Share/Split (ms)": split * 1000.0,
                    "Recover (ms)": recover * 1000.0,
                    "Total (ms)": (split + recover) * 1000.0,
                    "Mode": "Hybrid" if sz > block_size else "Standard",
                }
            )

    feldman_rows = []
    with ProcessPoolExecutor() as executor:
        futures = {}
        for impl_name, cls in (
            ("Our", FastFeldmanVSS),
            ("Naive", SlowFeldmanVSS),
        ):
            for sz in sizes:
                future = executor.submit(bench_feldman, cls, impl_name, sz, prime_bits, rounds, n, t, seed)
                futures[future] = (impl_name, sz)
        for future in as_completed(futures):
            impl_name, sz = futures[future]
            share, verify, recover = future.result()
            feldman_rows.append(
                {
                    "Implementation": impl_name,
                    "Secret Size (bytes)": sz,
                    "Share+Commit (ms)": share * 1000.0,
                    "Batch Verify (ms)": verify * 1000.0,
                    "Recover (ms)": recover * 1000.0,
                    "Total (ms)": (share + verify + recover) * 1000.0,
                    "Mode": "Hybrid" if sz > block_size else "Standard",
                }
            )

    basic_df = (
        pd.DataFrame(basic_rows)
        .sort_values(["Implementation", "Secret Size (bytes)"])
        .reset_index(drop=True)
    )
    feldman_df = (
        pd.DataFrame(feldman_rows)
        .sort_values(["Implementation", "Secret Size (bytes)"])
        .reset_index(drop=True)
    )

    to_kb = lambda x: x / 1024.0
    basic_df["Size (KB)"] = basic_df["Secret Size (bytes)"].apply(to_kb)
    feldman_df["Size (KB)"] = feldman_df["Secret Size (bytes)"].apply(to_kb)

    _plot_task1(basic_df, font_size=font_size)
    _plot_task2(feldman_df, font_size=font_size)

    return basic_df, feldman_df


def _plot_task1(df: pd.DataFrame, font_size: float | None = None) -> None:
    colors = {"Our": "#1f77b4", "Naive": "#ff7f0e"}
    styles = {
        "Share/Split (ms)": ("o", "-"),
        "Recover (ms)": ("s", "--"),
    }

    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharex=True)

    for implementation, group in df.groupby("Implementation"):
        for metric, (marker, linestyle) in styles.items():
            axes[0].plot(
                group["Size (KB)"],
                group[metric],
                marker=marker,
                linestyle=linestyle,
                color=colors[implementation],
                label=f"{implementation} {metric}",
            )

        axes[1].plot(
            group["Size (KB)"],
            group["Total (ms)"],
            marker="^",
            linestyle="-",
            color=colors[implementation],
            label=f"{implementation} Total",
        )

    for ax in axes:
        _apply_log_axis_style(ax)

    axes[0].set_title("BasicShamir Split/Recover Time")
    axes[0].set_xlabel("Secret Size (KB)")
    axes[0].set_ylabel("Time (ms)")
    axes[0].grid(True, linestyle="--", alpha=0.4)

    axes[1].set_title("BasicShamir Total Time")
    axes[1].set_xlabel("Secret Size (KB)")
    axes[1].set_ylabel("Time (ms)")
    axes[1].grid(True, linestyle="--", alpha=0.4)

    for ax in axes:
        _apply_axis_text_style(ax, font_size)

    legend_kwargs = {"fontsize": font_size - 10} if font_size is not None else {}
    axes[0].legend(**legend_kwargs)
    axes[1].legend(**legend_kwargs)
    fig.tight_layout()
    fig.savefig("shamir.png", bbox_inches="tight")
    plt.close(fig)


def _plot_task2(df: pd.DataFrame, font_size: float | None = None) -> None:
    colors = {"Our": "#1f77b4", "Naive": "#ff7f0e"}
    styles = {
        "Share+Commit (ms)": ("o", "-"),
        "Batch Verify (ms)": ("s", "--"),
        "Recover (ms)": ("^", "-."),
    }

    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharex=True)

    for implementation, group in df.groupby("Implementation"):
        for metric, (marker, linestyle) in styles.items():
            axes[0].plot(
                group["Size (KB)"],
                group[metric],
                marker=marker,
                linestyle=linestyle,
                color=colors[implementation],
                label=f"{implementation} {metric}",
            )

        axes[1].plot(
            group["Size (KB)"],
            group["Total (ms)"],
            marker="d",
            linestyle="-",
            color=colors[implementation],
            label=f"{implementation} Total",
        )

    for ax in axes:
        _apply_log_axis_style(ax)

    axes[0].set_title("Feldman VSS Every Phase Time")
    axes[0].set_xlabel("Secret Size (KB)")
    axes[0].set_ylabel("Time (ms)")
    axes[0].grid(True, linestyle="--", alpha=0.4)

    axes[1].set_title("Feldman VSS Total Time")
    axes[1].set_xlabel("Secret Size (KB)")
    axes[1].set_ylabel("Time (ms)")
    axes[1].grid(True, linestyle="--", alpha=0.4)

    for ax in axes:
        _apply_axis_text_style(ax, font_size)

    legend_kwargs = {"fontsize": font_size - 14} if font_size is not None else {}
    axes[0].legend(**legend_kwargs)
    axes[1].legend(**legend_kwargs)
    fig.tight_layout()
    fig.savefig("feldman.png", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    bdf, fdf = run_benchmark(font_size=24)
    print("Task 1 — BasicShamir timings (ms):")
    print(bdf.to_string(index=False))
    print("\nTask 2 — Feldman VSS timings (ms):")
    print(fdf.to_string(index=False))
