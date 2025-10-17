from __future__ import annotations

import math
import sys
import time
import random
import statistics
from typing import List, Tuple, Dict
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import font_manager, ticker

sys.path.append(".")

# 假设以下模块已正确实现
from src.basic_shamir import BasicShamir as FastBasicShamir
from src.feldman_vss import FeldmanVSS as FastFeldmanVSS
from src.block_shamir import BasicShamir as SlowBasicShamir
from src.basic_feldman import FeldmanVSS as SlowFeldmanVSS


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
    prime_bits_list: List[int] = [192, 256, 384, 512, 1024],  # 更多素数位
    n: int = 10,
    t: int = 4,
    rounds: int = 1,
    sizes: List[int] | None = None,
    seed: int = 1337,
) -> Tuple[Dict[int, pd.DataFrame], Dict[int, pd.DataFrame]]:
    all_basic_dfs = {}
    all_feldman_dfs = {}
    for prime_bits in prime_bits_list:
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
                ("Optimized", FastFeldmanVSS),
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

        all_basic_dfs[prime_bits] = basic_df
        all_feldman_dfs[prime_bits] = feldman_df

        _plot_task1(basic_df, prime_bits)
        _plot_task2(feldman_df, prime_bits)

    return all_basic_dfs, all_feldman_dfs


def _plot_task1(df: pd.DataFrame, prime_bits: int) -> None:
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

    axes[0].set_title(f"BasicShamir (prime_bits={prime_bits}) Split/Recover Time")
    axes[0].set_xlabel("Secret Size (KB)")
    axes[0].set_ylabel("Time (ms)")
    axes[0].grid(True, linestyle="--", alpha=0.4)

    axes[1].set_title(f"BasicShamir (prime_bits={prime_bits}) Total Time")
    axes[1].set_xlabel("Secret Size (KB)")
    axes[1].set_ylabel("Time (ms)")
    axes[1].grid(True, linestyle="--", alpha=0.4)

    axes[0].legend()
    axes[1].legend()
    fig.tight_layout()
    fig.savefig(f"shamir_{prime_bits}.png", bbox_inches="tight")
    plt.close(fig)


def _plot_task2(df: pd.DataFrame, prime_bits: int) -> None:
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

    axes[0].set_title(f"Feldman VSS (prime_bits={prime_bits}) Every Phase Time")
    axes[0].set_xlabel("Secret Size (KB)")
    axes[0].set_ylabel("Time (ms)")
    axes[0].grid(True, linestyle="--", alpha=0.4)

    axes[1].set_title(f"Feldman VSS (prime_bits={prime_bits}) Total Time")
    axes[1].set_xlabel("Secret Size (KB)")
    axes[1].set_ylabel("Time (ms)")
    axes[1].grid(True, linestyle="--", alpha=0.4)

    axes[0].legend()
    axes[1].legend()
    fig.tight_layout()
    fig.savefig(f"feldman_{prime_bits}.png", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    prime_bits_list = [192, 256, 384, 512, 1024]
    all_basic_dfs, all_feldman_dfs = run_benchmark(prime_bits_list=prime_bits_list)
    for prime_bits in prime_bits_list:
        print(f"\nTask 1 — BasicShamir (prime_bits={prime_bits}) timings (ms):")
        print(all_basic_dfs[prime_bits].to_string(index=False))
        print(f"\nTask 2 — Feldman VSS (prime_bits={prime_bits}) timings (ms):")
        print(all_feldman_dfs[prime_bits].to_string(index=False))