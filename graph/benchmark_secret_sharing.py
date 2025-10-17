
import sys, time, random, statistics
import pandas as pd
import matplotlib.pyplot as plt

sys.path.append(".")  # assume basic_shamir.py & feldman_vss.py in the same folder

from src.basic_shamir import BasicShamir
from src.feldman_vss import FeldmanVSS

def run_benchmark(prime_bits=256, n=10, t=4, rounds=100, sizes=None, seed=1337):
    rng = random.Random(seed)
    def rand_bytes(n):
        return bytes(rng.getrandbits(8) for _ in range(n))

    tmp = BasicShamir(prime_bits=prime_bits)
    block_size = tmp.block_size

    if sizes is None:
        small_sizes = sorted(set([1, max(2, block_size//4), max(4, block_size//2), max(2, block_size//4) * 3, max(8, block_size-1)]))
        large_sizes = [1024,2048, 4096,8192, 12288, 16384, 20480, 24586, 28582, 32768]  # 1KB, 4KB, 32KB
        sizes = small_sizes + large_sizes

    def bench_basic_shamir(size):
        shamir = BasicShamir(prime_bits=prime_bits)
        split_times, recover_times = [], []
        for _ in range(rounds):
            secret = rand_bytes(size)
            t0 = time.perf_counter()
            shares = shamir.split_secret(secret, n=n, t=t)
            split_times.append(time.perf_counter() - t0)
            if size >= 1024:
                meta, keys = shares[:4], shares[4:]
                rec_input = meta + rng.sample(keys, t)
            else:
                rec_input = rng.sample(shares, t)
            t1 = time.perf_counter()
            recovered = shamir.recover_secret(rec_input)
            recover_times.append(time.perf_counter() - t1)
            assert recovered == secret
        return statistics.mean(split_times), statistics.mean(recover_times)

    def bench_feldman_vss(size):
        vss = FeldmanVSS(bits=prime_bits)
        sct, vt, rt = [], [], []
        for _ in range(rounds):
            secret = rand_bytes(size)
            t0 = time.perf_counter()
            shares, commits = vss.share_with_commitments(secret, n=n, t=t)
            sct.append(time.perf_counter() - t0)
            t1 = time.perf_counter()
            ok = vss.batch_verification(shares, commits)
            vt.append(time.perf_counter() - t1)
            assert all(ok)
            rec_shares = rng.sample(shares, t)
            t2 = time.perf_counter()
            recovered = vss.recover_secret_from_shares(rec_shares, commits)
            rt.append(time.perf_counter() - t2)
            assert recovered == secret
        return statistics.mean(sct), statistics.mean(vt), statistics.mean(rt)

    basic_rows, feldman_rows = [], []
    for sz in sizes:
        bs_split, bs_recover = bench_basic_shamir(sz)
        basic_rows.append({
            "Secret Size (bytes)": sz,
            "Share/Split (ms)": bs_split * 1000.0,
            "Recover (ms)": bs_recover * 1000.0,
            "Mode": "Hybrid" if sz >= 1024 else "Standard"
        })
        f_share, f_verify, f_recover = bench_feldman_vss(sz)
        feldman_rows.append({
            "Secret Size (bytes)": sz,
            "Share+Commit (ms)": f_share * 1000.0,
            "Batch Verify (ms)": f_verify * 1000.0,
            "Recover (ms)": f_recover * 1000.0,
            "Mode": "Hybrid" if sz >= 1024 else "Standard"
        })

    basic_df = pd.DataFrame(basic_rows)
    feldman_df = pd.DataFrame(feldman_rows)

    # plots
    def to_kb(x): return x / 1024.0
    basic_df["Size (KB)"] = basic_df["Secret Size (bytes)"].apply(to_kb)
    feldman_df["Size (KB)"] = feldman_df["Secret Size (bytes)"].apply(to_kb)

    plt.figure()
    plt.plot(basic_df["Size (KB)"], basic_df["Share/Split (ms)"], marker="o", label="Share/Split")
    plt.plot(basic_df["Size (KB)"], basic_df["Recover (ms)"], marker="s", label="Recover")
    plt.title("Problem 1 — BasicShamir Performance vs Secret Size")
    plt.xlabel("Secret Size (KB)")
    plt.ylabel("Time (ms)")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.savefig("perf_basic_shamir2.png", bbox_inches="tight")
    plt.close()

    plt.figure()
    plt.plot(feldman_df["Size (KB)"], feldman_df["Share+Commit (ms)"], marker="o", label="Share+Commit")
    plt.plot(feldman_df["Size (KB)"], feldman_df["Batch Verify (ms)"], marker="s", label="Batch Verify")
    plt.plot(feldman_df["Size (KB)"], feldman_df["Recover (ms)"], marker="^", label="Recover")
    plt.title("Problem 2 — Feldman VSS Performance vs Secret Size")
    plt.xlabel("Secret Size (KB)")
    plt.ylabel("Time (ms)")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.savefig("perf_feldman_vss2.png", bbox_inches="tight")
    plt.close()

    return basic_df, feldman_df

if __name__ == "__main__":
    bdf, fdf = run_benchmark()
    print("BasicShamir timings:")
    print(bdf.to_string(index=False))
    print("\nFeldmanVSS timings:")
    print(fdf.to_string(index=False))
