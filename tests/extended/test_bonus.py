import os
import time

from src.basic_shamir import BasicShamir
from src.feldman_vss import FeldmanVSS

def test_large_secret_32kb():
    print("== Test: BasicShamir large-secret (32KB) ==")
    shamir = BasicShamir(prime_bits=256)
    secret = os.urandom(32768)  # 32KB

    n, t = 7, 3
    shares = shamir.split_secret_large(secret, n=n, t=t)

    # 任取 t 份恢复
    recovered = shamir.recover_secret_large(shares[:t], t=t)
    assert recovered == secret, "Large secret round-trip failed"
    print("round-trip OK; one participant payload bytes =", len(shares[0][1]))


def test_vss_aggregate_and_batch():
    print("== Test: FeldmanVSS aggregate & batch verification ==")
    vss = FeldmanVSS(bits=256)
    secret = os.urandom(20)  # 单块即可
    n, t = 120, 5
    shares, commits = vss.share_with_commitments(secret, n, t)

    # 1) 聚合一次性验证（全部应为真）
    t0 = time.time()
    ok_all = vss.aggregate_batch_verify(shares, commits, seed=42)
    t1 = time.time()
    assert ok_all, "Aggregate verification should pass when all shares are valid"
    print(f"aggregate verify time: {t1 - t0:.6f}s (n={n}, t={t})")

    # 2) 对比逐份验证时间
    t2 = time.time()
    per_results = [vss.verify_share(i, s, commits) for (i, s) in shares]
    t3 = time.time()
    assert all(per_results), "All per-share verifications should pass"
    print(f"per-share verify time: {t3 - t2:.6f}s (n={n}, t={t})")

    # 3) 破坏一个份额，batch_verification 应定位该坏份额
    bad = shares.copy()
    bad_index = 3
    bad[bad_index] = (bad[bad_index][0], (bad[bad_index][1] + 1) % vss.q)

    res = vss.batch_verification(bad, commits)
    assert res.count(False) == 1 and not res[bad_index], "Batch verification should flag exactly the bad share"
    print("batch-verification flagged the bad share correctly.")


if __name__ == "__main__":
    test_large_secret_32kb()
    test_vss_aggregate_and_batch()
    print("All bonus tests passed.")
