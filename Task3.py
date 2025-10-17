import secrets
import time
from typing import Dict, List, Optional, Tuple

from Task1 import BasicSS


class ProactiveSecretSharing:
    def __init__(
        self,
        refresh_interval: int = 30 * 24 * 3600,
        prime_bits: int = 256,
        prime: Optional[int] = None,
    ):
        """
        初始化主动秘密分享系统。

        参数:
        refresh_interval: 刷新间隔（秒），默认 30 天。
        prime_bits: 使用的素数位数。
        prime: 共享的有限域素数（可选，缺省时尝试复用 BasicSS 缓存）。
        """
        if prime_bits < 32:
            raise ValueError("prime_bits 过小，无法提供安全的有限域")

        self.refresh_interval = refresh_interval
        self.prime_bits = prime_bits
        self.epoch = 0
        self.last_refresh_time = time.time()

        cached_prime = prime or BasicSS.get_cached_prime(prime_bits)
        if cached_prime is None:
            cached_prime = BasicSS(prime_bits=prime_bits).prime
        self.prime = cached_prime
        # self.last_refresh_details: Dict[int, Dict[str, object]] = {}

    def _generate_zero_polynomial(self, t: int) -> List[int]:
        """
        生成零常数项的随机多项式系数列表: [0, b1, b2, ..., b_{t-1}].
        """
        coefficients = [0]
        for _ in range(1, t):
            coefficients.append(secrets.randbelow(self.prime))
        return coefficients

    def _evaluate_delta(self, coeffs: List[int], x: int) -> int:
        """
        计算 δ(x)，其中 coeffs[0] = 0。
        """
        result = 0
        power = x % self.prime
        for coeff in coeffs[1:]:
            result = (result + coeff * power) % self.prime
            power = (power * x) % self.prime
        return result

    def active_refresh(
        self, old_shares: List[Tuple[int, int]], n: int, t: int
    ) -> List[Tuple[int, int]]:
        """
        执行份额刷新，保持秘密不变。
        """
        if not old_shares:
            raise ValueError("old_shares 不能为空")
        if n != len(old_shares):
            raise ValueError("n 必须与旧份额数量一致")
        if not (2 <= t <= n):
            raise ValueError("需要满足 2 ≤ t ≤ n")

        # 检查份额编号唯一性，并初始化增量累加器。
        share_ids = [share_id for share_id, _ in old_shares]
        if len(set(share_ids)) != len(share_ids):
            raise ValueError("旧份额中存在重复编号")

        delta_sums = {share_id: 0 for share_id in share_ids}
        # self.last_refresh_details = {}

        for participant_id in range(1, n + 1):
            refresh_info = self.generate_refresh_polynomial(participant_id, n, t)
            # self.last_refresh_details[participant_id] = refresh_info
            for share_id, delta_value in refresh_info["shares"]:
                if share_id not in delta_sums:
                    raise ValueError("份额编号与刷新贡献不一致")
                delta_sums[share_id] = (delta_sums[share_id] + delta_value) % self.prime

        new_shares = []
        for share_id, share_value in old_shares:
            updated_value = (share_value + delta_sums[share_id]) % self.prime
            new_shares.append((share_id, updated_value))

        self.epoch += 1
        self.last_refresh_time = time.time()
        return new_shares

    def schedule_automatic_refresh(self) -> bool:
        """
        判断是否到达刷新时间。
        """
        return (time.time() - self.last_refresh_time) >= self.refresh_interval

    def generate_refresh_polynomial(
        self, participant_id: int, n: int, t: int
    ) -> Dict:
        """
        为指定参与者生成刷新多项式，返回新份额贡献。
        """
        if not (1 <= participant_id <= n):
            raise ValueError("参与者编号超出范围")
        if not (2 <= t <= n):
            raise ValueError("参数需满足 2 ≤ t ≤ n")

        coefficients = self._generate_zero_polynomial(t)
        contributions = []
        for share_id in range(1, n + 1):
            contributions.append((share_id, self._evaluate_delta(coefficients, share_id)))

        return {
            "polynomial": coefficients,
            "shares": contributions,
            "epoch": self.epoch + 1,
        }




# 测试函数
import itertools

def _equal_secret(a: bytes, b: bytes) -> bool:
    # 恒定时比较，避免被无意的早停优化影响输出判断
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= (x ^ y)
    return res == 0

def try_recover(ss: BasicSS, shares):
    """安全尝试恢复；若 recover_secret 抛错则返回 (False, None, errstr)"""
    try:
        recovered = ss.recover_secret(shares)
        return True, recovered, ""
    except Exception as e:
        return False, None, str(e)

def test_mixed_share_attack(ss: BasicSS,
                            initial_shares: List[Tuple[int, int]],
                            refreshed_shares: List[Tuple[int, int]],
                            t: int,
                            baseline_secret: bytes):
    """
    测试“混用不同轮次份额”的攻击能否成功。
    - initial_shares: 刷新前的 n 份额（第0轮）
    - refreshed_shares: 刷新后的 n 份额（第1轮）
    - t: 阈值
    - baseline_secret: 用同轮 t 份额恢复得到的正确明文（做对照）
    """
    n = len(initial_shares)
    print("\n[Attack Test #1] 混用 第0轮旧份额 + 第1轮新份额")
    attack_succeeded = False
    case_idx = 0

    # 选择 j 个旧份额 + (t-j) 个新份额（j = 1..t-1），且 share_id 不重复
    for j in range(1, t):
        for old_idx_subset in itertools.combinations(range(n), j):
            # 不能使用与旧份额同 id 的新份额
            old_ids = {initial_shares[i][0] for i in old_idx_subset}
            new_candidates = [k for k in range(n) if refreshed_shares[k][0] not in old_ids]
            for new_idx_subset in itertools.combinations(new_candidates, t - j):
                mixed = [initial_shares[i] for i in old_idx_subset] + \
                        [refreshed_shares[k] for k in new_idx_subset]
                case_idx += 1
                ok, rec, err = try_recover(ss, mixed)
                if not ok:
                    print(f"  - Case {case_idx:03d} 失败（抛错）：{err}")
                    continue
                # 成功返回了某个字节串，但应与 baseline_secret 不同
                if _equal_secret(rec, baseline_secret):
                    attack_succeeded = True
                    print(f"  !!! Case {case_idx:03d} 意外成功：混用份额却恢复出了正确秘密（应当不可能）")
                else:
                    print(f"  - Case {case_idx:03d} 恢复出错误值（符合预期）")

    if not attack_succeeded:
        print("  => 结论：混用旧/新份额无法恢复正确秘密（攻击失败）")

def test_cross_epoch_mix(ss: BasicSS,
                         shares_round1: List[Tuple[int, int]],
                         shares_round2: List[Tuple[int, int]],
                         t: int,
                         baseline_secret: bytes):
    """
    再做一次刷新，测试“跨两个刷新轮次的份额混用”。
    """
    n = len(shares_round1)
    print("\n[Attack Test #2] 跨轮混用：第1轮份额 + 第2轮份额")
    attack_succeeded = False
    case_idx = 0

    for j in range(1, t):
        for r1_subset in itertools.combinations(range(n), j):
            r1_ids = {shares_round1[i][0] for i in r1_subset}
            r2_candidates = [k for k in range(n) if shares_round2[k][0] not in r1_ids]
            for r2_subset in itertools.combinations(r2_candidates, t - j):
                mixed = [shares_round1[i] for i in r1_subset] + \
                        [shares_round2[k] for k in r2_subset]
                case_idx += 1
                ok, rec, err = try_recover(ss, mixed)
                if not ok:
                    print(f"  - Case {case_idx:03d} 失败（抛错）：{err}")
                    continue
                if _equal_secret(rec, baseline_secret):
                    attack_succeeded = True
                    print(f"  !!! Case {case_idx:03d} 意外成功：跨轮混用恢复正确秘密（应当不可能）")
                else:
                    print(f"  - Case {case_idx:03d} 恢复出错误值（符合预期）")

    if not attack_succeeded:
        print("  => 结论：跨轮混用份额无法恢复正确秘密（攻击失败）")

if __name__ == "__main__":
    ss = BasicSS(prime_bits=256)
    proactive = ProactiveSecretSharing(refresh_interval=3600, prime_bits=256)

    secret = b"Refresh_Test_2024"
    n, t = 5, 3

    # 第0轮：拆分
    initial_shares = ss.split_secret(secret, n, t)

    # 第1轮：刷新
    refreshed_shares = proactive.active_refresh(initial_shares, n, t)

    # 基线：用“同一轮”的 t 份额做两次恢复，结果应一致
    recovered_before = ss.recover_secret(initial_shares[:t])
    recovered_after = ss.recover_secret(refreshed_shares[:t])
    print("Recovered before:", recovered_before)
    print("Recovered after :", recovered_after)
    assert _equal_secret(recovered_before, recovered_after), "同轮恢复不一致，逻辑应检查"

    # 攻击测试 #1：混用旧/新份额
    test_mixed_share_attack(ss, initial_shares, refreshed_shares, t, recovered_after)

    # 再刷新一次，获得第2轮份额
    refreshed_shares_round2 = proactive.active_refresh(refreshed_shares, n, t)

    # 验证第1轮与第2轮各自能恢复同一个秘密
    recovered_after_round2 = ss.recover_secret(refreshed_shares_round2[:t])
    print("Recovered after round2:", recovered_after_round2)
    assert _equal_secret(recovered_after, recovered_after_round2)

    # 攻击测试 #2：跨轮混用（第1轮 + 第2轮）
    test_cross_epoch_mix(ss, refreshed_shares, refreshed_shares_round2, t, recovered_after_round2)

    print("\n所有测试完成。若仅“同一轮同版本”的份额能成功恢复，而任何混用都失败，则说明 PSS 刷新机制有效。")




    # 原测试点

    ss = BasicSS(prime_bits=256)
    proactive = ProactiveSecretSharing(refresh_interval=3600, prime_bits=256)

    secret = b"Refresh_Test_2024"
    n, t = 5, 3

    initial_shares = ss.split_secret(secret, n, t)
    refreshed_shares = proactive.active_refresh(initial_shares, n, t)

    recovered_before = ss.recover_secret(initial_shares[:t])
    recovered_after = ss.recover_secret(refreshed_shares[:t])

    print("Recovered before:", recovered_before)
    print("Recovered after:", recovered_after)
