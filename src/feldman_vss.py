"""
Feldman 可验证秘密分享模板实现。
Feldman verifiable secret sharing template implementation.

建议参赛者将本文件复制到 `src/feldman_vss.py`，再按照公开的接口说明
实现可验证秘密分享逻辑与承诺生成。
Contest participants should copy this file into `src/feldman_vss.py` and follow
the public interface specification to implement commitment generation and
verifiable sharing logic.
"""

from typing import Dict, List, Tuple

# 兼容包内/脚本两种导入方式
try:
    from .basic_shamir import BasicShamir
except Exception:  # pragma: no cover
    from basic_shamir import BasicShamir

import secrets
import time
from sympy import isprime, nextprime

try:
    from Crypto.Util import number  # type: ignore
except ImportError:
    number = None


class FeldmanVSS(BasicShamir):
    """
    Feldman 可验证秘密分享算法模板。
    """

    def __init__(self, bits: int = 256):
        """
        生成 (p, q, g) 并将 q 作为 BasicShamir 的有限域素数。
        """
        if bits < 32:
            raise ValueError("bits 参数过小，无法保证安全性")

        self.p, self.q, self.g = self._generate_safe_prime_parameters(bits)
        super().__init__(prime=self.q)

    @staticmethod
    def _generate_safe_prime_parameters(bits: int) -> Tuple[int, int, int]:
        """
        生成安全素数 p = 2q + 1 以及一个阶为 q 的生成元 g。
        """
        if number is not None:
            candidate_q = number.getPrime(bits - 2)
        else:
            candidate_q = nextprime(1 << (bits - 2))
        while True:
            p = 2 * candidate_q + 1
            if isprime(p):
                for _ in range(10):
                    h = secrets.randbelow(p - 3) + 2  # 避免平凡元素
                    g = pow(h, 2, p)
                    if g != 1 and pow(g, candidate_q, p) == 1:
                        return p, candidate_q, g
            if number is not None:
                candidate_q = number.getPrime(bits - 2)
            else:
                candidate_q = nextprime(candidate_q + 2)

    # ------------------ 生成份额与承诺 ------------------
    def share_with_commitments(self, secret: bytes, n: int, t: int) -> Tuple[List[Tuple[int, int]], List[int]]:
        """
        生成可验证份额及公开承诺。
        """
        if not (2 <= t <= n <= 255):
            raise ValueError("Invalid parameters: 需要满足 2 ≤ t ≤ n ≤ 255")

        encoded_secret = self._encode_secret(secret)
        coeffs = [encoded_secret]
        for _ in range(t - 1):
            coeffs.append(secrets.randbelow(self.prime))

        shares = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))

        commitments = [pow(self.g, coeff % self.q, self.p) for coeff in coeffs]
        return shares, commitments

    # ------------------ 单份验证 ------------------
    def verify_share(self, share_id: int, share_value: int, commitments: List[int]) -> bool:
        """
        验证单个份额是否与承诺匹配。
        """
        lhs = pow(self.g, share_value, self.p)

        rhs = 1
        for j, commitment in enumerate(commitments):
            exponent = pow(share_id, j, self.q)
            rhs = (rhs * pow(commitment, exponent, self.p)) % self.p

        return lhs == rhs

    # ------------------ 批处理验证（性能优化） ------------------
    def aggregate_batch_verify(self, shares: List[Tuple[int, int]], commitments: List[int], *, seed: int | None = None) -> bool:
        """
        使用**随机线性组合**的一次性聚合验证来批量检查多份份额。

        核心公式：
            g^{sum r_i s_i} ?= ∏_j C_j^{ sum r_i i^j } (mod p)
        将 O(len(shares)*t) 次模幂降为 O(t) 次，非常适合“批处理验证”。
        """
        if not shares:
            return True

        # 生成随机权重 r_i
        if seed is not None:
            # 简易可重复 PRNG：仅用于测试复现
            a, c, m = 1103515245, 12345, 2**31
            x = seed % m

            def next_rand():
                nonlocal x
                x = (a * x + c) % m
                return x

            rand = lambda: 1 + (next_rand() % (self.q - 1))
        else:
            rand = lambda: 1 + secrets.randbelow(self.q - 1)

        t = len(commitments)
        E = [0] * t
        sum_rs = 0
        for share_id, share_value in shares:
            r = rand()
            sum_rs = (sum_rs + (r * (share_value % self.q))) % self.q

            # 迭代式生成 i^j，避免重复 pow
            pow_ij = 1
            for j in range(t):
                E[j] = (E[j] + r * pow_ij) % self.q
                pow_ij = (pow_ij * (share_id % self.q)) % self.q

        lhs = pow(self.g, sum_rs, self.p)

        rhs = 1
        for j, Cj in enumerate(commitments):
            rhs = (rhs * pow(Cj, E[j], self.p)) % self.p

        return lhs == rhs

    def batch_verification(self, shares: List[Tuple[int, int]], commitments: List[int]) -> List[bool]:
        """
        批量验证多份份额（快慢结合）：
        1) 先聚合一次性验证（全部通过则直接全 True）；
        2) 若聚合失败，再逐份精确验证定位坏份额。
        """
        if not shares:
            return []

        # 快路径：大批量时先跑聚合
        try:
            if len(shares) >= 4 and self.aggregate_batch_verify(shares, commitments):
                return [True] * len(shares)
        except Exception:
            pass  # 聚合异常不影响正确性

        # 逐份精确验证
        results = []
        for share_id, share_value in shares:
            powers = [1]
            for j in range(1, len(commitments)):
                powers.append((powers[-1] * share_id) % self.q)

            rhs = 1
            for power, commitment in zip(powers, commitments):
                rhs = (rhs * pow(commitment, power, self.p)) % self.p

            lhs = pow(self.g, share_value, self.p)
            results.append(lhs == rhs)
        return results

    # ------------------ 投诉与恢复 ------------------
    def generate_complaint(self, share_id: int, share_value: int, commitments: List[int]) -> Dict:
        """
        针对无效份额生成投诉信息。
        """
        if self.verify_share(share_id, share_value, commitments):
            raise ValueError("Cannot generate complaint: 份额验证通过，不应生成投诉")

        expected_rhs = 1
        powers = [pow(share_id, j, self.q) for j in range(len(commitments))]
        for power, commitment in zip(powers, commitments):
            expected_rhs = (expected_rhs * pow(commitment, power, self.p)) % self.p

        left = pow(self.g, share_value, self.p)
        return {
            "accuser": share_id,
            "invalid_share": share_value,
            "expected_verification": {
                "left": left,
                "right": expected_rhs,
                "powers": powers,
            },
            "commitments": commitments,
            "timestamp": time.time(),
        }

    def recover_secret_from_shares(self, shares: List[Tuple[int, int]], commitments: List[int]) -> bytes:
        """
        在验证后从份额恢复秘密（全部份额必须为真）。
        """
        verification = self.batch_verification(shares, commitments)
        if not all(verification):
            raise ValueError("Invalid share detected: 存在无效份额，拒绝恢复秘密")
        return self.recover_secret(shares)
