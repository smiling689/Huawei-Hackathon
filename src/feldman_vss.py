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
from .basic_shamir import BasicShamir

import secrets
import time
from typing import Dict, List, Tuple

from sympy import isprime, nextprime

try:
    from Crypto.Util import number  # type: ignore
except ImportError:
    number = None


class FeldmanVSS(BasicShamir):
    """
    Feldman 可验证秘密分享算法模板。
    Template class for Feldman verifiable secret sharing.

    参赛者需实现承诺生成、份额验证与投诉机制，确保分享过程可公开验证。
    Contestants must implement commitment creation, share verification, and
    complaint handling so the sharing process is publicly verifiable.
    """

    # def __init__(self, bits: int = 2048):
    def __init__(self, bits: int = 256):
        """
        初始化 Feldman VSS 系统。
        Initialize the Feldman VSS system.

        参数:
            bits: 安全参数位数，需生成满足 p = 2q + 1 的安全素数。
        Args:
            bits: Security parameter bit-length; must produce safe primes where p = 2q + 1.

        返回:
            None
        Returns:
            None

        实现要求:
            - 生成安全素数对 (p, q) 以及阶为 q 的生成元 g；
            - 将 BasicShamir 的有限域素数设置为 q；
            - 缓存所有公共参数供后续使用。
        Implementation Requirements:
            - Generate a safe prime pair (p, q) and find a generator g of order q.
            - Set the BasicShamir field prime to q.
            - Store public parameters for subsequent operations.

        示例:
            >>> vss = FeldmanVSS(bits=256)
        Example:
            >>> vss = FeldmanVSS(bits=256)
        """
        if bits < 32:
            raise ValueError("bits 参数过小，无法保证安全性")

        self.p, self.q, self.g = self._generate_safe_prime_parameters(bits)

        # 以 q 作为有限域素数，复用 BasicSS 的运算能力。
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

    def share_with_commitments(self, secret: bytes, n: int, t: int) -> Tuple[List[Tuple[int, int]], List[int]]:
        """
        生成可验证份额及公开承诺。
        Generate verifiable shares and public commitments.

        参数:
            secret: 待分享的秘密字节串。
            n: 份额总数，满足 2 ≤ t ≤ n ≤ 255。
            t: 恢复所需的阈值。
        Args:
            secret: Secret bytes to share.
            n: Total number of shares (2 ≤ t ≤ n ≤ 255).
            t: Threshold required for recovery.

        返回:
            包含两部分内容的元组 `(shares, commitments)`：
            - shares: 份额列表 `[(share_id, share_value), ...]`
            - commitments: 多项式系数的承诺 `[C_0, C_1, ..., C_{t-1}]`
        Returns:
            Tuple `(shares, commitments)` where:
            - shares: list of `(share_id, share_value)` pairs.
            - commitments: list `[C_0, C_1, ..., C_{t-1}]` with polynomial commitments.

        实现要求:
            - 复用 BasicShamir 的多项式生成逻辑；
            - 使用生成元 g 计算承诺 `C_j = g^{a_j} mod p`；
            - 确保份额与承诺使用相同的多项式系数。
        Implementation Requirements:
            - Reuse BasicShamir polynomial generation.
            - Compute commitments as `C_j = g^{a_j} mod p`.
            - Ensure shares and commitments share identical coefficients.

        异常:
            ValueError: 参数越界（信息包含 "Invalid parameters"）或秘密长度超过限制
                （信息包含 "Secret too large"）。
        Raises:
            ValueError: If parameters violate bounds ("Invalid parameters") or secret
                exceeds block size ("Secret too large").

        示例:
            >>> shares, commitments = FeldmanVSS().share_with_commitments(b"demo", 5, 3)
        Example:
            >>> shares, commitments = FeldmanVSS().share_with_commitments(b"demo", 5, 3)
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

    def verify_share(self, share_id: int, share_value: int, commitments: List[int]) -> bool:
        """
        验证单个份额是否与承诺匹配。
        Verify whether a share matches the published commitments.

        参数:
            share_id: 份额编号。
            share_value: 份额值。
            commitments: 承诺值列表。
        Args:
            share_id: Share identifier.
            share_value: Share value.
            commitments: List of commitments.

        返回:
            若份额有效返回 True，否则返回 False。
        Returns:
            True if the share verifies against the commitments, otherwise False.

        实现要求:
            - 计算身份验证等式 `g^{s_i} ?= ∏ C_j^{i^j} mod p`；
            - 任何人都可使用公开承诺完成验证。
        Implementation Requirements:
            - Evaluate `g^{s_i} ?= ∏ C_j^{i^j} mod p`.
            - Allow anyone to perform verification using public commitments.

        示例:
            >>> FeldmanVSS().verify_share(1, 123, [1, 2, 3])
        Example:
            >>> FeldmanVSS().verify_share(1, 123, [1, 2, 3])
        """
        lhs = pow(self.g, share_value, self.p)

        rhs = 1
        for j, commitment in enumerate(commitments):
            exponent = pow(share_id, j, self.q)
            rhs = (rhs * pow(commitment, exponent, self.p)) % self.p

        return lhs == rhs

    def batch_verification(self, shares: List[Tuple[int, int]], commitments: List[int]) -> List[bool]:
        """
        批量验证多份份额。
        Verify multiple shares in a batch.

        参数:
            shares: 待验证的份额列表。
            commitments: 承诺值列表。
        Args:
            shares: List of shares to check.
            commitments: List of commitments.

        返回:
            布尔值列表，对应每个份额的验证结果。
        Returns:
            List of booleans for each share's verification result.

        实现要求:
            - 通过幂次缓存等技巧减少重复计算；
            - 对无法验证的份额返回 False。
        Implementation Requirements:
            - Use power caching or similar optimizations to reduce exponentiation.
            - Return False for any share that fails verification.

        示例:
            >>> FeldmanVSS().batch_verification([(1, 123)], [1, 2])
        Example:
            >>> FeldmanVSS().batch_verification([(1, 123)], [1, 2])
        """
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

    def generate_complaint(self, share_id: int, share_value: int, commitments: List[int]) -> Dict:
        """
        针对无效份额生成投诉信息。
        Create a complaint record for an invalid share.

        参数:
            share_id: 举报的份额编号。
            share_value: 无效份额数值。
            commitments: 对应的承诺值列表。
        Args:
            share_id: Identifier of the reported share.
            share_value: Value of the invalid share.
            commitments: Corresponding commitment list.

        返回:
            投诉证明字典，例如::

                {
                    "accuser": share_id,
                    "invalid_share": share_value,
                    "expected_verification": {
                        "left": ...,
                        "right": ...
                    },
                    "commitments": commitments,
                    "timestamp": ...
                }
        Returns:
            Complaint evidence dictionary, for example::

                {
                    "accuser": share_id,
                    "invalid_share": share_value,
                    "expected_verification": {
                        "left": ...,
                        "right": ...
                    },
                    "commitments": commitments,
                    "timestamp": ...
                }

        实现要求:
            - 仅在份额验证失败时生成投诉；
            - 计算验证等式左右两侧数值并写入 `expected_verification`；
            - 保留当前承诺列表的快照和时间戳用于审计。
        Implementation Requirements:
            - Only generate a complaint when verification fails.
            - Compute both sides of the verification equation and store them in
              `expected_verification`.
            - Preserve a snapshot of the commitments and a timestamp for audits.

        异常:
            ValueError: 若份额验证通过仍试图投诉（信息包含 "Cannot generate complaint"）。
        Raises:
            ValueError: If the share actually verifies ("Cannot generate complaint").

        示例:
            >>> complaint = FeldmanVSS().generate_complaint(1, 999, [1, 2, 3])
            >>> complaint["expected_verification"]["left"] != complaint["expected_verification"]["right"]
            True # 若份额有效，则会抛出 ValueError: "Cannot generate complaint"
        Example:
            >>> complaint = FeldmanVSS().generate_complaint(1, 999, [1, 2, 3])
            >>> complaint["expected_verification"]["left"] != complaint["expected_verification"]["right"]
            True # If the share verifies, a ValueError("Cannot generate complaint") is raised.
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
        在验证后从份额恢复秘密。
        Recover the secret from shares after verification.

        参数:
            shares: 待恢复的份额列表。
            commitments: 对应的承诺值列表。
        Args:
            shares: List of shares for recovery.
            commitments: Corresponding commitment list.

        返回:
            原始秘密字节串。
        Returns:
            The original secret as bytes.

        实现要求:
            - 先对所有份额执行验证；
            - 仅在全部合法时调用 `recover_secret`；
            - 验证失败时抛出异常。
        Implementation Requirements:
            - Verify all shares before recovery.
            - Invoke `recover_secret` only if every share passes verification.
            - Raise an error when verification fails.

        异常:
            ValueError: 检测到无效份额（信息包含 "Invalid share detected"）。
        Raises:
            ValueError: If an invalid share is encountered ("Invalid share detected").

        示例:
            >>> FeldmanVSS().recover_secret_from_shares([(1, 10), (2, 20)], [1, 2, 3])
        Example:
            >>> FeldmanVSS().recover_secret_from_shares([(1, 10), (2, 20)], [1, 2, 3])
        """
        verification = self.batch_verification(shares, commitments)
        if not all(verification):
            raise ValueError("Invalid share detected: 存在无效份额，拒绝恢复秘密")
        return self.recover_secret(shares)
