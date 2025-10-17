import secrets
import time
from typing import Dict, List, Tuple

from sympy import isprime, nextprime

from Task1 import BasicSS
from Crypto.Util import number

class FeldmanVSS(BasicSS):
    # def __init__(self, bits: int = 2048):
    def __init__(self, bits: int = 256):
        """
        初始化 Feldman VSS 系统。

        参数:
        bits: 安全参数位数（默认256位，测试时可降低）。

        实现说明:
        - 生成安全素数对 (p, q)，满足 p = 2q + 1 且 p、q 均为素数。
        - 寻找阶为 q 的生成元 g（位于二次剩余子群）。
        - 使用 q 作为 BasicSS 的有限域素数，以便继承的多项式运算复用。
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
        candidate_q = number.getPrime(bits - 2)
        # candidate_q = nextprime(1 << (bits - 2))
        while True:
            p = 2 * candidate_q + 1
            if isprime(p):
                for _ in range(10):
                    h = secrets.randbelow(p - 3) + 2  # 避免平凡元素
                    g = pow(h, 2, p)
                    if g != 1 and pow(g, candidate_q, p) == 1:
                        return p, candidate_q, g
            # candidate_q = nextprime(candidate_q + 2)
            candidate_q = number.getPrime(bits - 2)

    def share_with_commitments(
        self, secret: bytes, n: int, t: int
    ) -> Tuple[List[Tuple[int, int]], List[int]]:
        """
        生成可验证的份额与公开承诺。
        """
        if not (2 <= t <= n <= 255):
            raise ValueError("需要满足 2 ≤ t ≤ n ≤ 255")

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

    def verify_share(
        self, share_id: int, share_value: int, commitments: List[int]
    ) -> bool:
        """
        验证单个份额的有效性。
        """
        lhs = pow(self.g, share_value, self.p)

        rhs = 1
        for j, commitment in enumerate(commitments):
            exponent = pow(share_id, j, self.q)
            rhs = (rhs * pow(commitment, exponent, self.p)) % self.p

        return lhs == rhs

    def batch_verification(
        self, shares: List[Tuple[int, int]], commitments: List[int]
    ) -> List[bool]:
        """
        批量验证多个份额，复用 share_id 的幂次以减少重复计算。
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

    def generate_complaint(
        self, share_id: int, share_value: int, commitments: List[int]
    ) -> Dict:
        """
        对无效份额生成投诉，包含验证细节。
        """
        if self.verify_share(share_id, share_value, commitments):
            raise ValueError("份额验证通过，不应生成投诉")

        expected_rhs = 1
        powers = [pow(share_id, j, self.q) for j in range(len(commitments))]
        for power, commitment in zip(powers, commitments):
            expected_rhs = (expected_rhs * pow(commitment, power, self.p)) % self.p

        return {
            "accuser": share_id,
            "invalid_share": share_value,
            "evidence": {
                "lhs": pow(self.g, share_value, self.p),
                "rhs": expected_rhs,
                "powers": powers,
            },
            "commitments": commitments,
            "timestamp": time.time(),
        }

    def recover_secret_from_shares(
        self, shares: List[Tuple[int, int]], commitments: List[int]
    ) -> bytes:
        """
        在验证份额有效后恢复秘密。
        """
        verification = self.batch_verification(shares, commitments)
        if not all(verification):
            raise ValueError("存在无效份额，拒绝恢复秘密")
        return self.recover_secret(shares)


if __name__ == "__main__":
    # 测试用例 2.1：生成份额并逐个验证
    vss = FeldmanVSS(bits=256)
    shares, commitments = vss.share_with_commitments(b"VSS_Secret_2024", 5, 3)
    print("Test 2.1:", [vss.verify_share(sid, sval, commitments) for sid, sval in shares])

    # 测试用例 2.2：修改份额后应检测到异常
    vss2 = FeldmanVSS(bits=256)
    shares2, commitments2 = vss2.share_with_commitments(b"Malicious Test", 4, 2)
    malicious = shares2[0][1] + 999
    print("Test 2.2:", vss2.verify_share(shares2[0][0], malicious, commitments2))
