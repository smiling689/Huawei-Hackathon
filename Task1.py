import secrets
from itertools import combinations
from typing import List, Tuple

from sympy import mod_inverse, nextprime


class BasicSS:
    def __init__(self, prime_bits: int = 256):
        """
        初始化安全秘密分享实例。

        参数:
        prime_bits: 有限域素数的位数，默认256位
                    决定了可以处理的秘密大小和安全性。

        属性:
        - prime: 有限域素数
        - block_size: 最大支持的秘密大小 = (prime_bits - 16) // 8
        """
        if prime_bits <= 16:
            raise ValueError("prime_bits 必须大于 16 才能支持长度前缀编码")

        self.prime_bits = prime_bits
        self.block_size = (prime_bits - 16) // 8
        if self.block_size <= 0:
            raise ValueError("prime_bits 太小，无法编码秘密")

        # 在指定位数范围内构造一个随机奇数，随后寻找下一个素数，保证 prime 足够大。
        high_bit = 1 << (prime_bits - 1)
        random_part = secrets.randbits(prime_bits - 1)
        candidate = (random_part | high_bit) | 1
        self.prime = nextprime(candidate)

    def _encode_secret(self, secret: bytes) -> int:
        # 将秘密字节串转换为整数，并附加2字节长度前缀用于精确恢复。
        if len(secret) > self.block_size:
            raise ValueError(f"秘密长度不能超过 {self.block_size} 字节")

        secret_int = int.from_bytes(secret, "big") if secret else 0
        encoded = (secret_int << 16) | len(secret)
        if encoded >= self.prime:
            raise ValueError("编码后的秘密超过了有限域取值范围")
        return encoded

    def _decode_secret(self, value: int) -> bytes:
        # 使用长度前缀拆出原始秘密，长度信息保存在低16位。
        length = value & 0xFFFF
        secret_int = value >> 16
        length = min(length, self.block_size)

        # 将整数转换为字节串，并按长度指示进行截断或补零。
        if secret_int == 0:
            return b"\x00" * length if length else b""

        raw_bytes = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, "big")
        if length == 0:
            return b""
        if len(raw_bytes) < length:
            return b"\x00" * (length - len(raw_bytes)) + raw_bytes
        return raw_bytes[-length:]

    def _eval_polynomial(self, coeffs: List[int], x: int) -> int:
        # 采用霍纳法则快速计算多项式在指定点的值。
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % self.prime
        return result

    def _lagrange_interpolate_zero(self, shares: List[Tuple[int, int]]) -> int:
        # 在有限域上执行拉格朗日插值，求得多项式在 x=0 的取值。
        secret = 0
        for i, (x_i, y_i) in enumerate(shares):
            numerator = 1
            denominator = 1
            for j, (x_j, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = (numerator * (-x_j)) % self.prime
                denominator = (denominator * (x_i - x_j)) % self.prime
            inv = mod_inverse(denominator % self.prime, self.prime)
            secret = (secret + y_i * numerator * inv) % self.prime
        return secret

    def split_secret(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
        """
        将秘密分割成 n 个份额，需要至少 t 个份额才能恢复。

        参数:
        secret: 要分享的秘密（字节串）
        n: 生成的份额总数 (2 ≤ t ≤ n ≤ 255)
        t: 恢复秘密所需的最小份额数（阈值）
        """
        if not (2 <= t <= n <= 255):
            raise ValueError("需要满足 2 ≤ t ≤ n ≤ 255")

        # 构造随机多项式：常数项为秘密，其余系数均随机生成。
        encoded_secret = self._encode_secret(secret)
        coeffs = [encoded_secret]
        for _ in range(t - 1):
            coeffs.append(secrets.randbelow(self.prime))

        shares = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))
        return shares

    def recover_secret(self, shares: List[Tuple[int, int]]) -> bytes:
        """
        从份额恢复秘密。

        参数:
        shares: 份额列表 [(share_id, share_value), ...]
        """
        if len(shares) == 0:
            raise ValueError("至少需要提供一个份额")

        # 每个份额编号必须唯一，否则插值会出现重复点。
        ids = [share_id for share_id, _ in shares]
        if len(ids) != len(set(ids)):
            raise ValueError("存在重复的份额编号")

        secret_int = self._lagrange_interpolate_zero(shares)
        return self._decode_secret(secret_int)

    def verify_shares_consistency(self, shares: List[Tuple[int, int]], t: int) -> bool:
        """
        验证份额集合是否来自同一个多项式。

        参数:
        shares: 要验证的份额列表
        t: 原始阈值
        """
        if t < 2 or len(shares) < t:
            return False

        combo_iter = combinations(shares, t)
        try:
            first_subset = next(combo_iter)
        except StopIteration:
            return False

        try:
            baseline = self.recover_secret(list(first_subset))
        except Exception:
            return False

        for subset in combo_iter:
            try:
                recovered = self.recover_secret(list(subset))
            except Exception:
                return False
            if recovered != baseline:
                return False
        return True


if __name__ == "__main__":
    # 测试用例 1.1：基本的分享与恢复流程
    ss = BasicSS(prime_bits=256)
    secret = b"Hello_World_2024"
    shares = ss.split_secret(secret, n=5, t=3)
    recovered = ss.recover_secret(shares[:3])
    print("Test 1.1 recovered:", recovered)

    # 测试用例 1.2：份额不足时无法正确恢复秘密（结果应当与原秘密不同）
    ss2 = BasicSS(prime_bits=256)
    secret2 = b"Test_Secret"
    shares2 = ss2.split_secret(secret2, n=5, t=3)
    recovered_insufficient = ss2.recover_secret(shares2[:2])
    print("Test 1.2 recovered with insufficient shares:", recovered_insufficient)
