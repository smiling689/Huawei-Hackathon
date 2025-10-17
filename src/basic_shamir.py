"""
BasicShamir 模板实现。
BasicShamir template implementation.

参赛者可将本文件复制到 `src/basic_shamir.py` 后，根据公开的接口说明
填充具体逻辑，逐步完成基础 Shamir 分享功能。
Participants can copy this file to `src/basic_shamir.py` and, following the
published interface description, implement the core Shamir secret-sharing
logic step by step.
"""

import secrets
from itertools import combinations
from typing import Dict, List, Optional, Tuple
from sympy import mod_inverse, nextprime
from Crypto.Util import number

class BasicShamir:
    """
    基础 Shamir 阈值秘密分享算法模板。
    Template for the basic Shamir threshold secret-sharing algorithm.

    参赛者需要根据公开的接口说明完成具体实现，
    支持按阈值对秘密进行拆分与恢复。
    Participants should implement the official interfaces so the class can
    split a secret into shares and recover it with the specified threshold.
    """
    _PRIME_CACHE: Dict[int, int] = {}

    def __init__(self, prime_bits: int = 256, prime: Optional[int] = None):
        """
        初始化 Shamir 秘密分享实例。
        Initialize a Shamir secret-sharing instance.

        参数:
            prime_bits: 有限域素数的位数，决定可处理的密钥大小与安全等级。
            prime_bits: Bit-length of the finite-field prime; defines secret size
                        and security level.

        返回:
            None
            None

        实现要求:
            - 生成或选择一枚 `prime_bits` 位的大素数；
            - 计算最大支持的密钥大小 `block_size`；
            - 缓存素数与块尺寸供后续拆分/恢复使用。
        Implementation Requirements:
            - Generate or select a `prime_bits`-bit large prime.
            - Compute the maximum supported secret size `block_size`.
            - Store the prime and block size for later split/recover operations.

        示例:
            >>> shamir = BasicShamir(prime_bits=256)
        Example:
            >>> shamir = BasicShamir(prime_bits=256)
        """
        if prime_bits < 32:
            raise ValueError("安全起见，prime_bits 必须至少为 32 位")

        if prime is not None:
            if prime <= 0:
                raise ValueError("prime 必须为正整数")
            self.prime = prime
            self.prime_bits = prime.bit_length()
            self._PRIME_CACHE[self.prime_bits] = self.prime
        else:
            cached_prime = self._PRIME_CACHE.get(prime_bits)
            if cached_prime is not None:
                self.prime = cached_prime
            else:
                if number is not None:
                    self.prime = number.getPrime(prime_bits)
                else:
                    candidate = secrets.randbits(prime_bits - 1)
                    candidate |= 1 << (prime_bits - 1)
                    candidate |= 1
                    self.prime = nextprime(candidate)
                self._PRIME_CACHE[prime_bits] = self.prime
            self.prime_bits = prime_bits

        # block_size 是秘密的最大字节长度，预留2字节用于长度前缀
        # 例如，256位素数允许的最大秘密长度为 (256-16)/8 = 30 字节
        # 这样可以确保编码后的秘密不会超过有限域的范围
        self.block_size = (self.prime_bits - 16) // 8
    
    def _encode_secret(self, secret: bytes) -> int:
        # 将秘密字节串转换为整数，并附加2字节长度前缀用于精确恢复。
        if len(secret) > self.block_size:
            raise ValueError(f"secret is too long, longer than {self.block_size} bytes")

        secret_int = int.from_bytes(secret, "big") if secret else 0
        # 多留16位用于存储长度信息
        encoded = (secret_int << 16) | len(secret)
        if encoded >= self.prime:
            raise ValueError("secret is too large to encode in the chosen prime field")
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
        将秘密分割成份额列表。
        Split a secret into a list of shares.

        参数:
            secret: 待分享的原始密钥字节串。
            n: 需要生成的份额总数，遵循 2 ≤ t ≤ n ≤ 255。
            t: 恢复所需的最小份额阈值。
        Args:
            secret: Secret bytes to share.
            n: Total number of shares to produce (2 ≤ t ≤ n ≤ 255).
            t: Minimum threshold required to recover the secret.

        返回:
            份额列表，格式为 `[(share_id, share_value), ...]`。
        Returns:
            A list of shares formatted as `[(share_id, share_value), ...]`.

        实现要求:
            - 对秘密添加长度前缀并转换为有限域元素；
            - 构造 t-1 次随机多项式，常数项为秘密；
            - 对 i=1..n 计算多项式值得到份额；
            - 保证份额值始终落在有限域范围内。
        Implementation Requirements:
            - Add a length prefix and convert the secret to a field element.
            - Build a random polynomial of degree t-1 with the secret as the constant.
            - Evaluate the polynomial for i=1..n to produce shares.
            - Ensure share values remain within the finite-field range.

        异常:
            ValueError: 当阈值参数非法（错误信息包含 "Invalid parameters"）
                或密钥长度超过 `block_size`（错误信息包含 "Secret too large"）。
        Raises:
            ValueError: If parameters violate 2 ≤ t ≤ n ≤ 255 (message includes
                "Invalid parameters") or the secret exceeds `block_size`
                (message includes "Secret too large").

        示例:
            >>> shamir = BasicShamir()
            >>> shares = shamir.split_secret(b"demo", n=5, t=3)
        Example:
            >>> shamir = BasicShamir()
            >>> shares = shamir.split_secret(b"demo", n=5, t=3)
        """
        if not (2 <= t <= n <= 255):
            raise ValueError("需要满足 2 ≤ t ≤ n ≤ 255")

        # 构造随机多项式：常数项为秘密，其余系数均随机生成。
        encoded_secret = self._encode_secret(secret)
        coeffs = [encoded_secret]
        # 生成 t-1 个随机系数
        for _ in range(t - 1):
            # randbelow 生成 [0, prime) 范围内的随机整数
            coeffs.append(secrets.randbelow(self.prime))

        shares = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))
        return shares

    def recover_secret(self, shares: List[Tuple[int, int]]) -> bytes:
        """
        使用拉格朗日插值从份额恢复秘密。
        Recover the secret from shares via Lagrange interpolation.

        参数:
            shares: 份额列表，元素形如 `(share_id, share_value)`。
        Args:
            shares: List of `(share_id, share_value)` tuples used for recovery.

        返回:
            恢复得到的原始秘密字节串。
        Returns:
            The recovered secret as bytes.

        实现要求:
            - 使用至少两个合法份额执行拉格朗日插值；
            - 通过模逆还原常数项；
            - 去除长度前缀并返回原始密钥。
        Implementation Requirements:
            - Use at least two valid shares for Lagrange interpolation.
            - Apply modular inverse operations to reconstruct the constant term.
            - Strip the length prefix and return the original secret bytes.

        异常:
            ValueError: 份额数量少于 2（信息包含 "Need at least 2 shares"），
                或模逆不存在导致恢复失败（信息包含 "Modular inverse does not exist"）。
        Raises:
            ValueError: If fewer than two shares are provided ("Need at least 2 shares")
                or a modular inverse cannot be computed ("Modular inverse does not exist").

        示例:
            >>> shamir = BasicShamir()
            >>> shamir.recover_secret([(1, 10), (2, 20)])
        Example:
            >>> shamir = BasicShamir()
            >>> shamir.recover_secret([(1, 10), (2, 20)])
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
        验证份额集合是否来自同一多项式。
        Check whether a set of shares originates from the same polynomial.

        参数:
            shares: 待验证的份额列表。
            t: 生成份额时的阈值。
        Args:
            shares: List of shares to verify.
            t: Threshold used during share generation.

        返回:
            若所有份额一致则返回 True，否则返回 False。
        Returns:
            True if all shares are consistent, otherwise False.

        实现要求:
            - 对不同的 t 大小子集执行恢复操作；
            - 检查恢复结果是否一致；
            - 对不足阈值的份额集合返回 False。
        Implementation Requirements:
            - Attempt recovery on multiple subsets of size t.
            - Confirm that recovered secrets match.
            - Return False when fewer than t shares are supplied.

        示例:
            >>> shamir = BasicShamir()
            >>> shamir.verify_shares_consistency([(1, 10), (2, 20)], t=2)
        Example:
            >>> shamir = BasicShamir()
            >>> shamir.verify_shares_consistency([(1, 10), (2, 20)], t=2)
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
    @classmethod
    def get_cached_prime(cls, bits: int) -> Optional[int]:
        """返回指定位数的缓存素数（如存在）。"""
        return cls._PRIME_CACHE.get(bits)