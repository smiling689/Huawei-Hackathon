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

# 优先使用 pycryptodome 库
from Crypto.Util import number

# 导入 AES 加密相关的模块
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


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
                self.prime = number.getPrime(prime_bits)
                self._PRIME_CACHE[prime_bits] = self.prime
            self.prime_bits = prime_bits

        # block_size 是直接被Shamir算法处理的秘密的最大字节长度
        self.block_size = (self.prime_bits - 16) // 8

    def _encode_secret(self, secret: bytes) -> int:
        # 这个内部方法现在只在标准模式下被调用，此时 len(secret) <= self.block_size
        # 因此不再需要复杂的标志位检查
        secret_int = int.from_bytes(secret, "big") if secret else 0
        # 多留16位用于存储长度信息
        encoded = (secret_int << 16) | len(secret)
        # 理论上 encoded 应该总是小于 prime，但双重检查更安全
        if encoded >= self.prime:
            raise ValueError("Secret too large, secret is too large to encode in the chosen prime field")
        return encoded

    def _decode_secret(self, value: int) -> bytes:
        # 使用长度前缀拆出原始秘密，长度信息保存在低16位。
        length = value & 0xFFFF
        secret_int = value >> 16
        # 使用原始分享时的 block_size 进行长度限制，防止解码出过长的数据
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
            try:
                inv = mod_inverse(denominator, self.prime)
            except Exception:
                raise ValueError("Modular inverse does not exist")
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
        if len(secret) <= self.block_size:
            return self._split_secret_standard(secret, n, t)
        elif len(secret) >= 1024:
            return self._split_secret_hybrid(secret, n, t)
        else:
            raise ValueError("Secret too large")

    def _split_secret_standard(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
        """
        标准的 Shamir 分割逻辑，仅用于处理小于等于 block_size 的秘密。
        """
        if not (2 <= t <= n <= 255):
            raise ValueError("Invalid parameters, 需要满足 2 ≤ t ≤ n ≤ 255")

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

    def _split_secret_hybrid(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
        """
        处理大秘密的混合加密分割逻辑。
        """
        # [修复] 动态选择最合适的AES密钥大小，确保它能被当前 block_size 处理
        key_size = 0
        if self.block_size >= 32:
            key_size = 32  # 足够容纳AES-256
        elif self.block_size >= 24:
            key_size = 24  # 退而求其次，使用AES-192
        elif self.block_size >= 16:
            key_size = 16  # 最后选择，使用AES-128
        else:
            raise ValueError(
                f"prime_bits ({self.prime_bits}) 太小，无法处理大秘密。 "
                f"其 block_size 为 {self.block_size} 字节，但混合加密至少需要16字节。"
            )

        # 1. 生成一个动态大小的、一次性的AES密钥
        symmetric_key = get_random_bytes(key_size)

        # 2. 使用AES-GCM模式加密大秘密
        cipher = AES.new(symmetric_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(secret)
        nonce = cipher.nonce

        # 3. [关键修复] 使用 *当前实例* 和其 *正确的prime* 来分割短的AES密钥
        # 因为 symmetric_key 的长度 (key_size) <= self.block_size，
        # 这个调用会安全地进入 _split_secret_standard。
        key_shares = self._split_secret_standard(symmetric_key, n, t)

        # 4. 将加密数据打包成特殊的“元数据份额”
        meta_shares = [
            (-1, len(ciphertext)),
            (-2, len(nonce)),
            (-3, len(tag)),
            (-4, int.from_bytes(ciphertext + nonce + tag, 'big'))
        ]

        return meta_shares + key_shares

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
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")

        if shares[0][0] > 0:
            return self._recover_secret_standard(shares)
        else:
            return self._recover_secret_hybrid(shares)

    def _recover_secret_standard(self, shares: List[Tuple[int, int]]) -> bytes:
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")

        # 每个份额编号必须唯一，否则插值会出现重复点。
        ids = [share_id for share_id, _ in shares]
        if len(ids) != len(set(ids)):
            raise ValueError("存在重复的份额编号")

        secret_int = self._lagrange_interpolate_zero(shares)
        return self._decode_secret(secret_int)

    def _recover_secret_hybrid(self, shares: List[Tuple[int, int]]) -> bytes:
        """
        混合加密的恢复逻辑。
        """
        if len(shares) < 4 or not all(s[0] < 0 for s in shares[:4]):
            raise ValueError("混合模式恢复时，需要提供完整的元数据份额。")

        meta_map = dict(shares[:4])
        ciphertext_len = meta_map[-1]
        nonce_len = meta_map[-2]
        tag_len = meta_map[-3]
        blob_int = meta_map[-4]

        total_len = ciphertext_len + nonce_len + tag_len
        blob_bytes = blob_int.to_bytes((blob_int.bit_length() + 7) // 8, 'big')
        if len(blob_bytes) < total_len:
            blob_bytes = b'\x00' * (total_len - len(blob_bytes)) + blob_bytes

        ciphertext = blob_bytes[:ciphertext_len]
        nonce = blob_bytes[ciphertext_len: ciphertext_len + nonce_len]
        tag = blob_bytes[ciphertext_len + nonce_len:]

        # 提取真正的密钥份额
        key_shares_subset = shares[4:]
        # [关键修复] 调用 _recover_secret_standard 来恢复AES密钥
        recovered_symmetric_key = self._recover_secret_standard(key_shares_subset)

        cipher = AES.new(recovered_symmetric_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted_secret = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_secret
        except ValueError:
            raise ValueError("解密失败：数据可能已被篡改或密钥份额错误。")

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
        if shares and shares[0][0] < 0:
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