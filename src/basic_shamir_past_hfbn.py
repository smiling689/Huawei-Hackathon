import secrets
from itertools import combinations
from typing import Dict, List, Optional, Tuple
from sympy import mod_inverse, nextprime

# 优先使用 pycryptodome 库，提供更快的密码学原生实现
try:
    from Crypto.Util import number  # type: ignore
except ImportError:
    number = None

# 导入 AES 加密相关的模块
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class BasicShamir:
    """
    基础 Shamir 阈值秘密分享算法模板。
    此类已集成混合加密方案，并修复了无限递归问题，可透明地处理大尺寸秘密。
    """
    _PRIME_CACHE: Dict[int, int] = {}

    def __init__(self, prime_bits: int = 256, prime: Optional[int] = None):
        if prime_bits < 32:
            raise ValueError("安全起见，prime_bits 必须至少为 32 位")
        
        self.big_secret_key = False
        
        if prime is not None:
            if prime <= 0:
                raise ValueError("prime 必须为正整数")
            self.prime = prime
            self.prime_bits = prime.bit_length()
            self._PRIME_CACHE[self.prime_bits] = self.prime
            self.block_size = (self.prime_bits - 16) // 8
        else:
            self.block_size = (prime_bits - 16) // 8
            
            # if len(secrets) >= 33 Byte then use AES
            if prime_bits > 280:
                self.big_secret_key = True
                prime_bits = 280
            
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

        self.inner_size = (self.prime_bits - 16) // 8

    def _encode_secret(self, secret: bytes) -> int:
        if len(secret) > self.block_size:
            raise ValueError(f"Secret too large, secret is too long, longer than {self.block_size} bytes")
        secret_int = int.from_bytes(secret, "big") if secret else 0
        encoded = (secret_int << 16) | len(secret)
        if encoded >= self.prime:
            raise ValueError("Secret too large, secret is too large to encode in the chosen prime field")
        return encoded

    def _decode_secret(self, value: int) -> bytes:
        length = value & 0xFFFF
        secret_int = value >> 16
        length = min(length, self.inner_size)
        if secret_int == 0:
            return b"\x00" * length if length else b""
        raw_bytes = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, "big")
        if length == 0:
            return b""
        if len(raw_bytes) < length:
            return b"\x00" * (length - len(raw_bytes)) + raw_bytes
        return raw_bytes[-length:]

    def _eval_polynomial(self, coeffs: List[int], x: int) -> int:
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % self.prime
        return result

    def _lagrange_interpolate_zero(self, shares: List[Tuple[int, int]]) -> int:
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
        if len(secret) > self.block_size:
            raise ValueError(f"Secret too large, secret is too long, longer than {self.block_size} bytes")
        if self.big_secret_key:
            return self._split_secret_hybrid(secret, n, t)
        else:
            return self._split_secret_standard(secret, n, t)

    def _split_secret_standard(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
        if not (2 <= t <= n <= 255):
            raise ValueError("Invalid parameters, 需要满足 2 ≤ t ≤ n ≤ 255")
        encoded_secret = self._encode_secret(secret)
        coeffs = [encoded_secret]
        for _ in range(t - 1):
            coeffs.append(secrets.randbelow(self.prime))
        shares = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))
        return shares

    def _split_secret_hybrid(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
        """
        处理大秘密的混合加密分割逻辑 (已修复无限递归问题)。
        """
        assert self.inner_size >= 32
        
        key_size = 32  # AES-256

        # 1. 生成一个动态大小的、一次性的AES密钥
        symmetric_key = get_random_bytes(key_size)

        # 2. 使用AES-GCM模式加密大秘密
        cipher = AES.new(symmetric_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(secret)
        nonce = cipher.nonce

        # 3. 使用本类的标准模式来分割那个短的AES密钥
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
        if not shares:
            raise ValueError("Need at least 1 share")
        
        if shares[0][0] > 0:
            return self._recover_secret_standard(shares)
        else:
            return self._recover_secret_hybrid(shares)

    def _recover_secret_standard(self, shares: List[Tuple[int, int]]) -> bytes:
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")
        ids = [share_id for share_id, _ in shares]
        if len(ids) != len(set(ids)):
            raise ValueError("存在重复的份额编号")
        secret_int = self._lagrange_interpolate_zero(shares)
        return self._decode_secret(secret_int)

    def _recover_secret_hybrid(self, shares: List[Tuple[int, int]]) -> bytes:
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
        nonce = blob_bytes[ciphertext_len : ciphertext_len + nonce_len]
        tag = blob_bytes[ciphertext_len + nonce_len:]
        
        key_shares_subset = shares[4:]
        recovered_symmetric_key = self.recover_secret(key_shares_subset)

        cipher = AES.new(recovered_symmetric_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted_secret = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_secret
        except ValueError:
            raise ValueError("解密失败：数据可能已被篡改或密钥份额错误。")

    def verify_shares_consistency(self, shares: List[Tuple[int, int]], t: int) -> bool:
        # (此方法逻辑不变)
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