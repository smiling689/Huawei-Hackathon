import secrets
from itertools import combinations
from typing import List, Tuple

from sympy import mod_inverse, nextprime

try:
    from Crypto.Util import number  # type: ignore
except ImportError:
    number = None  # 在无 PyCryptodome 环境下回退到本地生成

class BasicSS:
    def __init__(self, prime_bits: int = 256):
        """
        初始化安全秘密分享实例

        参数:
            prime_bits: 有限域素数的位数，默认256位
                        决定了可以处理的秘密大小和安全性
        """
        if prime_bits < 32:
            raise ValueError("安全起见，prime_bits 必须至少为 32 位")
        self.prime_bits = prime_bits
        if number is not None:
            self.prime = number.getPrime(self.prime_bits)
        else:
            # Fallback: 使用随机奇数 + nextprime 生成大素数
            candidate = secrets.randbits(self.prime_bits - 1)
            candidate |= 1 << (self.prime_bits - 1)
            candidate |= 1
            self.prime = nextprime(candidate)
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

    # 1. 初始化实例
    # 使用较小的 prime_bits 以便快速演示
    sss = BasicSS(prime_bits=256)
    print(f"使用素数位数: {sss.prime_bits}, 最大秘密长度: {sss.block_size} 字节")

    # 2. 定义秘密和分享参数
    original_secret = b'hello world!'
    n = 5  # 总共生成 5 份
    t = 3  # 至少需要 3 份才能恢复

    print(f"\n原始秘密: {original_secret}")
    print(f"总份额数 (n): {n}, 恢复阈值 (t): {t}")

    # 3. 分割秘密
    all_shares = sss.split_secret(original_secret, n, t)
    print("\n生成的全部 5 个份额:")
    for share in all_shares:
        print(f"  份额 {share[0]}: {share[1]}")

    # 4. 使用足够的份额恢复秘密
    # 从全部份额中任选 t=3 份
    shares_for_recovery = [all_shares[0], all_shares[2], all_shares[4]]
    print(f"\n使用份额 {[s[0] for s in shares_for_recovery]} 进行恢复...")

    recovered_secret = sss.recover_secret(shares_for_recovery)
    print(f"恢复的秘密: {recovered_secret}")

    # 验证恢复是否成功
    assert original_secret == recovered_secret
    print("✅ 恢复成功！")

    # 5. 尝试用不足的份额恢复
    not_enough_shares = [all_shares[1], all_shares[3]]
    print(f"\n尝试使用 {len(not_enough_shares)} (少于{t}) 个份额进行恢复...")
    try:
        failed_recovery = sss.recover_secret(not_enough_shares)
        # 如果恢复出的结果和原始秘密碰巧一样（概率极小），也视为失败
        if failed_recovery == original_secret:
            print("❌ 恢复失败：恢复结果不应与原始秘密相同！")
        else:
            print(f"恢复出错误的数据: {failed_recovery}")

    except Exception as e:
        print(f"❌ 正确地抛出错误或恢复出错误数据: 恢复出的秘密与原始秘密不同。")

    # 6. 验证份额一致性
    print("\n验证份额一致性:")
    is_consistent = sss.verify_shares_consistency(all_shares, t)
    print(f"全部 5 个份额是否一致? {is_consistent}")

    # 创建一个不一致的份额列表 (将最后一个份额替换成别的)
    inconsistent_shares = all_shares[:-1] + [(99, 123456)]
    is_consistent = sss.verify_shares_consistency(inconsistent_shares, t)
    print(f"包含伪造份额的列表是否一致? {is_consistent}")
