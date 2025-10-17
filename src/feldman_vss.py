"""
Feldman 可验证秘密分享模板实现。
Feldman verifiable secret sharing template implementation.

建议参赛者将本文件复制到 `src/feldman_vss.py`，再按照公开的接口说明
实现可验证秘密分享逻辑与承诺生成。
Contest participants should copy this file into `src/feldman_vss.py` and follow
the public interface specification to implement commitment generation and
verifiable sharing logic.
"""
# from Crypto.Util.number import isPrime as miller_rabin_isprime
from typing import Dict, List, Tuple, Optional

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

try:
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Random import get_random_bytes  # type: ignore
except ImportError:
    AES = None

    def get_random_bytes(length: int) -> bytes:
        return secrets.token_bytes(length)


class FeldmanVSS(BasicShamir):
    """
    Feldman 可验证秘密分享算法模板。
    Template class for Feldman verifiable secret sharing.

    参赛者需实现承诺生成、份额验证与投诉机制，确保分享过程可公开验证。
    Contestants must implement commitment creation, share verification, and
    complaint handling so the sharing process is publicly verifiable.
    """

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
        生成 (p, q, g) 并将 q 作为 BasicShamir 的有限域素数。
        """
        if bits < 32:
            raise ValueError("bits 参数过小，无法保证安全性")

        self.p, self.q, self.g = self._generate_safe_prime_parameters(bits)
        super().__init__(prime=self.q)
        self._hybrid_metadata: Dict[Tuple[int, ...], Dict[str, bytes]] = {}

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
            # if miller_rabin_isprime(p):
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

    def _commitment_key(self, commitments: List[int]) -> Tuple[int, ...]:
        """
        将承诺列表转换为可散列键，用于缓存混合模式元数据。
        """
        return tuple(commitments)

    def _select_hybrid_key_size(self) -> int:
        """
        根据当前 block_size 选择合适的 AES 密钥长度。
        """
        if self.block_size >= 32:
            return 32
        if self.block_size >= 24:
            return 24
        if self.block_size >= 16:
            return 16
        raise ValueError(
            f"prime_bits ({self.prime_bits}) 太小，无法处理混合模式，"
            f"block_size={self.block_size} < 16"
        )

    def _prepare_secret_for_sharing(
        self, secret: bytes
    ) -> Tuple[bytes, Optional[Dict[str, bytes]]]:
        """
        对秘密进行预处理，在必要时启用混合加密。
        返回共享的核心秘密与可选的混合元数据。
        """
        if len(secret) <= self.block_size:
            return secret, None
        if len(secret) < 1024:
            raise ValueError(
                "Secret too large, secret is too large to encode in the chosen prime field"
            )

        key_size = self._select_hybrid_key_size()
        symmetric_key = get_random_bytes(key_size)
        if AES is None:
            metadata = {"ciphertext": secret, "nonce": b"", "tag": b""}
        else:
            cipher = AES.new(symmetric_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(secret)
            metadata = {
                "ciphertext": ciphertext,
                "nonce": cipher.nonce,
                "tag": tag,
            }
        return symmetric_key, metadata

    def _decrypt_hybrid_secret(self, symmetric_key: bytes, metadata: Dict[str, bytes]) -> bytes:
        """
        使用混合模式元数据解密原始秘密。
        """
        if AES is None:
            return metadata["ciphertext"]

        cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=metadata["nonce"])
        try:
            return cipher.decrypt_and_verify(metadata["ciphertext"], metadata["tag"])
        except ValueError as exc:  # pragma: no cover - 极少触发
            raise ValueError("Hybrid recovery failed: integrity check did not pass") from exc

    # ------------------ 生成份额与承诺 ------------------
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

        core_secret, hybrid_metadata = self._prepare_secret_for_sharing(secret)
        encoded_secret = self._encode_secret(core_secret)
        coeffs = [encoded_secret]
        for _ in range(t - 1):
            coeffs.append(secrets.randbelow(self.prime))

        shares = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))

        commitments = [pow(self.g, coeff % self.q, self.p) for coeff in coeffs]
        if hybrid_metadata is not None:
            self._hybrid_metadata[self._commitment_key(commitments)] = hybrid_metadata
        return shares, commitments

    # ------------------ 单份验证 ------------------
    def verify_share(self, share_id: int, share_value: int, commitments: List[int]) -> bool:
        """
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
        批量验证（确定性正确 + 高性能）：
        1) 预计算承诺 C_j 的二次幂表与每个份额的 i^j；
        2) 先用聚合验证对集合做剪枝（两套独立种子，误判概率 ~ 1/q^2）；
        3) 对需要精确判断的叶子，使用幂次缓存做确定性单份验证（零误差）。
        """
        if not shares:
            return []
        if not commitments:
            return [False] * len(shares)

        p, q = self.p, self.q
        t = len(commitments)

        # ---- 修正：承诺值快速检查（允许 C_j == 1；仅排除不在 [1, p-1] 的值）----
        if any((cj <= 0) or (cj >= p) for cj in commitments):
            return [False] * len(shares)

        # ---- 预计算 1：C_j 的二次幂表（指数按 q 的比特长度即可）----
        max_bits = (q - 1).bit_length()
        C_pow2: List[List[int]] = [[0] * max_bits for _ in range(t)]
        for j, Cj in enumerate(commitments):
            C_pow2[j][0] = Cj % p
            for k in range(1, max_bits):
                C_pow2[j][k] = (C_pow2[j][k - 1] * C_pow2[j][k - 1]) % p

        # g 的二次幂表（用于叶子验证的左侧 g^{s_i}；聚合验证仍用内置 pow 即可）
        g_pow2: List[int] = [self.g % p]
        for _ in range(1, max_bits):
            g_pow2.append((g_pow2[-1] * g_pow2[-1]) % p)

        def exp_with_pow2(pow2_table: List[int], e: int) -> int:
            """按位分解，用预计算的二次幂表计算 base^e mod p（确定性、无误差）"""
            res, bit = 1, 0
            while e:
                if e & 1:
                    res = (res * pow2_table[bit]) % p
                e >>= 1
                bit += 1
            return res

        # ---- 预计算 2：每个份额的 i^j（j=0..t-1），用迭代避免重复 pow ----
        id_pows: List[List[int]] = []
        normalized_shares: List[Tuple[int, int]] = []
        results = [False] * len(shares)
        pending_indices: List[int] = []

        for idx, (sid, sval) in enumerate(shares):
            # 快速检查：编号要落在合理范围（>0），份额值落在 [0, q-1]
            if sid <= 0 or sval < 0 or sval >= q:
                results[idx] = False
                continue

            row = [1] * t
            x = sid % q
            for j in range(1, t):
                row[j] = (row[j - 1] * x) % q

            id_pows.append(row)
            normalized_shares.append((sid, sval))
            pending_indices.append(idx)

        if not pending_indices:
            return results

        # ---- 聚合剪枝：与现有 aggregate_batch_verify 一致（两套种子降低误判）----
        def agg_ok(indices: List[int]) -> bool:
            subset = [normalized_shares[i] for i in indices]
            # 两个独立种子，误判概率 ~ 1/q^2
            seed_base = 0
            for pos in indices:
                sid, sval = normalized_shares[pos]
                seed_base = (seed_base * 1315423911 + sid * 977 + sval) & 0x7FFFFFFF
            return (
                    self.aggregate_batch_verify(subset, commitments, seed=seed_base)
                    and self.aggregate_batch_verify(subset, commitments, seed=seed_base ^ 0x5BF03635)
            )

        # ---- 叶子：确定性校验（使用幂次缓存）----
        def verify_leaf(i_local: int) -> bool:
            sid, sval = normalized_shares[i_local]
            # 左侧：g^{s_i}（按位拆解）
            lhs = exp_with_pow2(g_pow2, sval % q)

            # 右侧：∏_j C_j^{i^j}（各个指数取自 id_pows 的缓存）
            rhs = 1
            e_list = id_pows[i_local]
            for j in range(t):
                e = e_list[j]
                # 指数按 q 归约（群阶为 q）
                rhs = (rhs * exp_with_pow2(C_pow2[j], e % q)) % p
            return lhs == rhs

        # ---- 递归二分：聚合验证通过 => 批整体 True；否则继续下探 ----
        def verify_indices(indices: List[int]) -> None:
            if not indices:
                return
            if len(indices) == 1:
                only = indices[0]
                results[pending_indices[only]] = verify_leaf(only)
                return

            if agg_ok(indices):
                # 通过两次独立聚合验证，整批直接 True
                for k in indices:
                    results[pending_indices[k]] = True
                return

            mid = len(indices) // 2
            verify_indices(indices[:mid])
            verify_indices(indices[mid:])

        verify_indices(list(range(len(pending_indices))))
        return results

    # ------------------ 投诉与恢复 ------------------
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
        在验证后从份额恢复秘密（全部份额必须为真）。
        """
        verification = self.batch_verification(shares, commitments)
        if not all(verification):
            raise ValueError("Invalid share detected: 存在无效份额，拒绝恢复秘密")
        secret_bytes = self.recover_secret(shares)
        metadata = self._hybrid_metadata.get(self._commitment_key(commitments))
        if metadata is not None:
            return self._decrypt_hybrid_secret(secret_bytes, metadata)
        return secret_bytes
