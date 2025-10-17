"""
Feldman 可验证秘密分享（慢速基线实现）。
Feldman verifiable secret sharing — reference slow implementation.

该版本与 `src/feldman_vss.py` 的高速实现功能一致，但刻意保持朴素逻辑，
以便在基准测试中对比性能差异：
    - 份额生成仍遵循 Feldman VSS，支持 32KB 大秘密（分块方案）；
    - 批量验证采用逐份验证的“朴素”实现；
    - 相关辅助流程（投诉、恢复）同样基于最直接的算法流程。
"""

from typing import Any, Dict, List, Tuple, Union

# 优先使用同目录下的慢速 BasicShamir，避免对 Crypto 库的依赖。
try:
    from .basic_task1 import BasicShamir
except Exception:  # pragma: no cover - 兼容脚本直接运行
    from basic_task1 import BasicShamir  # type: ignore

import secrets
import time
from sympy import isprime, nextprime

try:
    from Crypto.Util import number  # type: ignore
except ImportError:
    number = None

ShareValue = Union[int, bytes]
Commitments = Union[List[int], Dict[str, Any]]


class FeldmanVSS(BasicShamir):
    """
    Feldman VSS 的慢速参考实现。
    在保证正确性的前提下，刻意采用朴素算法，以凸显优化前后的性能差异。
    """

    def __init__(self, bits: int = 256):
        if bits < 32:
            raise ValueError("bits 参数过小，无法保证安全性")

        self.p, self.q, self.g = self._generate_safe_prime_parameters(bits)
        super().__init__(prime=self.q)

    @staticmethod
    def _generate_safe_prime_parameters(bits: int) -> Tuple[int, int, int]:
        """
        生成安全素数对 (p, q) 及其生成元 g，其中 p = 2q + 1。
        """
        if number is not None:
            candidate_q = number.getPrime(bits - 2)
        else:
            candidate_q = nextprime(1 << (bits - 2))
        while True:
            p = 2 * candidate_q + 1
            if isprime(p):
                for _ in range(10):
                    h = secrets.randbelow(p - 3) + 2
                    g = pow(h, 2, p)
                    if g != 1 and pow(g, candidate_q, p) == 1:
                        return p, candidate_q, g
            if number is not None:
                candidate_q = number.getPrime(bits - 2)
            else:
                candidate_q = nextprime(candidate_q + 2)

    # ------------------ 份额生成 ------------------
    def _share_large_secret_with_commitments(
        self, secret: bytes, n: int, t: int
    ) -> Tuple[List[Tuple[int, bytes]], Dict[str, Any]]:
        """
        针对超出 block_size 的大秘密，采用“分块 + 朴素多项式”方案：
            - 每个分块独立生成多项式并计算承诺；
            - 每位参与者的份额为所有分块 y 值的串联（带 4 字节头部）；
            - 承诺结构记录每个分块的承诺列表，供验证与恢复使用。
        """
        if len(secret) == 0:
            header = t.to_bytes(2, "big") + (0).to_bytes(2, "big")
            shares = [(i, header) for i in range(1, n + 1)]
            commitments = {
                "mode": "block",
                "threshold": t,
                "num_blocks": 0,
                "value_bytes": self.value_bytes,
                "block_commitments": [],
                "header": header,
            }
            return shares, commitments

        buffers = [bytearray() for _ in range(n)]
        block_commitments: List[List[int]] = []

        mv = memoryview(secret)
        block_size = self.block_size
        val_len = self.value_bytes

        offset = 0
        block_count = 0
        while offset < len(secret):
            size = min(block_size, len(secret) - offset)
            while True:
                block = bytes(mv[offset: offset + size])
                try:
                    encoded = self._encode_secret(block)
                    break
                except ValueError as exc:
                    if "too large" in str(exc) and size > 0:
                        size -= 1
                        continue
                    raise

            coeffs = [encoded]
            for _ in range(t - 1):
                coeffs.append(secrets.randbelow(self.prime))

            commitments_block = [pow(self.g, coeff % self.q, self.p) for coeff in coeffs]
            block_commitments.append(commitments_block)

            for i in range(1, n + 1):
                y = self._eval_polynomial(coeffs, i)
                buffers[i - 1] += y.to_bytes(val_len, "big")

            offset += size
            block_count += 1

        header = t.to_bytes(2, "big") + block_count.to_bytes(2, "big")
        shares = [(i + 1, header + bytes(buf)) for i, buf in enumerate(buffers)]
        commitments = {
            "mode": "block",
            "threshold": t,
            "num_blocks": block_count,
            "value_bytes": val_len,
            "block_commitments": block_commitments,
            "header": header,
        }
        return shares, commitments

    def share_with_commitments(
        self, secret: bytes, n: int, t: int
    ) -> Tuple[List[Tuple[int, ShareValue]], Commitments]:
        if not (2 <= t <= n <= 255):
            raise ValueError("Invalid parameters: 需要满足 2 ≤ t ≤ n ≤ 255")

        if len(secret) > self.block_size:
            return self._share_large_secret_with_commitments(secret, n, t)

        encoded_secret = self._encode_secret(secret)
        coeffs = [encoded_secret]
        for _ in range(t - 1):
            coeffs.append(secrets.randbelow(self.prime))

        shares: List[Tuple[int, int]] = []
        for i in range(1, n + 1):
            share_value = self._eval_polynomial(coeffs, i)
            shares.append((i, share_value))

        commitments = [pow(self.g, coeff % self.q, self.p) for coeff in coeffs]
        return shares, commitments

    # ------------------ 验证逻辑（朴素） ------------------
    def _verify_block_share(self, share_id: int, share_value: ShareValue, meta: Dict[str, Any]) -> bool:
        if not isinstance(share_value, (bytes, bytearray)):
            return False
        if share_id <= 0 or share_id >= self.p:
            return False

        header_len = self._LARGE_HEADER_LEN
        if len(share_value) < header_len:
            return False

        header = share_value[:header_len]
        expected_header = meta.get("header")
        if expected_header is None or header != expected_header:
            return False

        threshold = meta.get("threshold")
        num_blocks = meta.get("num_blocks")
        value_bytes = meta.get("value_bytes")
        block_commitments = meta.get("block_commitments")

        if not isinstance(threshold, int) or threshold < 2:
            return False
        if not isinstance(num_blocks, int) or num_blocks < 0:
            return False
        if not isinstance(value_bytes, int) or value_bytes <= 0:
            if num_blocks == 0:
                return True  # 空秘密，头部已校验
            return False
        if not isinstance(block_commitments, list) or len(block_commitments) != num_blocks:
            return False

        body = share_value[header_len:]
        if len(body) != num_blocks * value_bytes:
            return False

        for block_index in range(num_blocks):
            y_bytes = body[block_index * value_bytes:(block_index + 1) * value_bytes]
            y = int.from_bytes(y_bytes, "big")
            if y < 0 or y >= self.q:
                return False

            commitments_block = block_commitments[block_index]
            if not isinstance(commitments_block, list) or len(commitments_block) < threshold:
                return False

            rhs = 1
            for j, commitment in enumerate(commitments_block):
                exponent = pow(share_id, j, self.q)
                rhs = (rhs * pow(commitment, exponent, self.p)) % self.p
            lhs = pow(self.g, y, self.p)
            if lhs != rhs:
                return False

        return True

    def verify_share(self, share_id: int, share_value: ShareValue, commitments: Commitments) -> bool:
        if isinstance(commitments, dict) and commitments.get("mode") == "block":
            return self._verify_block_share(share_id, share_value, commitments)

        if share_id <= 0 or share_id >= self.p:
            return False
        if not isinstance(share_value, int) or share_value < 0 or share_value >= self.q:
            return False
        if not isinstance(commitments, list) or not commitments:
            return False

        lhs = pow(self.g, share_value, self.p)
        rhs = 1
        for j, commitment in enumerate(commitments):
            exponent = pow(share_id, j, self.q)
            rhs = (rhs * pow(commitment, exponent, self.p)) % self.p
        return lhs == rhs

    def batch_verification(self, shares: List[Tuple[int, ShareValue]], commitments: Commitments) -> List[bool]:
        if isinstance(commitments, dict) and commitments.get("mode") == "block":
            return [self._verify_block_share(sid, val, commitments) for sid, val in shares]

        if not shares or not commitments:
            return [False] * len(shares)

        results: List[bool] = []
        for share_id, share_value in shares:
            results.append(self.verify_share(share_id, share_value, commitments))
        return results

    # ------------------ 投诉与恢复 ------------------
    def generate_complaint(self, share_id: int, share_value: ShareValue, commitments: Commitments) -> Dict[str, Any]:
        if isinstance(commitments, dict) and commitments.get("mode") == "block":
            if self._verify_block_share(share_id, share_value, commitments):
                raise ValueError("Cannot generate complaint: 份额验证通过，不应生成投诉")

            header_len = self._LARGE_HEADER_LEN
            body = bytes(share_value)[header_len:] if isinstance(share_value, (bytes, bytearray)) else b""
            value_bytes = commitments.get("value_bytes", 0)
            block_commitments = commitments.get("block_commitments", [])

            failing_info = None
            for idx, commitments_block in enumerate(block_commitments):
                start = idx * value_bytes
                end = start + value_bytes
                if end > len(body):
                    failing_info = (idx, 0, 1)
                    break
                y = int.from_bytes(body[start:end], "big")
                lhs = pow(self.g, y, self.p)
                rhs = 1
                for j, commitment in enumerate(commitments_block):
                    exponent = pow(share_id, j, self.q)
                    rhs = (rhs * pow(commitment, exponent, self.p)) % self.p
                if lhs != rhs:
                    failing_info = (idx, lhs, rhs)
                    break

            block_index, lhs_val, rhs_val = failing_info if failing_info else (-1, 0, 1)
            return {
                "accuser": share_id,
                "invalid_share": share_value,
                "block_index": block_index,
                "expected_verification": {
                    "left": lhs_val,
                    "right": rhs_val,
                },
                "commitments": commitments,
                "timestamp": time.time(),
            }

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

    def _recover_large_secret_from_shares(
        self, shares: List[Tuple[int, ShareValue]], meta: Dict[str, Any]
    ) -> bytes:
        threshold = meta["threshold"]
        num_blocks = meta["num_blocks"]
        value_bytes = meta["value_bytes"]
        header = meta["header"]
        header_len = self._LARGE_HEADER_LEN

        uniq: Dict[int, bytes] = {}
        for sid, payload in shares:
            if sid in uniq:
                continue
            if not isinstance(payload, (bytes, bytearray)):
                continue
            if len(payload) < header_len:
                continue
            if payload[:header_len] != header:
                continue
            if len(payload) != header_len + num_blocks * value_bytes:
                continue
            uniq[sid] = bytes(payload)
            if len(uniq) == threshold:
                break

        if len(uniq) < threshold:
            raise ValueError(f"Need at least {threshold} unique shares for recovery")

        share_items = sorted(uniq.items(), key=lambda x: x[0])
        share_ids = [sid for sid, _ in share_items]
        payloads = [payload[header_len:] for _, payload in share_items]

        result = bytearray()
        for block_index in range(num_blocks):
            block_shares: List[Tuple[int, int]] = []
            for sid, body in zip(share_ids, payloads):
                start = block_index * value_bytes
                end = start + value_bytes
                y = int.from_bytes(body[start:end], "big")
                block_shares.append((sid, y))
            const = self._lagrange_interpolate_zero(block_shares)
            result += self._decode_secret(const)

        return bytes(result)

    def recover_secret_from_shares(self, shares: List[Tuple[int, ShareValue]], commitments: Commitments) -> bytes:
        verification = self.batch_verification(shares, commitments)
        if not all(verification):
            raise ValueError("Invalid share detected: 存在无效份额，拒绝恢复秘密")

        if isinstance(commitments, dict) and commitments.get("mode") == "block":
            return self._recover_large_secret_from_shares(shares, commitments)

        return self.recover_secret(shares)
