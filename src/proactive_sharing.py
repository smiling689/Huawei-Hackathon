"""
主动秘密分享（Proactive Secret Sharing）模板实现。
Proactive Secret Sharing template implementation.

参赛者可将本文件复制到 `src/proactive_sharing.py`，并按照公开的接口
说明补全定期刷新与多项式生成逻辑。
Participants can copy this file to `src/proactive_sharing.py` and implement the
periodic refresh and polynomial generation logic described by the public API.
"""

import time
from typing import Dict, List, Tuple
import secrets

# from src.basic_shamir import BasicShamir


class ProactiveSecretSharing:
    """
    主动秘密分享协议模板。
    Template for proactive secret-sharing protocols.

    聚焦定期刷新份额的核心流程，可与 Feldman VSS 联动更新承诺。
    Focuses on the share-refresh workflow, interoperating with Feldman VSS to
    keep commitments in sync.
    """

    def __init__(self, vss, refresh_interval: int = 30 * 24 * 3600):
        """
        初始化主动秘密分享系统。
        Initialize the proactive secret-sharing system.

        参数:
            vss: FeldmanVSS 实例，用于生成承诺与共享群参数。
            refresh_interval: 刷新周期（秒），默认 30 天。
            prime_bits: 若需要自行生成素数时的位数。
            prime: 可选的外部素数，用于与 VSS 共享有限域。
        Args:
            vss: FeldmanVSS instance providing commitments and group parameters.
            refresh_interval: Refresh interval in seconds (30 days by default).
            prime_bits: Bit-length for generating a prime when necessary.
            prime: Optional external prime to align with the VSS field.

        返回:
            None
        Returns:
            None

        实现要求:
            - 记录刷新周期、最后刷新时间与当前 epoch；
            - 绑定 Feldman VSS 的群参数（p、q、g）；
            - 校验 `vss` 参数（缺失时抛出 `ValueError`）；
            - 为刷新调度提供基础元数据。
        Implementation Requirements:
            - Store refresh interval, last refresh timestamp, and current epoch.
            - Attach the Feldman VSS group parameters (p, q, g).
            - Validate the `vss` argument (raise `ValueError` when missing).
            - Provide metadata needed for refresh scheduling.

        示例:
            >>> pss = ProactiveSecretSharing(vss, refresh_interval=10)
        Example:
            >>> pss = ProactiveSecretSharing(vss, refresh_interval=10)
        """
        if vss is None:
            raise ValueError("FeldmanVSS instance is required")

        self.refresh_interval = refresh_interval
        # self.prime_bits = prime_bits
        self.last_refresh_time = time.time()
        self.epoch = 0
        self.last_refresh_time = time.time()
        self.vss = vss
        self.prime = getattr(vss, "q", None)
        self.g = getattr(vss, "g", None)
        self.p = getattr(vss, "p", None)
        self.prime_bits = self.vss.prime_bits
        self.prime = self.vss.q


    def _generate_zero_polynomial(self, t: int) -> List[int]:
        """
        生成零常数项的随机多项式系数列表: [0, b1, b2, ..., b_{t-1}].
        """
        coefficients = [0]
        for _ in range(1, t):
            coefficients.append(secrets.randbelow(self.prime))
        return coefficients

    def _evaluate_delta(self, coeffs: List[int], x: int) -> int:
        """
        计算 δ(x)，其中 coeffs[0] = 0。
        """
        result = 0
        power = x % self.prime
        for coeff in coeffs[1:]:
            result = (result + coeff * power) % self.prime
            power = (power * x) % self.prime
        return result



    def active_refresh(self, old_shares: List[Tuple[int, int]], n: int, t: int) -> List[Tuple[int, int]]:
        """
        执行主动刷新，生成新的份额集合。
        Perform proactive refresh to produce updated shares.

        参数:
            old_shares: 旧份额列表。
            n: 刷新后期望的份额总数。
            t: 刷新使用的阈值。
        Args:
            old_shares: Existing shares before refresh.
            n: Desired number of shares after refresh.
            t: Threshold used during refresh.

        返回:
            新的份额列表。
        Returns:
            A list containing the refreshed shares.

        实现要求:
            - 生成零常数项多项式 δ(x)；
            - 通过旧份额加 δ(x_i) 的方式更新份额；
            - 维护 epoch 与刷新时间。
        Implementation Requirements:
            - Generate a zero-constant polynomial δ(x).
            - Update each share by adding δ(x_i) to the old value.
            - Update epoch and last refresh timestamps.

        异常:
            ValueError: 份额数量小于阈值（信息包含 "Need at least"）。
        Raises:
            ValueError: If fewer than t shares are supplied (message contains "Need at least").

        示例:
            >>> ProactiveSecretSharing(vss).active_refresh([(1, 10), (2, 20)], 2, 2)
        Example:
            >>> ProactiveSecretSharing(vss).active_refresh([(1, 10), (2, 20)], 2, 2)
        """
        actual_n = len(old_shares)
        if actual_n == 0:
            raise ValueError("Need at least one share to refresh")
        if actual_n < t:
            raise ValueError(f"Need at least {t} shares for refresh")
        if n != actual_n:
            raise ValueError("Invalid parameters: n must match share count")
        if not (2 <= t <= n):
            raise ValueError("Invalid parameters: need 2 ≤ t ≤ n")

        # 检查份额编号唯一性，并初始化增量累加器。
        share_ids = [share_id for share_id, _ in old_shares]
        if len(set(share_ids)) != len(share_ids):
            raise ValueError("旧份额中存在重复编号")

        delta_sums = {share_id: 0 for share_id in share_ids}
        # self.last_refresh_details = {}

        for participant_id in range(1, n + 1):
            refresh_info = self.generate_refresh_polynomial(participant_id, n, t)
            # self.last_refresh_details[participant_id] = refresh_info
            for share_id, delta_value in refresh_info["shares"]:
                if share_id not in delta_sums:
                    raise ValueError("份额编号与刷新贡献不一致")
                delta_sums[share_id] = (delta_sums[share_id] + delta_value) % self.prime
            if participant_id in delta_sums:
                self_delta = self._evaluate_delta(refresh_info["polynomial"], participant_id)
                delta_sums[participant_id] = (delta_sums[participant_id] + self_delta) % self.prime

        new_shares = []
        for share_id, share_value in old_shares:
            updated_value = (share_value + delta_sums[share_id]) % self.prime
            new_shares.append((share_id, updated_value))

        self.epoch += 1
        self.last_refresh_time = time.time()
        return new_shares


    def active_refresh_with_coeffs(self, old_shares: List[Tuple[int, int]], n: int, t: int) -> Tuple[List[Tuple[int, int]], List[int]]:
        """
        刷新份额并返回刷新多项式的系数。
        Refresh shares and return coefficients of the refresh polynomial.

        参数:
            old_shares: 旧份额列表。
            n: 刷新后份额总数。
            t: 刷新阈值。
        Args:
            old_shares: Existing shares before refresh.
            n: Total number of refreshed shares.
            t: Threshold applied to the refresh polynomial.

        返回:
            `(new_shares, coeffs)` 元组，其中 coeffs 为 δ(x) 的系数列表。
        Returns:
            Tuple `(new_shares, coeffs)` where `coeffs` lists δ(x) coefficients.

        实现要求:
            - 与 `active_refresh` 逻辑一致；
            - 提供刷新多项式系数以便上层更新承诺；
            - 缓存刷新系数供 `generate_refresh_polynomial` 使用。
        Implementation Requirements:
            - Follow the same logic as `active_refresh`.
            - Expose polynomial coefficients for commitment updates.
            - Store coefficients for later use in `generate_refresh_polynomial`.

        异常:
            ValueError: 份额数量小于阈值（信息包含 "Need at least"）。
        Raises:
            ValueError: If provided shares are fewer than t ("Need at least").

        示例:
            >>> ProactiveSecretSharing(vss).active_refresh_with_coeffs([(1, 10)], 1, 1)
        Example:
            >>> ProactiveSecretSharing(vss).active_refresh_with_coeffs([(1, 10)], 1, 1)
        """
        actual_n = len(old_shares)
        if actual_n == 0:
            raise ValueError("Need at least one share to refresh")
        if actual_n < t:
            raise ValueError(f"Need at least {t} shares for refresh")
        if n != actual_n:
            raise ValueError("Invalid parameters: n must match share count")
        if not (2 <= t <= n):
            raise ValueError("Invalid parameters: need 2 ≤ t ≤ n")

        share_ids = [share_id for share_id, _ in old_shares]
        if len(set(share_ids)) != len(share_ids):
            raise ValueError("旧份额中存在重复编号")

        delta_sums = {share_id: 0 for share_id in share_ids}
        aggregated_coeffs = [0] * t

        for participant_id in range(1, n + 1):
            refresh_info = self.generate_refresh_polynomial(participant_id, n, t)
            coeffs = refresh_info["polynomial"]
            if len(coeffs) != t:
                raise ValueError("刷新多项式系数长度异常")

            for idx in range(t):
                aggregated_coeffs[idx] = (aggregated_coeffs[idx] + coeffs[idx]) % self.prime

            for share_id, delta_value in refresh_info["shares"]:
                if share_id not in delta_sums:
                    raise ValueError("份额编号与刷新贡献不一致")
                delta_sums[share_id] = (delta_sums[share_id] + delta_value) % self.prime
            if participant_id in delta_sums:
                self_delta = self._evaluate_delta(refresh_info["polynomial"], participant_id)
                delta_sums[participant_id] = (delta_sums[participant_id] + self_delta) % self.prime

        new_shares = []
        for share_id, share_value in old_shares:
            updated_value = (share_value + delta_sums[share_id]) % self.prime
            new_shares.append((share_id, updated_value))

        self.epoch += 1
        self.last_refresh_time = time.time()
        return new_shares, aggregated_coeffs

    def schedule_automatic_refresh(self) -> bool:
        """
        判断是否到达自动刷新时间。
        Determine whether it is time to trigger an automatic refresh.

        返回:
            若需刷新返回 True，否则返回 False。
        Returns:
            True when a refresh should occur, otherwise False.

        实现要求:
            - 根据 `refresh_interval` 与 `last_refresh_time` 做时间比较；
            - 在触发刷新时更新内部计时。
        Implementation Requirements:
            - Compare `refresh_interval` with `last_refresh_time`.
            - Update internal timing when a refresh is triggered.

        示例:
            >>> ProactiveSecretSharing(vss).schedule_automatic_refresh()
        Example:
            >>> ProactiveSecretSharing(vss).schedule_automatic_refresh()
        """
        return (time.time() - self.last_refresh_time) >= self.refresh_interval

    def generate_refresh_polynomial(self, participant_id: int, n: int, t: int) -> Dict:
        """
        为单个参与者生成刷新多项式及推送份额。
        Generate a refresh polynomial and outbound shares for a participant.

        参数:
            participant_id: 参与者编号。
            n: 参与者总数。
            t: 刷新阈值。
        Args:
            participant_id: Identifier of the participant generating data.
            n: Total number of participants.
            t: Threshold for the refresh polynomial.

        返回:
            刷新数据字典，例如::

                {
                    "participant_id": int,
                    "polynomial": [0, a1, a2, ...],
                    "shares": [(id, value), ...],
                    "commitments": [C0, C1, ...],
                    "epoch": int
                }
        Returns:
            Dictionary such as::

                {
                    "participant_id": int,
                    "polynomial": [0, a1, a2, ...],
                    "shares": [(id, value), ...],
                    "commitments": [C0, C1, ...],
                    "epoch": int
                }

        实现要求:
            - 多项式常数项固定为 0；
            - 为所有参与者计算 δ_i(j)；
            - 使用 `vss.compute_commitments` 生成承诺列表；
            - 记录生成时的 epoch 信息。
        Implementation Requirements:
            - Keep the polynomial constant term at 0.
            - Compute δ_i(j) values for every participant.
            - Generate commitments via `vss.compute_commitments`.
            - Record epoch information when generating data.

        示例:
            >>> ProactiveSecretSharing(vss).generate_refresh_polynomial(1, 5, 3)
        Example:
            >>> ProactiveSecretSharing(vss).generate_refresh_polynomial(1, 5, 3)
        """
        if not (1 <= participant_id <= n):
            raise ValueError("Invalid participant identifier")
        if not (2 <= t <= n):
            raise ValueError("Invalid parameters: need 2 ≤ t ≤ n")

        coefficients = self._generate_zero_polynomial(t)
        contributions = []
        for share_id in range(1, n + 1):
            if share_id == participant_id:
                continue
            contributions.append((share_id, self._evaluate_delta(coefficients, share_id)))

        self.epoch += 1
        return {
            "participant_id": participant_id,
            "polynomial": coefficients,
            "shares": contributions,
            "commitments": [],
            "epoch": self.epoch,
        }
