"""
分层可验证秘密分享模板实现。
Hierarchical verifiable secret-sharing template implementation.

参赛者可将本文件复制到 `src/hierarchical_sharing.py`，按照公开的接口
说明完成主密钥、区域密钥与分行密钥的分层分享逻辑。
Participants can copy this file into `src/hierarchical_sharing.py` and use the
published interface description to implement master, regional, and branch-level
sharing logic.
"""

import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

from .feldman_vss import FeldmanVSS
from .proactive_sharing import ProactiveSecretSharing


@dataclass
class Share:
    """
    份额数据结构模板。
    Share data-structure template.

    字段:
        id: 份额编号。
        value: 份额数值。
        holder: 持有者标识，用于审计追踪。
        level: 份额所属级别 ('master'|'regional'|'branch')。
        secret_length: 可选的原始密钥长度，用于恢复时的额外校验。
    Fields:
        id: Share identifier.
        value: Share value.
        holder: Holder label for audit tracking.
        level: Share level (`master`, `regional`, or `branch`).
        secret_length: Optional original secret length for recovery checks.
    """
    id: int
    value: int
    holder: str = ""
    level: str = ""
    secret_length: Optional[int] = None


class HierarchicalSecretSharing:
    """
    分层秘密分享系统模板。
    Template for the hierarchical secret-sharing system.

    整合 Feldman VSS 与主动刷新能力，支持主密钥、区域密钥与分行密钥的不同
    阈值组合及验证流程。
    Integrates Feldman VSS and proactive refresh to support master, regional,
    and branch keys with distinct thresholds and verification flows.
    """

    DEFAULT_ORGANIZATION = {
        "regions": {
            "asia": {"branches": 15},
            "europe": {"branches": 12},
            "americas": {"branches": 13},
            "africa": {"branches": 10},
            "oceania": {"branches": 10},
        }
    }

    def __init__(self, organization: Optional[Dict] = None, prime_bits: int = 256,
                 vss_bits: int = 128, refresh_interval: int = 30 * 24 * 3600):
        """
        初始化分层秘密分享系统。
        Initialize the hierarchical secret-sharing system.

        参数:
            organization: 组织结构定义，未提供时使用 DEFAULT_ORGANIZATION。
            prime_bits: 兼容参数，建议使用 `vss_bits`。
            vss_bits: Feldman VSS 安全参数位数。
            refresh_interval: 主动刷新间隔（秒）。
        Args:
            organization: Structure definition; defaults to DEFAULT_ORGANIZATION.
            prime_bits: Backward-compatible parameter; prefer `vss_bits`.
            vss_bits: Security parameter for Feldman VSS.
            refresh_interval: Share refresh period in seconds.

        返回:
            None
        Returns:
            None

        实现要求:
            - 创建 FeldmanVSS 与 ProactiveSecretSharing 实例；
            - 校验组织结构（区域数量、分行数量等）；
            - 初始化审计日志与活跃密钥记录。
        Implementation Requirements:
            - Instantiate FeldmanVSS and ProactiveSecretSharing.
            - Validate organization data (regions, branch counts, etc.).
            - Initialize audit logs and active key records.

        示例:
            >>> hss = HierarchicalSecretSharing()
        Example:
            >>> hss = HierarchicalSecretSharing()
        """
        self.organization = organization or self.DEFAULT_ORGANIZATION.copy()
        self.vss = FeldmanVSS(bits=vss_bits)
        self.proactive = ProactiveSecretSharing(refresh_interval=refresh_interval,
                                                prime=self.vss.q if getattr(self.vss, "q", None) else None)
        self.commitments: Dict[str, Any] = {
            "master": None,
            "regional": {},
            "branch": None,
        }
        self.audit_logs: List[Dict] = []
        self.active_keys: Dict[str, Dict] = {}

        self.region_names = list(self.organization.get("regions", {}).keys())

        # VSS 提供可验证性；Proactive 提供周期性刷新能力
        self.vss = FeldmanVSS(bits=vss_bits)
        self.proactive = ProactiveSecretSharing(
            refresh_interval=refresh_interval,
            prime_bits=self.vss.prime.bit_length(),
            prime=self.vss.prime,
        )

        self.master_key_info: Optional[Dict] = None
        self.regional_keys: Dict[str, Dict] = {}
        self.branch_keys: Dict[str, Dict] = {}

        self.regional_share_map: Dict[int, str] = {}
        self.branch_share_map: Dict[int, str] = {}

        # 系统状态版本
        self.system_epoch = 0

    def _log(self, action: str, detail: Dict) -> None:
        entry = {"timestamp": time.time(), "action": action, "detail": detail}
        self.audit_logs.append(entry)


    def create_master_key(self, secret: bytes) -> Dict:
        """
        创建主密钥的分层份额结构。
        Create the hierarchical share structure for the master key.

        参数:
            secret: 主密钥字节串。
        Args:
            secret: Master-key bytes.

        返回:
            包含总部份额与区域份额的字典，例如::

                {
                    "level": "master",
                    "hq_shares": [Share对象, ...],
                    "regional_shares": {
                        "asia": Share对象,
                        ...
                    },
                    "commitments": [...]
                }
        Returns:
            Dictionary including HQ and regional shares, for example::

                {
                    "level": "master",
                    "hq_shares": [Share objects, ...],
                    "regional_shares": {
                        "asia": Share object,
                        ...
                    },
                    "commitments": [...]
                }

        实现要求:
            - 为主密钥添加级别前缀以防跨级别恢复；
            - 使用 FeldmanVSS 生成可验证份额并缓存承诺；
            - 设定恢复阈值：总部份额需与足够多的区域中心联合。
        Implementation Requirements:
            - Prefix the secret to prevent cross-level recovery.
            - Use FeldmanVSS to produce verifiable shares and store commitments.
            - Enforce recovery requirements (HQ plus sufficient regional centers).

        异常:
            ValueError: 当 VSS 参数非法或密钥过长时，
                错误信息需包含 "Invalid parameters" 或 "Secret too large"。
                TODO 不确定
        Raises:
            ValueError: If underlying VSS parameter or secret checks fail ("Invalid parameters" /
                "Secret too large").

        示例:
            >>> HierarchicalSecretSharing().create_master_key(b"MASTER_SECRET")
        Example:
            >>> HierarchicalSecretSharing().create_master_key(b"MASTER_SECRET")
        """
        if len(self.region_names) < 5:
            raise ValueError("组织结构必须包含5个区域")

        total_shares = 8
        threshold = 6
        shares_raw, commitments = self.vss.share_with_commitments(
            secret, total_shares, threshold
        )

        secret_len = len(secret)
        hq_shares: List[Share] = []
        regional_shares: Dict[str, Share] = {}

        for idx, (share_id, share_value) in enumerate(shares_raw):
            if idx < 3:
                # HQ总部获得3个份额
                share = Share(
                    id=share_id,
                    value=share_value,
                    holder=f"hq_{idx + 1}",
                    level="master",
                    secret_length=secret_len,
                )
                hq_shares.append(share)
            else:
                # 区域获得一个份额
                region_name = self.region_names[idx - 3]
                share = Share(
                    id=share_id,
                    value=share_value,
                    holder=f"{region_name}_center",
                    level="master",
                    secret_length=secret_len,
                )
                regional_shares[region_name] = share

        self.master_key_info = {
            "commitments": commitments,
            "threshold": threshold,
            "n": total_shares,
            "hq_ids": {share.id for share in hq_shares},
            "region_ids": {region: share.id for region, share in regional_shares.items()},
            "secret_length": secret_len,
        }

        self._log(
            "create_master_key",
            {"secret_length": secret_len, "shares": total_shares, "threshold": threshold},
        )

        self.commitments["master"] = commitments

        return {
            "level": "master",
            "hq_shares": hq_shares,
            "regional_shares": regional_shares,
            "commitments": commitments,
        }


    def create_regional_key(self, secret: bytes, region: str) -> Dict:
        """
        创建指定区域的密钥份额结构。
        Create share structures for a specific regional key.

        参数:
            secret: 区域密钥字节串。
            region: 区域名称，例如 "asia"。
        Args:
            secret: Regional-key bytes.
            region: Region name (e.g., "asia").

        返回:
            区域级份额信息，例如::

                {
                    "level": "regional",
                    "region": region,
                    "center_shares": [Share对象, ...],
                    "branch_shares": [Share对象, ...],
                    "commitments": [...]
                }
        Returns:
            Regional share information such as::

                {
                    "level": "regional",
                    "region": region,
                    "center_shares": [Share objects, ...],
                    "branch_shares": [Share objects, ...],
                    "commitments": [...]
                }

        实现要求:
            - 校验 region 是否存在；
            - 根据分行业务量确定阈值（区域中心全部份额 + 至少 60% 分行份额）；
            - 使用 FeldmanVSS 生成份额与承诺。
        Implementation Requirements:
            - Validate the region name.
            - Determine thresholds (all center shares plus ≥60% branch shares).
            - Use FeldmanVSS for share generation and commitments.

        异常:
            ValueError: 非法 region（信息包含 "Invalid region"）或 VSS 报错
                （信息包含 "Invalid parameters" 或 "Secret too large"）。
        Raises:
            ValueError: If the region is invalid ("Invalid region") or the VSS call fails
                ("Invalid parameters" / "Secret too large").

        示例:
            >>> HierarchicalSecretSharing().create_regional_key(b"REGION", "asia")
        Example:
            >>> HierarchicalSecretSharing().create_regional_key(b"REGION", "asia")
        """
        region_info = self.organization.get("regions", {}).get(region)
        if region_info is None:
            raise ValueError(f"Invalid region: {region}")

        branch_count = int(region_info.get("branches", 0))
        if branch_count <= 0:
            raise ValueError("区域必须至少拥有一个分行")

        branch_names = region_info.get(
            "branch_names",
            [f"{region}_branch_{idx + 1}" for idx in range(branch_count)],
        )
        if len(branch_names) != branch_count:
            raise ValueError("branch_names 长度必须与分行数量匹配")

        center_share_count = max(3, math.ceil(branch_count / 2))
        branch_support_required = max(1, int(branch_count * 0.6))
        total_shares = center_share_count + branch_count
        threshold = center_share_count + branch_support_required

        shares_raw, commitments = self.vss.share_with_commitments(
            secret, total_shares, threshold
        )

        secret_len = len(secret)
        center_shares: List[Share] = []
        branch_shares: List[Share] = []

        self.regional_keys[region] = {
            "commitments": commitments,
            "threshold": threshold,
            "center_ids": set(),
            "branch_ids": set(),
            "branch_support_required": branch_support_required,
            "branch_total": branch_count,
            "center_share_count": center_share_count,
            "n": total_shares,
            "secret_length": secret_len,
        }

        for idx, (share_id, share_value) in enumerate(shares_raw):
            if idx < center_share_count:
                share = Share(
                    id=share_id,
                    value=share_value,
                    holder=f"{region}_center_{idx + 1}",
                    level="regional",
                    secret_length=secret_len,
                )
                center_shares.append(share)
                self.regional_keys[region]["center_ids"].add(share_id)
            else:
                branch_idx = idx - center_share_count
                branch_name = branch_names[branch_idx]
                share = Share(
                    id=share_id,
                    value=share_value,
                    holder=branch_name,
                    level="regional",
                    secret_length=secret_len,
                )
                branch_shares.append(share)
                self.regional_keys[region]["branch_ids"].add(share_id)
            self.regional_share_map[share_id] = region

        self._log(
            "create_regional_key",
            {
                "region": region,
                "secret_length": secret_len,
                "shares": total_shares,
                "threshold": threshold,
            },
        )

        self.commitments["regional"][region] = commitments

        return {
            "level": "regional",
            "region": region,
            "center_shares": center_shares,
            "branch_shares": branch_shares,
            "commitments": commitments,
        }

    def create_branch_key(self, secret: bytes, branches: List[str]) -> Dict:
        """
        创建分行级别的密钥份额。
        Create branch-level secret shares.

        参数:
            secret: 分行密钥字节串。
            branches: 参与的分行名称列表。
        Args:
            secret: Branch secret bytes.
            branches: List of participating branch identifiers.

        返回:
            分行份额信息，例如::

                {
                    "level": "branch",
                    "shares": [Share对象, ...],
                    "commitments": [...]
                }
        Returns:
            Branch share data such as::

                {
                    "level": "branch",
                    "shares": [Share objects, ...],
                    "commitments": [...]
                }

        实现要求:
            - 至少 3 个分行参与；
            - 使用 (n, 3) 阈值生成可验证份额；
            - 缓存承诺供后续验证。
        Implementation Requirements:
            - Require at least three branches.
            - Use an (n, 3) threshold to produce verifiable shares.
            - Store commitments for future verification.

        异常:
            ValueError: 分行数量不足（信息包含 "Need at least 3 branches"）
                或 VSS 调用失败（信息包含 "Invalid parameters" 或 "Secret too large"）。
        Raises:
            ValueError: When fewer than three branches are provided ("Need at least 3 branches")
                or the VSS call fails ("Invalid parameters" / "Secret too large").

        示例:
            >>> HierarchicalSecretSharing().create_branch_key(b"BRANCH", ["a", "b", "c"])
        Example:
            >>> HierarchicalSecretSharing().create_branch_key(b"BRANCH", ["a", "b", "c"])
        """
        if len(branches) < 3:
            raise ValueError("Need at least 3 branches to create a branch key")

        n = len(branches)
        threshold = 3
        shares_raw, commitments = self.vss.share_with_commitments(secret, n, threshold)
        secret_len = len(secret)

        key_id = f"branch_key_{len(self.branch_keys) + 1}"
        share_objects: List[Share] = []
        share_id_set = set()

        for (share_id, share_value), branch_name in zip(shares_raw, branches):
            share = Share(
                id=share_id,
                value=share_value,
                holder=branch_name,
                level="branch",
                secret_length=secret_len,
            )
            share_objects.append(share)
            share_id_set.add(share_id)
            self.branch_share_map[share_id] = key_id

        self.branch_keys[key_id] = {
            "commitments": commitments,
            "threshold": threshold,
            "share_ids": share_id_set,
            "branches": list(branches),
            "n": n,
            "secret_length": secret_len,
        }

        self._log(
            "create_branch_key",
            {"key_id": key_id, "secret_length": secret_len, "shares": n},
        )

        self.commitments["branch"] = commitments

        return {"level": "branch", "key_id": key_id, "shares": share_objects, "commitments": commitments}

    def cascade_recovery(self, level: str, shares: List[Share]) -> bytes:
        """
        根据层级规则执行密钥恢复。
        Perform key recovery according to hierarchical rules.

        参数:
            level: 待恢复级别 ('master'|'regional'|'branch')。
            shares: 份额对象列表。
        Args:
            level: Level to recover ('master' | 'regional' | 'branch').
            shares: List of share objects.

        返回:
            恢复得到的原始密钥字节串。
        Returns:
            The recovered secret bytes.

        实现要求:
            - 校验份额级别与请求级别匹配；
            - Master 恢复需总部份额与足够多区域中心；
            - Regional 恢复需区域中心全部份额与 60% 分行份额；
            - Branch 恢复需至少 3 个分行份额；
            - 使用 FeldmanVSS 的恢复接口并移除级别前缀。
        Implementation Requirements:
            - Confirm share levels match the requested level.
            - Master recovery requires HQ plus enough regional centers.
            - Regional recovery needs all center shares plus ≥60% branch shares.
            - Branch recovery requires at least three branch shares.
            - Use FeldmanVSS for verification/recovery and strip level prefixes.

        异常:
            ValueError: 份额级别错误（信息包含 "Invalid share level"），
                份额不足（信息包含 "Insufficient shares" 或 "Need at least"），
                或跨级别访问（信息包含 "Security violation"）。
        Raises:
            ValueError: For mismatched levels ("Invalid share level"), insufficient shares
                ("Insufficient shares" / "Need at least"), or cross-level violations
                ("Security violation").

        示例:
            >>> HierarchicalSecretSharing().cascade_recovery("branch", [])
        Example:
            >>> HierarchicalSecretSharing().cascade_recovery("branch", [])
        """
        if not shares:
            raise ValueError("需要提供至少一个份额")

        if level == "master":
            if self.master_key_info is None:
                raise ValueError("主密钥尚未生成")

            meta = self.master_key_info
            share_tuples: List[Tuple[int, int]] = []
            hq_count = 0
            regional_included: set = set()

            for share in shares:
                if share.level != "master":
                    raise ValueError("Invalid share level, 份额级别与目标密钥不匹配")
                if share.id in meta["hq_ids"]:
                    hq_count += 1
                elif share.id in meta["region_ids"].values():
                    for region_name, share_id in meta["region_ids"].items():
                        if share_id == share.id:
                            regional_included.add(region_name)
                            break
                else:
                    raise ValueError("份额不属于当前主密钥")
                if not self.verify_share(share, "master"):
                    raise ValueError("份额验证失败")
                share_tuples.append((share.id, share.value))

            if hq_count < len(meta["hq_ids"]):
                raise ValueError("Insufficient shares: missing HQ contributions")
            if len(regional_included) < 3:
                raise ValueError("Insufficient shares: need at least 3 regional centers")
            if len(share_tuples) < meta["threshold"]:
                raise ValueError("Insufficient shares: threshold not met")

            secret_bytes = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret_bytes

        if level == "regional":
            if not shares:
                raise ValueError("需要提供至少一个份额")

            region_candidates = set()
            for share in shares:
                mapped = self.regional_share_map.get(share.id)
                if mapped:
                    region_candidates.add(mapped)
            if len(region_candidates) == 0:
                # 尝试从 holder 推断
                holders = {share.holder.split("_", 1)[0] for share in shares if share.holder}
                region_candidates = {holder for holder in holders if holder in self.regional_keys}
            if len(region_candidates) != 1:
                raise ValueError("Security violation: ambiguous regional shares")
            region_name = next(iter(region_candidates))

            meta = self.regional_keys.get(region_name)
            if meta is None:
                raise ValueError("区域密钥尚未生成")

            share_tuples: List[Tuple[int, int]] = []
            center_present: set = set()
            branch_present = 0

            for share in shares:
                if share.level != "regional":
                    raise ValueError("Invalid share level, Security violation: share level mismatch")
                if self.regional_share_map.get(share.id) != region_name:
                    raise ValueError("Security violation: incorrect regional share")
                if share.id in meta["center_ids"]:
                    center_present.add(share.id)
                elif share.id in meta["branch_ids"]:
                    branch_present += 1
                else:
                    raise ValueError("Security violation: unknown regional share id")
                if not self.verify_share(share, "regional", region=region_name):
                    raise ValueError("份额验证失败")
                share_tuples.append((share.id, share.value))

            if len(center_present) < len(meta["center_ids"]):
                raise ValueError("Insufficient shares: missing regional center contributions")
            if branch_present < meta["branch_support_required"]:
                raise ValueError("Insufficient shares: branch participation below 60%")
            if len(share_tuples) < meta["threshold"]:
                raise ValueError("Insufficient shares: threshold not met")

            secret_bytes = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret_bytes

        if level == "branch":
            key_id_candidates = set()
            for share in shares:
                mapped = self.branch_share_map.get(share.id)
                if mapped:
                    key_id_candidates.add(mapped)
            if len(key_id_candidates) != 1:
                raise ValueError("Security violation: ambiguous branch shares")
            key_id = next(iter(key_id_candidates))

            meta = self.branch_keys.get(key_id)
            if meta is None:
                raise ValueError("分行密钥尚未生成")

            share_tuples = []
            for share in shares:
                if share.level != "branch":
                    raise ValueError("Invalid share level, Security violation: share level mismatch")
                if self.branch_share_map.get(share.id) != key_id:
                    raise ValueError("Security violation: incorrect branch share")
                if not self.verify_share(share, "branch"):
                    raise ValueError("份额验证失败")
                share_tuples.append((share.id, share.value))

            if len(share_tuples) < meta["threshold"]:
                raise ValueError("Insufficient shares: need at least 3 branch shares")

            secret_bytes = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret_bytes

        raise ValueError("Security violation: unknown recovery level")


    def verify_share(self, share: Share, level: str, region: Optional[str] = None) -> bool:
        """
        使用公开承诺验证单个份额。
        Verify a single share using stored commitments.

        参数:
            share: 待验证的份额对象。
            level: 密钥级别。
            region: 区域名称，区域级别验证时可选。
        Args:
            share: Share object to check.
            level: Key level ('master', 'regional', or 'branch').
            region: Optional region name for regional keys.

        返回:
            若份额有效返回 True，否则返回 False。
        Returns:
            True if the share is valid, otherwise False.

        实现要求:
            - 根据级别检索对应承诺；
            - 必要时从 holder 字段推断区域；
            - 调用 FeldmanVSS.verify_share 完成验证。
        Implementation Requirements:
            - Fetch commitments based on the level.
            - Infer region from the holder field when needed.
            - Delegate verification to FeldmanVSS.verify_share.

        示例:
            >>> HierarchicalSecretSharing().verify_share(Share(1, 2), "master")
        Example:
            >>> HierarchicalSecretSharing().verify_share(Share(1, 2), "master")
        """
        if level == "master":
            if self.master_key_info is None:
                return False
            meta = self.master_key_info
            if share.id not in meta["hq_ids"] and share.id not in meta["region_ids"].values():
                return False
            return self.vss.verify_share(share.id, share.value, meta["commitments"])

        if level == "regional":
            if region is None:
                region = self.regional_share_map.get(share.id)
                if region is None and share.holder:
                    prefix = share.holder.split("_", 1)[0]
                    if prefix in self.regional_keys:
                        region = prefix
            if region is None:
                return False
            meta = self.regional_keys.get(region)
            if meta is None:
                return False
            if share.id not in meta["center_ids"] and share.id not in meta["branch_ids"]:
                return False
            return self.vss.verify_share(share.id, share.value, meta["commitments"])

        if level == "branch":
            key_id = self.branch_share_map.get(share.id)
            if key_id is None:
                return False
            meta = self.branch_keys.get(key_id)
            if meta is None:
                return False
            if share.id not in meta["share_ids"]:
                return False
            return self.vss.verify_share(share.id, share.value, meta["commitments"])

        raise ValueError(f"未知密钥级别: {level}")


    def refresh_shares(self, level: str, old_shares: List[Share],
                       n: int, t: int, region: Optional[str] = None) -> List[Share]:
        """
        刷新指定层级的份额。
        Refresh shares for a specified hierarchy level.

        参数:
            level: 密钥级别。
            old_shares: 旧份额列表。
            n: 刷新后份额总数。
            t: 刷新阈值。
            region: 区域名称（区域级密钥时使用）。
        Args:
            level: Level of the key being refreshed.
            old_shares: Existing share objects.
            n: Total number of refreshed shares.
            t: Threshold for the refreshed shares.
            region: Optional region name for regional-level refresh.

        返回:
            刷新后的新份额列表。
        Returns:
            List of refreshed share objects.

        实现要求:
            - 调用 ProactiveSecretSharing.active_refresh_with_coeffs；
            - 更新 FeldmanVSS 承诺；
            - 保留份额持有者、级别等元信息；
            - 写入审计日志。
        Implementation Requirements:
            - Use ProactiveSecretSharing.active_refresh_with_coeffs.
            - Update FeldmanVSS commitments accordingly.
            - Preserve share metadata (holder, level, etc.).
            - Record the refresh action in audit logs.

        异常:
            ValueError: 份额数量小于阈值（信息包含 "Need at least"）
                或 VSS 错误（信息包含 "Invalid parameters" 或 "Secret too large"）。
        Raises:
            ValueError: If supplied shares are fewer than t ("Need at least") or VSS
                validation fails ("Invalid parameters" / "Secret too large").

        示例:
            >>> HierarchicalSecretSharing().refresh_shares("master", [], 0, 0)
        Example:
            >>> HierarchicalSecretSharing().refresh_shares("master", [], 0, 0)
        """
        if level == "master":
            if self.master_key_info is None:
                raise ValueError("主密钥尚未生成")
            meta = self.master_key_info
            secret = self.vss.recover_secret_from_shares(
                [(s.id, s.value) for s in old_shares], meta["commitments"]
            )
            new_structure = self.create_master_key(secret)
            holder_map = {
                share.holder: share
                for share in new_structure["hq_shares"]
                + list(new_structure["regional_shares"].values())
            }
            refreshed = []
            for old_share in old_shares:
                refreshed_share = holder_map.get(old_share.holder)
                if refreshed_share is None:
                    raise ValueError("无法匹配 holder 获取新的份额")
                refreshed.append(refreshed_share)
            self._log("refresh_master", {"holder_count": len(refreshed)})
            return refreshed

        if level == "regional":
            if region is None:
                raise ValueError("刷新区域密钥时需要指定 region")
            meta = self.regional_keys.get(region)
            if meta is None:
                raise ValueError("区域密钥尚未生成")
            secret = self.vss.recover_secret_from_shares(
                [(s.id, s.value) for s in old_shares], meta["commitments"]
            )
            new_structure = self.create_regional_key(secret, region)
            holder_map = {
                share.holder: share
                for share in new_structure["center_shares"] + new_structure["branch_shares"]
            }
            refreshed = []
            for old_share in old_shares:
                refreshed_share = holder_map.get(old_share.holder)
                if refreshed_share is None:
                    raise ValueError("无法匹配 holder 获取新的份额")
                refreshed.append(refreshed_share)
            self._log("refresh_regional", {"region": region, "holder_count": len(refreshed)})
            return refreshed

        if level == "branch":
            key_id = None
            for share in old_shares:
                detected = self.branch_share_map.get(share.id)
                if detected:
                    key_id = detected
                    break
            if key_id is None:
                raise ValueError("无法识别份额归属的分行密钥")
            meta = self.branch_keys.get(key_id)
            if meta is None:
                raise ValueError("分行密钥尚未生成")
            secret = self.vss.recover_secret_from_shares(
                [(s.id, s.value) for s in old_shares], meta["commitments"]
            )
            # 移除旧映射
            for old_id in list(meta["share_ids"]):
                self.branch_share_map.pop(old_id, None)

            shares_raw, commitments = self.vss.share_with_commitments(
                secret, meta["n"], meta["threshold"]
            )

            new_share_objects = []
            new_share_ids = set()
            holder_map: Dict[str, Share] = {}
            for (share_id, share_value), branch_name in zip(shares_raw, meta["branches"]):
                share = Share(
                    id=share_id,
                    value=share_value,
                    holder=branch_name,
                    level="branch",
                    secret_length=len(secret),
                )
                new_share_objects.append(share)
                new_share_ids.add(share_id)
                holder_map[branch_name] = share
                self.branch_share_map[share_id] = key_id

            meta["commitments"] = commitments
            meta["share_ids"] = new_share_ids
            meta["secret_length"] = len(secret)
            self.commitments["branch"] = commitments
            refreshed = []
            for old_share in old_shares:
                refreshed_share = holder_map.get(old_share.holder)
                if refreshed_share is None:
                    raise ValueError("无法匹配 holder 获取新的份额")
                refreshed.append(refreshed_share)
            self._log("refresh_branch", {"key_id": key_id, "holder_count": len(refreshed)})
            return refreshed

        raise ValueError(f"未知密钥级别: {level}")



    def initialize_bank_system(self) -> Dict:
        """
        初始化银行三层密钥系统
        """
        system_info = {
            "hq": {"id": "hq_main", "status": "active"},
            "regions": {},
            "branches": {},
            "vss_params": {"p": self.vss.p, "q": self.vss.q, "g": self.vss.g},
            "refresh_schedule": {"interval": self.proactive.refresh_interval},
            "system_epoch": self.system_epoch,
        }

        for region_name, info in self.organization.get("regions", {}).items():
            branch_count = info.get("branches", 0)
            system_info["regions"][region_name] = {
                "branch_count": branch_count,
                "status": "active",
            }
            branch_names = info.get("branch_names")
            if branch_names is None:
                branch_names = [f"{region_name}_branch_{i+1}" for i in range(branch_count)]
            if len(branch_names) != branch_count:
                raise ValueError("branch_names 与分行数量不匹配")
            for branch_name in branch_names:
                system_info["branches"][branch_name] = {
                    "region": region_name,
                    "status": "active",
                }

        self._log("initialize_bank_system", {"regions": list(system_info["regions"].keys())})
        return system_info
