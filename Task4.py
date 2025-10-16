import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from Task2 import FeldmanVSS
from Task3 import ProactiveSecretSharing


@dataclass
class Share:
    """份额数据结构"""

    id: int
    value: int
    holder: str = ""
    level: str = ""
    secret_length: Optional[int] = None


class HierarchicalSecretSharing:
    def __init__(
        self,
        organization: Optional[Dict] = None,
        prime_bits: int = 256,
        vss_bits: int = 128,
        refresh_interval: int = 30 * 24 * 3600,
    ):
        """
        初始化分层秘密分享系统（集成版本）
        """
        if organization is None:
            organization = {
                "regions": {
                    "asia": {"branches": 12},
                    "europe": {"branches": 11},
                    "americas": {"branches": 10},
                    "africa": {"branches": 10},
                    "oceania": {"branches": 10},
                }
            }

        self.organization = organization
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

        # 审计日志
        self.audit_log: List[Dict] = []
        # 系统状态版本
        self.system_epoch = 0

    def _log(self, action: str, detail: Dict) -> None:
        entry = {"timestamp": time.time(), "action": action, "detail": detail}
        self.audit_log.append(entry)

    def create_master_key(self, secret: bytes) -> Dict:
        """
        创建主密钥的分层份额结构
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

        return {
            "level": "master",
            "hq_shares": hq_shares,
            "regional_shares": regional_shares,
            "commitments": commitments,
        }

    def create_regional_key(self, secret: bytes, region: str) -> Dict:
        """
        创建区域密钥的分享结构
        """
        region_info = self.organization.get("regions", {}).get(region)
        if region_info is None:
            raise ValueError(f"未知区域: {region}")

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

        return {
            "level": "regional",
            "region": region,
            "center_shares": center_shares,
            "branch_shares": branch_shares,
            "commitments": commitments,
        }

    def create_branch_key(self, secret: bytes, branches: List[str]) -> Dict:
        """
        创建分行密钥的分享结构
        """
        if len(branches) < 3:
            raise ValueError("分行业务密钥至少需要 3 个参与分行")

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

        return {"level": "branch", "key_id": key_id, "shares": share_objects, "commitments": commitments}

    def cascade_recovery(self, level: str, shares: List[Share]) -> bytes:
        """
        级联恢复机制，支持跨层级恢复
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
                    raise ValueError("份额级别与目标密钥不匹配")
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
                raise ValueError("HQ 份额不足")
            if len(regional_included) < 3:
                raise ValueError("区域份额不足，至少需要 3 个")
            if len(share_tuples) < meta["threshold"]:
                raise ValueError("份额数量未达到阈值")

            secret = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret

        if level == "regional":
            region = None
            for share in shares:
                detected = self.regional_share_map.get(share.id)
                if detected:
                    region = detected
                    break
            if region is None:
                raise ValueError("无法推断份额所属区域")
            meta = self.regional_keys.get(region)
            if meta is None:
                raise ValueError(f"区域 {region} 尚未生成密钥")

            share_tuples = []
            center_present = set()
            branch_present = 0

            for share in shares:
                if share.level != "regional":
                    raise ValueError("份额级别与目标密钥不匹配")
                if self.regional_share_map.get(share.id) != region:
                    raise ValueError("份额不属于目标区域")
                if share.id in meta["center_ids"]:
                    center_present.add(share.id)
                elif share.id in meta["branch_ids"]:
                    branch_present += 1
                else:
                    raise ValueError("未知份额编号")
                if not self.verify_share(share, "regional", region=region):
                    raise ValueError("份额验证失败")
                share_tuples.append((share.id, share.value))

            if len(center_present) < len(meta["center_ids"]):
                raise ValueError("区域中心份额不足")
            if branch_present < meta["branch_support_required"]:
                raise ValueError("分行份额不足（需达到 60%）")
            if len(share_tuples) < meta["threshold"]:
                raise ValueError("份额数量未达到阈值")

            secret = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret

        if level == "branch":
            key_id = None
            for share in shares:
                detected = self.branch_share_map.get(share.id)
                if detected:
                    key_id = detected
                    break
            if key_id is None:
                raise ValueError("无法识别份额归属的分行密钥")

            meta = self.branch_keys.get(key_id)
            if meta is None:
                raise ValueError("分行密钥尚未生成")

            share_tuples = []
            for share in shares:
                if share.level != "branch":
                    raise ValueError("份额级别与目标密钥不匹配")
                if self.branch_share_map.get(share.id) != key_id:
                    raise ValueError("份额不属于目标分行密钥")
                if not self.verify_share(share, "branch"):
                    raise ValueError("份额验证失败")
                share_tuples.append((share.id, share.value))

            if len(share_tuples) < meta["threshold"]:
                raise ValueError("分行业务密钥至少需要 3 个份额")

            secret = self.vss.recover_secret_from_shares(
                share_tuples, meta["commitments"]
            )
            return secret

        raise ValueError(f"未知密钥级别: {level}")

    def verify_share(self, share: Share, level: str, region: Optional[str] = None) -> bool:
        """
        验证单个份额的有效性
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

    def refresh_shares(
        self,
        level: str,
        old_shares: List[Share],
        n: int,
        t: int,
        region: Optional[str] = None,
    ) -> List[Share]:
        """
        刷新份额（保持密钥不变）
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


def _format_bool(result: bool) -> str:
    return "PASS" if result else "FAIL"


def main() -> None:
    print("=== Hierarchical Secret Sharing Tests ===")
    hss = HierarchicalSecretSharing(vss_bits=256)

    # Test 4.1: Master key recovery
    master_secret = b"MASTER_KEY_2024"
    master_shares = hss.create_master_key(master_secret)
    recovery_shares_master = master_shares["hq_shares"] + [
        master_shares["regional_shares"]["asia"],
        master_shares["regional_shares"]["europe"],
        master_shares["regional_shares"]["americas"],
    ]
    recovered_master = hss.cascade_recovery("master", recovery_shares_master)
    print("Test 4.1 Master Recovery:", _format_bool(recovered_master == master_secret))

    # Negative: missing regional share
    try:
        hss.cascade_recovery("master", master_shares["hq_shares"] + [master_shares["regional_shares"]["asia"]])
        print("Test 4.1 Negative (insufficient regions): FAIL")
    except Exception:
        print("Test 4.1 Negative (insufficient regions): PASS")

    # Test 4.2: Regional key recovery
    regional_secret = b"REGIONAL_KEY"
    region = "asia"
    regional_shares = hss.create_regional_key(regional_secret, region)
    required_branches = max(1, int(len(regional_shares["branch_shares"]) * 0.6))
    recovery_shares_regional = (
        regional_shares["center_shares"] + regional_shares["branch_shares"][:required_branches]
    )
    recovered_regional = hss.cascade_recovery("regional", recovery_shares_regional)
    print("Test 4.2 Regional Recovery:", _format_bool(recovered_regional == regional_secret))

    # Negative: insufficient branch shares
    try:
        hss.cascade_recovery(
            "regional", regional_shares["center_shares"] + regional_shares["branch_shares"][: required_branches - 1]
        )
        print("Test 4.2 Negative (insufficient branches): FAIL")
    except Exception:
        print("Test 4.2 Negative (insufficient branches): PASS")

    # Branch level test
    branch_secret = b"BRANCH_SECRET"
    branch_data = hss.create_branch_key(branch_secret, ["asia_branch_1", "asia_branch_2", "asia_branch_3", "asia_branch_4"])
    branch_recovered = hss.cascade_recovery("branch", branch_data["shares"][:3])
    print("Test 4.3 Branch Recovery:", _format_bool(branch_recovered == branch_secret))

    # Negative: only two shares
    try:
        hss.cascade_recovery("branch", branch_data["shares"][:2])
        print("Test 4.3 Negative (not enough shares): FAIL")
    except Exception:
        print("Test 4.3 Negative (not enough shares): PASS")

    # Verify share checks
    print("Test 4.4 Master Share Verify:", _format_bool(all(hss.verify_share(s, "master") for s in master_shares["hq_shares"])))
    print(
        "Test 4.4 Regional Share Verify:",
        _format_bool(all(hss.verify_share(s, "regional", region=region) for s in regional_shares["center_shares"])),
    )
    print(
        "Test 4.4 Branch Share Verify:",
        _format_bool(all(hss.verify_share(s, "branch") for s in branch_data["shares"])),
    )

    # Refresh tests
    refreshed_master = hss.refresh_shares("master", recovery_shares_master, 8, 6)
    regional_meta = hss.regional_keys[region]
    refreshed_regional = hss.refresh_shares(
        "regional",
        regional_shares["center_shares"] + regional_shares["branch_shares"],
        regional_meta["n"],
        regional_meta["threshold"],
        region=region,
    )
    refreshed_branch = hss.refresh_shares("branch", branch_data["shares"], len(branch_data["shares"]), 3)
    print(
        "Test 4.5 Refresh Master Consistency:",
        _format_bool(hss.cascade_recovery("master", refreshed_master) == master_secret),
    )
    print(
        "Test 4.5 Refresh Regional Consistency:",
        _format_bool(hss.cascade_recovery("regional", refreshed_regional[: len(regional_shares["center_shares"]) + required_branches]) == regional_secret),
    )
    print(
        "Test 4.5 Refresh Branch Consistency:",
        _format_bool(hss.cascade_recovery("branch", refreshed_branch[:3]) == branch_secret),
    )

    # Tampering detection
    tampered_master_share = Share(
        id=recovery_shares_master[0].id,
        value=(recovery_shares_master[0].value + 1) % hss.vss.prime,
        holder=recovery_shares_master[0].holder,
        level=recovery_shares_master[0].level,
    )
    print(
        "Test 4.6 Tampered Master Share Detect:",
        _format_bool(not hss.verify_share(tampered_master_share, "master")),
    )

    # Mismatched level recovery should fail
    try:
        hss.cascade_recovery("master", branch_data["shares"][:3])
        print("Test 4.6 Negative (level mismatch): FAIL")
    except Exception:
        print("Test 4.6 Negative (level mismatch): PASS")


if __name__ == "__main__":
    main()
