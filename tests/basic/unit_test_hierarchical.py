#!/usr/bin/env python3
"""
分层秘密分享单元测试 (Hierarchical secret sharing unit tests)
覆盖 HierarchicalSecretSharing 的公开接口 (Covers public APIs listed in API_SPECIFICATION.md)
"""

import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.hierarchical_sharing import HierarchicalSecretSharing
from Crypto.Random import get_random_bytes

def test_master_key_recovery():
    # secret = b"MASTER_KEY_2024"
    secret = get_random_bytes(32 * 1024)
    hss = HierarchicalSecretSharing(vss_bits=256)
    master_shares = hss.create_master_key(secret)

    recovery_shares = master_shares["hq_shares"] + [
        master_shares["regional_shares"]["asia"],
        master_shares["regional_shares"]["europe"],
        master_shares["regional_shares"]["americas"],
    ]
    recovered = hss.cascade_recovery("master", recovery_shares)
    assert recovered == secret
    print("PASS - HQ+3区域成功恢复主密钥 (HQ plus 3 regions successfully recovered master key)")
    return True


def test_regional_key_recovery():
    # secret = b"REGIONAL_KEY"
    secret = get_random_bytes(32 * 1024)
    region = "asia"
    hss = HierarchicalSecretSharing(vss_bits=256)
    regional = hss.create_regional_key(secret, region)

    branch_required = math.ceil(len(regional["branch_shares"]) * 0.6)
    recovery_shares = regional["center_shares"] + regional["branch_shares"][:branch_required]
    recovered = hss.cascade_recovery("regional", recovery_shares)
    assert recovered == secret
    print("PASS - 区域中心+60%分行恢复区域密钥成功 (Regional center plus 60% branches recovered regional key)")
    return True


def test_branch_key_recovery():
    # secret = b"BRANCH_KEY"
    secret = get_random_bytes(32 * 1024)
    branches = ["branch_001", "branch_002", "branch_003", "branch_004"]

    hss = HierarchicalSecretSharing(vss_bits=256)
    branch_info = hss.create_branch_key(secret, branches)
    recovered = hss.cascade_recovery("branch", branch_info["shares"][:3])
    assert recovered == secret
    print("PASS - 任意3个分行恢复分行密钥成功 (Any 3 branches recovered branch key)")
    return True


def test_verify_share_interface():
    hss = HierarchicalSecretSharing(vss_bits=256)
    master = hss.create_master_key(b"VERIFY_TEST")
    share = master["hq_shares"][0]
    assert hss.verify_share(share, "master")
    print("PASS - verify_share 接口正常 (verify_share interface works correctly)")
    return True


def test_refresh_shares_interface():
    # secret = b"REFRESH_MASTER"
    secret = get_random_bytes(32 * 1024)
    hss = HierarchicalSecretSharing(vss_bits=256)
    master = hss.create_master_key(secret)

    all_shares = master["hq_shares"] + list(master["regional_shares"].values())
    num_regions = len(hss.organization["regions"])
    regions_required = max(1, (num_regions + 1) // 2)
    t_master = 3 + regions_required

    refreshed = hss.refresh_shares("master", all_shares, len(all_shares), t_master)

    for share in refreshed:
        assert hss.verify_share(share, "master")

    refreshed_recovery = refreshed[:3] + refreshed[3:3 + regions_required]
    assert hss.cascade_recovery("master", refreshed_recovery) == secret
    print("PASS - refresh_shares 接口保持密钥不变 (refresh_shares keeps master secret unchanged)")
    return True


def test_master_insufficient_shares():
    """不足阈值的主密钥恢复应失败"""
    hss = HierarchicalSecretSharing(vss_bits=256)
    master = hss.create_master_key(b"INSUFFICIENT")

    # 只提供区域份额（缺少 HQ）
    insufficient = list(master["regional_shares"].values())
    try:
        hss.cascade_recovery("master", insufficient)
        assert False, "缺少 HQ 份额不应成功恢复主密钥"
    except ValueError as e:
        assert "Insufficient shares" in str(e)
    print("PASS - 主密钥在份额不足时正确拒绝 (Master recovery correctly rejected with insufficient shares)")
    return True


def test_branch_level_enforcement():
    """跨级别恢复应触发安全检查"""
    hss = HierarchicalSecretSharing(vss_bits=256)
    master = hss.create_master_key(b"LEVEL_TEST")

    # 将 master 份额误用于 branch 恢复应报错
    try:
        hss.cascade_recovery("branch", master["hq_shares"])
        assert False, "跨级别恢复应被拒绝"
    except ValueError as e:
        assert "Security violation" in str(e)
    print("PASS - 跨级别恢复被正确拒绝 (Cross-level recovery correctly rejected)")
    return True


def main():
    print("=" * 60)
    print("HierarchicalSecretSharing - 单元测试 (HierarchicalSecretSharing - Unit Tests)")
    print("=" * 60)

    tests = [
        test_master_key_recovery,
        test_regional_key_recovery,
        test_branch_key_recovery,
        test_verify_share_interface,
        test_refresh_shares_interface,
        test_master_insufficient_shares,
        test_branch_level_enforcement,
    ]

    results = []
    for test in tests:
        try:
            results.append(bool(test()))
        except AssertionError as exc:
            print(f"FAIL - {test.__name__} 断言失败: {exc} (Assertion failed: {exc})")
            results.append(False)
        except Exception as exc:
            print(f"FAIL - {test.__name__} 出现异常: {exc} (raised unexpected exception)")
            results.append(False)

    passed = sum(1 for success in results if success)
    total = len(results)

    emoji = "✅" if passed == total else "⚠️"
    print(f"\n{emoji} 汇总: {passed}/{total} 测试通过 (Summary: {passed}/{total} tests passed)")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
