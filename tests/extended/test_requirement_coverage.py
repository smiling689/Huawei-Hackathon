#!/usr/bin/env python3
"""
需求覆盖测试 (Requirement coverage test suite)
逐项验证 src 目录中各模块的参数限制、错误信息与核心流程。
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.basic_shamir import BasicShamir
from src.feldman_vss import FeldmanVSS
from src.proactive_sharing import ProactiveSecretSharing
from src.hierarchical_sharing import HierarchicalSecretSharing, Share


def _print_status(ok: bool, message: str) -> bool:
    status = "PASS" if ok else "FAIL"
    print(f"{status} - {message}")
    return ok


def test_basic_shamir_requirements() -> bool:
    shamir = BasicShamir(prime_bits=256)

    # 超出 block_size 应触发 Secret too large
    long_secret = b"x" * (shamir.block_size + 1)
    try:
        shamir.split_secret(long_secret, n=3, t=2)
        return _print_status(False, "BasicShamir 过长秘密未触发异常")
    except ValueError as exc:
        if "Secret too large" not in str(exc):
            return _print_status(False, "BasicShamir 异常信息未包含 'Secret too large'")

    # 非法参数 (t > n)
    try:
        shamir.split_secret(b"demo", n=2, t=3)
        return _print_status(False, "BasicShamir 非法参数未触发异常")
    except ValueError as exc:
        if "需要满足" not in str(exc):
            return _print_status(False, "BasicShamir 非法参数信息不正确")

    # 正常流程：验证一致性接口
    shares = shamir.split_secret(b"demo", n=5, t=3)
    if not shamir.verify_shares_consistency(shares, t=3):
        return _print_status(False, "BasicShamir verify_shares_consistency 返回 False")

    return _print_status(True, "BasicShamir 参数与错误处理符合要求")


def test_feldman_vss_requirements() -> bool:
    vss = FeldmanVSS(bits=256)

    # 非法参数
    try:
        vss.share_with_commitments(b"demo", n=2, t=3)
        return _print_status(False, "FeldmanVSS 非法参数未触发异常")
    except ValueError as exc:
        if "Invalid parameters" not in str(exc):
            return _print_status(False, "FeldmanVSS 非法参数信息不正确")

    # 正常生成并验证投诉结构
    shares, commitments = vss.share_with_commitments(b"demo_vss", n=4, t=2)
    valid = vss.verify_share(shares[0][0], shares[0][1], commitments)
    if not valid:
        return _print_status(False, "FeldmanVSS 正常份额验证失败")

    tampered_value = (shares[0][1] + 1) % vss.q
    if vss.verify_share(shares[0][0], tampered_value, commitments):
        return _print_status(False, "FeldmanVSS 被篡改份额仍通过验证")

    complaint = vss.generate_complaint(shares[0][0], tampered_value, commitments)
    expected = complaint.get("expected_verification", {})
    if not {"left", "right", "powers"} <= expected.keys():
        return _print_status(False, "FeldmanVSS 投诉结构缺少期望字段")

    return _print_status(True, "FeldmanVSS 参数与投诉逻辑符合要求")


def test_proactive_sharing_requirements() -> bool:
    pss = ProactiveSecretSharing(refresh_interval=1)
    shamir_shares = [(1, 10), (2, 20), (3, 30)]

    # n 与份额数量不一致
    try:
        pss.active_refresh(shamir_shares, n=4, t=2)
        return _print_status(False, "ProactiveShare n 与份额不一致未触发异常")
    except ValueError as exc:
        if "n 必须与旧份额数量一致" not in str(exc):
            return _print_status(False, "ProactiveShare 异常信息不正确")

    # 重复份额编号
    try:
        pss.active_refresh([(1, 10), (1, 20)], n=2, t=2)
        return _print_status(False, "ProactiveShare 重复编号未触发异常")
    except ValueError as exc:
        if "旧份额中存在重复编号" not in str(exc):
            return _print_status(False, "ProactiveShare 重复编号异常信息不正确")

    # 正常刷新与 schedule 判定
    refreshed = pss.active_refresh(shamir_shares, n=3, t=2)
    if refreshed == shamir_shares:
        return _print_status(False, "ProactiveShare 刷新未改变份额")

    if pss.schedule_automatic_refresh():
        return _print_status(False, "ProactiveShare 刷新后立即触发调度不正确")

    pss.last_refresh_time -= 2
    if not pss.schedule_automatic_refresh():
        return _print_status(False, "ProactiveShare 调度判断失败")

    return _print_status(True, "ProactiveSecretSharing 参数与刷新逻辑符合要求")


def test_hierarchical_sharing_requirements() -> bool:
    hss = HierarchicalSecretSharing(vss_bits=256)

    master = hss.create_master_key(b"MASTER_REQ")
    regional = hss.create_regional_key(b"REGIONAL_REQ", "asia")

    # 主密钥缺少 HQ 份额
    try:
        hss.cascade_recovery("master", list(master["regional_shares"].values()))
        return _print_status(False, "主密钥缺少 HQ 份额仍成功恢复")
    except ValueError as exc:
        if "Insufficient shares" not in str(exc):
            return _print_status(False, "主密钥缺份额异常信息不正确")

    # 区域密钥错误区域
    try:
        hss.create_regional_key(b"BAD", "unknown_region")
        return _print_status(False, "未知区域未触发异常")
    except ValueError as exc:
        if "未知区域" not in str(exc):
            return _print_status(False, "未知区域异常信息不正确")

    # 分行数量不足
    try:
        hss.create_branch_key(b"BRANCH_REQ", ["only_two", "branch"])
        return _print_status(False, "分行数量不足未触发异常")
    except ValueError as exc:
        if "至少需要 3" not in str(exc):
            return _print_status(False, "分行数量不足异常信息不正确")

    # 跨级别恢复
    try:
        hss.cascade_recovery("branch", master["hq_shares"])
        return _print_status(False, "跨级别恢复未触发安全异常")
    except ValueError as exc:
        if "Security violation" not in str(exc):
            return _print_status(False, "跨级别安全异常信息不正确")

    # 承诺映射检查
    branch_info = hss.create_branch_key(b"BRANCH_REQ", ["br1", "br2", "br3"])
    if hss.commitments["branch"] != branch_info["commitments"]:
        return _print_status(False, "分行承诺未保存到 commitments['branch']")

    # 刷新区域份额后保持可验证
    region_all_shares = regional["center_shares"] + regional["branch_shares"]
    refreshed_region = hss.refresh_shares(
        "regional",
        region_all_shares,
        n=len(region_all_shares),
        t=hss.regional_keys["asia"]["threshold"],
        region="asia",
    )
    for share in refreshed_region:
        if not hss.verify_share(share, "regional", region="asia"):
            return _print_status(False, "刷新后的区域份额验证失败")

    return _print_status(True, "HierarchicalSecretSharing 安全校验与错误处理符合要求")


def main() -> int:
    print("=" * 60)
    print("Requirement Coverage Test Suite")
    print("=" * 60)

    start = time.perf_counter()

    test_functions = [
        test_basic_shamir_requirements,
        test_feldman_vss_requirements,
        test_proactive_sharing_requirements,
        test_hierarchical_sharing_requirements,
    ]

    results = []
    for func in test_functions:
        try:
            results.append(bool(func()))
        except Exception as exc:  # pragma: no cover - defensive handling
            print(f"FAIL - {func.__name__} raised unexpected exception: {exc}")
            results.append(False)

    duration = time.perf_counter() - start
    passed = sum(results)
    total = len(results)
    emoji = "✅" if passed == total else "⚠️"
    print("-" * 60)
    print(f"{emoji} 汇总: {passed}/{total} 项需求覆盖测试通过 (Summary)")
    print(f"⏱️  总用时: {duration:.3f}s")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
