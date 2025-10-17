#!/usr/bin/env python3
"""
主动份额刷新单元测试 (Proactive share refresh unit tests)
覆盖 ProactiveSecretSharing 的公开接口 (Covers public APIs listed in API_SPECIFICATION.md)
"""

import sys
import os
import time
from functools import lru_cache

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.feldman_vss import FeldmanVSS
from src.proactive_sharing import ProactiveSecretSharing


@lru_cache(maxsize=None)
def create_vss(bits: int = 256) -> FeldmanVSS:
    return FeldmanVSS(bits=bits)


def test_refresh_consistency():
    secret = b"Refresh_Test_2024"
    n, t = 5, 3

    vss = create_vss()
    proactive = ProactiveSecretSharing(vss=vss, refresh_interval=3600)

    initial_shares = vss.split_secret(secret, n, t)
    refreshed_shares = proactive.active_refresh(initial_shares, n, t)

    assert vss.recover_secret(initial_shares[:t]) == secret
    assert vss.recover_secret(refreshed_shares[:t]) == secret
    print("PASS - active_refresh 前后恢复一致 (active_refresh preserves recovery result)")
    return True


def test_shares_changed():
    secret = b"Share_Change_Test"
    n, t = 4, 2

    vss = create_vss()
    proactive = ProactiveSecretSharing(vss=vss, refresh_interval=1)

    initial_shares = vss.split_secret(secret, n, t)
    refreshed_shares = proactive.active_refresh(initial_shares, n, t)

    changed = any(before[1] != after[1] for before, after in zip(initial_shares, refreshed_shares))
    assert changed
    assert vss.recover_secret(refreshed_shares[:t]) == secret
    print("PASS - active_refresh 更新了份额值 (active_refresh updates share values)")
    return True


def test_multiple_refresh():
    secret = b"Multi_Refresh"
    n, t = 5, 3
    refresh_times = 3

    vss = create_vss()
    proactive = ProactiveSecretSharing(vss=vss, refresh_interval=1)
    shares = vss.split_secret(secret, n, t)

    for _ in range(refresh_times):
        shares = proactive.active_refresh(shares, n, t)
        assert vss.recover_secret(shares[:t]) == secret

    print("PASS - 多次 active_refresh 仍然保持正确恢复 (Repeated active_refresh maintains correct recovery)")
    return True


def test_active_refresh_with_coeffs():
    secret = b"WITH_COEFFS"
    n, t = 5, 3

    vss = create_vss()
    proactive = ProactiveSecretSharing(vss=vss, refresh_interval=1)
    initial_shares = vss.split_secret(secret, n, t)

    refreshed_shares, coeffs = proactive.active_refresh_with_coeffs(initial_shares, n, t)
    assert len(coeffs) == t
    assert coeffs[0] == 0
    assert vss.recover_secret(refreshed_shares[:t]) == secret
    print("PASS - active_refresh_with_coeffs 返回刷新系数并保持正确恢复 (active_refresh_with_coeffs returns coefficients and preserves recovery)")
    return True


def test_schedule_and_generate_polynomial():
    vss = create_vss()
    proactive = ProactiveSecretSharing(vss=vss, refresh_interval=10)
    assert not proactive.schedule_automatic_refresh()

    proactive.last_refresh_time -= 20
    assert proactive.schedule_automatic_refresh()

    payload = proactive.generate_refresh_polynomial(participant_id=1, n=4, t=3)
    coeffs = payload["polynomial"]
    shares = payload["shares"]
    commitments = payload["commitments"]

    assert coeffs[0] == 0
    assert len(coeffs) == 3
    assert len(shares) == 3  # participant doesn't send to itself
    assert payload["participant_id"] == 1
    assert payload["epoch"] == proactive.epoch

    if commitments:
        assert len(commitments) == len(coeffs)
        for receiver_id, value in shares:
            assert vss.verify_share(receiver_id, value, commitments)

    print("PASS - schedule_automatic_refresh 与 generate_refresh_polynomial 正常 (schedule_automatic_refresh and generate_refresh_polynomial behave correctly)")
    return True


def main():
    print("=" * 60)
    print("ProactiveSecretSharing - 单元测试 (ProactiveSecretSharing - Unit Tests)")
    print("=" * 60)

    tests = [
        test_refresh_consistency,
        test_shares_changed,
        test_multiple_refresh,
        test_active_refresh_with_coeffs,
        test_schedule_and_generate_polynomial,
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
