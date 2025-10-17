#!/usr/bin/env python3
"""
基础Shamir秘密分享单元测试 (Basic Shamir secret sharing unit tests)
覆盖 API_SPECIFICATION.md 中 BasicShamir 的公开接口 (Covers public APIs listed in API_SPECIFICATION.md)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.basic_shamir import BasicShamir


def test_basic_shamir_recovery():
    """基础分割与恢复"""
    secret = b"Hello_World_2024"
    n, t = 5, 3

    shamir = BasicShamir(prime_bits=256)
    shares = shamir.split_secret(secret, n, t)
    recovered = shamir.recover_secret(shares[:t])

    assert recovered == secret
    print("PASS - 基础分割/恢复成功 (Basic split/recovery succeeded)")
    return True


def test_insufficient_shares():
    """少于阈值的份额无法恢复"""
    secret = b"Test_Secret"
    n, t = 5, 3

    shamir = BasicShamir(prime_bits=256)
    shares = shamir.split_secret(secret, n, t)
    recovered = shamir.recover_secret(shares[:t - 1])

    success = recovered != secret
    if success:
        print("PASS - 份额不足恢复结果不正确 (Insufficient shares produced incorrect result)")
    else:
        print("FAIL - 份额不足恢复仍然成功 (Insufficient shares unexpectedly recovered)")
    return success


def test_all_shares_recovery():
    """使用全部份额恢复"""
    secret = b"All_Shares_Test"
    n, t = 7, 4

    shamir = BasicShamir(prime_bits=256)
    shares = shamir.split_secret(secret, n, t)
    recovered = shamir.recover_secret(shares)

    assert recovered == secret
    print("PASS - 全部份额恢复成功 (Recovery with all shares succeeded)")
    return True


def test_verify_shares_consistency():
    """验证 verify_shares_consistency 接口"""
    secret = b"CONSISTENT_SECRET"
    n, t = 5, 3

    shamir = BasicShamir()
    shares = shamir.split_secret(secret, n, t)

    assert shamir.verify_shares_consistency(shares, t), "一致份额应返回 True"

    tampered = list(shares)
    tampered[0] = (tampered[0][0], (tampered[0][1] + 1) % shamir.prime)
    assert not shamir.verify_shares_consistency(tampered, t), "篡改份额应返回 False"
    print("PASS - verify_shares_consistency 行为正确 (verify_shares_consistency behaves correctly)")
    return True


def test_split_secret_too_large():
    """密钥超过 block_size 时应抛出异常"""
    shamir = BasicShamir(prime_bits=256)
    oversized = os.urandom(shamir.block_size + 1)
    try:
        shamir.split_secret(oversized, 5, 3)
        assert False, "超过 block_size 的密钥应被拒绝"
    except ValueError as e:
        assert "Secret too large" in str(e)
        print("PASS - 超长密钥被正确拒绝 (Oversized secret correctly rejected)")
    return True


def main():
    print("=" * 60)
    print("BasicShamir - 单元测试 (BasicShamir - Unit Tests)")
    print("=" * 60)

    tests = [
        test_basic_shamir_recovery,
        test_insufficient_shares,
        test_all_shares_recovery,
        test_verify_shares_consistency,
        test_split_secret_too_large,
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
