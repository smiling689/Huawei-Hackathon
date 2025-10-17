#!/usr/bin/env python3
"""
Feldman 可验证秘密分享单元测试 (Feldman verifiable secret sharing unit tests)
覆盖 API_SPECIFICATION.md 中 FeldmanVSS 的公开接口 (Covers public APIs listed in API_SPECIFICATION.md)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.feldman_vss import FeldmanVSS


def test_vss_creation_and_verify():
    secret = b"VSS_Secret_2024"
    n, t = 5, 3

    vss = FeldmanVSS(bits=256)
    shares, commitments = vss.share_with_commitments(secret, n, t)

    all_valid = all(vss.verify_share(share_id, share_value, commitments)
                    for share_id, share_value in shares)
    assert all_valid, "所有份额都应该通过验证"
    print("PASS - 份额生成与验证通过 (Share generation and verification succeeded)")
    return True


def test_vss_detect_and_complaint():
    secret = b"Malicious_Test"
    n, t = 4, 2

    vss = FeldmanVSS(bits=256)
    shares, commitments = vss.share_with_commitments(secret, n, t)

    malicious_id = shares[0][0]
    malicious_value = shares[0][1] + 999

    assert not vss.verify_share(malicious_id, malicious_value, commitments)

    complaint = vss.generate_complaint(malicious_id, malicious_value, commitments)
    assert complaint["accuser"] == malicious_id
    assert complaint["invalid_share"] == malicious_value
    print("PASS - 恶意份额检测与投诉生成通过 (Malicious share detected and complaint generated)")
    return True


def test_vss_recovery():
    secret = b"Recovery_Test"
    n, t = 5, 3

    vss = FeldmanVSS(bits=256)
    shares, commitments = vss.share_with_commitments(secret, n, t)
    recovered = vss.recover_secret_from_shares(shares[:t], commitments)

    assert recovered == secret
    print("PASS - 恢复接口工作正常 (Recovery interface succeeded)")
    return True


def test_vss_batch_verification():
    secret = b"BATCH_TEST"
    n, t = 6, 3

    vss = FeldmanVSS(bits=256)
    shares, commitments = vss.share_with_commitments(secret, n, t)

    results = vss.batch_verification(shares, commitments)
    assert all(results), "批量验证应全部通过"

    tampered = list(shares)
    tampered[0] = (tampered[0][0], tampered[0][1] + 1)
    results = vss.batch_verification(tampered, commitments)
    assert not results[0], "篡改后的份额应在批量验证中失败"
    print("PASS - 批量验证接口行为正确 (Batch verification behaves correctly)")
    return True


def main():
    print("=" * 60)
    print("FeldmanVSS - 单元测试 (FeldmanVSS - Unit Tests)")
    print("=" * 60)

    tests = [
        test_vss_creation_and_verify,
        test_vss_detect_and_complaint,
        test_vss_recovery,
        test_vss_batch_verification,
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
