import secrets
from typing import List, Tuple

import sys
import os
# 项目根目录 → 子目录 src
src_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.append(src_dir)  # 将 src 目录加入搜索路径

# 导入类
from feldman_vss import FeldmanVSS


def assert_equal(actual, expected, msg: str):
    """自定义断言：判断实际值与预期值是否相等，不相等则抛出异常"""
    if actual != expected:
        raise AssertionError(f"断言失败：{msg}\n实际值: {actual}\n预期值: {expected}")


def assert_true(condition, msg: str):
    """自定义断言：判断条件是否为True，否则抛出异常"""
    if not condition:
        raise AssertionError(f"断言失败：{msg}")


def assert_false(condition, msg: str):
    """自定义断言：判断条件是否为False，否则抛出异常"""
    if condition:
        raise AssertionError(f"断言失败：{msg}")


def generate_valid_test_data(vss: FeldmanVSS, n: int, t: int) -> Tuple[List[Tuple[int, int]], List[int], bytes]:
    """生成合法测试数据：有效份额+对应承诺+原始秘密"""
    secret = secrets.token_bytes(20)  # 随机16字节秘密（模拟真实场景）
    shares, commitments = vss.share_with_commitments(secret, n, t)
    return shares, commitments, secret


def generate_invalid_shares(valid_shares: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """篡改部分份额，生成含无效份额的列表"""
    invalid_shares = valid_shares.copy()
    # 篡改第1个份额的value（+100，确保无效）
    if invalid_shares:
        share_id, old_value = invalid_shares[0]
        invalid_shares[0] = (share_id, old_value + 100)
    # 新增非法share_id=0（不符合share_id>0要求）
    invalid_shares.append((0, secrets.randbelow(1000)))
    # 新增非法share_value=-1（不符合value≥0要求）
    invalid_shares.append((secrets.randbelow(255) + 1, -1))
    return invalid_shares


def generate_invalid_commitments(valid_commitments: List[int], p: int) -> List[int]:
    """篡改部分承诺值，生成含无效承诺的列表"""
    invalid_commitments = valid_commitments.copy()
    # 篡改第1个承诺值为1（平凡值，无效）
    if invalid_commitments:
        invalid_commitments[0] = 1
    # 篡改第2个承诺值为p-1（非法值，无效）
    if len(invalid_commitments) >= 2:
        invalid_commitments[1] = p - 1
    return invalid_commitments


def test_batch_verify_all_valid(vss: FeldmanVSS):
    """测试1：所有份额均有效 → 全部返回True"""
    print("\n=== 测试1：验证所有有效份额 ===")
    # 测试3组不同的n（份额数）和t（阈值）
    test_cases = [(5, 3), (10, 5), (20, 8)]
    for n, t in test_cases:
        print(f"  测试组：n={n}, t={t}")
        # 生成合法数据
        valid_shares, valid_commitments, _ = generate_valid_test_data(vss, n, t)
        # 执行批量验证
        results = vss.batch_verification(valid_shares, valid_commitments)
        # 断言检查
        assert_equal(len(results), len(valid_shares), f"结果数量不匹配（预期{len(valid_shares)}，实际{len(results)}）")
        assert_true(all(results), f"存在有效份额未通过验证（结果：{results}）")
    print("  ✅ 测试1通过")


def test_batch_verify_with_invalid_shares(vss: FeldmanVSS):
    """测试2：含无效份额 → 无效份额返回False，有效份额返回True"""
    print("\n=== 测试2：验证含无效份额的列表 ===")
    # 生成基础合法数据（n=5, t=3）
    valid_shares, valid_commitments, _ = generate_valid_test_data(vss, n=5, t=3)
    # 生成含3种无效份额的列表（共5+2=7个份额）
    mixed_shares = generate_invalid_shares(valid_shares)
    # 执行批量验证
    results = vss.batch_verification(mixed_shares, valid_commitments)
    # 断言检查：结果数量匹配
    assert_equal(len(results), len(mixed_shares), f"结果数量不匹配（预期{len(mixed_shares)}，实际{len(results)}）")
    # 断言：篡改value的份额（第0个）→ False
    assert_false(results[0], "篡改value的份额应验证失败（第0个）")
    # 断言：非法share_id=0的份额（第5个）→ False
    assert_false(results[5], "share_id=0的份额应验证失败（第5个）")
    # 断言：非法value=-1的份额（第6个）→ False
    assert_false(results[6], "share_value=-1的份额应验证失败（第6个）")
    # 断言：原始未篡改的份额（第1-4个）→ True
    assert_true(all(results[1:5]), "未篡改的有效份额应全部通过验证（第1-4个）")
    print("  ✅ 测试2通过")


def test_batch_verify_with_invalid_commitments(vss: FeldmanVSS):
    """测试3：含无效承诺 → 所有份额均返回False"""
    print("\n=== 测试3：验证含无效承诺的场景 ===")
    # 生成基础合法数据（n=5, t=3）
    valid_shares, valid_commitments, _ = generate_valid_test_data(vss, n=5, t=3)
    # 生成含无效承诺的列表
    invalid_commitments = generate_invalid_commitments(valid_commitments, vss.p)
    # 执行批量验证
    results = vss.batch_verification(valid_shares, invalid_commitments)
    # 断言：所有份额均验证失败
    assert_true(all(not res for res in results), "含无效承诺时，所有份额应验证失败")
    print("  ✅ 测试3通过")


def test_batch_verify_edge_cases(vss: FeldmanVSS):
    """测试4：边界场景（空份额、单份额、最小阈值t=2）"""
    print("\n=== 测试4：验证边界场景 ===")
    # 用例4.1：空份额列表 → 返回空列表
    empty_results = vss.batch_verification([], [1, 2, 3])
    assert_equal(empty_results, [], "空份额列表应返回空结果")
    print("  子用例4.1（空份额）通过")

    # 用例4.2：单份额（n=1，t=2的承诺）→ 有效份额返回True
    valid_shares, valid_commitments, _ = generate_valid_test_data(vss, n=3, t=2)
    single_share = [valid_shares[0]]  # 仅保留1个有效份额
    single_results = vss.batch_verification(single_share, valid_commitments)
    assert_equal(len(single_results), 1, "单份额应返回1个结果")
    assert_true(single_results[0], "单份有效份额应验证通过")
    print("  子用例4.2（单份额）通过")

    # 用例4.3：最小阈值t=2（n=2，t=2）→ 全部通过
    two_shares, two_commitments, _ = generate_valid_test_data(vss, n=2, t=2)
    two_results = vss.batch_verification(two_shares, two_commitments)
    assert_true(all(two_results), "t=2的有效份额应全部通过验证")
    print("  子用例4.3（最小阈值t=2）通过")
    print("  ✅ 测试4通过")


def test_pow_optimization_correctness(vss: FeldmanVSS):
    """测试5：验证优化逻辑（幂次迭代+2的幂次预处理）的正确性"""
    print("\n=== 测试5：验证优化逻辑正确性 ===")
    # 生成测试数据
    valid_shares, valid_commitments, _ = generate_valid_test_data(vss, n=5, t=3)
    share_id, _ = valid_shares[0]
    q = vss.q  # 有限域素数
    p = vss.p  # 大素数

    # 验证1：幂次迭代生成的i^j 与 原生pow结果一致
    t_val = len(valid_commitments)
    # 迭代生成i^0 ~ i^(t-1)
    iter_powers = [1] * t_val
    for j in range(1, t_val):
        iter_powers[j] = (iter_powers[j-1] * share_id) % q
    # 原生pow生成i^0 ~ i^(t-1)
    native_powers = [pow(share_id, j, q) for j in range(t_val)]
    # 断言：两种方式结果一致
    assert_equal(iter_powers, native_powers, "幂次迭代生成结果与原生pow不一致")
    print("  子用例5.1（幂次迭代）通过")

    # 验证2：2的幂次预处理的Cj^e 与 原生pow结果一致
    cj = valid_commitments[0]  # 取第一个承诺值
    e = iter_powers[1]  # 取i^1作为指数
    # 预处理Cj的2的幂次（最大位数=q的二进制位数）
    max_bits = q.bit_length()
    cj_pow2 = [1] * (max_bits + 1)
    cj_pow2[0] = cj
    for k in range(1, max_bits + 1):
        cj_pow2[k] = pow(cj_pow2[k-1], 2, p)
    # 二进制分解计算Cj^e
    decomposed_val = 1
    temp_e = e
    bit_idx = 0
    while temp_e > 0:
        if temp_e & 1:
            decomposed_val = (decomposed_val * cj_pow2[bit_idx]) % p
        temp_e >>= 1
        bit_idx += 1
    # 原生pow计算Cj^e
    native_val = pow(cj, e, p)
    # 断言：两种方式结果一致
    assert_equal(decomposed_val, native_val, "2的幂次预处理结果与原生pow不一致")
    print("  子用例5.2（2的幂次预处理）通过")
    print("  ✅ 测试5通过")


def main():
    """主函数：初始化VSS实例并执行所有测试"""
    print("=" * 60)
    print("开始测试 FeldmanVSS.batch_verification 函数")
    print("=" * 60)

    # 初始化FeldmanVSS实例（bits=256，平衡速度与安全性）
    try:
        vss = FeldmanVSS(bits=256)
        print(f"\n✅ VSS实例初始化成功（p={vss.p}, q={vss.q}, g={vss.g}）")
    except Exception as e:
        print(f"\n❌ VSS实例初始化失败：{str(e)}")
        return

    # 执行所有测试
    test_functions = [
        test_batch_verify_all_valid,
        test_batch_verify_with_invalid_shares,
        test_batch_verify_with_invalid_commitments,
        test_batch_verify_edge_cases,
        test_pow_optimization_correctness
    ]

    passed = 0
    failed = 0
    for test_func in test_functions:
        try:
            test_func(vss)
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {test_func.__name__} 失败：{str(e)}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {test_func.__name__} 异常：{str(e)}")
            failed += 1

    # 输出测试总结
    print("\n" + "=" * 60)
    print(f"测试总结：共{len(test_functions)}个测试，通过{passed}个，失败{failed}个")
    print("=" * 60)


if __name__ == "__main__":
    main()