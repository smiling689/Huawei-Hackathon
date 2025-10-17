#!/usr/bin/env python3
"""
分层可验证秘密分享系统 - 测试运行器 (Hierarchical verifiable secret sharing system - test runner)
"""

import subprocess
import sys
from pathlib import Path

def run_test_suite(name, test_file):
    """运行测试套件"""
    print(f"\n{'='*60}")
    print(f"  {name} (Running suite: {name})")
    print('='*60)
    
    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # 只显示关键输出
        lines = result.stdout.split('\n')
        highlights = ("PASS", "FAIL", "汇总", "Summary", "通过", "失败")
        for line in lines:
            if any(keyword in line for keyword in highlights):
                print(line)
        
        return result.returncode == 0
    except Exception as e:
        print(f"✗ 运行失败: {e} (Execution failed)")
        return False


def main():
    """主函数"""
    print("="*70)
    print(" " * 10 + "分层可验证秘密分享系统 - 测试套件")
    print(" " * 10 + "Hierarchical verifiable secret sharing system - test suites")
    print("="*70)
    
    base_dir = Path(__file__).parent
    test_suites = [
        ("基础测试", base_dir / "run_basic_tests.py"),
        ("扩展测试", base_dir / "run_extended_tests.py"),
    ]
    
    results = []
    for name, test_file in test_suites:
        if test_file.exists():
            success = run_test_suite(name, test_file)
            results.append((name, success))
        else:
            print(f"\n✗ 测试文件不存在: {test_file} (Test file not found)")
            results.append((name, False))
    
    # 汇总
    print("\n" + "="*70)
    print(" " * 25 + "测试结果汇总 (Test summary)")
    print("="*70)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for name, success in results:
        status = "PASS (passed)" if success else "FAIL (failed)"
        print(f"  {name:15} {status}")

    print("-"*70)
    emoji = "✅" if passed == total else "⚠️"
    print(f"\n{emoji} 总计: {passed}/{total} 测试套件通过 (Total: {passed}/{total} suites passed)")

    if passed == total:
        print("\n🎉 所有测试通过！ (All tests passed!)")
        return 0
    else:
        print(f"\n⚠️  有 {total - passed} 个测试套件失败 (Warning: {total - passed} suites failed)")
        return 1


if __name__ == "__main__":
    exit(main())
