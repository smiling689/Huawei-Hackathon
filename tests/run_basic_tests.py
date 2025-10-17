#!/usr/bin/env python3
"""
运行 tests/basic 目录下的所有基础单元测试 (Run all basic unit tests under tests/basic)
"""

import subprocess
import sys
from pathlib import Path


def run_test_file(test_file: Path) -> bool:
    """运行单个测试文件"""
    print(f"\n{'=' * 60}")
    print(f"运行测试: {test_file.name} (Running test: {test_file.name})")
    print('=' * 60)

    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print("错误输出 (Stderr):", result.stderr)

        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("✗ 测试超时 (>60秒) (Test timed out >60s)")
        return False
    except Exception as exc:
        print(f"✗ 运行失败: {exc} (Execution failed)")
        return False


def main() -> int:
    print("=" * 70)
    print(" " * 18 + "基础单元测试套件 - tests/basic")
    print(" " * 18 + "Basic unit test suite - tests/basic")
    print("=" * 70)

    base_dir = Path(__file__).parent
    test_dir = base_dir / "basic"
    test_files = sorted(
        f for f in test_dir.glob("*.py") if f.name != "__init__.py"
    )

    if not test_files:
        print("未找到任何测试文件 (No test files found)")
        return 1

    results = []
    for test_file in test_files:
        success = run_test_file(test_file)
        results.append((test_file.name, success))

    print("\n" + "=" * 70)
    print(" " * 25 + "测试结果汇总 (Test summary)")
    print("=" * 70)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "PASS (passed)" if success else "FAIL (failed)"
        print(f"  {name:30} {status}")

    print("-" * 70)
    emoji = "✅" if passed == total else "⚠️"
    print(f"\n{emoji} 总计: {passed}/{total} 测试文件通过 (Total: {passed}/{total} test files passed)")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
