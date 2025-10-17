# 分层可验证秘密分享竞赛模板

## 项目概述
- **目标：** 本仓库提供分层可验证秘密分享系统的比赛模板，`templates/` 中给出了全部必需的接口骨架，选手需将其拷贝到 `src/` 后补全实现。
- **核心组件：**
  - `BasicShamir`：基础阈值秘密分享。
  - `FeldmanVSS`：在基础方案上加入承诺验证与投诉机制。
  - `ProactiveSecretSharing`：主动刷新份额，保持长期密钥安全。
  - `HierarchicalSecretSharing`：整合上述模块，覆盖总部-区域-分行的层级架构。
- **参考文档：** `tests/basic/UNIT_TEST_SPECIFICATION.md` 给出基础测例说明。

## 目录结构
- `templates/`：官方提供的 API 模板文件。建议复制到 `src/` 中作为起点。
- `src/`：选手实现目录。提交前请确认对外接口与模板保持一致。
- `tests/`
  - `basic/`：针对各模块的单元测试（Shamir、Feldman VSS、主动刷新、分层流程）。
  - `extended/`：整体验收流程测试，模拟分层密钥的实际运转、投诉与刷新场景。
  - `run_basic_tests.py` / `run_extended_tests.py` / `run_tests.py`：便捷执行脚本，可单独或批量运行测试套件。
- `requirements.txt`：官方评测依赖列表。

## 开发流程
1. **复制模板：** 将 `templates/*.py` 复制到 `src/` 中（保持文件名一致），并根据注释完成实现。
2. **遵循接口约定：** 所有公开方法的参数、返回值、异常信息需与模板保持一致，尤其是错误信息中的关键字（如 "Invalid parameters"、"Secret too large" 等）。
3. **分阶段实现：** 建议先实现 `BasicShamir`，再完成 `FeldmanVSS`、`ProactiveSecretSharing`，最后组合出 `HierarchicalSecretSharing`，并在每一步运行对应测试。
4. **记录审计信息：** 模板中预留了审计日志、承诺缓存等字段，实际实现时应遵循文档约束。

## 测试体系
> 建议使用 Python 3.10+ 并在虚拟环境中执行测试。

- **运行全部测试：**
  ```bash
  python tests/run_tests.py
  ```
- **仅运行基础单测：**
  ```bash
  python tests/run_basic_tests.py
  ```
  - 覆盖点包括：秘密拆分/恢复、份额一致性检测、承诺验证、主动刷新、分层密钥的阈值规则与安全检查。
- **仅运行扩展测试：**
  ```bash
  python tests/run_extended_tests.py
  ```
  - 模拟完整业务流程：生成多层份额、验证持有者、执行恢复、检测恶意份额并生成投诉、刷新后再次恢复。
- **运行单个测试文件：** 可直接执行 `tests/basic/unit_test_*.py` 或 `tests/extended/test_flow_integration.py` 以排查问题。

### 测试覆盖摘要
- `tests/basic/unit_test_basic.py`：验证 `BasicShamir` 的拆分/恢复、异常处理与份额一致性检查。
- `tests/basic/unit_test_vss.py`：检查 `FeldmanVSS` 的承诺生成、份额验证、投诉、批量验证与恢复逻辑。
- `tests/basic/unit_test_refresh.py`：覆盖主动刷新、刷新系数、自动调度以及刷新多项式的正确性。
- `tests/basic/unit_test_hierarchical.py`：检验层级密钥的阈值规则、跨级访问防护、刷新后验证等。
- `tests/extended/test_flow_integration.py`：串联整个系统，确保在真实流程中能检测恶意份额并维持刷新后的可用性。

## 依赖与环境
- 可以考虑安装 `requirements.txt` 中列出的 `cryptography`、`pycryptodome`、`numpy`、`sympy` 等依赖，以便与官方评测环境保持一致。
- 建议流程：
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate  # Windows 使用 .venv\Scripts\activate
  pip install -r requirements.txt
  ```

## 其他说明
- **语言选择：** **可以使用非 Python 语言**（如 C/C++、Rust 等）实现核心算法，但需要提供可被 Python 调用的接口；测试脚本会严格按照 Python API 进行调用。
- **秘密大小：** 【基础实现】需确保秘密长度不超过 `block_size`，超出时抛出 `ValueError`（官方单测仅覆盖此情形）。【扩展实现】需支持超长秘密并满足子问题 1～4，可根据设计调整或新增接口；若完成扩展，请在演示与答辩材料中说明，我们也会参考扩展测试脚本进行验证。
- **保持错误信息一致：** 单元测试会对异常信息做字符串匹配，请按模板中的提示返回精确短语。
- **有限域与承诺：** `BasicShamir` 与 `FeldmanVSS` 对素数、生成元的选取有严格要求，应确保与刷新模块共享同一有限域，并在刷新时同步更新承诺。
- **层级阈值：** 层级恢复必须满足各自的最小份额要求（HQ+区域、区域中心+60%分行、至少3个分行），否则应抛出含指定关键字的异常。

祝比赛顺利，欢迎根据模板与测试加速迭代，及时运行测试套件确保实现符合规范！
