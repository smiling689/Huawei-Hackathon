# Hierarchical Verifiable Secret Sharing Competition Template

## Project Overview
- **Goal:** Provide a competition starter kit for the hierarchical verifiable secret sharing system. Skeleton implementations live under `templates/`; copy them into `src/` and fill in the required logic.
- **Core components:**
  - `BasicShamir`: baseline threshold secret sharing.
  - `FeldmanVSS`: adds public commitments, share verification, and complaint handling.
  - `ProactiveSecretSharing`: keeps shares fresh through proactive refresh cycles.
  - `HierarchicalSecretSharing`: combines the above modules for headquarters–regional–branch workflows.
- **Reference doc:** `tests/basic/UNIT_TEST_SPECIFICATION.md` outlines the basic test scenarios.

## Directory Layout
- `templates/`: official API skeletons. Treat them as reference; copy into `src/` before editing.
- `src/`: contestant implementation area. Keep the public APIs identical to the templates.
- `tests/`
  - `basic/`: unit tests for the individual modules (Shamir, Feldman VSS, proactive refresh, hierarchical orchestration).
  - `extended/`: end-to-end workflow tests covering distribution, verification, complaints, and refresh.
  - `run_basic_tests.py` / `run_extended_tests.py` / `run_tests.py`: helpers to execute suites individually or in bulk.
- `requirements.txt`: dependency snapshot used by the official judge.

## Development Workflow
1. **Copy templates:** Move `templates/*.py` into `src/` with identical filenames and implement the TODO sections.
2. **Honor API contracts:** Match method signatures, return values, and exception messages exactly as the templates specify (e.g., include key phrases like "Invalid parameters" or "Secret too large").
3. **Iterative build-up:** Implement `BasicShamir` first, then `FeldmanVSS`, `ProactiveSecretSharing`, and finally assemble `HierarchicalSecretSharing`, running the matching tests after each milestone.
4. **Audit & commitments:** Populate the logging and commitment fields left in the templates to satisfy the higher-level orchestration tests.

## Testing
> Python 3.10+ is recommended. Create a virtual environment if possible.

- **Run all suites**
  ```bash
  python tests/run_tests.py
  ```
- **Basic unit tests only**
  ```bash
  python tests/run_basic_tests.py
  ```
  - Exercises sharing/recovery, consistency checks, commitments, proactive refresh, and hierarchical threshold validation.
- **Extended workflow tests only**
  ```bash
  python tests/run_extended_tests.py
  ```
  - Covers the full lifecycle: multi-level distribution, share verification, complaint generation, and post-refresh recovery.
- **Single test files**: Execute `tests/basic/unit_test_*.py` or `tests/extended/test_flow_integration.py` directly for focused debugging.

### Coverage Highlights
- `tests/basic/unit_test_basic.py`: split/recover paths, error handling, share consistency for `BasicShamir`.
- `tests/basic/unit_test_vss.py`: commitments, verification, complaints, batch verification, and recovery for `FeldmanVSS`.
- `tests/basic/unit_test_refresh.py`: proactive refresh behavior, delta coefficients, scheduler, and refresh polynomial correctness.
- `tests/basic/unit_test_hierarchical.py`: hierarchical thresholds, cross-level safeguards, refresh validation.
- `tests/extended/test_flow_integration.py`: full-system integration, malicious share detection, and refresh validation.

## Dependencies & Environment
- Consider installing the dependencies listed in `requirements.txt` (`cryptography`, `pycryptodome`, `numpy`, `sympy`) to mirror the judging environment.
- Suggested setup:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate  # On Windows use .venv\Scripts\activate
  pip install -r requirements.txt
  ```

## Additional Notes
- **Language choice:** **You may implement the core algorithms in a non-Python language** (e.g., C/C++, Rust) as long as they expose Python-callable bindings; the official tests invoke the APIs from Python.
- **Secret size:** *Baseline implementation* must reject secrets longer than `block_size` by raising `ValueError` (the official unit tests only cover this scenario). *Extended implementation* should handle oversized secrets while satisfying subproblems 1–4; you may adjust or add interfaces as needed. Showcase the extended design during demos and presentations, and expect reference checks via extended tests.
- **Error messages:** Tests assert against specific message fragments, so reproduce the wording shown in the templates.
- **Field and commitments:** Ensure the field parameters used by `BasicShamir` and `FeldmanVSS` remain consistent with proactive refresh logic, and synchronize commitments during refresh.
- **Hierarchical thresholds:** Enforce the documented share requirements (HQ + regions, region centers + ≥60% branches, at least three branch shares) and raise errors containing the expected keywords when validation fails.
