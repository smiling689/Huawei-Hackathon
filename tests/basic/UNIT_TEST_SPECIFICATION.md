# UNIT Test Specification (Basic Suite)

详细列出 `tests/basic` 中各单元测试的输入、调用链与预期结果。
This document enumerates inputs, API call sequences, and expected results for the basic unit-test suite.

---

## unit_test_basic.py — BasicShamir

### 用例 B1: 基础秘密分享与恢复 (Basic split/recovery)
**输入 (Input):**
```python
secret = b"Hello_World_2024"
n = 5
t = 3
```
**API调用链 (Call chain):**
```python
shamir = BasicShamir(prime_bits=256)
shares = shamir.split_secret(secret, n, t)
recovered = shamir.recover_secret(shares[:t])
```
**预期输出 (Expected result):**
```
recovered == b"Hello_World_2024"
```

### 用例 B2: 份额不足无法恢复 (Insufficient shares)
**输入:**
```python
secret = b"Test_Secret"
n = 5
t = 3
```
**API调用链:**
```python
shares = shamir.split_secret(secret, n, t)
recovered = shamir.recover_secret(shares[:t-1])
```
**预期输出:**
```
recovered != b"Test_Secret"
```

### 用例 B3: 使用全部份额恢复 (All shares)
**输入:**
```python
secret = b"All_Shares_Test"
n = 7
t = 4
```
**API调用链:**
```python
shares = shamir.split_secret(secret, n, t)
recovered = shamir.recover_secret(shares)
```
**预期输出:**
```
recovered == b"All_Shares_Test"
```

### 用例 B4: verify_shares_consistency 检测篡改
**输入:**
```python
shares = shamir.split_secret(b"CONSISTENT", 5, 3)
```
**API调用链:**
```python
shamir.verify_shares_consistency(shares, 3)
shares[0] = (shares[0][0], (shares[0][1] + 1) % shamir.prime)
shamir.verify_shares_consistency(shares, 3)
```
**预期输出:**
```
第一次调用返回 True，第二次返回 False
```

### 用例 B5: 超过 block_size 的密钥 (Oversized secret)
**输入:**
```python
oversized = os.urandom(shamir.block_size + 1)
```
**API调用链:**
```python
shamir.split_secret(oversized, 5, 3)
```
**预期输出:**
```
Raises ValueError("Secret too large ...")
```

---

## unit_test_vss.py — FeldmanVSS

### 用例 F1: 份额生成与验证 (Share generation & verify)
**输入:**
```python
secret = b"VSS_Secret"
n = 5
t = 3
```
**API调用链:**
```python
shares, commitments = vss.share_with_commitments(secret, n, t)
results = [vss.verify_share(i, s, commitments) for i, s in shares]
```
**预期输出:**
```
all(results) == True
```

### 用例 F2: 恶意份额与投诉 (Malicious share + complaint)
**输入:**
```python
secret = b"Malicious"
n = 4
t = 2
```
**API调用链:**
```python
shares, commitments = vss.share_with_commitments(secret, n, t)
malicious_id = shares[0][0]
malicious_val = shares[0][1] + 999
valid = vss.verify_share(malicious_id, malicious_val, commitments)
complaint = vss.generate_complaint(malicious_id, malicious_val, commitments)
```
**预期输出:**
```
valid == False
complaint['accuser'] == malicious_id
```

### 用例 F3: 恢复接口 (Recovery)
**输入:**
```python
secret = b"Recovery"
n = 5
t = 3
```
**API调用链:**
```python
shares, commitments = vss.share_with_commitments(secret, n, t)
recovered = vss.recover_secret_from_shares(shares[:t], commitments)
```
**预期输出:**
```
recovered == b"Recovery"
```

### 用例 F4: 批量验证 (Batch verification)
**输入:**
```python
secret = b"BATCH"
n = 6
t = 3
```
**API调用链:**
```python
shares, commitments = vss.share_with_commitments(secret, n, t)
results = vss.batch_verification(shares, commitments)

tampered = list(shares)
tampered[0] = (tampered[0][0], tampered[0][1] + 1)
results_tampered = vss.batch_verification(tampered, commitments)
```
**预期输出:**
```
all(results) == True and results_tampered[0] == False
```

---

## unit_test_refresh.py — ProactiveSecretSharing

### 用例 P1: 刷新前后恢复一致 (Consistency)
**输入:**
```python
secret = b"Refresh_Test"
n = 5
t = 3
```
**API调用链:**
```python
initial = shamir.split_secret(secret, n, t)
refreshed = proactive.active_refresh(initial, n, t)
recovered_before = shamir.recover_secret(initial[:t])
recovered_after = shamir.recover_secret(refreshed[:t])
```
**预期输出:**
```
recovered_before == recovered_after == secret
```

### 用例 P2: 份额值变化 (Shares changed)
**输入:**
```python
secret = b"Change"
n = 4
t = 2
```
**API调用链:**
```python
initial = shamir.split_secret(secret, n, t)
refreshed = proactive.active_refresh(initial, n, t)
changed = any(a[1] != b[1] for a, b in zip(initial, refreshed))
recovered = shamir.recover_secret(refreshed[:t])
```
**预期输出:**
```
changed is True and recovered == secret
```

### 用例 P3: 多次刷新 (Multiple refreshes)
**输入:**
```python
secret = b"Multi"
n = 5
t = 3
refresh_times = 3
```
**API调用链:**
```python
shares = shamir.split_secret(secret, n, t)
for _ in range(refresh_times):
    shares = proactive.active_refresh(shares, n, t)
    assert shamir.recover_secret(shares[:t]) == secret
```
**预期输出:**
```
循环内每次恢复均等于 secret
```

### 用例 P4: active_refresh_with_coeffs 返回系数
**输入:**
```python
secret = b"COEFF"
n = 5
t = 3
```
**API调用链:**
```python
shares = shamir.split_secret(secret, n, t)
refreshed, coeffs = proactive.active_refresh_with_coeffs(shares, n, t)
```
**预期输出:**
```
coeffs[0] == 0, len(coeffs) == t, refreshed 能恢复 secret
```

### 用例 P5: 自动刷新判定与刷新多项式
**输入:**
- 调度：修改 `last_refresh_time` 控制 True/False
- 多项式：`participant_id=1, n=4, t=3`

**API调用链:**
```python
flag = proactive.schedule_automatic_refresh()
payload = proactive.generate_refresh_polynomial(1, 4, 3)
```
**预期输出:**
```
flag 在未到期时 False、到期后 True；payload['polynomial'][0] == 0 且 shares/commitments 校验通过
```

---

## unit_test_hierarchical.py — HierarchicalSecretSharing

### 用例 H1: 主密钥恢复 (Master recovery)
**输入:**
```python
secret = b"MASTER_KEY"
```
**API调用链:**
```python
master = hss.create_master_key(secret)
shares = master["hq_shares"] + [master["regional_shares"][r] for r in ["asia","europe","americas"]]
recovered = hss.cascade_recovery("master", shares)
```
**预期输出:**
```
recovered == secret
```

### 用例 H2: 区域密钥恢复 (Regional recovery)
**输入:**
```python
secret = b"REGIONAL"
region = "asia"
```
**API调用链:**
```python
regional = hss.create_regional_key(secret, region)
required = math.ceil(len(regional["branch_shares"]) * 0.6)
shares = regional["center_shares"] + regional["branch_shares"][:required]
recovered = hss.cascade_recovery("regional", shares)
```
**预期输出:**
```
recovered == secret
```

### 用例 H3: 分行密钥恢复 (Branch recovery)
**输入:**
```python
secret = b"BRANCH"
branches = ["branch_001", "branch_002", "branch_003", "branch_004"]
```
**API调用链:**
```python
branch = hss.create_branch_key(secret, branches)
recovered = hss.cascade_recovery("branch", branch["shares"][:3])
```
**预期输出:**
```
recovered == secret
```

### 用例 H4: master 份额不足 (Insufficient master shares)
**输入:**
```python
secret = b"INSUFFICIENT"
```
**API调用链:**
```python
master = hss.create_master_key(secret)
only_regions = list(master["regional_shares"].values())
```
**API调用链:**
```python
with pytest.raises(ValueError):
    hss.cascade_recovery("master", only_regions)
```
**预期输出:**
```
抛出 ValueError("Insufficient shares ...")
```

### 用例 H5: 跨级别访问 (Cross-level protection)
**输入:**
```python
master = hss.create_master_key(b"LEVEL_TEST")
```
**API调用链:**
```python
with pytest.raises(ValueError):
    hss.cascade_recovery("branch", master["hq_shares"])
```
**预期输出:**
```
抛出 ValueError("Security violation ...")
```

### 用例 H6: verify_share & refresh_shares
**输入:**
```python
secret = b"REFRESH_MASTER"
```
**API调用链:**
```python
master = hss.create_master_key(secret)
for share in master_shares:
    assert hss.verify_share(share, "master")
refreshed = hss.refresh_shares("master", master_shares, len(master_shares), threshold)
ref_recovery = refreshed[:3] + refreshed[3:3+regions_required]
```
**预期输出:**
```
刷新后份额验证通过，恢复结果等于 secret
```

## 备注 (Notes)
- 所有基础单测均使用 `pytest` 风格断言；若在手工运行中需要，可直接执行 `python tests/run_basic_tests.py`。
