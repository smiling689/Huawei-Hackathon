import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.hierarchical_sharing import HierarchicalSecretSharing, Share


def test_classic_hierarchical_flow():
    """按照 FLOW_OVERVIEW.md 描述的经典流程完成集成测试"""
    master_secret = b"MASTER_FLOW_SECRET"
    regional_secret = b"REGIONAL_FLOW_SECRET"
    branch_secret = b"BRANCH_FLOW_SECRET"

    print("[初始化] 创建分层密钥系统 (Initialization: create hierarchical secret sharing system)")
    hss = HierarchicalSecretSharing(vss_bits=256)

    print("[分发] 生成 master/regional/branch 份额 (Distribution: generate master/regional/branch shares)")
    master_result = hss.create_master_key(master_secret)
    regional_result = hss.create_regional_key(regional_secret, "asia")
    branch_names = [f"integration_branch_{i}" for i in range(1, 6)]
    branch_result = hss.create_branch_key(branch_secret, branch_names)

    print("[验证] 首次校验各层份额 (Verification: validate shares for each level)")
    all_master_shares = master_result["hq_shares"] + list(master_result["regional_shares"].values())
    for share in all_master_shares:
        assert hss.verify_share(share, "master")
    for share in regional_result["center_shares"] + regional_result["branch_shares"]:
        assert hss.verify_share(share, "regional")
    for share in branch_result["shares"]:
        assert hss.verify_share(share, "branch")

    print("[恢复] 首次执行 master/regional/branch 恢复 (Recovery: perform initial master/regional/branch recovery)")
    master_recovery_set = master_result["hq_shares"] + list(master_result["regional_shares"].values())[:3]
    assert hss.cascade_recovery("master", master_recovery_set) == master_secret

    branch_threshold = math.ceil(len(regional_result["branch_shares"]) * 0.6)
    regional_recovery_set = (
        regional_result["center_shares"]
        + regional_result["branch_shares"][:branch_threshold]
    )
    assert hss.cascade_recovery("regional", regional_recovery_set) == regional_secret

    branch_recovery_set = branch_result["shares"][:3]
    assert hss.cascade_recovery("branch", branch_recovery_set) == branch_secret

    print("[验证] 模拟恶意分行份额并执行投诉生成 (Verification: simulate malicious branch share and generate complaint)")
    tampered_original = branch_result["shares"][0]
    tampered_share = Share(
        id=tampered_original.id,
        value=(tampered_original.value + 1) % hss.vss.q,
        holder=tampered_original.holder,
        level=tampered_original.level,
    )
    print(f"  - 篡改份额: id={tampered_share.id}, 原值={tampered_original.value}, 新值={tampered_share.value} (Tampered share details)")
    assert not hss.verify_share(tampered_share, "branch")
    complaint = hss.vss.generate_complaint(
        tampered_share.id,
        tampered_share.value,
        hss.commitments["branch"],
    )
    assert complaint["accuser"] == tampered_share.id
    expected = complaint["expected_verification"]
    print(f"  - 投诉生成完成: left={expected['left']}, right={expected['right']} (Complaint generated: expected verification)")

    print("[刷新] 对 master 份额执行主动刷新 (Refresh: perform proactive refresh on master shares)")
    n_master = len(all_master_shares)
    num_regions = len(hss.organization["regions"])
    regions_required = max(1, (num_regions + 1) // 2)
    t_master = 3 + regions_required
    refreshed_master = hss.refresh_shares("master", all_master_shares, n_master, t_master)

    print("[验证] 刷新后校验 master 份额并再次恢复 (Verification: validate refreshed master shares and recover again)")
    for share in refreshed_master:
        assert hss.verify_share(share, "master")

    refreshed_hq = refreshed_master[: len(master_result["hq_shares"])]
    refreshed_regions = refreshed_master[len(master_result["hq_shares"]):]
    refreshed_recovery_set = refreshed_hq + refreshed_regions[:3]
    assert hss.cascade_recovery("master", refreshed_recovery_set) == master_secret
    print("  - 刷新后恢复结果与原主密钥一致 (Post-refresh recovery matches original master secret)")


if __name__ == "__main__":
    print("=" * 60)
    print("运行经典流程集成测试 (Running classic flow integration test)")
    print("=" * 60)
    test_classic_hierarchical_flow()
    print("PASS - 流程集成测试完成 (Flow integration test completed)")
