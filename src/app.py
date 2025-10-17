import math
import os
import secrets
import time
from typing import Dict, List, Optional, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

try:  # 兼容直接运行与作为包导入两种场景
    from .hierarchical_sharing import HierarchicalSecretSharing, Share
except ImportError:  # pragma: no cover
    from hierarchical_sharing import HierarchicalSecretSharing, Share


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_FOLDER = APP_ROOT

app = Flask(__name__, static_folder=STATIC_FOLDER, static_url_path="")
CORS(app)

SESSION_ID = "demo_session"
systems: Dict[str, Dict] = {}

REGION_DISPLAY_NAMES = {
    "asia": "亚太区",
    "europe": "欧洲区",
    "americas": "美洲区",
    "africa": "非洲区",
    "oceania": "大洋洲区",
}


def get_region_display_name(region: str) -> str:
    return REGION_DISPLAY_NAMES.get(region, _titled(region))


def friendly_branch_label(holder: str) -> str:
    if "_branch_" in holder:
        prefix, suffix = holder.split("_branch_", 1)
        if suffix.isdigit():
            return f"{get_region_display_name(prefix)} 分行 #{int(suffix)}"
    return _titled(holder)


def friendly_center_label(holder: str) -> str:
    if holder.endswith("_center"):
        prefix = holder[:-7]
        return f"{get_region_display_name(prefix)} 主中心份额"
    if "_center_" in holder:
        prefix, suffix = holder.split("_center_", 1)
        if suffix.isdigit():
            return f"{get_region_display_name(prefix)} 中心份额 #{int(suffix)}"
    return _titled(holder)


def friendly_hq_label(index: int) -> str:
    return f"总部份额 #{index}"


def _titled(identifier: str) -> str:
    """将标识符转换为可读名称。"""
    return identifier.replace("_", " ").title()


def serialize_share(share: Share, label_map: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    data: Dict[str, object] = {
        "id": share.id,
        "value": str(share.value),
        "holder": share.holder,
        "level": share.level,
        "secret_length": share.secret_length,
    }
    if label_map:
        label = label_map.get(share.holder)
        if label:
            data["label"] = label
    return data


def serialize_commitments(commitments: List[int]) -> List[str]:
    return [str(c) for c in commitments]


def clone_share(share: Share) -> Share:
    return Share(
        id=share.id,
        value=share.value,
        holder=share.holder,
        level=share.level,
        secret_length=share.secret_length,
    )


def snapshot_shares(shares: List[Share]) -> List[Dict[str, object]]:
    return [
        {
            "id": share.id,
            "value": share.value,
            "holder": share.holder,
            "level": share.level,
            "secret_length": share.secret_length,
        }
        for share in shares
    ]


def share_from_snapshot(data: Dict[str, object]) -> Share:
    return Share(
        id=int(data["id"]),
        value=int(data["value"]),
        holder=str(data.get("holder", "")),
        level=str(data.get("level", "")),
        secret_length=data.get("secret_length"),
    )


def get_threshold(key_record: Dict) -> int:
    threshold = key_record.get("threshold")
    if threshold is None:
        shares = key_record.get("shares") or []
        return len(shares)
    return int(threshold)


def resolve_label(share: Share, label_map: Optional[Dict[str, str]] = None) -> str:
    mapping = label_map or {}
    label = mapping.get(share.holder)
    if label:
        return label
    if share.holder:
        return _titled(share.holder)
    return f"ID {share.id}"


def build_key_payload(key_id: str, record: Dict) -> Dict:
    label_map: Dict[str, str] = record.get("label_map", {}) if isinstance(record.get("label_map"), dict) else {}
    payload = {
        "key_id": key_id,
        "level": record["level"],
        "shares": [serialize_share(s, label_map) for s in record["shares"]],
        "commitments": serialize_commitments(record["commitments"]),
        "threshold": record.get("threshold"),
        "n": record.get("n"),
    }
    if record.get("region"):
        payload["region"] = record["region"]
    if record.get("branches"):
        payload["branches"] = record["branches"]
    history = record.get("history")
    if isinstance(history, list):
        payload["refresh_count"] = len(history)
        if history:
            payload["last_refresh_epoch"] = str(history[-1].get("timestamp", ""))
    if label_map:
        payload["labels"] = label_map
    return payload


def build_organization_structure(hss: HierarchicalSecretSharing) -> Dict:
    hq_nodes = [
        {"id": f"hq_{idx}", "name": f"总部份额 #{idx}"}
        for idx in range(1, 4)
    ]

    regions = []
    all_branches = []
    region_info_map = hss.organization.get("regions", {})

    for region_name in hss.region_names:
        info = region_info_map.get(region_name, {})
        branch_count = int(info.get("branches", 0))
        branch_names = info.get(
            "branch_names",
            [f"{region_name}_branch_{idx + 1}" for idx in range(branch_count)],
        )
        region_label = get_region_display_name(region_name)

        center_share_count = max(3, math.ceil(branch_count / 2)) if branch_count else 3

        master_node = {
            "id": f"{region_name}_center",
            "name": f"{region_label} 主中心份额",
        }

        regional_centers = [
            {
                "id": f"{region_name}_center_{idx}",
                "name": f"{region_label} 中心份额 #{idx}",
            }
            for idx in range(1, center_share_count + 1)
        ]

        branches = []
        for idx, branch_identifier in enumerate(branch_names, start=1):
            branch_label = f"{region_label} 分行 #{idx}"
            branch_entry = {"id": branch_identifier, "name": branch_label}
            branches.append(branch_entry)
            all_branches.append(branch_entry.copy())

        regions.append(
            {
                "value": region_name,
                "name": region_label,
                "master_node": master_node,
                "regional_centers": regional_centers,
                "centers": regional_centers,  # 向后兼容旧前端字段
                "branches": branches,
            }
        )

    return {
        "hq": {"name": "全球总部", "nodes": hq_nodes},
        "regions": regions,
        "all_branches": all_branches,
    }


def get_system(session_id: str = SESSION_ID) -> Optional[Dict]:
    return systems.get(session_id)


@app.route("/")
def index():
    return app.send_static_file("verifiable_secret_sharing_demo.html")


@app.route("/api/initialize", methods=["POST"])
def initialize_system():
    hss = HierarchicalSecretSharing(vss_bits=256)
    systems[SESSION_ID] = {
        "hss_instance": hss,
        "keys": {},
        "organization": build_organization_structure(hss),
        "limits": {"max_secret_bytes": hss.vss.block_size},
    }

    vss_params = {
        "p": str(hss.vss.p),
        "q": str(hss.vss.q),
        "g": str(hss.vss.g),
    }

    app.logger.info("System initialized successfully.")
    return jsonify(
        {
            "status": "success",
            "message": "System initialized.",
            "vss_params": vss_params,
            "organization_structure": systems[SESSION_ID]["organization"],
            "limits": systems[SESSION_ID]["limits"],
        }
    )


@app.route("/api/create_key", methods=["POST"])
def create_key():
    data = request.get_json(silent=True) or {}
    session = get_system()
    if session is None:
        return jsonify({"status": "error", "message": "System not initialized."}), 400

    hss: HierarchicalSecretSharing = session["hss_instance"]
    level = (data.get("level") or "").lower()
    secret_bytes = (data.get("secret") or "").encode("utf-8")

    key_record: Dict[str, object]
    key_id: str

    try:
        if level == "master":
            key_data = hss.create_master_key(secret_bytes)
            combined_shares = key_data["hq_shares"] + list(key_data["regional_shares"].values())
            meta = hss.master_key_info or {}
            key_id = f"master_key_{len(session['keys']) + 1}"
            label_map = {}
            for idx, share in enumerate(key_data["hq_shares"], start=1):
                label_map[share.holder] = friendly_hq_label(idx)
            for region_name, share in key_data["regional_shares"].items():
                label_map[share.holder] = friendly_center_label(share.holder)
            key_record = {
                "level": "master",
                "shares": combined_shares,
                "commitments": key_data["commitments"],
                "n": meta.get("n"),
                "threshold": meta.get("threshold"),
                "label_map": label_map,
                "history": [],
            }
        elif level == "regional":
            region = data.get("region")
            if not region:
                return jsonify({"status": "error", "message": "Region is required."}), 400
            key_data = hss.create_regional_key(secret_bytes, region)
            combined_shares = key_data["center_shares"] + key_data["branch_shares"]
            meta = hss.regional_keys.get(region, {})
            key_id = f"regional_key_{region}_{len(session['keys']) + 1}"
            region_label = get_region_display_name(region)
            label_map = {}
            for idx, share in enumerate(key_data["center_shares"], start=1):
                label_map[share.holder] = f"{region_label} 中心份额 #{idx}"
            for branch_share in key_data["branch_shares"]:
                label_map[branch_share.holder] = friendly_branch_label(branch_share.holder)
            key_record = {
                "level": "regional",
                "shares": combined_shares,
                "commitments": key_data["commitments"],
                "n": meta.get("n"),
                "threshold": meta.get("threshold"),
                "region": region,
                "branches": [share.holder for share in key_data["branch_shares"]],
                "label_map": label_map,
                "history": [],
            }
        elif level == "branch":
            branches = data.get("branches") or []
            if not isinstance(branches, list) or len(branches) < 3:
                return (
                    jsonify({"status": "error", "message": "Need at least 3 branches."}),
                    400,
                )
            key_data = hss.create_branch_key(secret_bytes, branches)
            combined_shares = key_data["shares"]
            meta = hss.branch_keys.get(key_data["key_id"], {})
            key_id = key_data["key_id"]
            label_map = {}
            for share in combined_shares:
                label_map[share.holder] = friendly_branch_label(share.holder)
            key_record = {
                "level": "branch",
                "shares": combined_shares,
                "commitments": key_data["commitments"],
                "n": meta.get("n"),
                "threshold": meta.get("threshold"),
                "branches": branches,
                "label_map": label_map,
                "history": [],
            }
        else:
            return jsonify({"status": "error", "message": "Invalid key level specified."}), 400
    except ValueError as exc:
        app.logger.error("Error creating key: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - 捕获意外错误
        app.logger.error("Unexpected error creating key: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Failed to create key."}), 500

    session["keys"][key_id] = key_record
    app.logger.info("Created key of level '%s' with id '%s'.", level, key_id)
    return jsonify(
        {
            "status": "success",
            "key_id": key_id,
            "key_info": build_key_payload(key_id, key_record),
            "polynomial": None,
        }
    )


@app.route("/api/recover_secret", methods=["POST"])
def recover_secret():
    data = request.get_json(silent=True) or {}
    session = get_system()
    if session is None:
        return jsonify({"status": "error", "message": "System not initialized."}), 400

    hss: HierarchicalSecretSharing = session["hss_instance"]
    key_id = data.get("key_id")
    key_data = session["keys"].get(key_id)
    if key_data is None:
        return jsonify({"status": "error", "message": "Key ID not found."}), 404

    provided_shares_data = data.get("shares", [])
    shares_for_recovery = [
        Share(
            id=int(s["id"]),
            value=int(s["value"]),
            holder=s.get("holder", ""),
            level=s.get("level", ""),
            secret_length=s.get("secret_length"),
        )
        for s in provided_shares_data
    ]

    try:
        level = key_data["level"]
        recovered_secret_bytes = hss.cascade_recovery(level, shares_for_recovery)
        return jsonify(
            {
                "status": "success",
                "recovered_secret": recovered_secret_bytes.decode("utf-8", errors="ignore"),
            }
        )
    except ValueError as exc:
        app.logger.error("Error recovering secret: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:  # pragma: no cover
        app.logger.error("Unexpected error recovering secret: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Failed to recover secret."}), 500


@app.route("/api/refresh_shares", methods=["POST"])
def refresh_shares_api():
    data = request.get_json(silent=True) or {}
    session = get_system()
    if session is None:
        return jsonify({"status": "error", "message": "System not initialized."}), 400

    hss: HierarchicalSecretSharing = session["hss_instance"]
    key_id = data.get("key_id")
    key_record = session["keys"].get(key_id)
    if key_record is None:
        return jsonify({"status": "error", "message": "Key ID not found."}), 404

    try:
        level = key_record["level"]
        region = key_record.get("region")
        old_shares = key_record["shares"]
        history_entry = {
            "timestamp": time.time(),
            "shares": snapshot_shares(old_shares),
            "commitments": [int(c) for c in key_record.get("commitments", [])],
        }
        key_record.setdefault("history", []).append(history_entry)
        new_shares = hss.refresh_shares(level, old_shares, key_record.get("n"), key_record.get("threshold"), region=region)

        key_record["shares"] = new_shares
        if level == "master":
            meta = hss.master_key_info or {}
            key_record["commitments"] = meta.get("commitments", [])
            key_record["n"] = meta.get("n")
            key_record["threshold"] = meta.get("threshold")
        elif level == "regional" and region:
            meta = hss.regional_keys.get(region, {})
            key_record["commitments"] = meta.get("commitments", [])
            key_record["n"] = meta.get("n")
            key_record["threshold"] = meta.get("threshold")
        elif level == "branch":
            meta = hss.branch_keys.get(key_id, {})
            key_record["commitments"] = meta.get("commitments", [])
            key_record["n"] = meta.get("n")
            key_record["threshold"] = meta.get("threshold")

        session["keys"][key_id] = key_record

        return jsonify({"status": "success", "new_key_info": build_key_payload(key_id, key_record)})
    except ValueError as exc:
        app.logger.error("Error refreshing shares: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:  # pragma: no cover
        app.logger.error("Unexpected error refreshing shares: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Failed to refresh shares."}), 500


@app.route("/api/get_verification_details", methods=["POST"])
def get_verification_details():
    data = request.get_json(silent=True) or {}
    session = get_system()
    if session is None:
        return jsonify({"status": "error", "message": "System not initialized."}), 400

    hss: HierarchicalSecretSharing = session["hss_instance"]
    key_id = data.get("key_id")
    key_record = session["keys"].get(key_id)
    if key_record is None:
        return jsonify({"status": "error", "message": "Key ID not found."}), 404

    share_data = data.get("share")
    if not share_data:
        return jsonify({"status": "error", "message": "Share data missing."}), 400

    vss = hss.vss
    try:
        share = Share(
            id=int(share_data["id"]),
            value=int(share_data["value"]),
            holder=share_data.get("holder", ""),
            level=share_data.get("level", ""),
        )
    except (TypeError, ValueError, KeyError) as exc:
        return jsonify({"status": "error", "message": f"Invalid share payload: {exc}"}), 400

    commitments = key_record["commitments"]
    is_valid = vss.verify_share(share.id, share.value, commitments)

    lhs = pow(vss.g, share.value, vss.p)
    rhs = 1
    for j, Cj in enumerate(commitments):
        exponent = pow(share.id, j, vss.q)
        rhs = (rhs * pow(Cj, exponent, vss.p)) % vss.p

    return jsonify(
        {
            "status": "success",
            "is_valid": is_valid,
            "lhs": str(lhs),
            "rhs": str(rhs),
        }
    )


def _simulate_tamper_share(hss: HierarchicalSecretSharing, key_id: str, key_record: Dict) -> Dict:
    label_map = key_record.get("label_map") if isinstance(key_record.get("label_map"), dict) else {}
    shares: List[Share] = key_record.get("shares") or []
    report: Dict[str, object] = {
        "title": "伪造份额绕过 Feldman 验证",
        "steps": [],
        "overall_success": False,
    }
    if not shares:
        report["skipped"] = True
        report["skipped_reason"] = "当前密钥没有可操作的份额，无法演示伪造攻击。"
        report["summary"] = report["skipped_reason"]
        return report

    target_share = shares[0]
    modulus = getattr(hss.vss, "q", None) or (hss.vss.prime if hasattr(hss.vss, "prime") else None)
    offset = 1
    if isinstance(modulus, int) and modulus > 1:
        offset = (secrets.randbelow(modulus - 1) + 1) % modulus
        if offset == 0:
            offset = 1
    tampered_value = (target_share.value + offset) % modulus if modulus else target_share.value + offset
    if tampered_value == target_share.value:
        tampered_value += 1
    tampered_share = Share(
        id=target_share.id,
        value=tampered_value,
        holder=target_share.holder,
        level=target_share.level,
        secret_length=target_share.secret_length,
    )

    target_label = resolve_label(target_share, label_map)
    report["steps"].append(
        {
            "name": "构造伪造份额",
            "status": "attempt",
            "detail": f"攻击者截获 {target_label} 的份额后，将份额值从 {target_share.value} 修改为 {tampered_value}。",
        }
    )

    region = key_record.get("region")
    is_valid = hss.verify_share(tampered_share, key_record["level"], region=region)
    report["steps"].append(
        {
            "name": "Feldman 承诺校验",
            "status": "breach" if is_valid else "blocked",
            "detail": "伪造份额仍通过了承诺验证，承诺体系被攻破。" if is_valid else "公开承诺识别出伪造份额，验证失败。",
        }
    )

    recovery_success = False
    recovery_message = ""
    try:
        shares_for_recovery: List[Share] = []
        replaced = False
        for share in shares:
            if share.id == target_share.id and not replaced:
                shares_for_recovery.append(tampered_share)
                replaced = True
            else:
                shares_for_recovery.append(clone_share(share))
        hss.cascade_recovery(key_record["level"], shares_for_recovery)
        recovery_success = True
        recovery_message = "伪造份额仍成功恢复出密钥。"
    except ValueError as exc:
        recovery_message = f"恢复失败：{exc}"
    except Exception as exc:  # pragma: no cover
        recovery_message = f"恢复过程中发生异常：{exc}"

    report["steps"].append(
        {
            "name": "阈值恢复尝试",
            "status": "breach" if recovery_success else "blocked",
            "detail": recovery_message,
        }
    )

    overall_success = is_valid or recovery_success
    report["overall_success"] = overall_success
    if overall_success:
        report["summary"] = "伪造份额绕过了防护，密钥已被攻破。"
    else:
        report["summary"] = "伪造份额被 Feldman 验证与阈值恢复流程阻挡，攻击失败。"

    report["artifacts"] = {
        "target_share": serialize_share(target_share, label_map),
        "tampered_share": serialize_share(tampered_share, label_map),
    }
    return report


def _simulate_insufficient_threshold(hss: HierarchicalSecretSharing, key_id: str, key_record: Dict) -> Dict:
    shares: List[Share] = key_record.get("shares") or []
    threshold = get_threshold(key_record)
    report: Dict[str, object] = {
        "title": "不足阈值尝试恢复秘密",
        "steps": [],
        "overall_success": False,
    }
    if threshold <= 1:
        report["skipped"] = True
        report["skipped_reason"] = "该密钥阈值为 1，无法演示“不足阈值”攻击。"
        report["summary"] = report["skipped_reason"]
        return report
    if len(shares) < threshold:
        report["skipped"] = True
        report["skipped_reason"] = "当前密钥的份额数量不足，无法构造攻击场景。"
        report["summary"] = report["skipped_reason"]
        return report

    subset = [clone_share(share) for share in shares[: threshold - 1]]
    report["steps"].append(
        {
            "name": "收集份额",
            "status": "attempt",
            "detail": f"攻击者仅收集到 {len(subset)}/{threshold} 个份额，故意少于阈值要求。",
        }
    )

    recovery_success = False
    recovery_message = ""
    try:
        hss.cascade_recovery(key_record["level"], subset)
        recovery_success = True
        recovery_message = "意外：少于阈值的份额仍然恢复出密钥。"
    except ValueError as exc:
        recovery_message = f"恢复失败：{exc}"
    except Exception as exc:  # pragma: no cover
        recovery_message = f"恢复过程中发生异常：{exc}"

    report["steps"].append(
        {
            "name": "阈值恢复尝试",
            "status": "breach" if recovery_success else "blocked",
            "detail": recovery_message,
        }
    )
    report["overall_success"] = recovery_success
    if recovery_success:
        report["summary"] = "阈值策略被绕过，密钥遭泄露。"
    else:
        report["summary"] = "不足阈值的份额无法恢复秘密，阈值机制成功阻挡了攻击。"
    return report


def _simulate_cross_level(session_state: Dict, hss: HierarchicalSecretSharing, key_id: str, key_record: Dict) -> Dict:
    shares: List[Share] = key_record.get("shares") or []
    threshold = get_threshold(key_record)
    report: Dict[str, object] = {
        "title": "跨层级滥用份额",
        "steps": [],
        "overall_success": False,
    }
    required_valid = max(1, threshold - 1)
    if len(shares) < required_valid:
        report["skipped"] = True
        report["skipped_reason"] = "当前密钥的有效份额数量不足，无法构造跨层组合。"
        report["summary"] = report["skipped_reason"]
        return report

    foreign_info: Optional[Tuple[str, Dict, Share]] = None
    for other_id, other_record in session_state.get("keys", {}).items():
        if other_id == key_id:
            continue
        if other_record.get("level") == key_record.get("level"):
            continue
        other_shares = other_record.get("shares") or []
        if other_shares:
            foreign_info = (other_id, other_record, other_shares[0])
            break

    if foreign_info is None:
        report["skipped"] = True
        report["skipped_reason"] = "请至少再生成一个不同层级的密钥，以演示跨层攻击。"
        report["summary"] = report["skipped_reason"]
        return report

    _, other_record, foreign_share_obj = foreign_info
    foreign_share = clone_share(foreign_share_obj)
    level_display = {
        "master": "主密钥",
        "regional": "区域密钥",
        "branch": "分行密钥",
    }.get(key_record.get("level"), key_record.get("level", "")) or "目标密钥"
    foreign_level_display = {
        "master": "主密钥",
        "regional": "区域密钥",
        "branch": "分行密钥",
    }.get(other_record.get("level"), other_record.get("level", "")) or "其他层级"

    label_map = key_record.get("label_map") if isinstance(key_record.get("label_map"), dict) else {}
    foreign_label_map = other_record.get("label_map") if isinstance(other_record.get("label_map"), dict) else {}
    foreign_label = resolve_label(foreign_share, foreign_label_map)

    valid_shares: List[Share] = []
    for share in shares:
        if len(valid_shares) >= required_valid:
            break
        valid_shares.append(clone_share(share))

    report["steps"].append(
        {
            "name": "拼接跨层份额",
            "status": "attempt",
            "detail": f"攻击者拿到 {foreign_level_display} 的 {foreign_label} 份额，与 {required_valid} 个合法份额组合，试图解出 {level_display}。",
        }
    )

    attempt_shares = valid_shares + [foreign_share]
    cross_success = False
    cross_message = ""
    try:
        hss.cascade_recovery(key_record["level"], attempt_shares)
        cross_success = True
        cross_message = "跨层份额绕过了层级限制，成功恢复出密钥。"
    except ValueError as exc:
        cross_message = f"恢复失败：{exc}"
    except Exception as exc:  # pragma: no cover
        cross_message = f"恢复过程中发生异常：{exc}"

    report["steps"].append(
        {
            "name": "层级策略校验",
            "status": "breach" if cross_success else "blocked",
            "detail": cross_message if cross_success else f"层级策略阻止了跨层攻击：{cross_message}",
        }
    )
    report["overall_success"] = cross_success
    if cross_success:
        report["summary"] = "跨层份额成功绕过防护，密钥泄露。"
    else:
        report["summary"] = "层级安全策略阻止了跨层份额的滥用，攻击被拦截。"
    report["artifacts"] = {
        "foreign_share": serialize_share(foreign_share, foreign_label_map),
        "used_legit_shares": [serialize_share(s, label_map) for s in valid_shares],
    }
    return report


def _simulate_stale_share(hss: HierarchicalSecretSharing, key_id: str, key_record: Dict) -> Dict:
    history = key_record.get("history") or []
    report: Dict[str, object] = {
        "title": "利用刷新前的过期份额",
        "steps": [],
        "overall_success": False,
    }
    if not history:
        report["skipped"] = True
        report["skipped_reason"] = "尚未刷新过该密钥，请先执行一次份额刷新。"
        report["summary"] = report["skipped_reason"]
        return report

    snapshot = history[-1]
    snapshot_shares = snapshot.get("shares") or []
    if not snapshot_shares:
        report["skipped"] = True
        report["skipped_reason"] = "无法找到刷新前的份额快照。"
        report["summary"] = report["skipped_reason"]
        return report

    stale_share = share_from_snapshot(snapshot_shares[0])
    timestamp = snapshot.get("timestamp")
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)) if timestamp else "未知时间"
    label_map = key_record.get("label_map") if isinstance(key_record.get("label_map"), dict) else {}
    stale_label = resolve_label(stale_share, label_map)
    report["steps"].append(
        {
            "name": "使用过期份额",
            "status": "attempt",
            "detail": f"攻击者窃取刷新前的 {stale_label} 份额（快照时间：{ts_str}），尝试继续使用。",
        }
    )

    region = key_record.get("region")
    is_valid = hss.verify_share(stale_share, key_record["level"], region=region)
    report["steps"].append(
        {
            "name": "Feldman 承诺校验",
            "status": "breach" if is_valid else "blocked",
            "detail": "旧份额依然通过了承诺校验。" if is_valid else "刷新后的公开承诺拒绝了旧份额，验证失败。",
        }
    )

    threshold = get_threshold(key_record)
    new_shares: List[Share] = key_record.get("shares") or []
    companions: List[Share] = []
    needed = max(0, threshold - 1)
    for share in new_shares:
        if share.holder == stale_share.holder:
            continue
        if len(companions) >= needed:
            break
        companions.append(clone_share(share))

    if needed and len(companions) < needed:
        report["skipped"] = True
        report["skipped_reason"] = "当前可用的新份额不足，无法完整模拟攻击。"
        report["summary"] = report["skipped_reason"]
        return report

    attempt_shares = [stale_share] + companions if companions else [stale_share]
    stale_success = False
    stale_message = ""
    try:
        hss.cascade_recovery(key_record["level"], attempt_shares)
        stale_success = True
        stale_message = "旧份额依旧可以恢复密钥。"
    except ValueError as exc:
        stale_message = f"恢复失败：{exc}"
    except Exception as exc:  # pragma: no cover
        stale_message = f"恢复过程中发生异常：{exc}"

    report["steps"].append(
        {
            "name": "阈值恢复尝试",
            "status": "breach" if stale_success else "blocked",
            "detail": stale_message,
        }
    )
    report["overall_success"] = stale_success or is_valid
    if report["overall_success"]:
        report["summary"] = "旧份额未被刷新机制完全作废，攻击成功恢复出密钥。"
    else:
        report["summary"] = "刷新机制使旧份额立即失效，攻击被成功阻断。"
    report["artifacts"] = {
        "stale_share": serialize_share(stale_share, label_map),
        "snapshot_time": ts_str,
    }
    return report


@app.route("/api/simulate_attack", methods=["POST"])
def simulate_attack():
    data = request.get_json(silent=True) or {}
    session = get_system()
    if session is None:
        return jsonify({"status": "error", "message": "System not initialized."}), 400

    attack_type = (data.get("attack_type") or "").strip()
    if not attack_type:
        return jsonify({"status": "error", "message": "attack_type is required."}), 400
    key_id = data.get("key_id")
    if not key_id:
        return jsonify({"status": "error", "message": "key_id is required."}), 400

    key_record = session["keys"].get(key_id)
    if key_record is None:
        return jsonify({"status": "error", "message": "Key ID not found."}), 404

    hss: HierarchicalSecretSharing = session["hss_instance"]
    if attack_type == "tamper_share":
        report = _simulate_tamper_share(hss, key_id, key_record)
    elif attack_type == "insufficient_threshold":
        report = _simulate_insufficient_threshold(hss, key_id, key_record)
    elif attack_type == "cross_level":
        report = _simulate_cross_level(session, hss, key_id, key_record)
    elif attack_type == "stale_share":
        report = _simulate_stale_share(hss, key_id, key_record)
    else:
        return jsonify({"status": "error", "message": f"Unknown attack_type: {attack_type}"}), 400

    report["attack_type"] = attack_type
    report["target_key_id"] = key_id
    return jsonify({"status": "success", "report": report})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
