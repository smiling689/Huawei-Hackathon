import math
import os
from typing import Dict, List, Optional

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
