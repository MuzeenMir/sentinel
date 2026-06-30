"""
SENTINEL Policy Orchestrator Service

Translates AI/DRL policy decisions into vendor-specific firewall rules.
Supports multiple firewall vendors and provides policy validation,
conflict detection, and rollback capabilities.
"""

import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import redis

from policies.policy_engine import PolicyEngine
from policies.rule_generator import RuleGenerator
from vendors.vendor_factory import VendorFactory
from validation.policy_validator import PolicyValidator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth_middleware import require_auth, require_role  # noqa: E402
from tenant_middleware import get_tenant_id, require_tenant  # noqa: E402
from audit_logger import audit_log, AuditCategory  # noqa: E402
from observability import configure_logging  # noqa: E402
from metrics import init_metrics, POLICIES_APPLIED  # noqa: E402
from _lib.net import bind_host  # noqa: E402
from _lib.proposal_sig import NonceGuard, ProposalError  # noqa: E402
from enforcement_actions import EnforcementActionStore  # noqa: E402
from proposal_approval import verify_approved_proposal  # noqa: E402

# Initialize Flask app
app = Flask(__name__)
CORS(app)
configure_logging(service_name="policy-orchestrator")
init_metrics(app, service_name="policy-orchestrator")

# Configuration
app.config["REDIS_URL"] = os.environ.get("REDIS_URL", "redis://localhost:6379")
app.config["POLICY_TTL"] = int(os.environ.get("POLICY_TTL", "3600"))  # 1 hour default
app.config["MAX_RULES_PER_POLICY"] = int(os.environ.get("MAX_RULES_PER_POLICY", "1000"))
app.config["SANDBOX_ENABLED"] = (
    os.environ.get("SANDBOX_ENABLED", "true").lower() == "true"
)
app.config["AUTO_ROLLBACK_THRESHOLD"] = float(
    os.environ.get("AUTO_ROLLBACK_THRESHOLD", "0.05")
)
app.config["USE_V2_REVERSIBLE_ENFORCEMENT"] = (
    os.environ.get("USE_V2_REVERSIBLE_ENFORCEMENT", "false").lower() == "true"
)
app.config["ENFORCEMENT_DEFAULT_TTL_SECONDS"] = int(
    os.environ.get("ENFORCEMENT_DEFAULT_TTL_SECONDS", "900")
)
# A self-protecting node has a single firewall adapter; copilot proposals are
# enforced through it. Configurable so the same path serves other deploy shapes.
app.config["ENFORCEMENT_DEFAULT_VENDOR"] = os.environ.get(
    "ENFORCEMENT_DEFAULT_VENDOR", "iptables"
)

# Initialize Redis
redis_client = redis.from_url(app.config["REDIS_URL"], decode_responses=True)

logger = logging.getLogger(__name__)

# Initialize components
policy_engine = PolicyEngine(redis_client)
rule_generator = RuleGenerator()
vendor_factory = VendorFactory()
policy_validator = PolicyValidator()
enforcement_store = EnforcementActionStore.from_env()


def _enforcement_ttl_seconds(data):
    raw = (
        data.get("enforcement_ttl_seconds")
        or data.get("ttl_seconds")
        or app.config["ENFORCEMENT_DEFAULT_TTL_SECONDS"]
    )
    return max(1, int(raw))


def _record_reversible_enforcement(policy, vendor_name, rules, apply_result, data):
    if not app.config["USE_V2_REVERSIBLE_ENFORCEMENT"]:
        return None

    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=_enforcement_ttl_seconds(data)
    )
    record = enforcement_store.create_active_record(
        policy_id=policy["id"],
        vendor_name=vendor_name,
        rules=rules,
        apply_result=apply_result,
        expires_at=expires_at,
        tenant_id=get_tenant_id(),
    )
    audit_log(
        AuditCategory.POLICY,
        "enforcement_applied",
        tenant_id=get_tenant_id(),
        detail={
            "action_id": record["action_id"],
            "policy_id": policy["id"],
            "vendor": vendor_name,
            "expires_at": expires_at.isoformat(),
            "rollback_state": "active",
        },
    )
    return record


# How a copilot's advisory action_type maps to a concrete firewall action.
# On a single self-protecting host, "quarantine" == cut the entity off the box,
# which the firewall expresses as a full DENY.
_PROPOSAL_ACTION_MAP = {
    "block": "DENY",
    "quarantine": "DENY",
    "rate_limit": "RATE_LIMIT",
}


def _rules_from_proposal(proposal):
    """Translate a verified proposal into canonical firewall rules.

    A proposal is entity-centric (``entity_id`` + ``action_type``); the firewall
    adapter acts on network identifiers, so ``entity_id`` must be an IP/CIDR.
    Raises ``ValueError`` if the action_type is unsupported or the entity is not
    an enforceable network identifier (the caller turns that into a 4xx and
    enforces nothing).
    """
    action = _PROPOSAL_ACTION_MAP.get(proposal.get("action_type"))
    if action is None:
        raise ValueError(f"unsupported action_type: {proposal.get('action_type')!r}")
    return rule_generator.generate(
        {
            "name": f"copilot-{proposal.get('proposal_id', 'proposal')}",
            "action": action,
            "source": {"ip": proposal.get("entity_id")},
        }
    )


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "policy_engine": policy_engine.is_ready(),
                "validator": policy_validator.is_ready(),
                "vendors": vendor_factory.get_available_vendors(),
            },
        }
    ), 200


@app.route("/api/v1/policies", methods=["GET"])
@require_auth
@require_tenant
def get_policies():
    """Get all active policies."""
    try:
        policies = policy_engine.get_all_policies()
        return jsonify({"policies": policies, "total": len(policies)}), 200
    except Exception as e:
        logger.error(f"Get policies error: {e}")
        return jsonify({"error": "Failed to retrieve policies"}), 500


@app.route("/api/v1/policies/<policy_id>", methods=["GET"])
@require_auth
@require_tenant
def get_policy(policy_id):
    """Get specific policy details."""
    try:
        policy = policy_engine.get_policy(policy_id)
        if not policy:
            return jsonify({"error": "Policy not found"}), 404
        return jsonify(policy), 200
    except Exception as e:
        logger.error(f"Get policy error: {e}")
        return jsonify({"error": "Failed to retrieve policy"}), 500


@app.route("/api/v1/policies", methods=["POST"])
@require_auth
@require_role("admin")
def create_policy():
    """
    Create a new firewall policy.

    Request body:
    {
        "name": "Block suspicious IPs",
        "description": "Block traffic from detected malicious sources",
        "action": "DENY",
        "source": {"ip": "192.168.1.100", "cidr": "/32"},
        "destination": {"port": 22},
        "protocol": "TCP",
        "priority": 100,
        "duration": 3600,  # seconds, optional
        "vendors": ["iptables", "aws_security_group"]
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Validate required fields
        required = ["name", "action"]
        for field in required:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Generate rules from policy
        rules = rule_generator.generate(data)

        # Validate policy
        validation_result = policy_validator.validate(rules)
        if not validation_result["valid"]:
            return jsonify(
                {
                    "error": "Policy validation failed",
                    "issues": validation_result["issues"],
                }
            ), 400

        # Check for conflicts
        conflicts = policy_engine.check_conflicts(rules)
        if conflicts and not data.get("force", False):
            return jsonify(
                {
                    "error": "Policy conflicts detected",
                    "conflicts": conflicts,
                    "hint": "Use force=true to override",
                }
            ), 409

        # Audit BEFORE policy persistence and vendor side effects (T-031
        # audit-then-act ordering). If audit fails the policy is never created
        # and no firewall rule is pushed downstream.
        audit_log(
            AuditCategory.POLICY,
            "policy_created",
            detail={"name": data.get("name"), "action": data.get("action")},
        )

        # Create policy
        policy = policy_engine.create_policy(data, rules)

        # Apply to vendors if specified
        vendors = data.get("vendors", [])
        if vendors:
            apply_results = []
            for vendor_name in vendors:
                try:
                    vendor = vendor_factory.get_vendor(vendor_name)
                    if vendor:
                        result = vendor.apply_rules(rules)
                        result_entry = {
                            "vendor": vendor_name,
                            "success": result["success"],
                            "message": result.get("message"),
                        }
                        if result.get("success"):
                            record = _record_reversible_enforcement(
                                policy,
                                vendor_name,
                                rules,
                                result,
                                data,
                            )
                            if record:
                                result_entry["enforcement_action_id"] = record[
                                    "action_id"
                                ]
                                result_entry["expires_at"] = record[
                                    "expires_at"
                                ].isoformat()
                        apply_results.append(result_entry)
                except Exception as e:
                    apply_results.append(
                        {"vendor": vendor_name, "success": False, "message": str(e)}
                    )

            policy["apply_results"] = apply_results

        POLICIES_APPLIED.labels(action=data.get("action", "unknown")).inc()
        return jsonify(
            {"message": "Policy created successfully", "policy": policy}
        ), 201

    except Exception as e:
        logger.error(f"Create policy error: {e}")
        return jsonify({"error": "Failed to create policy"}), 500


@app.route("/api/v1/policies/<policy_id>", methods=["PUT"])
@require_auth
@require_role("admin")
def update_policy(policy_id):
    """Update an existing policy."""
    try:
        data = request.get_json()

        existing = policy_engine.get_policy(policy_id)
        if not existing:
            return jsonify({"error": "Policy not found"}), 404

        # Merge with existing
        updated_data = {**existing, **data, "id": policy_id}

        # Regenerate rules
        rules = rule_generator.generate(updated_data)

        # Validate
        validation_result = policy_validator.validate(rules)
        if not validation_result["valid"]:
            return jsonify(
                {
                    "error": "Policy validation failed",
                    "issues": validation_result["issues"],
                }
            ), 400

        # Update policy
        policy = policy_engine.update_policy(policy_id, updated_data, rules)

        return jsonify(
            {"message": "Policy updated successfully", "policy": policy}
        ), 200

    except Exception as e:
        logger.error(f"Update policy error: {e}")
        return jsonify({"error": "Failed to update policy"}), 500


@app.route("/api/v1/policies/<policy_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_policy(policy_id):
    """Delete a policy."""
    try:
        existing = policy_engine.get_policy(policy_id)
        if not existing:
            return jsonify({"error": "Policy not found"}), 404

        # Remove from vendors
        vendors = existing.get("vendors", [])
        for vendor_name in vendors:
            try:
                vendor = vendor_factory.get_vendor(vendor_name)
                if vendor:
                    vendor.remove_rules(existing.get("rules", []))
            except Exception as e:
                logger.warning(f"Failed to remove rules from {vendor_name}: {e}")

        # Delete policy
        policy_engine.delete_policy(policy_id)

        return jsonify({"message": "Policy deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Delete policy error: {e}")
        return jsonify({"error": "Failed to delete policy"}), 500


@app.route("/api/v1/policies/apply", methods=["POST"])
@require_auth
@require_role("admin")
def apply_drl_decision():
    """
    Apply a DRL policy decision.

    Request body:
    {
        "decision_id": "drl_12345",
        "action": "DENY",
        "target": {
            "source_ip": "192.168.1.100",
            "source_cidr": "/32",
            "dest_port": 22,
            "protocol": "TCP"
        },
        "duration": 3600,
        "confidence": 0.95,
        "threat_type": "brute_force",
        "vendors": ["iptables"]
    }
    """
    try:
        data = request.get_json()

        if not data or "action" not in data or "target" not in data:
            return jsonify({"error": "action and target are required"}), 400

        # Shadow-mode guard: refuse to enforce decisions explicitly tagged shadow=true
        # by the DRL engine. Caller must promote out of shadow before enforcement.
        if data.get("shadow") is True or data.get("enforce") is False:
            logger.info(
                "Refusing to enforce shadow DRL decision %s (action=%s)",
                data.get("decision_id"),
                data["action"],
            )
            return jsonify(
                {
                    "message": "shadow decision logged, not enforced",
                    "shadow": True,
                    "decision_id": data.get("decision_id"),
                    "action": data["action"],
                }
            ), 202

        # Convert DRL decision to policy
        policy_data = {
            "name": f"DRL Decision {data.get('decision_id', 'unknown')}",
            "description": f"Auto-generated from DRL decision for {data.get('threat_type', 'unknown')}",
            "action": data["action"],
            "source": {
                "ip": data["target"].get("source_ip"),
                "cidr": data["target"].get("source_cidr", "/32"),
            },
            "destination": {"port": data["target"].get("dest_port")},
            "protocol": data["target"].get("protocol", "any"),
            "priority": 50,  # High priority for automated decisions
            "duration": data.get("duration", 3600),
            "vendors": data.get("vendors", []),
            "metadata": {
                "drl_decision_id": data.get("decision_id"),
                "confidence": data.get("confidence"),
                "threat_type": data.get("threat_type"),
                "automated": True,
            },
        }

        # Generate and validate rules
        rules = rule_generator.generate(policy_data)

        validation_result = policy_validator.validate(rules)
        if not validation_result["valid"]:
            return jsonify(
                {
                    "error": "DRL decision validation failed",
                    "issues": validation_result["issues"],
                }
            ), 400

        # Apply in sandbox mode first if enabled
        if app.config["SANDBOX_ENABLED"]:
            sandbox_result = policy_engine.test_in_sandbox(rules)
            if not sandbox_result["success"]:
                return jsonify(
                    {"error": "Sandbox test failed", "details": sandbox_result}
                ), 400

        # Create and apply policy
        policy = policy_engine.create_policy(policy_data, rules)

        # Apply to vendors
        apply_results = []
        for vendor_name in data.get("vendors", []):
            vendor = vendor_factory.get_vendor(vendor_name)
            if vendor:
                result = vendor.apply_rules(rules)
                result_entry = {
                    "vendor": vendor_name,
                    "success": result["success"],
                    "rules_applied": len(rules),
                }
                if result.get("success"):
                    record = _record_reversible_enforcement(
                        policy,
                        vendor_name,
                        rules,
                        result,
                        data,
                    )
                    if record:
                        result_entry["enforcement_action_id"] = record["action_id"]
                        result_entry["expires_at"] = record["expires_at"].isoformat()
                apply_results.append(result_entry)

        return jsonify(
            {
                "message": "DRL decision applied successfully",
                "policy_id": policy["id"],
                "rules_generated": len(rules),
                "apply_results": apply_results,
            }
        ), 201

    except Exception as e:
        logger.error(f"Apply DRL decision error: {e}")
        return jsonify({"error": "Failed to apply DRL decision"}), 500


@app.route("/api/v1/policies/<policy_id>/rollback", methods=["POST"])
@require_auth
@require_role("admin")
def rollback_policy(policy_id):
    """Rollback a policy to previous version."""
    try:
        result = policy_engine.rollback_policy(policy_id)

        if not result["success"]:
            return jsonify(
                {"error": "Rollback failed", "message": result.get("message")}
            ), 400

        return jsonify(
            {
                "message": "Policy rolled back successfully",
                "previous_version": result.get("previous_version"),
                "current_version": result.get("current_version"),
            }
        ), 200

    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return jsonify({"error": "Failed to rollback policy"}), 500


@app.route("/api/v1/enforcement-actions/<action_id>/confirm", methods=["POST"])
@require_role("admin")
def confirm_enforcement_action(action_id):
    """Confirm a TTL-bound enforcement action as permanent."""
    try:
        record = enforcement_store.confirm_permanent(
            action_id,
            tenant_id=get_tenant_id(),
        )
        if not record:
            return jsonify({"error": "Enforcement action not found"}), 404

        audit_log(
            AuditCategory.POLICY,
            "enforcement_confirmed",
            tenant_id=get_tenant_id(),
            detail={
                "action_id": action_id,
                "rollback_state": "confirmed",
                "confirmed_permanent": True,
            },
        )

        return jsonify(
            {
                "message": "Enforcement action confirmed permanent",
                "enforcement_action": record,
            }
        ), 200

    except Exception as e:
        logger.error(f"Confirm enforcement action error: {e}")
        return jsonify({"error": "Failed to confirm enforcement action"}), 500


@app.route("/enforcement", methods=["POST"])
@require_role("admin")
def enforce_proposal():
    """Enforce a copilot proposal after verified HUMAN approval.

    This is the ONLY path from an advisory, signed proposal to a live firewall
    action, and where the project's #1 hard constraint lives in code: no LLM
    output reaches an adapter; an authenticated human admin approves; the
    proposal is cryptographically verified (authentic, unexpired, single-use);
    and the resulting action is TTL-bound and auto-reverted by the reaper.

    The approver is the AUTHENTICATED admin identity, never a body field -- the
    copilot has no admin session, so it cannot self-approve. Every verification
    failure (forgery, replay, expiry, missing human) fails closed: no rule is
    applied and no record is created. This route is intentionally always
    reversible (it records regardless of USE_V2_REVERSIBLE_ENFORCEMENT) because a
    proposal that advertises a TTL must actually be revertible.

    Request body: ``{"proposal": {<signed proposal from the copilot>}}``
    """
    try:
        data = request.get_json(silent=True) or {}
        proposal = data.get("proposal")
        if not isinstance(proposal, dict):
            return jsonify({"error": "proposal object required"}), 400

        approver = (getattr(g, "current_user", {}) or {}).get("username")
        if not approver:
            return jsonify({"error": "authenticated approver required"}), 403

        # Verify authenticity + freshness + single-use AND a human approver.
        # Raises before any enforcement; ApprovalError subclasses ProposalError.
        try:
            approval = verify_approved_proposal(
                proposal,
                approver=approver,
                nonce_guard=NonceGuard(redis_client),
            )
        except ProposalError as exc:
            logger.warning("Refusing enforcement: %s", exc)
            return jsonify({"error": str(exc), "enforced": False}), 403

        # Verified + human-approved -> translate to firewall rules. A proposal
        # that can't be expressed as a network rule fails closed (not silently
        # mis-enforced).
        try:
            rules = _rules_from_proposal(proposal)
        except ValueError as exc:
            logger.warning("Approved proposal is not enforceable: %s", exc)
            return jsonify({"error": str(exc), "enforced": False}), 422

        vendor_name = app.config["ENFORCEMENT_DEFAULT_VENDOR"]
        vendor = vendor_factory.get_vendor(vendor_name)
        if vendor is None:
            return jsonify({"error": f"Unknown vendor: {vendor_name}"}), 500

        apply_result = vendor.apply_rules(rules)
        if not apply_result.get("success"):
            # The adapter didn't apply anything, so there is nothing to make
            # reversible -- fail closed without a dangling record.
            logger.error(
                "Enforcement adapter %s failed for %s: %s",
                vendor_name,
                proposal.get("proposal_id"),
                apply_result,
            )
            return jsonify(
                {"error": "enforcement adapter failed", "details": apply_result}
            ), 502

        # Record the reversible contract so the reaper rolls it back at TTL.
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=_enforcement_ttl_seconds(proposal)
        )
        try:
            record = enforcement_store.create_active_record(
                policy_id=proposal["proposal_id"],
                vendor_name=vendor_name,
                rules=rules,
                apply_result=apply_result,
                expires_at=expires_at,
                tenant_id=get_tenant_id(),
            )
        except Exception as exc:
            # The rule is applied but its reversible record didn't persist, so
            # the reaper would never roll it back. Compensate immediately --
            # remove the just-applied rule rather than leave an un-revertible
            # enforcement change. Best-effort; a failed rollback is logged loudly.
            logger.error(
                "Failed to record enforcement for %s; rolling back applied rule: %s",
                proposal.get("proposal_id"),
                exc,
            )
            try:
                vendor.remove_rules(rules)
            except Exception:
                logger.exception(
                    "Compensating rollback FAILED for %s -- manual review required",
                    proposal.get("proposal_id"),
                )
            return jsonify({"error": "Failed to record enforcement"}), 500

        audit_log(
            AuditCategory.POLICY,
            "enforcement_applied",
            tenant_id=get_tenant_id(),
            detail={
                "action_id": record["action_id"],
                "proposal_id": proposal["proposal_id"],
                "approver": approval["approver"],
                "entity_id": proposal.get("entity_id"),
                "action_type": proposal.get("action_type"),
                "vendor": vendor_name,
                "expires_at": expires_at.isoformat(),
                "rollback_state": "active",
                "source": "copilot_proposal",
            },
        )

        return jsonify(
            {
                "message": "Proposal enforced (reversible, TTL-bound)",
                "enforcement_action": {
                    "action_id": record["action_id"],
                    "proposal_id": proposal["proposal_id"],
                    "approver": approval["approver"],
                    "entity_id": proposal.get("entity_id"),
                    "action_type": proposal.get("action_type"),
                    "expires_at": expires_at.isoformat(),
                    "rollback_state": "active",
                },
            }
        ), 201

    except Exception as exc:
        logger.error("Enforce proposal error: %s", exc)
        return jsonify({"error": "Failed to enforce proposal"}), 500


@app.route("/api/v1/rules/translate", methods=["POST"])
@require_auth
@require_tenant
def translate_rules():
    """
    Translate generic rules to vendor-specific format.

    Request body:
    {
        "rules": [...],
        "target_vendor": "iptables"
    }
    """
    try:
        data = request.get_json()

        rules = data.get("rules", [])
        target_vendor = data.get("target_vendor")

        if not rules or not target_vendor:
            return jsonify({"error": "rules and target_vendor are required"}), 400

        vendor = vendor_factory.get_vendor(target_vendor)
        if not vendor:
            return jsonify({"error": f"Unknown vendor: {target_vendor}"}), 400

        translated = vendor.translate_rules(rules)

        return jsonify(
            {
                "vendor": target_vendor,
                "translated_rules": translated,
                "count": len(translated),
            }
        ), 200

    except Exception as e:
        logger.error(f"Rule translation error: {e}")
        return jsonify({"error": "Failed to translate rules"}), 500


@app.route("/api/v1/vendors", methods=["GET"])
@require_auth
@require_tenant
def get_vendors():
    """Get available firewall vendors."""
    return jsonify({"vendors": vendor_factory.get_available_vendors()}), 200


@app.route("/api/v1/vendors/<vendor_name>/status", methods=["GET"])
@require_auth
@require_tenant
def get_vendor_status(vendor_name):
    """Get vendor connection status."""
    try:
        vendor = vendor_factory.get_vendor(vendor_name)
        if not vendor:
            return jsonify({"error": f"Unknown vendor: {vendor_name}"}), 404

        status = vendor.get_status()
        return jsonify(status), 200

    except Exception as e:
        logger.error(f"Vendor status error: {e}")
        return jsonify({"error": "Failed to get vendor status"}), 500


@app.route("/api/v1/validate", methods=["POST"])
@require_auth
@require_tenant
def validate_policy():
    """Validate a policy without applying it."""
    try:
        data = request.get_json()

        rules = rule_generator.generate(data)
        validation_result = policy_validator.validate(rules)
        conflicts = policy_engine.check_conflicts(rules)

        return jsonify(
            {
                "valid": validation_result["valid"] and not conflicts,
                "validation": validation_result,
                "conflicts": conflicts,
                "rules_preview": rules,
            }
        ), 200

    except Exception as e:
        logger.error(f"Validation error: {e}")
        return jsonify({"error": "Validation failed"}), 500


@app.route("/api/v1/statistics", methods=["GET"])
@require_auth
@require_tenant
def get_statistics():
    """Get policy orchestrator statistics."""
    try:
        stats = policy_engine.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        return jsonify({"error": "Failed to get statistics"}), 500


@app.route("/api/v1/policies/auto-apply", methods=["POST"])
@require_auth
@require_role("admin")
@require_tenant
def auto_apply_policy():
    """
    Apply a policy decision emitted by the DRL engine / Flink feed job.

    SECURITY (audit SEC-04 / Wave B3): this endpoint writes firewall rules, so
    it is admin-gated like every other mutating policy route — it previously
    required only authentication, letting any authenticated principal (e.g. a
    viewer or analyst) write enforcement rules, which weakened the
    "write actions require human approval" invariant. DRL is demoted/de-wired,
    so there is no live automated caller today. If the drl_feed_job is ever
    re-wired, its service identity must present an admin role OR be re-routed
    through the human-confirmed propose→approve→enforce path (see the
    enforcement-actions confirm flow), not bypass RBAC here.

    Request body:
    {
        "name": "auto-deny-192.168.1.100-...",
        "action": "DENY" | "RATE_LIMIT" | "MONITOR" | "ALLOW",
        "source": {"ip": "192.168.1.100", "cidr": "/32"},
        "priority": 50,
        "duration": 1800,
        "auto_applied": true,
        "drl_decision": {...}
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        required = ["name", "action"]
        for field in required:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        rules = rule_generator.generate(data)
        validation_result = policy_validator.validate(rules)
        if not validation_result["valid"]:
            return jsonify(
                {
                    "error": "Policy validation failed",
                    "issues": validation_result["issues"],
                }
            ), 400

        policy_id = policy_engine.create_policy(
            data,
            rules=rules,
            auto_applied=True,
            source="drl-engine",
        )

        logger.info(
            "Auto-applied policy: id=%s action=%s source=%s",
            policy_id,
            data.get("action"),
            data.get("source", {}).get("ip", "n/a"),
        )

        audit_log(
            AuditCategory.POLICY,
            "policy_auto_applied",
            tenant_id=get_tenant_id(),
            detail={
                "policy_id": policy_id,
                "action": data.get("action"),
                "source_ip": data.get("source", {}).get("ip", "n/a"),
                "actor": getattr(g, "current_user", {}).get("username"),
            },
        )

        return jsonify(
            {
                "policy_id": policy_id,
                "status": "applied",
                "action": data.get("action"),
                "auto_applied": True,
            }
        ), 201

    except Exception as e:
        logger.error(f"Auto-apply policy error: {e}")
        return jsonify({"error": "Failed to auto-apply policy"}), 500


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(
        host=bind_host(),
        port=int(os.environ.get("PORT", 5004)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
