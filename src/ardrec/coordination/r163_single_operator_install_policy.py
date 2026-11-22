"""R163: signed single-operator installation policy, source-only.

This verifies a candidate development authorization and its revocation.
It does NOT authorize a root installation by itself. Trust-anchor provenance,
privileged deployment and B4/B9 operational releases require separate gates.
"""
from __future__ import annotations

from datetime import datetime
import re

from . import r146_independent_install as crypto

SCHEMA = "ARDREC-R163-SINGLE-OPERATOR-INSTALL-POLICY-v1"
TRUST_SCHEMA = SCHEMA + "-trust"
AUTH_SCHEMA = SCHEMA + "-authorization"
REV_SCHEMA = SCHEMA + "-revocation"
AUTH_PREFIX = (AUTH_SCHEMA + "\x00").encode("ascii")
REV_PREFIX = (REV_SCHEMA + "\x00").encode("ascii")

Refusal = crypto.Refusal
need = crypto.need
sha = crypto.sha
canonical = crypto.canonical

AUTH_FIELDS = frozenset({
    "schema", "session", "head", "tree", "boot_id",
    "operator_uid", "operator_id", "custody_mode",
    "independent_authority", "claims_verified_signer_independence",
    "source_b4_sha256", "source_b9_sha256",
    "inventory_sha256", "agent_bundle_sha256",
    "action", "destinations", "valid_from", "valid_until",
    "one_shot", "network_traffic_authorized",
    "vm_start_authorized", "automatic_execution_authorized",
    "grants_root_privileges", "root_authority_bootstrap_required", "p8",
})

REV_FIELDS = frozenset({
    "schema", "session", "authorization_sha256",
    "issued_at", "valid_until", "revoked", "reason_code",
})


def validate(*, trust_raw, authorization_raw, revocation_raw,
             head, tree, boot_id, inventory_sha256,
             agent_bundle_sha256, operator_uid, operator_id, now):
    """Validate signed scope, custody and freshness without host mutation."""
    now = crypto.current(now)

    need(type(operator_uid) is int and operator_uid > 0,
         "OPERATOR_UID_INVALID")
    need(type(operator_id) is str and
         re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", operator_id),
         "OPERATOR_ID_INVALID")

    trust = crypto.parse(trust_raw, 8192)
    need(set(trust) == {
        "schema", "authorization_signer", "revocation_signer"
    } and trust["schema"] == TRUST_SCHEMA,
         "TRUST_SCHEMA_INVALID")

    auth_signer = trust["authorization_signer"]
    rev_signer = trust["revocation_signer"]
    auth_pem = crypto.signer(auth_signer)
    rev_pem = crypto.signer(rev_signer)

    need(auth_signer["key_id"] != rev_signer["key_id"] and
         sha(auth_pem) != sha(rev_pem),
         "SIGNING_KEYS_NOT_DISTINCT")

    authorization = crypto.parse(authorization_raw, 16384)
    claim = crypto.signed(
        authorization, auth_signer, AUTH_PREFIX
    )

    need(set(claim) == AUTH_FIELDS, "AUTHORIZATION_FIELDS_INVALID")

    expected_scope = {
        "schema": AUTH_SCHEMA,
        "head": head,
        "tree": tree,
        "boot_id": boot_id,
        "operator_uid": operator_uid,
        "operator_id": operator_id,
        "custody_mode": "SINGLE_HUMAN_OPERATOR",
        "independent_authority": False,
        "claims_verified_signer_independence": False,
        "source_b4_sha256": crypto.B4_SHA,
        "source_b9_sha256": crypto.B9_SHA,
        "inventory_sha256": inventory_sha256,
        "agent_bundle_sha256": agent_bundle_sha256,
        "action": "INSTALL_B4_B9_ONLY",
        "destinations": list(crypto.DESTINATIONS),
        "one_shot": True,
        "network_traffic_authorized": False,
        "vm_start_authorized": False,
        "automatic_execution_authorized": False,
        "grants_root_privileges": False,
        "root_authority_bootstrap_required": True,
        "p8": "NO-GO",
    }

    need(all(claim.get(k) == v for k, v in expected_scope.items()),
         "AUTHORIZATION_SCOPE_INVALID")

    need(type(claim["session"]) is str and
         crypto.SESSION.fullmatch(claim["session"]),
         "SESSION_INVALID")

    need(type(head) is str and crypto.HEX40.fullmatch(head) and
         type(tree) is str and crypto.HEX40.fullmatch(tree) and
         type(boot_id) is str and crypto.BOOT.fullmatch(boot_id) and
         type(inventory_sha256) is str and
         crypto.HEX64.fullmatch(inventory_sha256) and
         type(agent_bundle_sha256) is str and
         crypto.HEX64.fullmatch(agent_bundle_sha256),
         "IDENTITY_INVALID")

    start = crypto.instant(claim["valid_from"])
    end = crypto.instant(claim["valid_until"])

    need(start < end and
         (end-start).total_seconds() <= 600 and
         start <= now < end and
         (end-now).total_seconds() >= 5,
         "AUTHORIZATION_WINDOW_INVALID")

    revocation = crypto.parse(revocation_raw, 16384)
    rev = crypto.signed(revocation, rev_signer, REV_PREFIX)

    need(set(rev) == REV_FIELDS, "REVOCATION_FIELDS_INVALID")

    need(rev["schema"] == REV_SCHEMA and
         rev["session"] == claim["session"] and
         rev["authorization_sha256"] == sha(authorization_raw) and
         rev["revoked"] is False and
         type(rev["reason_code"]) is str,
         "REVOKED_OR_UNBOUND")

    issued = crypto.instant(rev["issued_at"])
    expires = crypto.instant(rev["valid_until"])

    need(issued <= now < expires and
         0 <= (now-issued).total_seconds() <= 30,
         "REVOCATION_NOT_FRESH")

    return {
        "schema": SCHEMA + "-checked",
        "session": claim["session"],
        "head": head,
        "tree": tree,
        "boot_id": boot_id,
        "operator_uid": operator_uid,
        "operator_id": operator_id,
        "custody_mode": "SINGLE_HUMAN_OPERATOR",
        "authorization_sha256": sha(authorization_raw),
        "revocation_sha256": sha(revocation_raw),
        "inventory_sha256": inventory_sha256,
        "agent_bundle_sha256": agent_bundle_sha256,
        "signature_cryptographically_verified": True,
        "human_independence_verified": False,
        "trust_anchor_provenance_verified": False,
        "root_install_authorized": False,
        "network_traffic_authorized": False,
        "p8": "NO-GO",
    }
