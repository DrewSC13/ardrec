"""R237: signed prospective local scope review.

Reuses R146 Ed25519 verification and R205 plan validation.
Separate signing keys do not imply independent human operators.

This is a documentary contract verifier, not an installed
authority, dispatch authorization or experimental admission.
"""

import base64

from ardrec.coordination import (
    r146_independent_install as crypto,
    prospective_local_pilot as durable,
)

from ardrec.experiments import (
    prospective_attempt_journal as journal,
)

SCHEMA = "ARDREC-R237-SIGNED-PROSPECTIVE-SCOPE-v1"
TRUST_SCHEMA = SCHEMA + "-trust"
AUTH_SCHEMA = SCHEMA + "-authorization"
REV_SCHEMA = SCHEMA + "-revocation"

AUTH_PREFIX = (AUTH_SCHEMA + "\x00").encode("ascii")
REV_PREFIX = (REV_SCHEMA + "\x00").encode("ascii")

MAX_REVOCATION_TTL = 60

canonical = crypto.canonical
sha = crypto.sha


def need(value, reason):

    if not value:
        raise ValueError(reason)


def public_identity(signer):

    pem = crypto.signer(signer)
    lines = pem.splitlines()

    need(
        len(lines) == 3,
        "NONCANONICAL_PUBLIC_KEY",
    )

    raw = base64.b64decode(
        lines[1],
        validate=True,
    )

    # Canonical Ed25519 SubjectPublicKeyInfo:
    # fixed ASN.1 header followed by 32 public-key bytes.

    need(
        len(raw) == 44
        and raw.startswith(bytes.fromhex(
            "302a300506032b6570032100"
        ))
        and base64.b64encode(raw) == lines[1],
        "ED25519_PUBLIC_KEY_REQUIRED",
    )

    return sha(raw)


def authorization_statement(plan):

    journal.verify_plan(plan)

    return {
        "schema": AUTH_SCHEMA,
        "plan_sha256": plan["sha256"],
        "code_head": plan["code_head"],
        "code_tree": plan["code_tree"],
        "operator_uid": plan["operator_uid"],
        "protocol": plan["protocol"],
        "operation": plan["operation"],
        "destination": "127.0.0.1",
        "scope": "LOCAL_ISOLATED_SOFTWARE_FIXTURE_ONLY",
        "valid_from": plan["created_at"],
        "valid_until": plan["expires_at"],
        "maximum_attempts": 1,
        "human_operator_count": 1,
        "human_independence_claimed": False,
        "historical_authority_granted": False,
        "privileged_execution_authorized": False,
        "operational_activation": False,
        "experimental_admission": False,
        "p8": "NO-GO",
    }


def review(
    *,
    plan,
    trust_raw,
    authorization_raw,
    revocation_raw,
    expected_trust_sha256,
    expected_plan_sha256,
    minimum_revocation_sequence,
    now,
):

    journal.verify_plan(plan)

    need(
        journal.valid_hex(expected_plan_sha256, 64)
        and plan["sha256"] == expected_plan_sha256,
        "PLAN_ANCHOR_MISMATCH",
    )

    need(
        journal.valid_hex(expected_trust_sha256, 64)
        and sha(trust_raw) == expected_trust_sha256,
        "TRUST_ANCHOR_MISMATCH",
    )

    need(
        type(now) is int
        and plan["created_at"] <= now < plan["expires_at"],
        "PLAN_NOT_CURRENT",
    )

    need(
        type(minimum_revocation_sequence) is int
        and 1 <= minimum_revocation_sequence < 2**63,
        "REVOCATION_FLOOR_INVALID",
    )

    trust = crypto.parse(trust_raw, 8192)

    need(
        set(trust) == {
            "schema",
            "authorization_signer",
            "revocation_signer",
        }
        and trust["schema"] == TRUST_SCHEMA,
        "TRUST_SCHEMA_INVALID",
    )

    auth_key = trust["authorization_signer"]
    rev_key = trust["revocation_signer"]

    need(
        public_identity(auth_key) != public_identity(rev_key)
        and auth_key["key_id"] != rev_key["key_id"],
        "SIGNING_KEYS_NOT_DISTINCT",
    )

    authorization = crypto.signed(
        crypto.parse(authorization_raw, 16384),
        auth_key,
        AUTH_PREFIX,
    )

    need(
        canonical(authorization)
            == canonical(authorization_statement(plan)),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )

    revocation = crypto.signed(
        crypto.parse(revocation_raw, 16384),
        rev_key,
        REV_PREFIX,
    )

    need(
        set(revocation) == {
            "schema",
            "authorization_sha256",
            "plan_sha256",
            "sequence",
            "issued_at",
            "valid_until",
            "revoked",
            "reason",
        }
        and revocation["schema"] == REV_SCHEMA,
        "REVOCATION_SCHEMA_INVALID",
    )

    need(
        revocation["authorization_sha256"]
            == sha(authorization_raw)
        and revocation["plan_sha256"]
            == plan["sha256"],
        "REVOCATION_BINDING_INVALID",
    )

    sequence = revocation["sequence"]
    issued = revocation["issued_at"]
    expires = revocation["valid_until"]

    need(
        type(sequence) is int
        and minimum_revocation_sequence
            <= sequence < 2**63,
        "REVOCATION_ROLLBACK",
    )

    need(
        type(issued) is int
        and type(expires) is int
        and plan["created_at"] <= issued <= now < expires
        and expires <= plan["expires_at"]
        and 0 < expires - issued <= MAX_REVOCATION_TTL,
        "REVOCATION_NOT_CURRENT",
    )

    need(
        revocation["revoked"] is False
        and revocation["reason"] == "ACTIVE",
        "AUTHORIZATION_REVOKED",
    )

    return durable.seal({
        "schema": SCHEMA,
        "plan_sha256": plan["sha256"],
        "trust_sha256": expected_trust_sha256,
        "authorization_sha256": sha(authorization_raw),
        "revocation_sha256": sha(revocation_raw),
        "revocation_sequence": sequence,
        "verified_at": now,
        "valid_until": expires,
        "cryptographic_signatures_verified": True,
        "documentary_scope_verified": True,
        "human_operator_count": 1,
        "human_independence_verified": False,
        "trust_provenance_attested": False,
        "durable_revocation_floor_attested": False,
        "runtime_installed": False,
        "operational_authorization": False,
        "operational_dispatch": False,
        "historical_authority_granted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "a9_generation": None,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })
