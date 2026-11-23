"""R163-F3: phased signed-policy review without privileged authority.

Reviews a signed R163 authorization and newly supplied signed revocation
before every phase. The SHA-256 receipt chain is an in-memory audit of
checks, NOT an authenticated durable root journal or install permit.
No filesystem mutation, VM, FTP, network or root operation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from . import r163_single_operator_install_policy as policy

crypto = policy.crypto
Refusal = policy.Refusal
need = policy.need

SCHEMA = "ARDREC-R163-PHASE-REVIEW-v1"
PLAN_SCHEMA = SCHEMA + "-plan"
RECEIPT_SCHEMA = SCHEMA + "-receipt"
PHASES = (
    "before_journal",
    "before_b4",
    "before_b9",
    "before_receipt",
)

PLAN_FIELDS = frozenset({
    "schema", "session", "head", "tree", "boot_id",
    "operator_uid", "operator_id",
    "inventory_sha256", "agent_bundle_sha256",
    "source_b4_sha256", "source_b9_sha256",
    "destinations", "custody_mode",
    "independent_authority", "root_install_authorized",
    "network_traffic_authorized", "vm_start_authorized",
    "action", "p8",
})

BODY_FIELDS = frozenset({
    "schema", "sequence", "phase", "plan_sha256",
    "authorization_sha256", "revocation_sha256",
    "previous_sha256", "checked_at",
    "root_install_authorized", "network_traffic_authorized",
    "status", "p8",
})
RECEIPT_FIELDS = BODY_FIELDS | {"record_sha256"}
ZERO_HASH = "0" * 64


def sha(raw):
    return crypto.sha(raw)


def canon(value):
    return crypto.canonical(value)


def require_plan(plan):
    need(type(plan) is dict and set(plan) == PLAN_FIELDS,
         "PLAN_FIELDS_INVALID")
    expected = {
        "schema": PLAN_SCHEMA,
        "source_b4_sha256": crypto.B4_SHA,
        "source_b9_sha256": crypto.B9_SHA,
        "destinations": list(crypto.DESTINATIONS),
        "custody_mode": "SINGLE_HUMAN_OPERATOR",
        "independent_authority": False,
        "root_install_authorized": False,
        "network_traffic_authorized": False,
        "vm_start_authorized": False,
        "action": "INSTALL_B4_B9_ONLY",
        "p8": "NO-GO",
    }
    need(all(type(plan[k]) is type(v) and plan[k] == v
             for k, v in expected.items()),
         "PLAN_SCOPE_INVALID")
    need(type(plan["head"]) is str and
         crypto.HEX40.fullmatch(plan["head"]) and
         type(plan["tree"]) is str and
         crypto.HEX40.fullmatch(plan["tree"]) and
         type(plan["boot_id"]) is str and
         crypto.BOOT.fullmatch(plan["boot_id"]) and
         type(plan["session"]) is str and
         crypto.SESSION.fullmatch(plan["session"]) and
         type(plan["inventory_sha256"]) is str and
         crypto.HEX64.fullmatch(plan["inventory_sha256"]) and
         type(plan["agent_bundle_sha256"]) is str and
         crypto.HEX64.fullmatch(plan["agent_bundle_sha256"]) and
         type(plan["operator_uid"]) is int and
         plan["operator_uid"] > 0 and
         type(plan["operator_id"]) is str and
         __import__("re").fullmatch(
             r"[A-Za-z0-9_.-]{1,64}", plan["operator_id"]),
         "PLAN_IDENTITY_INVALID")
    return sha(canon(plan))


def verify_history(receipts, *, plan_sha256, authorization_sha256):
    """Detect accidental receipt-chain drift. Not proof of root provenance."""
    need(type(receipts) in (tuple, list) and
         0 <= len(receipts) <= len(PHASES),
         "HISTORY_LENGTH_INVALID")
    need(type(plan_sha256) is str and
         crypto.HEX64.fullmatch(plan_sha256) and
         type(authorization_sha256) is str and
         crypto.HEX64.fullmatch(authorization_sha256),
         "HISTORY_IDENTITY_INVALID")

    previous = ZERO_HASH
    for index, receipt in enumerate(receipts):
        need(type(receipt) is dict and
             set(receipt) == RECEIPT_FIELDS,
             "RECEIPT_FIELDS_INVALID")
        body = {k: v for k, v in receipt.items()
                if k != "record_sha256"}
        need(type(receipt["sequence"]) is int and
             receipt["sequence"] == index and
             receipt["phase"] == PHASES[index] and
             receipt["schema"] == RECEIPT_SCHEMA and
             receipt["plan_sha256"] == plan_sha256 and
             receipt["authorization_sha256"] == authorization_sha256 and
             receipt["previous_sha256"] == previous and
             receipt["root_install_authorized"] is False and
             receipt["network_traffic_authorized"] is False and
             receipt["status"] == "REVIEW_ONLY_NOT_AUTHORITY" and
             receipt["p8"] == "NO-GO" and
             type(receipt["revocation_sha256"]) is str and
             crypto.HEX64.fullmatch(receipt["revocation_sha256"]) and
             type(receipt["checked_at"]) is str,
             "RECEIPT_SEMANTICS_INVALID")
        crypto.instant(receipt["checked_at"])
        digest = sha(canon(body))
        need(receipt["record_sha256"] == digest,
             "RECEIPT_HASH_INVALID")
        previous = digest

    return {
        "schema": SCHEMA + "-history-reviewed",
        "record_count": len(receipts),
        "complete": len(receipts) == len(PHASES),
        "last_sha256": previous,
        "root_install_authorized": False,
        "durable_root_provenance_verified": False,
        "p8": "NO-GO",
    }


class PhaseGate:
    """Source-only staged review: four fresh signed revocation checks."""

    def __init__(self, *, plan, trust_raw, authorization_raw,
                 read_live_revocation: Callable, now_provider: Callable):
        self.plan_sha256 = require_plan(plan)
        need(type(trust_raw) is bytes and
             type(authorization_raw) is bytes,
             "SIGNED_DOCUMENT_BYTES_INVALID")
        need(callable(read_live_revocation) and
             callable(now_provider),
             "LIVE_PROVIDERS_REQUIRED")
        self.plan = dict(plan)
        self.trust_raw = trust_raw
        self.authorization_raw = authorization_raw
        self.read_live_revocation = read_live_revocation
        self.now_provider = now_provider
        self._receipts = []

    @property
    def receipts(self):
        return tuple(dict(item) for item in self._receipts)

    def review(self, phase):
        need(type(phase) is str and
             phase in PHASES,
             "PHASE_INVALID")
        need(len(self._receipts) < len(PHASES) and
             phase == PHASES[len(self._receipts)],
             "PHASE_OUT_OF_ORDER")

        try:
            now = self.now_provider()
            revocation_raw = self.read_live_revocation(phase)
        except Exception as exc:
            raise Refusal("LIVE_PROVIDER_UNAVAILABLE") from exc

        need(type(now) is datetime and
             now.tzinfo is not None and
             now.utcoffset() is not None,
             "LIVE_CLOCK_INVALID")
        need(type(revocation_raw) is bytes and
             0 < len(revocation_raw) <= 16384,
             "LIVE_REVOCATION_BYTES_INVALID")

        checked = policy.validate(
            trust_raw=self.trust_raw,
            authorization_raw=self.authorization_raw,
            revocation_raw=revocation_raw,
            head=self.plan["head"],
            tree=self.plan["tree"],
            boot_id=self.plan["boot_id"],
            inventory_sha256=self.plan["inventory_sha256"],
            agent_bundle_sha256=self.plan["agent_bundle_sha256"],
            operator_uid=self.plan["operator_uid"],
            operator_id=self.plan["operator_id"],
            now=now,
        )

        need(checked["session"] == self.plan["session"] and
             checked["root_install_authorized"] is False and
             checked["human_independence_verified"] is False and
             checked["trust_anchor_provenance_verified"] is False and
             checked["network_traffic_authorized"] is False and
             checked["p8"] == "NO-GO",
             "CHECKED_AUTHORITY_INVALID")

        previous = (
            self._receipts[-1]["record_sha256"]
            if self._receipts else ZERO_HASH
        )

        body = {
            "schema": RECEIPT_SCHEMA,
            "sequence": len(self._receipts),
            "phase": phase,
            "plan_sha256": self.plan_sha256,
            "authorization_sha256":
                checked["authorization_sha256"],
            "revocation_sha256":
                checked["revocation_sha256"],
            "previous_sha256": previous,
            "checked_at": now.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "root_install_authorized": False,
            "network_traffic_authorized": False,
            "status": "REVIEW_ONLY_NOT_AUTHORITY",
            "p8": "NO-GO",
        }
        receipt = {
            **body,
            "record_sha256": sha(canon(body)),
        }
        self._receipts.append(receipt)
        return dict(receipt)

    def review_history(self):
        auth_sha = sha(self.authorization_raw)
        return verify_history(
            self.receipts,
            plan_sha256=self.plan_sha256,
            authorization_sha256=auth_sha,
        )
