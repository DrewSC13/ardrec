"""R107: deterministic 54-window A1-A10 *coverage* orchestration.

Consumes independently checked R104 and R106 documents.  A1-A10 entries
are a conservative, read-only processing ledger, NOT ten executed operational
algorithms, an A3 state transition, a physical A5, or an A9 publication.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r106_ssh_case_provenance as r106
from ardrec.coordination.r58k_unified_family_bridge import verify_unified_preview

SCHEMA = "ardrec-r107-offline-a1-a10-54-window-orchestration-v1"
R106_MANIFEST_SCHEMA = "ardrec-r106-private-provenance-manifest-v1"
ALGORITHMS = tuple("A" + str(i) for i in range(1, 11))
COUNTS = {"SSH_DEV": 16, "FTP_DEV": 20, "SMB_DEV": 18}
MAX_REPORT_BYTES = 900_000

STAGE_STATUS = (
    "SYNTHETIC_R104_INPUT_REGISTERED",
    "SYNTHETIC_PRECONDITIONS_REFERENCED",
    "PENDIENTE_ASSUMED_NO_A3_TRANSITION",
    "HYPOTHETICAL_FAMILY_RULE_EVALUATED",
    "A5_NO_OPERATIONAL_START",
    "A6_NOT_DETERMINED_NO_TECHNICAL_TRUTH",
    "A7_MATHEMATICAL_INTERVAL_UNCONFIRMED",
    "A8_PAUSE_RECOMMENDED_NOT_APPLIED",
    "A9_NO_GENERATION_PUBLISHED",
    "A10_READ_ONLY_TRACE_AVAILABLE",
)


class OrchestrationError(ValueError):
    """Reject conflicting identity, provenance, non-conservative facts or replay."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise OrchestrationError(code)


def _verified_digest(obj: dict[str, Any], code: str) -> None:
    need(type(obj) is dict and type(obj.get("sha256")) is str
         and obj["sha256"] == a5.digest({k: v for k, v in obj.items()
                                          if k != "sha256"}), code)


def verify_sources(report: dict, manifest104: dict,
                   link106: dict, manifest106: dict) -> None:
    """Validate document boundaries; caller also reopens original private receipts."""
    _verified_digest(manifest104, "R104_MANIFEST_DIGEST")
    _verified_digest(link106, "R106_LINK_DIGEST")
    _verified_digest(manifest106, "R106_MANIFEST_DIGEST")
    need(type(report) is dict and report.get("sha256") == r106.R104_REPORT_PIN
         and manifest104.get("sha256") == r106.R104_MANIFEST_PIN
         and manifest104.get("schema") == r106.R104_SCHEMA
         and manifest104.get("case_count") == 54
         and manifest104.get("report_sha256") == report["sha256"]
         and manifest104.get("a6_classification") == "ND"
         and manifest104.get("p8_operational") == "NO-GO",
         "R104_SOURCE_UNEXPECTED")
    verify_unified_preview(report)
    need(report.get("unit_count") == 54
         and report.get("supported_family_count") == 25
         and report.get("covered_family_count_in_batch") == 25
         and report.get("count_by_service") == COUNTS
         and report.get("a6_classification") == "ND"
         and report.get("technical_truth_accredited") is False
         and report.get("confirmed_final_risk") is None
         and report.get("applied_state_transition") is None
         and report.get("published_generation") is None
         and report.get("operational_dispatch") is False
         and report.get("p8_operational") == "NO-GO",
         "R104_PREVIEW_OR_AUTHORITY_DRIFT")
    need(link106.get("schema") == r106.SCHEMA
         and link106.get("r104_synthetic_report_sha256") == report["sha256"]
         and link106.get("r104_manifest_sha256") == manifest104["sha256"]
         and link106.get("r105_rust_source_sha256") == r106.R105_SOURCE_PIN
         and link106.get("r103_original_strict_acceptance") == "FAIL_PRESERVED"
         and link106.get("case_binding_kind") == "SYNTHETIC_IDENTITY_ASSOCIATION_ONLY"
         and link106.get("ssh_observation_kind") == "R105_LOCAL_FIXTURE_NOT_GUEST_EVIDENCE"
         and link106.get("f11_evidence_kind") == "R103_SINGLE_BOOT_DENIAL_OBSERVED_ONLY"
         and link106.get("ssh_authentication") is False
         and link106.get("a5_operational_starts") == 0
         and link106.get("a6_classification") == "ND"
         and link106.get("a6_technical_truth_accredited") is False
         and link106.get("a7_confirmed_rf") is None
         and link106.get("a8_transition_applied") is None
         and link106.get("a9_published_generation") is None
         and link106.get("dispatch_allowed") is False
         and link106.get("vm_starts") == 0
         and link106.get("p8_operational") == "NO-GO",
         "R106_LINK_AUTHORITY_DRIFT")
    need(manifest106.get("schema") == R106_MANIFEST_SCHEMA
         and manifest106.get("link_sha256") == link106["sha256"]
         and manifest106.get("r104_report_sha256") == report["sha256"]
         and manifest106.get("r103_f11_review_sha256") ==
             link106["r103_f11_forensic_review_sha256"]
         and manifest106.get("r105_rust_source_sha256") == r106.R105_SOURCE_PIN
         and manifest106.get("a5_operational_starts") == 0
         and manifest106.get("a6_classification") == "ND"
         and manifest106.get("a7_confirmed_rf") is None
         and manifest106.get("a8_transition_applied") is None
         and manifest106.get("dispatch_allowed") is False
         and manifest106.get("vm_starts") == 0
         and manifest106.get("p8_operational") == "NO-GO",
         "R106_MANIFEST_AUTHORITY_DRIFT")
    # A case association is not a statement that the fixture observed that case.
    linked = link106.get("case_identity")
    need(type(linked) is dict
         and (linked.get("service_id"), linked.get("session_id"),
              linked.get("derived_case_id"), linked.get("assessment_index")) == r106.CASE
         and linked.get("family_id") == "SSH-T01"
         and type(linked.get("case_id_a7")) is str,
         "R106_LINKED_CASE_INVALID")
    selected = [d for d in report["decisions"]
                if (d["service_id"], d["session_id"], d["derived_case_id"],
                    d["assessment_index"]) == r106.CASE]
    need(len(selected) == 1 and selected[0]["case_id_a7"] == linked["case_id_a7"],
         "R106_CASE_NOT_PRESENT_IN_R104")


def _stage_chain(row: dict, report_sha: str,
                 r106_sha: str | None) -> tuple[list[dict], str]:
    items = []
    previous = None
    for ordinal, (algorithm, status) in enumerate(zip(ALGORITHMS, STAGE_STATUS), 1):
        # R106 is a provenance note for the A5 boundary in only one synthetic
        # identity; this must not be mistaken for an A5 operational attempt.
        source_sha = (r106_sha if ordinal == 5 and r106_sha is not None
                      else report_sha)
        entry = {
            "ordinal": ordinal,
            "algorithm": algorithm,
            "case_id_a7": row["case_id_a7"],
            "status": status,
            "source_sha256": source_sha,
            "previous_stage_sha256": previous,
            "operationally_executed": False,
            "technical_truth_accredited": False,
            "dispatch_allowed": False,
        }
        entry["event_sha256"] = a5.digest(entry)
        previous = entry["event_sha256"]
        items.append(entry)
    return items, previous


def build(report: dict, manifest104: dict,
          link106: dict, manifest106: dict) -> dict:
    """Build a deterministic 10-stage *status trace* for all 54 case windows."""
    verify_sources(report, manifest104, link106, manifest106)
    decisions = sorted(report["decisions"], key=lambda d: (
        d["service_id"], d["session_id"], d["derived_case_id"],
        d["assessment_index"], d["family_id"], d.get("variant") or ""))
    linked_case = link106["case_identity"]["case_id_a7"]
    entries = []
    heads = []
    found = 0
    families = set()
    counts = Counter()
    for d in decisions:
        need(d["a6_classification"] == "ND"
             and d["technical_truth_accredited"] is False
             and d["confirmed_rf"] is None
             and d["applied_transition"] is None
             and d["published_generation"] is None
             and d["a8_recommendation"] == "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA"
             and d["phase_assumed"] == "PENDIENTE",
             "CASE_WAS_PROMOTED")
        associated = d["case_id_a7"] == linked_case
        found += int(associated)
        stages, head = _stage_chain(
            d, report["sha256"], link106["sha256"] if associated else None)
        case = {
            "service_id": d["service_id"],
            "session_id": d["session_id"],
            "derived_case_id": d["derived_case_id"],
            "assessment_index": d["assessment_index"],
            "family_id": d["family_id"],
            "variant": d.get("variant"),
            "case_id_a7": d["case_id_a7"],
            "phase_assumed_not_applied": d["phase_assumed"],
            "hypothetical_result_class": d["hypothetical_result_class"],
            "simulated_guard": d["guard_simulated"],
            "r106_provenance_association_only": associated,
            "a5_operational_starts": 0,
            "a6_classification": "ND",
            "a7_interval_lower": d["a7_rf_lower"],
            "a7_interval_upper": d["a7_rf_upper"],
            "a7_confirmed_rf": None,
            "a8_recommendation": d["a8_recommendation"],
            "a8_applied_transition": None,
            "a9_published_generation": None,
            "stages": stages,
            "stage_head_sha256": head,
        }
        case["case_sha256"] = a5.digest(case)
        entries.append(case)
        heads.append(case["case_sha256"])
        counts[d["service_id"]] += 1
        families.add(d["family_id"])
    need(found == 1 and len(entries) == 54 and len(families) == 25
         and dict(counts) == COUNTS, "R107_COVERAGE_OR_CASE_IDENTITY")
    result = {
        "schema": SCHEMA,
        "mode": "OFFLINE_A1_A10_STATUS_ORCHESTRATION_NO_AUTHORITY",
        "r104_report_sha256": report["sha256"],
        "r104_manifest_sha256": manifest104["sha256"],
        "r106_link_sha256": link106["sha256"],
        "r106_manifest_sha256": manifest106["sha256"],
        "case_window_count": len(entries),
        "family_count": len(families),
        "count_by_service": COUNTS,
        "algorithm_ids": list(ALGORITHMS),
        "stage_status_count": len(entries) * len(ALGORITHMS),
        "r106_linked_identity_count": found,
        "cases": entries,
        "case_digest_chain_sha256": a5.digest(heads),
        "a1_a10_operational_implementation_complete": False,
        "a3_state_transitions_applied": 0,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "a8_applied_transitions": 0,
        "a9_published_generations": 0,
        "technical_truth_accredited": False,
        "ssh_fixture_is_guest_evidence": False,
        "physical_boot_lifecycle_attested": False,
        "host_mutations": 0,
        "vm_starts": 0,
        "operational_dispatch": False,
        "p8_operational": "NO-GO",
    }
    need(len(a5.canonical(result)) < MAX_REPORT_BYTES, "R107_REPORT_TOO_LARGE")
    result["sha256"] = a5.digest(result)
    return result


def verify_trace(value: dict, report: dict, manifest104: dict,
                 link106: dict, manifest106: dict) -> bool:
    """Recompute every case, stage hash and cross-document binding."""
    need(type(value) is dict
         and value == build(report, manifest104, link106, manifest106),
         "R107_TRACE_NOT_REPRODUCIBLE")
    return True
