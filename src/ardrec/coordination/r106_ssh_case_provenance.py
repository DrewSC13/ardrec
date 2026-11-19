"""R106: bind R103 denial, R104 synthetic case, and R105 loopback observation.

This is a *provenance association*, never a physical SSH case witness or
permission for A5, A6, A7, A8, P8, guest boot, or remote authentication.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as a5

SCHEMA = "ardrec-r106-ssh-case-provenance-deny-only-v1"
R105_SCHEMA = "ardrec-r105-sshv2-loopback-kexinit-v1"
R104_SCHEMA = "ardrec-r104-54-unit-functional-offline-v1"
F11_SCHEMA = "ardrec-r103-f5-independent-forensic-review-v1"
F11_PIN = "00c67e63b1426364f1b086f8da209dfff84afa1cdc803c62736bee0fbf2635ae"
F11_R103_RESULT = "2fac7a983d2132762678848d34b00dbc11c0c44ddeebc9a77ea1e4408c530f84"
R104_REPORT_PIN = "0444eb33527de3fc1af93558fdb4c26f236a59909da6bf9060940618d22615dc"
R104_MANIFEST_PIN = "448dbb70e6bbd07afc368ce7905b4f0fbbc6e75ce78e5f0c316ab0cf6edfbb08"
R105_SOURCE_PIN = "a76de4ebb5d7fcd2ddd1a54fc8ba035643470b73e19df9186c0ef2fac2eb4093"
R105_KEX_SHA = "b518972be133c3f2f499b06b233c5e338e04ac5077b93ae23ef0e835e85264c5"
R105_SERVER_SHA = a5.sha(b"SSH-2.0-ARDREC_R105_FIXTURE\r\n")
R105_FIELDS = frozenset({
    "schema", "transport", "server_identification", "identification_sha256",
    "kexinit_sha256", "kexinit_bytes", "offered_kex_algorithms",
    "offered_host_key_algorithms", "elapsed_ms", "tcp_connections",
    "client_identifications_sent", "keys_negotiated", "authenticated",
    "remote_commands", "a5_operational_attempts", "a6_classification",
    "a7_confirmed_rf", "evidence_accredited", "dispatch_allowed", "p8_operational",
})
CASE = ("SSH_DEV", "DEV_TUTOR_001", "SSH-T01-S01-01", 0)
HEX = re.compile(r"[0-9a-f]{64}\Z")


class ProvenanceError(ValueError):
    """Source identity, logical provenance, or conservative boundary mismatch."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise ProvenanceError(code)


def verify_r105(observation: dict[str, Any]) -> bool:
    """Check exact bounded R105 fixture report, not independent Rust attestation."""
    need(type(observation) is dict and set(observation) == R105_FIELDS,
         "R105_REPORT_SCHEMA")
    v = observation
    need(v["schema"] == R105_SCHEMA
         and v["transport"] == "REAL_TCP_IPV4_LOOPBACK_ONLY"
         and v["server_identification"] == "SSH-2.0-ARDREC_R105_FIXTURE"
         and v["identification_sha256"] == R105_SERVER_SHA
         and v["kexinit_sha256"] == R105_KEX_SHA
         and type(v["kexinit_bytes"]) is int and v["kexinit_bytes"] == 160
         and v["offered_kex_algorithms"] == ["curve25519-sha256"]
         and v["offered_host_key_algorithms"] == ["ssh-ed25519"]
         and type(v["elapsed_ms"]) is int and 0 <= v["elapsed_ms"] <= 10000
         and type(v["tcp_connections"]) is int and v["tcp_connections"] == 1
         and type(v["client_identifications_sent"]) is int
         and v["client_identifications_sent"] == 1,
         "R105_FIXTURE_OR_PACKET_DRIFT")
    need(v["keys_negotiated"] is False
         and v["authenticated"] is False
         and type(v["remote_commands"]) is int and v["remote_commands"] == 0
         and type(v["a5_operational_attempts"]) is int
         and v["a5_operational_attempts"] == 0
         and v["a6_classification"] == "ND"
         and v["a7_confirmed_rf"] is None
         and v["evidence_accredited"] is False
         and v["dispatch_allowed"] is False
         and v["p8_operational"] == "NO-GO",
         "R105_FALSE_AUTHORITY")
    return True


def verify_f11(review: dict[str, Any], *, expected_sha: str = F11_PIN) -> bool:
    """Check F5 forensic review and its expected digest, never promote F3 FAIL."""
    need(type(review) is dict and type(expected_sha) is str
         and HEX.fullmatch(expected_sha) is not None,
         "F11_REVIEW_FORMAT")
    need(review.get("sha256") == expected_sha
         and review["sha256"] == a5.digest({k: v for k, v in review.items()
                                             if k != "sha256"}),
         "F11_PIN_OR_DIGEST_MISMATCH")
    need(review.get("schema") == F11_SCHEMA
         and review.get("target") == "ardrec-r33-dev-ssh"
         and review.get("original_result_sha256") == F11_R103_RESULT
         and review.get("physical_hook_denial_recorded") is True
         and review.get("virsh_start_rejected") is True
         and review.get("watcher_finalization_defect_confirmed") is True
         and review.get("original_strict_acceptance") == "FAIL_PRESERVED"
         and review.get("independent_boot_lifecycle_attested") is False
         and review.get("new_start_attempts") == 0
         and review.get("p8_operational") == "NO-GO"
         and review.get("authorized_dispatch") is False,
         "F11_FALSE_ATTESTATION_OR_SCOPE")
    return True


def select_case(report: dict[str, Any], manifest: dict[str, Any]) -> dict:
    """Select exactly one R104 SSH identity from the 54-unit synthetic batch."""
    need(type(report) is dict and type(manifest) is dict
         and report.get("sha256") == manifest.get("report_sha256")
         and report.get("unit_count") == 54
         and manifest.get("case_count") == 54
         and manifest.get("schema") == R104_SCHEMA
         and manifest.get("a6_classification") == "ND"
         and manifest.get("p8_operational") == "NO-GO"
         and report.get("a6_classification") == "ND"
         and report.get("p8_operational") == "NO-GO"
         and report.get("technical_truth_accredited") is False
         and report.get("published_generation") is None
         and report.get("confirmed_final_risk") is None,
         "R104_CASE_SOURCE_INVALID")
    choices = [d for d in report["decisions"] if (
        d.get("service_id"), d.get("session_id"),
        d.get("derived_case_id"), d.get("assessment_index")
    ) == CASE]
    need(len(choices) == 1, "R104_SSH_CASE_NOT_UNIQUE")
    c = choices[0]
    need(c.get("family_id") == "SSH-T01"
         and c.get("a6_classification") == "ND"
         and c.get("technical_truth_accredited") is False
         and c.get("confirmed_rf") is None
         and c.get("applied_transition") is None
         and c.get("published_generation") is None
         and c.get("a8_recommendation") == "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA"
         and type(c.get("case_id_a7")) is str
         and re.fullmatch(r"CASE_[A-F0-9]{48}", c["case_id_a7"]) is not None,
         "R104_CASE_PROMOTED_OR_CORRUPT")
    return c


def build(report: dict, manifest: dict, observation: dict, review: dict,
          *, f11_expected_sha: str = F11_PIN) -> dict:
    """Pure deterministic proof-of-association with explicit non-authority."""
    verify_r105(observation)
    verify_f11(review, expected_sha=f11_expected_sha)
    case = select_case(report, manifest)
    result = {
        "schema": SCHEMA,
        "source_mode": "MIXED_PROVENANCE_NO_INDEPENDENT_CASE_ATTESTATION",
        "r104_synthetic_report_sha256": report["sha256"],
        "r104_manifest_sha256": manifest["sha256"],
        "r103_f11_forensic_review_sha256": review["sha256"],
        "r103_original_strict_acceptance": "FAIL_PRESERVED",
        "r105_rust_source_sha256": R105_SOURCE_PIN,
        "r105_observation_sha256": a5.digest(observation),
        "case_identity": {
            "service_id": CASE[0], "session_id": CASE[1],
            "derived_case_id": CASE[2], "assessment_index": CASE[3],
            "family_id": "SSH-T01", "case_id_a7": case["case_id_a7"],
        },
        "case_binding_kind": "SYNTHETIC_IDENTITY_ASSOCIATION_ONLY",
        "ssh_observation_kind": "R105_LOCAL_FIXTURE_NOT_GUEST_EVIDENCE",
        "f11_evidence_kind": "R103_SINGLE_BOOT_DENIAL_OBSERVED_ONLY",
        "ssh_authentication": False,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a6_technical_truth_accredited": False,
        "a7_confirmed_rf": None,
        "a8_recommendation": "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
        "a8_transition_applied": None,
        "a9_published_generation": None,
        "dispatch_allowed": False,
        "vm_starts": 0,
        "p8_operational": "NO-GO",
    }
    result["sha256"] = a5.digest(result)
    return result


def verify_link(link: dict, report: dict, manifest: dict,
                observation: dict, review: dict, *,
                f11_expected_sha: str = F11_PIN) -> bool:
    need(type(link) is dict and link == build(
        report, manifest, observation, review,
        f11_expected_sha=f11_expected_sha,
    ), "R106_LINK_OR_PROVENANCE_TAMPERING")
    return True
