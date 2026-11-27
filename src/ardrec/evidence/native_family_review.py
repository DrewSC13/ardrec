"""R362: source-bound family readiness, uncertainty and stop review.

No verified support bytes are promoted to technical truth.
No operational authority, dispatch or A9 publication is established.
"""

from copy import deepcopy

from ardrec.analytics.exact_preview import canonical, digest, rational
from ardrec.analytics.r58d_interval_kernel import (
    build_intervals, verify_intervals,
)
from ardrec.analytical_references import fingerprint, identifier
from ardrec.evidence import native_evidence_provenance as provenance
from ardrec.evidence import native_support_integrity as material
from ardrec.evidence import r58h_ssh_family_logic as ssh
from ardrec.evidence import r58i_ftp_family_logic as ftp
from ardrec.evidence import r58j_smb_family_logic as smb
from ardrec.stopping.development_stop import preview_stop, verify_stop

SCHEMA = "ARDREC-R362-NATIVE-FAMILY-REVIEW-v1"
PLAN_SCHEMA = SCHEMA + "-plan"

MAX_ATTEMPTS = 54

PLAN_FIELDS = {
    "attempt_id",
    "family_id",
    "variant",
    "assessment_index",
    "support_roles",
    "initial_risk",
    "normalized_criticality",
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def family_catalog():

    result = {}

    for spec in ssh.load_pinned_catalog():

        result[(spec["id"], None)] = {
            "protocol": "ssh",
            "family_id": spec["id"],
            "variant": None,
            "preconditions": list(spec["preconditions"]),
            "required_supports": list(spec["required_supports"]),
            "acceptance_supports": list(spec["acceptance_supports"]),
            "cleanup_required": spec["cleanup"] != "NO_MUTATION",
        }

    for protocol, module, loader in (
        ("ftp", ftp, ftp.load_pinned_ftp_catalog),
        ("smb", smb, smb.load_pinned_smb_catalog),
    ):

        for spec in loader():

            fid = spec["id"]

            for variant in module.VARIANTS.get(fid, (None,)):

                pre, required, accepted, _, cleanup = (
                    module._requirements(spec, variant)
                )

                result[(fid, variant)] = {
                    "protocol": protocol,
                    "family_id": fid,
                    "variant": variant,
                    "preconditions": list(pre),
                    "required_supports": list(required),
                    "acceptance_supports": list(accepted),
                    "cleanup_required": cleanup,
                }

    require(
        len(result) == 29
        and len({key[0] for key in result}) == 25,
        "FAMILY_INVENTORY_DRIFT",
    )

    require(
        {
            protocol: sum(
                row["protocol"] == protocol
                for row in result.values()
            )
            for protocol in ("ssh", "ftp", "smb")
        } == {"ssh": 8, "ftp": 10, "smb": 11},
        "PROTOCOL_INVENTORY_DRIFT",
    )

    return result


def validate_plan(plan, pin, source, support_report):

    fingerprint(pin)

    require(
        type(plan) is dict
        and set(plan) == {
            "schema", "provenance_sha256",
            "manifest_sha256", "attempts",
        }
        and plan["schema"] == PLAN_SCHEMA,
        "FAMILY_PLAN_SCHEMA_INVALID",
    )

    plan = deepcopy(plan)

    require(
        digest(plan) == pin,
        "FAMILY_PLAN_PIN_MISMATCH",
    )

    require(
        plan["provenance_sha256"] == source["sha256"]
        and plan["manifest_sha256"]
            == support_report["manifest_sha256"],
        "FAMILY_PLAN_SOURCE_MISMATCH",
    )

    require(
        type(plan["attempts"]) is list
        and len(plan["attempts"]) <= MAX_ATTEMPTS,
        "FAMILY_PLAN_ATTEMPT_LIMIT",
    )

    eligible = {
        row["attempt_id"]: row
        for row in source["attempts"]
        if row["documentary_link_verified"]
    }

    indexed = {}

    for row in plan["attempts"]:

        require(
            type(row) is dict
            and set(row) == PLAN_FIELDS,
            "FAMILY_PLAN_ENTRY_SCHEMA",
        )

        identifier(row["attempt_id"])
        identifier(row["family_id"])

        aid = row["attempt_id"]

        require(
            aid in eligible,
            "FAMILY_PLAN_FOREIGN_ATTEMPT",
        )

        require(
            aid not in indexed,
            "FAMILY_PLAN_DUPLICATE_ATTEMPT",
        )

        require(
            type(row["assessment_index"]) is int
            and 0 <= row["assessment_index"] < 2**31,
            "ASSESSMENT_INDEX_INVALID",
        )

        rational(row["initial_risk"])
        rational(row["normalized_criticality"])

        require(
            row["variant"] is None
            or type(row["variant"]) is str,
            "VARIANT_TYPE_INVALID",
        )

        require(
            type(row["support_roles"]) is dict,
            "SUPPORT_ROLE_MAP_INVALID",
        )

        for ref, role in row["support_roles"].items():
            identifier(ref)
            identifier(role)

        indexed[aid] = row

    require(
        set(indexed) == set(eligible),
        "FAMILY_PLAN_INVENTORY_INCOMPLETE",
    )

    return indexed, eligible


def preview_family(spec, case_id, session_id, index, roles):

    # Explicit hypothetical phase, never the recovered
    # operational state. Semantic support truth remains ND.
    unit = {
        "family_id": spec["family_id"],
        "derived_case_id": case_id,
        "assessment_index": index,
        "session_id": session_id,
        "phase": "PENDIENTE",
        "preconditions": {
            name: "ND"
            for name in spec["preconditions"]
        },
        "supports": {
            role: "ND"
            for role in roles
        },
        "integrity": "ND",
        "provenance": "ND",
        "cleanup": (
            "ND" if spec["cleanup_required"]
            else "NO_APLICA"
        ),
        "outcome": "INCONCLUSO",
    }

    protocol = spec["protocol"]

    if protocol == "ssh":

        report = ssh.build_ssh_simulation([unit])
        ssh.verify_ssh_simulation(report)

    elif protocol == "ftp":

        unit["variant"] = spec["variant"]

        report = ftp.build_ftp_simulation([unit])
        ftp.verify_ftp_simulation(report)

    else:

        unit["variant"] = spec["variant"]

        report = smb.build_smb_simulation([unit])
        smb.verify_smb_simulation(report)

    decision = report["decisions"][0]

    require(
        decision["a6_classification"] == "ND"
        and decision["technical_truth_accredited"] is False
        and decision["technical_contribution"] is None
        and decision["confirmed_rf"] is None
        and decision["applied_transition"] is None,
        "FAMILY_PREVIEW_PROMOTION",
    )

    require(
        set(decision["required_supports"])
            == set(spec["required_supports"])
        and set(decision["acceptance_supports"])
            == set(spec["acceptance_supports"]),
        "FAMILY_REQUIREMENTS_DRIFT",
    )

    return {
        "preview_sha256": report["sha256"],
        "hypothetical_class":
            decision["hypothetical_result_class"],
        "hypothetical_reason":
            decision["hypothetical_reason"],
        "guard": decision["guard_simulated"],
        "assumed_phase": "PENDIENTE",
        "a6": "ND",
    }


def review_attempt(plan, native, supports, specs, session_id):

    key = (plan["family_id"], plan["variant"])

    require(
        key in specs,
        "FAMILY_OR_VARIANT_UNKNOWN",
    )

    spec = specs[key]

    require(
        native["protocol"] == spec["protocol"],
        "FAMILY_PROTOCOL_MISMATCH",
    )

    cid = native["derived_case_id"]

    require(
        cid.startswith(spec["family_id"] + "-"),
        "FAMILY_CASE_ID_MISMATCH",
    )

    aid = native["attempt_id"]

    declared = set(native["declared_support_references"])

    attempt_supports = {
        row["support_reference"]: row
        for row in supports
        if row["attempt_id"] == aid
    }

    require(
        set(attempt_supports) == declared,
        "NATIVE_SUPPORT_INVENTORY_MISMATCH",
    )

    mapping = plan["support_roles"]

    require(
        set(mapping) <= declared,
        "SUPPORT_ROLE_UNDECLARED_REFERENCE",
    )

    require(
        set(mapping.values()) <= set(spec["required_supports"]),
        "SUPPORT_ROLE_NOT_REQUIRED",
    )

    require(
        len(set(mapping.values())) == len(mapping),
        "AMBIGUOUS_SUPPORT_ROLE",
    )

    role_rows = []
    verified_roles = set()
    verified_hashes = set()

    by_role = {
        role: ref
        for ref, role in mapping.items()
    }

    for role in spec["required_supports"]:

        ref = by_role.get(role)

        status = "ROLE_NOT_MAPPED"
        pin = None
        verified = False

        if ref is not None:

            source = attempt_supports[ref]
            status = source["status"]
            pin = source["support_sha256"]
            verified = source["bytes_verified"]

            if verified:

                require(
                    pin not in verified_hashes,
                    "SAME_BYTES_REUSED_ACROSS_ROLES",
                )

                verified_hashes.add(pin)
                verified_roles.add(role)

        role_rows.append({
            "role": role,
            "support_reference": ref,
            "support_sha256": pin,
            "material_status": status,
            "bytes_verified": verified,
            "semantic_truth": "ND",
        })

    required = set(spec["required_supports"])
    accepted = set(spec["acceptance_supports"])

    preview = preview_family(
        spec, cid, session_id,
        plan["assessment_index"],
        mapping.values(),
    )

    # This is a mathematical envelope conditional on
    # supplied candidate baseline and no downward replacement.
    interval = build_intervals([{
        "service_id": spec["protocol"].upper() + "_DEV",
        "case_id": cid,
        "assessment_index": plan["assessment_index"],
        "initial_risk": plan["initial_risk"],
        "normalized_criticality":
            plan["normalized_criticality"],
        "replacement_risk": plan["initial_risk"],
        "evidence": [{
            "evidence_id": "E_A6_UNRESOLVED",
            "kind": "UNRESOLVED",
            "lower": "0",
            "upper": "1",
        }],
    }])

    verify_intervals(interval)

    row = {
        "attempt_id": aid,
        "service_scenario_id":
            native["service_scenario_id"],
        "derived_case_id": cid,
        "condition_id": native["condition_id"],
        "protocol": spec["protocol"],
        "family_id": spec["family_id"],
        "variant": spec["variant"],
        "assessment_index": plan["assessment_index"],
        "decision_index": native["decision_index"],
        "request_sha256": native["request_sha256"],
        "report_sha256": native["report_sha256"],
        "incorporation_event":
            native["incorporation_event"],
        "incorporation_generation":
            native["incorporation_generation"],
        "support_roles": role_rows,
        "required_support_count": len(required),
        "required_supports_bytes_verified":
            len(verified_roles),
        "required_material_coverage":
            material.coverage(len(verified_roles), len(required)),
        "acceptance_support_count": len(accepted),
        "acceptance_supports_bytes_verified":
            len(accepted & verified_roles),
        "acceptance_material_coverage":
            material.coverage(
                len(accepted & verified_roles),
                len(accepted),
            ),
        "unmapped_support_references":
            sorted(declared - set(mapping)),
        "required_semantic_supports_accredited": 0,
        "family_preview": preview,
        "hypothetical_interval": interval["results"][0],
        "interval_sha256": interval["sha256"],
        "baseline_accredited": False,
        "downward_replacement_applied": False,
        "a6": "ND",
        "confirmed_rf": None,
    }

    stop = preview_stop(
        a6_classification="ND",
        accredited=False,
        vm_checked=False,
        operational_dispatch=False,
        source_sha256=digest(row),
    )

    verify_stop(stop)

    row["a8"] = stop

    return row


def build(
    store_path,
    *,
    plan,
    expected_plan_sha256,
    support_kwargs,
):

    source = provenance.build(
        store_path,
        **support_kwargs["provenance_kwargs"],
    )

    support_report = material.build(
        store_path,
        **support_kwargs,
    )

    require(
        source["sha256"]
            == support_report["provenance_sha256"],
        "FAMILY_NATIVE_SOURCE_DRIFT",
    )

    specs = family_catalog()

    indexed, eligible = validate_plan(
        plan,
        expected_plan_sha256,
        source,
        support_report,
    )

    reviews = []

    for aid in sorted(indexed):

        reviews.append(review_attempt(
            indexed[aid],
            eligible[aid],
            support_report["supports"],
            specs,
            source["record_id"],
        ))

    require(
        canonical(provenance.build(
            store_path,
            **support_kwargs["provenance_kwargs"],
        )) == canonical(source),
        "FAMILY_SOURCE_CHANGED_DURING_REVIEW",
    )

    result = {
        "schema": SCHEMA,
        "scope": "SOURCE_BOUND_NONOPERATIONAL_FAMILY_REVIEW",
        "catalog_sha256": ssh.CATALOG_SHA256,
        "catalog_families": 25,
        "catalog_family_variants": 29,
        "record_id": source["record_id"],
        "execution_id": source["execution_id"],
        "configuration_sha256":
            source["configuration_sha256"],
        "head_sha256": source["head_sha256"],
        "generation": source["generation"],
        "provenance_sha256": source["sha256"],
        "support_report_sha256": support_report["sha256"],
        "plan_sha256": expected_plan_sha256,
        "reviewed_attempts": len(reviews),
        "attempts": reviews,
        "families_materially_reviewed": len({
            row["family_id"] for row in reviews
        }),
        "technical_conditions_accredited": 0,
        "confirmed_rf_count": 0,
        "technical_truth_accredited": False,
        "operational_dispatch": False,
        "published_generation": None,
        "experimental_admitted": 0,
        "p8": "NO-GO",
    }

    result["sha256"] = digest(result)

    return result


def verify(report, expected_report_sha256, store_path, **kwargs):

    fingerprint(expected_report_sha256)

    require(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and digest({
            key: value
            for key, value in report.items()
            if key != "sha256"
        }) == expected_report_sha256,
        "FAMILY_REPORT_PIN_INVALID",
    )

    expected = build(store_path, **kwargs)

    require(
        canonical(report) == canonical(expected),
        "FAMILY_REPORT_REPLAY_MISMATCH",
    )

    return True
