//! Differential fixture coverage for the P8-R7 deny-only Rust parser.
use ardrec_executor::contract_gate::PROFILE_IDS;
use ardrec_executor::p8_diagnostic::{diagnostic_json, evaluate};
use serde_json::Value;

#[test]
fn all_shared_fixtures_denied_with_exact_reason() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/p8-diagnostic-v1.json"
    ))
    .expect("test fixture JSON");
    let entries = fixtures["cases"].as_array().expect("cases array");
    assert!(entries.len() >= 50);
    for entry in entries {
        let name = entry["name"].as_str().expect("case name");
        let raw = entry["payload"].as_str().expect("raw input");
        let expected = entry["reason_code"].as_str().expect("reason code");
        let result = evaluate(raw.as_bytes());
        assert_eq!(result.reason_code, expected, "fixture {name}");
        assert!(!result.authorized, "fixture {name}");
        assert!(!result.dispatch_allowed, "fixture {name}");
        let reply: Value = serde_json::from_str(&diagnostic_json(result)).unwrap();
        assert_eq!(reply["reason_code"], expected, "fixture {name}");
        assert_eq!(reply["decision"], "BLOCKED_UNBOUND_NO_EXECUTION");
        assert_eq!(reply["authorized"], false);
        assert_eq!(reply["dispatch_allowed"], false);
    }
}

#[test]
fn all_twenty_nine_profiles_remain_unbound() {
    assert_eq!(PROFILE_IDS.len(), 29);
    let baseline = serde_json::json!({
        "schema_version": "1.0", "message_type": "P8_R7_DIAGNOSTIC_PROPOSAL",
        "stage": "dev", "case_id": "SSH-T01-S01-01", "profile_id": "SSH-T01-BASE",
        "snapshot_sha256": "a".repeat(64), "r6_snapshot_sha256": "a".repeat(64),
        "material_epoch": 4, "r6_material_epoch": 4,
        "authorization_revision": 2, "r6_authorization_revision": 2,
        "r5_status": "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL",
        "r6_status": "SYNTHETIC_PRECONDITIONS_CONSISTENT_DENY_ALL",
        "r5_dispatch_allowed": false, "r5_case_authorized": false,
        "r6_dispatch_allowed": false, "r6_operational_authorization": false,
        "private_issuer_verified": false, "revocation_verified": false,
        "dispatch_requested": false
    });
    for profile in PROFILE_IDS {
        let mut record = baseline.clone();
        record["profile_id"] = Value::from(profile);
        let family = profile.get(..7).expect("known profile prefix");
        record["case_id"] = Value::from(format!("{family}-S01-01"));
        let result = evaluate(record.to_string().as_bytes());
        assert_eq!(
            result.reason_code, "P8_R7_UNVERIFIED_AUTHORITY",
            "{profile}"
        );
        assert!(!result.authorized);
        assert!(!result.dispatch_allowed);
    }
}

#[test]
fn duplicate_keys_are_rejected_before_authorization_review() {
    let diagnostic = evaluate(br#"{"x":1,"x":2}"#);
    assert_eq!(diagnostic.reason_code, "P8_R7_INVALID_SCHEMA");
}
