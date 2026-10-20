//! Casos directos para el contrato público Rust.
use super::*;
use serde_json::json;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../../../../tests/fixtures/messages-v2.json"))
        .expect("Ejemplos JSON válidos")
}
fn rejected(raw: &[u8], code: &str) {
    assert_eq!(
        decode_message(raw).expect_err("Debe rechazarse").code(),
        code
    );
}
#[test]
fn both_versions_preserve_canonical_bytes() {
    let legacy: Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/messages.json")).unwrap();
    for data in [legacy, fixtures()] {
        for m in data.as_object().unwrap().values() {
            let encoded = encode_message(m).unwrap();
            assert_eq!(decode_message(&encoded).unwrap(), *m);
            assert_eq!(
                encode_message(&decode_message(&encoded).unwrap()).unwrap(),
                encoded
            );
        }
    }
}
#[test]
fn integers_never_pass_through_float() {
    let mut message = fixtures()["request"].clone();
    for value in [0, 1, 9_007_199_254_740_993_i64, i64::MAX] {
        message["decision_index"] = json!(value);
        let raw = encode_message(&message).unwrap();
        assert!(
            std::str::from_utf8(&raw)
                .unwrap()
                .contains(&format!("\"decision_index\":{value},"))
        );
        assert_eq!(
            decode_message(&raw).unwrap()["decision_index"].as_i64(),
            Some(value)
        );
    }
    for invalid in [json!(true), json!(1.0), json!(u64::MAX), json!(-1)] {
        message["decision_index"] = invalid;
        assert_eq!(
            validate_message(&message).unwrap_err().code(),
            "schema_invalid"
        );
    }
}
#[test]
fn byte_boundary_and_invalid_utf8() {
    let message = fixtures()["request"].clone();
    let mut raw = encode_message(&message).unwrap();
    raw.resize(MAX_MESSAGE_BYTES, b' ');
    assert_eq!(decode_message(&raw).unwrap(), message);
    raw.push(b' ');
    rejected(&raw, "message_too_large");
    rejected(&[0xff], "schema_invalid");
}
#[test]
fn duplicate_and_approximate_numbers_are_rejected() {
    let raw = String::from_utf8(encode_message(&fixtures()["request"]).unwrap()).unwrap();
    for token in ["22.0", "22e0", "NaN", "Infinity", "022", "+22"] {
        rejected(
            raw.replace("\"port\":22", &format!("\"port\":{token}"))
                .as_bytes(),
            "schema_invalid",
        );
    }
    rejected(
        raw.replace("\"port\":22", "\"port\":22,\"\\u0070ort\":22")
            .as_bytes(),
        "schema_invalid",
    );
}
#[test]
fn negative_zero_is_an_integer() {
    let mut m = fixtures()["request"].clone();
    m["decision_index"] = json!(0);
    let encoded = encode_message(&m).unwrap();
    let raw = String::from_utf8(encoded.clone())
        .unwrap()
        .replace("\"decision_index\":0", "\"decision_index\":-0");
    assert_eq!(
        encode_message(&decode_message(raw.as_bytes()).unwrap()).unwrap(),
        encoded
    );
}
#[test]
fn unknown_version_is_explicit() {
    let mut m = fixtures()["request"].clone();
    m["schema_version"] = json!("3.0");
    assert_eq!(
        validate_message(&m).unwrap_err().code(),
        "version_incompatible"
    );
}
#[test]
fn replay_does_not_authorize_attempt_reuse() {
    let data = fixtures();
    let m = &data["request"];
    assert_eq!(compare_delivery(m, m).unwrap(), Delivery::Replay);
    let mut changed = m.clone();
    changed["message_id"] = json!("OTRO");
    assert_eq!(
        compare_delivery(m, &changed).unwrap_err().code(),
        "duplicate_conflict"
    );
    changed["attempt_id"] = json!("NUEVO");
    assert_eq!(compare_delivery(m, &changed).unwrap(), Delivery::New);
    assert_eq!(*m, fixtures()["request"]);
}
#[test]
fn correlation_rejects_other_identity_and_hash() {
    let data = fixtures();
    correlate(&data["request"], &data["result_completed"]).unwrap();
    correlate(&data["request"], &data["rejection"]).unwrap();
    let mut rejection = data["rejection"].clone();
    rejection["payload"]["rejected_sha256"] = json!("0".repeat(64));
    assert_eq!(
        correlate(&data["request"], &rejection).unwrap_err().code(),
        "integrity_failure"
    );
    let mut bad = data["result_completed"].clone();
    bad["record_id"] = json!("OTRO");
    assert_eq!(
        correlate(&data["request"], &bad).unwrap_err().code(),
        "identifier_mismatch"
    );
}

#[test]
fn midnight_rollover_matches_python314() {
    assert_eq!(
        timestamp(&json!("2024-02-29T24:00:00Z")).unwrap(),
        [2024, 3, 1, 0, 0, 0, 0]
    );
    assert_eq!(
        timestamp(&json!("2026-12-31T24:00:00.000000Z")).unwrap(),
        [2027, 1, 1, 0, 0, 0, 0]
    );
    for stamp in [
        "9999-12-31T24:00:00Z",
        "0000-12-31T24:00:00Z",
        "2026-01-00T24:00:00Z",
        "2026-00-01T24:00:00Z",
        "2026-04-31T24:00:00Z",
        "2026-01-01T24:00:00.000001Z",
    ] {
        assert_eq!(
            timestamp(&json!(stamp)).unwrap_err().code(),
            "schema_invalid"
        );
    }
}
