//! Pruebas de integración del puente simbólico P8-R62.
//!
//! Verifican identidades, denegaciones, catálogos y captura terminal.
//! No ejecutan clientes ni autorizan operaciones.

use ardrec_executor::contract_gate::PROFILE_IDS;
use ardrec_executor::p8_bounded_capture::Stream;
use ardrec_executor::p8_contract_bridge::{
    BridgeError, ContractBridge, summarize, symbolic_inventory,
};
use ardrec_executor::p8_resource_contract::{Limits, Violation};
use ardrec_executor::p8_terminal_capture::{Phase, TerminalError};

use serde_json::{Value, json};

const R10: &[u8] = include_bytes!("../../../lab/p8-profile-contract-v1/contracts.json");

const R13: &[u8] = include_bytes!("../../../lab/p8-cli-grammar-v1/spec.json");

fn bridge() -> ContractBridge {
    ContractBridge::new(R10, R13).unwrap()
}

fn limits() -> Limits {
    Limits {
        total_time_ms: 1_000,
        stdout_bytes: 32,
        stderr_bytes: 32,
        total_capture_bytes: 48,
        network_bytes: 100,
        result_entries: 3,
        attempts: 1,
    }
}

fn change_r10(action: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(R10).unwrap();
    action(&mut document);
    serde_json::to_vec(&document).unwrap()
}

fn change_r13(action: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(R13).unwrap();
    action(&mut document);
    serde_json::to_vec(&document).unwrap()
}

#[test]
fn real_r10_r13_catalogs_align_without_permission() {
    let b = bridge();

    assert_eq!(b.profile_count(), 29);
    assert!(!b.dispatch_allowed());

    let summary = summarize(&b);
    assert_eq!(summary.profiles, 29);
    assert_eq!(summary.authorized_profiles, 0);
    assert!(!summary.dispatch_allowed);

    let inventory = symbolic_inventory(&b);
    assert_eq!(inventory.len(), 29);

    for id in PROFILE_IDS {
        assert!(inventory.contains_key(id));
        assert!(b.operation_id(id).is_some());
    }
}

#[test]
fn unknown_profile_cannot_create_session() {
    let b = bridge();

    assert!(matches!(
        b.synthetic_case("SSH-T99-BASE", "UNKNOWN", limits()),
        Err(BridgeError::UnknownProfile)
    ));
}

#[test]
fn wrong_operation_cannot_create_session() {
    let b = bridge();
    let id = PROFILE_IDS[0];

    assert!(matches!(
        b.synthetic_case(id, "WRONG_OPERATION", limits()),
        Err(BridgeError::OperationMismatch)
    ));
}

#[test]
fn invalid_limits_cannot_create_session() {
    let b = bridge();
    let id = PROFILE_IDS[0];
    let operation = b.operation_id(id).unwrap();

    let mut invalid = limits();
    invalid.total_time_ms = 0;

    assert!(matches!(
        b.synthetic_case(id, operation, invalid),
        Err(BridgeError::InvalidBudget)
    ));
}

#[test]
fn matching_symbolic_session_remains_denied() {
    let b = bridge();

    for id in PROFILE_IDS {
        let operation = b.operation_id(id).unwrap();
        let mut session = b.synthetic_case(id, operation, limits()).unwrap();

        assert_eq!(session.profile_id(), id);
        assert_eq!(session.operation_id(), operation);
        assert!(!session.status().dispatch_allowed);

        session.begin_attempt().unwrap();
        session.push(Stream::Stdout, b"synthetic").unwrap();
        session.account_network_bytes(10).unwrap();
        session.account_result_entry().unwrap();
        session.observe_elapsed_ms(200).unwrap();

        assert_eq!(session.status().phase, Phase::Active);
        assert_eq!(session.stdout(), b"synthetic");
        assert!(session.stderr().is_empty());
        assert!(!session.status().dispatch_allowed);
    }
}

#[test]
fn failed_session_is_permanently_aborted() {
    let b = bridge();
    let id = PROFILE_IDS[0];
    let operation = b.operation_id(id).unwrap();
    let mut session = b.synthetic_case(id, operation, limits()).unwrap();

    session.begin_attempt().unwrap();
    session.push(Stream::Stdout, &[7; 32]).unwrap();

    assert!(matches!(
        session.push(Stream::Stdout, b"x"),
        Err(TerminalError::Rejected(
            ardrec_executor::p8_bounded_capture::CaptureError::LimitExceeded(
                Violation::StdoutExceeded
            )
        ))
    ));

    assert_eq!(session.status().phase, Phase::Aborted);

    assert_eq!(
        session.account_network_bytes(0),
        Err(TerminalError::AlreadyAborted)
    );

    assert_eq!(session.begin_attempt(), Err(TerminalError::AlreadyAborted));

    assert_eq!(session.stdout().len(), 32);
    assert!(!session.status().dispatch_allowed);
}

#[test]
fn malformed_json_is_denied() {
    assert!(matches!(
        ContractBridge::new(b"{", R13),
        Err(BridgeError::InvalidJson)
    ));
}

#[test]
fn empty_or_oversized_documents_are_denied() {
    assert!(matches!(
        ContractBridge::new(b"", R13),
        Err(BridgeError::InputSize)
    ));

    let oversized = vec![b' '; ardrec_executor::p8_contract_bridge::MAX_CONTRACT_BYTES + 1];

    assert!(matches!(
        ContractBridge::new(&oversized, R13),
        Err(BridgeError::InputSize)
    ));
}

#[test]
fn duplicate_json_keys_are_denied() {
    let original = change_r13(|_| {});
    let source = String::from_utf8(original).unwrap();

    let duplicate = source.replacen(
        "\"profile_count\":29",
        "\"profile_count\":29,\"profile_count\":29",
        1,
    );

    assert_ne!(duplicate, source);

    assert!(matches!(
        ContractBridge::new(R10, duplicate.as_bytes()),
        Err(BridgeError::DuplicateKey)
    ));
}

#[test]
fn missing_profile_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"].as_array_mut().unwrap().pop();
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn reordered_profiles_are_denied() {
    let altered = change_r13(|root| {
        root["profiles"].as_array_mut().unwrap().swap(0, 1);
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn mismatched_operation_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["semantic_operation_id"] = json!("UNRELATED_OPERATION");
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn mismatched_protocol_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["protocol"] = json!("SMB");
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn nonempty_cli_options_are_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["accepted_cli_options"] = json!(["--unexpected"]);
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn materialized_argv_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["argv_template"] = json!(["binary", "--help"]);
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn runtime_permission_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["runtime_permission"] = json!(true);
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn raw_command_permission_is_denied() {
    let altered = change_r10(|root| {
        root["profiles"][0]["argument_contract"]["raw_command_strings_allowed"] = json!(true);
    });

    assert!(matches!(
        ContractBridge::new(&altered, R13),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn materialized_target_is_denied() {
    let altered = change_r10(|root| {
        root["profiles"][0]["execution_boundary"]["approved_target"] = json!("synthetic-target");
    });

    assert!(matches!(
        ContractBridge::new(&altered, R13),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn materialized_resource_budget_is_denied() {
    let altered = change_r10(|root| {
        root["profiles"][0]["execution_boundary"]["resource_budget"] = json!({"attempts": 1});
    });

    assert!(matches!(
        ContractBridge::new(&altered, R13),
        Err(BridgeError::ExecutableMaterial)
    ));
}

#[test]
fn authorization_claim_in_r10_is_denied() {
    let altered = change_r10(|root| {
        root["authorized_cases"] = json!(1);
    });

    assert!(ContractBridge::new(&altered, R13).is_err());
}

#[test]
fn authorization_claim_in_r13_is_denied() {
    let altered = change_r13(|root| {
        root["authorized_profiles"] = json!(1);
    });

    assert!(ContractBridge::new(R10, &altered).is_err());
}

#[test]
fn r10_protocol_must_remain_canonical_lowercase() {
    let altered = change_r10(|root| {
        root["profiles"][0]["protocol"] = json!("SSH");
    });

    assert!(matches!(
        ContractBridge::new(&altered, R13),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn r13_protocol_must_remain_canonical_uppercase() {
    let altered = change_r13(|root| {
        root["profiles"][0]["protocol"] = json!("ssh");
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::ProfileMismatch)
    ));
}

#[test]
fn unknown_extra_profile_field_is_denied() {
    let altered = change_r13(|root| {
        root["profiles"][0]["unexpected"] = json!(true);
    });

    assert!(matches!(
        ContractBridge::new(R10, &altered),
        Err(BridgeError::InvalidSchema)
    ));
}
