//! ARDREC: synthetic denial tests, no dispatch or network.
//! Synthetic deny-only contract tests; no dispatch, network or VM access.

use ardrec_executor::contract_gate::{
    ArgToken, Auxiliary, Budget, Cleanup, Decision, Definition, Draft, Finding, Observation,
    PROFILE_IDS, Protocol, Variant, review,
};

const BASE_SLOTS: [&str; 2] = ["authorization_ref", "target_ref"];
const BASE_PRE: [&str; 3] = [
    "SCOPE_APPROVED",
    "LAB_ISOLATION_CONFIRMED",
    "DESTINATION_AUTHORIZED",
];
const BASE_SUPPORTS: [&str; 2] = ["TARGET_ATTESTATION", "INTEGRITY_PROVENANCE"];
const WRITE_PRE: [&str; 2] = ["SCOPE_APPROVED", "CLEANUP_VERIFIABLE"];
const WRITE_SUPPORTS: [&str; 3] = ["MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"];

fn descriptor() -> Definition<'static> {
    Definition {
        profile_id: "SSH-T01-BASE",
        family_id: "SSH-T01",
        protocol: Protocol::Ssh,
        variant: None,
        cleanup: Cleanup::NoMutation,
        required_material_slots: &BASE_SLOTS,
        required_preconditions: &BASE_PRE,
        required_supports: &BASE_SUPPORTS,
        status: "BLOCKED_UNBOUND_NO_EXECUTION",
    }
}

fn draft() -> Draft {
    Draft {
        executable_absolute_path: Some("/usr/bin/ssh".into()),
        executable_sha256: Some("a".repeat(64)),
        executable_version: Some("OpenSSH 10.0".into()),
        argv_typed_vector: Some(vec![
            ArgToken::Literal("-G".into()),
            ArgToken::MaterialSlot("target_ref".into()),
        ]),
        working_directory: Some("/home/ardrec-audit".into()),
        environment_allowlist: Some(vec![("LC_ALL".into(), "C".into())]),
        auxiliary_executables: Some(vec![]),
        case_authorization_ref: Some("ref:synthetic-case".into()),
        approved_target_ref: Some("ref:synthetic-target".into()),
        fixed_resource_budget: Some(Budget {
            max_attempts: 1,
            timeout_ms: 5000,
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        }),
        capture_policy_ref: Some("ref:synthetic-capture".into()),
        cleanup_receipt_ref: Some("ref:synthetic-cleanup".into()),
    }
}

fn observed() -> Vec<(&'static str, Observation)> {
    BASE_PRE.iter().map(|s| (*s, Observation::True)).collect()
}

fn findings(def: &Definition<'_>, draft: &Draft, obs: &[(&str, Observation)]) -> Vec<Finding> {
    let r = review(def, draft, obs);
    assert_eq!(r.decision, Decision::BlockedUnboundNoExecution);
    assert!(!r.dispatch_allowed);
    assert!(!r.authorized);
    assert!(r.findings.contains(&Finding::AuthorizationUnavailable));
    r.findings
}

#[test]
fn valid_synthetic_draft_still_denied() {
    assert_eq!(
        findings(&descriptor(), &draft(), &observed()),
        vec![Finding::AuthorizationUnavailable]
    );
}

#[test]
fn all_29_profile_ids_still_denied() {
    for id in PROFILE_IDS {
        let mut d = descriptor();
        d.profile_id = id;
        d.family_id = id.split_once('-').map(|_| &id[..7]).unwrap_or("");
        // Profile inventory is only a deny-only input; other fields are placeholders.
        findings(&d, &draft(), &observed());
    }
}

#[test]
fn frozen_profile_inventory_exact() {
    let text = include_str!("fixtures/contract_gate_profile_ids.txt");
    let ids: Vec<_> = text.lines().collect();
    assert_eq!(ids.len(), 29);
    assert_eq!(ids.as_slice(), PROFILE_IDS.as_slice());
}

#[test]
fn missing_fields_denied() {
    let empty = Draft::default();
    let result = findings(&descriptor(), &empty, &observed());
    assert_eq!(
        result
            .iter()
            .filter(|f| matches!(f, Finding::MissingField(_)))
            .count(),
        12
    );
}

#[test]
fn shell_binary_denied() {
    for shell in [
        "/usr/bin/bash",
        "/usr/bin/sh",
        "/usr/bin/env",
        "/usr/bin/busybox",
    ] {
        let mut d = draft();
        d.executable_absolute_path = Some(shell.into());
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidExecutable));
    }
}

#[test]
fn relative_and_traversal_binary_denied() {
    for bad in [
        "ssh",
        "/usr/bin/../bin/ssh",
        "/usr/bin//ssh",
        "/opt/ssh",
        "/usr/bin/ssh\\x",
    ] {
        let mut d = draft();
        d.executable_absolute_path = Some(bad.into());
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidExecutable));
    }
}

#[test]
fn malformed_sha_denied() {
    for bad in ["abc".to_string(), "G".repeat(64), "A".repeat(64)] {
        let mut d = draft();
        d.executable_sha256 = Some(bad);
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidSha256));
    }
}

#[test]
fn version_control_characters_denied() {
    let mut d = draft();
    d.executable_version = Some("version\n--malicious".into());
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidVersion));
}

#[test]
fn shell_metacharacter_in_literal_denied() {
    for bad in [
        "a|b",
        "$(whoami)",
        "hello;world",
        "hello world",
        "`id`",
        "\\x",
    ] {
        let mut d = draft();
        d.argv_typed_vector = Some(vec![ArgToken::Literal(bad.into())]);
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidArguments));
    }
}

#[test]
fn raw_string_args_not_representable() {
    let d = draft();
    assert!(matches!(
        &d.argv_typed_vector.unwrap()[0],
        ArgToken::Literal(_)
    ));
}

#[test]
fn undeclared_slot_denied() {
    let mut d = draft();
    d.argv_typed_vector = Some(vec![ArgToken::MaterialSlot("unknown".into())]);
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidArguments));
}

#[test]
fn duplicate_slot_denied() {
    let mut d = draft();
    d.argv_typed_vector = Some(vec![
        ArgToken::MaterialSlot("target_ref".into()),
        ArgToken::MaterialSlot("target_ref".into()),
    ]);
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidArguments));
}

#[test]
fn empty_or_unbounded_argv_denied() {
    for args in [vec![], vec![ArgToken::Literal("one".into()); 25]] {
        let mut d = draft();
        d.argv_typed_vector = Some(args);
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidArguments));
    }
}

#[test]
fn inherited_env_and_duplicates_denied() {
    for env in [
        vec![("PATH".into(), "/bin".into())],
        vec![("LD_PRELOAD".into(), "x".into())],
        vec![("LANG".into(), "C".into()), ("LANG".into(), "C".into())],
    ] {
        let mut d = draft();
        d.environment_allowlist = Some(env);
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidEnvironment));
    }
}

#[test]
fn helper_must_have_hash_and_path() {
    let mut d = draft();
    d.auxiliary_executables = Some(vec![Auxiliary {
        path: "/usr/bin/bash".into(),
        sha256: "a".repeat(64),
    }]);
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidAuxiliary));
    d.auxiliary_executables = Some(vec![Auxiliary {
        path: "/usr/bin/ssh".into(),
        sha256: "bad".into(),
    }]);
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidAuxiliary));
}

#[test]
fn duplicates_and_too_many_helpers_denied() {
    let h = Auxiliary {
        path: "/usr/bin/ssh".into(),
        sha256: "a".repeat(64),
    };
    for list in [vec![h.clone(), h.clone()], vec![h; 9]] {
        let mut d = draft();
        d.auxiliary_executables = Some(list);
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidAuxiliary));
    }
}

#[test]
fn raw_url_and_traversal_references_denied() {
    for bad in [
        "https://example.invalid",
        "ref:../../etc/passwd",
        "secret-value",
        "ref:x",
    ] {
        let mut d = draft();
        d.approved_target_ref = Some(bad.into());
        assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidReference));
    }
}

#[test]
fn retry_and_zero_budget_denied() {
    let mut d = draft();
    d.fixed_resource_budget = Some(Budget {
        max_attempts: 2,
        timeout_ms: 0,
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
    });
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidBudget));
}

#[test]
fn oversized_budget_denied() {
    let mut d = draft();
    d.fixed_resource_budget = Some(Budget {
        max_attempts: 1,
        timeout_ms: 60_001,
        max_stdout_bytes: 1_048_577,
        max_stderr_bytes: 1_048_577,
    });
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidBudget));
}

#[test]
fn not_determined_never_passes_preconditions() {
    let obs = vec![
        ("SCOPE_APPROVED", Observation::NotDetermined),
        ("LAB_ISOLATION_CONFIRMED", Observation::True),
        ("DESTINATION_AUTHORIZED", Observation::True),
    ];
    assert!(findings(&descriptor(), &draft(), &obs).contains(&Finding::UnmetPreconditions));
}

#[test]
fn false_precondition_never_passes() {
    let obs = vec![
        ("SCOPE_APPROVED", Observation::False),
        ("LAB_ISOLATION_CONFIRMED", Observation::True),
        ("DESTINATION_AUTHORIZED", Observation::True),
    ];
    assert!(findings(&descriptor(), &draft(), &obs).contains(&Finding::UnmetPreconditions));
}

#[test]
fn missing_and_duplicate_preconditions_denied() {
    let obs = vec![("SCOPE_APPROVED", Observation::True)];
    assert!(findings(&descriptor(), &draft(), &obs).contains(&Finding::UnmetPreconditions));
    let obs = vec![("SCOPE_APPROVED", Observation::True); 3];
    assert!(findings(&descriptor(), &draft(), &obs).contains(&Finding::UnmetPreconditions));
}

#[test]
fn unknown_profile_denied() {
    let mut desc = descriptor();
    desc.profile_id = "SSH-T99-BASE";
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidProfile));
}

#[test]
fn modified_status_denied() {
    let mut desc = descriptor();
    desc.status = "APPROVED";
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidProfileStatus));
}

#[test]
fn mutation_requires_cleanup_and_marker_evidence() {
    let mut desc = descriptor();
    desc.profile_id = "SSH-T07-BASE";
    desc.family_id = "SSH-T07";
    desc.cleanup = Cleanup::VerifyThenRemoveMarker;
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidDefinition));
    desc.required_supports = &WRITE_SUPPORTS;
    desc.required_preconditions = &WRITE_PRE;
    assert!(!findings(&desc, &draft(), &observed()).contains(&Finding::InvalidDefinition));
}

#[test]
fn read_write_variant_mismatch_denied() {
    let mut desc = descriptor();
    desc.profile_id = "FTP-T08-WRITE";
    desc.family_id = "FTP-T08";
    desc.protocol = Protocol::Ftp;
    desc.variant = Some(Variant::Write);
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidDefinition));
}

#[test]
fn signing_variant_mismatch_denied() {
    let mut desc = descriptor();
    desc.profile_id = "SMB-T03-SIGNING";
    desc.family_id = "SMB-T03";
    desc.protocol = Protocol::Smb;
    desc.variant = Some(Variant::Signing);
    // An independently valid definition does not imply any negotiated SMB signature.
    findings(&desc, &draft(), &observed());
}

#[test]
fn privileges_without_explicit_scope_denied() {
    static P: [&str; 1] = ["PRIVILEGE_SCOPE"];
    let mut desc = descriptor();
    desc.required_supports = &P;
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidDefinition));
}

#[test]
fn duplicate_definition_fields_denied() {
    static D: [&str; 2] = ["TARGET_ATTESTATION", "TARGET_ATTESTATION"];
    let mut desc = descriptor();
    desc.required_supports = &D;
    assert!(findings(&desc, &draft(), &observed()).contains(&Finding::InvalidDefinition));
}

#[test]
fn write_workdir_usr_denied() {
    let mut d = draft();
    d.working_directory = Some("/usr/bin".into());
    assert!(findings(&descriptor(), &d, &observed()).contains(&Finding::InvalidExecutable));
}
