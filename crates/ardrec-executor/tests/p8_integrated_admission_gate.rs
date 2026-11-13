//! Pruebas directas del enlace entre el gate tipado y P8.
//!
//! Todos los datos son sintéticos. No hay ejecución de clientes.

use ardrec_executor::contract_gate::{
    self, ArgToken, Budget, Cleanup, Definition, Draft, Finding, Observation, Protocol,
};
use ardrec_executor::p8_evidence_boundary::{EvidenceSources, repository_sources};
use ardrec_executor::p8_integrated_admission::{
    AdmissionBlocker, AdmissionReview, ConfigurationMode, EnvironmentMode, RequestSurface,
    review_draft,
};

const SLOTS: [&str; 2] = ["authorization_ref", "target_ref"];

const PRECONDITIONS: [&str; 3] = [
    "SCOPE_APPROVED",
    "LAB_ISOLATION_CONFIRMED",
    "DESTINATION_AUTHORIZED",
];

const SUPPORTS: [&str; 2] = ["TARGET_ATTESTATION", "INTEGRITY_PROVENANCE"];

fn descriptor() -> Definition<'static> {
    Definition {
        profile_id: "SSH-T01-BASE",
        family_id: "SSH-T01",
        protocol: Protocol::Ssh,
        variant: None,
        cleanup: Cleanup::NoMutation,
        required_material_slots: &SLOTS,
        required_preconditions: &PRECONDITIONS,
        required_supports: &SUPPORTS,
        status: "BLOCKED_UNBOUND_NO_EXECUTION",
    }
}

fn synthetic_draft() -> Draft {
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

fn observations() -> Vec<(&'static str, Observation)> {
    PRECONDITIONS
        .iter()
        .map(|name| (*name, Observation::True))
        .collect()
}

fn integrated(
    def: &Definition<'_>,
    draft: &Draft,
    observed: &[(&str, Observation)],
    sources: &EvidenceSources<'_>,
    surface: RequestSurface,
) -> AdmissionReview {
    review_draft(def, draft, observed, sources, surface)
}

fn assert_gate_preserved(
    def: &Definition<'_>,
    draft: &Draft,
    observed: &[(&str, Observation)],
    surface: RequestSurface,
) -> AdmissionReview {
    let gate = contract_gate::review(def, draft, observed);

    let result = integrated(def, draft, observed, &repository_sources(), surface);

    assert_eq!(result.contract_finding_details, gate.findings);

    assert_eq!(
        result.contract_findings,
        result.contract_finding_details.len()
    );

    assert!(!result.authorized);
    assert!(!result.dispatch_allowed);

    result
}

fn assert_structural_block(result: &AdmissionReview, finding: Finding) {
    assert!(
        result.contract_finding_details.contains(&finding),
        "Missing gate finding: {finding:?}"
    );

    assert!(
        result
            .blockers
            .contains(&AdmissionBlocker::ContractGateFindingsPresent),
        "Structural finding was not reported"
    );

    assert!(!result.authorized);
    assert!(!result.dispatch_allowed);
}

#[test]
fn syntactically_valid_draft_retains_only_inevitable_denial() {
    let result = assert_gate_preserved(
        &descriptor(),
        &synthetic_draft(),
        &observations(),
        RequestSurface::default(),
    );

    assert_eq!(
        result.contract_finding_details,
        vec![Finding::AuthorizationUnavailable]
    );

    assert_eq!(result.contract_findings, 1);

    assert!(
        !result
            .blockers
            .contains(&AdmissionBlocker::ContractGateFindingsPresent)
    );

    assert_eq!(result.unbound_fields_per_profile, 12);
    assert_eq!(result.unverified_gates_per_profile, 9);
    assert_eq!(result.unresolved_documentary_references, 22);
}

#[test]
fn missing_material_field_is_preserved() {
    let mut draft = synthetic_draft();
    draft.executable_sha256 = None;

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::MissingField("executable_sha256"));
}

#[test]
fn malformed_executable_hash_is_preserved() {
    let mut draft = synthetic_draft();
    draft.executable_sha256 = Some("bad".into());

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidSha256);
}

#[test]
fn forbidden_shell_binary_is_reported_by_gate() {
    let mut draft = synthetic_draft();
    draft.executable_absolute_path = Some("/bin/sh".into());

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidExecutable);
}

#[test]
fn inherited_environment_is_reported_by_gate() {
    let mut draft = synthetic_draft();

    draft.environment_allowlist = Some(vec![("PATH".into(), "/bin".into())]);

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface {
            environment: EnvironmentMode::Inherited,
            ..RequestSurface::default()
        },
    );

    assert_structural_block(&result, Finding::InvalidEnvironment);

    assert!(
        result
            .blockers
            .contains(&AdmissionBlocker::InheritedEnvironmentForbidden)
    );
}

#[test]
fn invalid_resource_budget_remains_distinguishable() {
    let mut draft = synthetic_draft();

    draft.fixed_resource_budget = Some(Budget {
        max_attempts: 2,
        timeout_ms: 0,
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
    });

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidBudget);
}

#[test]
fn missing_precondition_is_preserved() {
    let observed = vec![("SCOPE_APPROVED", Observation::True)];

    let result = assert_gate_preserved(
        &descriptor(),
        &synthetic_draft(),
        &observed,
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::UnmetPreconditions);
}

#[test]
fn undetermined_precondition_never_grants_authority() {
    let mut observed = observations();

    observed[0].1 = Observation::NotDetermined;

    let result = assert_gate_preserved(
        &descriptor(),
        &synthetic_draft(),
        &observed,
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::UnmetPreconditions);
}

#[test]
fn duplicated_precondition_is_rejected() {
    let mut observed = observations();

    observed.push(("SCOPE_APPROVED", Observation::True));

    let result = assert_gate_preserved(
        &descriptor(),
        &synthetic_draft(),
        &observed,
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::UnmetPreconditions);
}

#[test]
fn modified_profile_status_is_preserved() {
    let mut def = descriptor();
    def.status = "READY";

    let result = assert_gate_preserved(
        &def,
        &synthetic_draft(),
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidProfileStatus);
}

#[test]
fn unknown_profile_reports_both_layers() {
    let mut def = descriptor();
    def.profile_id = "SSH-UNKNOWN";

    let result = assert_gate_preserved(
        &def,
        &synthetic_draft(),
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidProfile);

    assert!(result.blockers.contains(&AdmissionBlocker::UnknownProfile));
}

#[test]
fn invalid_reference_cannot_be_hidden() {
    let mut draft = synthetic_draft();

    draft.approved_target_ref = Some("https://example.invalid".into());

    let result = assert_gate_preserved(
        &descriptor(),
        &draft,
        &observations(),
        RequestSurface::default(),
    );

    assert_structural_block(&result, Finding::InvalidReference);
}

#[test]
fn documentary_failure_does_not_erase_gate_findings() {
    let mut sources = repository_sources();

    sources.documents[13] = b"{}";

    let mut draft = synthetic_draft();
    draft.executable_sha256 = None;

    let gate = contract_gate::review(&descriptor(), &draft, &observations());

    let result = integrated(
        &descriptor(),
        &draft,
        &observations(),
        &sources,
        RequestSurface::default(),
    );

    assert_eq!(result.contract_finding_details, gate.findings);

    assert_structural_block(&result, Finding::MissingField("executable_sha256"));

    assert!(
        result
            .blockers
            .contains(&AdmissionBlocker::DocumentaryBoundaryRejected)
    );
}

#[test]
fn multiple_independent_findings_preserve_order() {
    let mut draft = synthetic_draft();

    draft.executable_sha256 = None;
    draft.environment_allowlist = Some(vec![("LD_PRELOAD".into(), "unsafe".into())]);

    let observed = vec![("SCOPE_APPROVED", Observation::False)];

    let result = assert_gate_preserved(&descriptor(), &draft, &observed, RequestSurface::default());

    assert_eq!(
        result.contract_finding_details,
        vec![
            Finding::MissingField("executable_sha256"),
            Finding::InvalidEnvironment,
            Finding::UnmetPreconditions,
            Finding::AuthorizationUnavailable,
        ]
    );

    assert_eq!(result.contract_findings, 4);
}

#[test]
fn repeated_draft_review_is_deterministic_and_denied() {
    let def = descriptor();
    let draft = synthetic_draft();
    let obs = observations();
    let sources = repository_sources();

    let surface = RequestSurface {
        configuration: ConfigurationMode::ExplicitFile,
        environment: EnvironmentMode::Inherited,
        dispatch_requested: true,
        ..RequestSurface::default()
    };

    let first = integrated(&def, &draft, &obs, &sources, surface);

    let second = integrated(&def, &draft, &obs, &sources, surface);

    assert_eq!(first, second);

    assert!(
        first
            .blockers
            .contains(&AdmissionBlocker::ConfigurationImportForbidden)
    );

    assert!(
        first
            .blockers
            .contains(&AdmissionBlocker::DispatchForbidden)
    );

    assert!(!first.authorized);
    assert!(!first.dispatch_allowed);
}
