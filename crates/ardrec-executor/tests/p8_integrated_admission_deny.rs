//! Pruebas de integración de la admisión P8-R73.
//! No ejecutan comandos, clientes ni operaciones de red.

use ardrec_executor::contract_gate::PROFILE_IDS;
use ardrec_executor::p8_evidence_boundary::repository_sources;
use ardrec_executor::p8_integrated_admission::{
    AdmissionBlocker, ConfigurationMode, EnvironmentMode, RequestSurface, inspect_profile,
};

fn evaluate(
    profile: &str,
    surface: RequestSurface,
) -> ardrec_executor::p8_integrated_admission::AdmissionReview {
    inspect_profile(profile, &repository_sources(), surface)
}

#[test]
fn every_registered_profile_is_denied() {
    assert_eq!(PROFILE_IDS.len(), 29);

    for profile in PROFILE_IDS {
        let review = evaluate(profile, RequestSurface::default());

        assert_eq!(review.profile_id, profile);
        assert!(review.symbolic_operation.is_some());
        assert!(!review.authorized);
        assert!(!review.dispatch_allowed);
        assert_eq!(review.unbound_fields_per_profile, 12);
        assert_eq!(review.unverified_gates_per_profile, 9);
        assert_eq!(review.unresolved_documentary_references, 22);

        assert!(
            review
                .blockers
                .contains(&AdmissionBlocker::MaterialBindingsUnverified)
        );

        assert!(
            review
                .blockers
                .contains(&AdmissionBlocker::RuntimeProofsUnverified)
        );

        assert!(
            review
                .blockers
                .contains(&AdmissionBlocker::CaseAuthorizationAbsent)
        );
    }
}

#[test]
fn unknown_profile_is_denied() {
    let review = evaluate("SSH-UNKNOWN", RequestSurface::default());

    assert!(review.symbolic_operation.is_none());
    assert!(review.blockers.contains(&AdmissionBlocker::UnknownProfile));
    assert!(!review.dispatch_allowed);
}

#[test]
fn empty_profile_is_denied() {
    let review = evaluate("", RequestSurface::default());

    assert!(review.blockers.contains(&AdmissionBlocker::UnknownProfile));
    assert!(!review.authorized);
}

#[test]
fn implicit_configuration_is_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            configuration: ConfigurationMode::ImplicitDefault,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::ConfigurationImportForbidden)
    );
    assert!(!review.dispatch_allowed);
}

#[test]
fn explicit_file_import_is_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            configuration: ConfigurationMode::ExplicitFile,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::ConfigurationImportForbidden)
    );
}

#[test]
fn stdin_configuration_is_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            configuration: ConfigurationMode::StandardInput,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::ConfigurationImportForbidden)
    );
}

#[test]
fn claimed_isolation_is_not_proof() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            configuration: ConfigurationMode::ClaimedIsolated,
            environment: EnvironmentMode::ClaimedClean,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::ConfigurationNotVerified)
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::EnvironmentNotVerified)
    );

    assert!(!review.authorized);
}

#[test]
fn inherited_environment_is_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            environment: EnvironmentMode::Inherited,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::InheritedEnvironmentForbidden)
    );
}

#[test]
fn materialized_arguments_are_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            materialized_arguments: 1,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::MaterializedArgumentsForbidden)
    );
}

#[test]
fn shell_and_remote_commands_are_forbidden() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            uses_shell: true,
            remote_command_present: true,
            ..RequestSurface::default()
        },
    );

    assert!(review.blockers.contains(&AdmissionBlocker::ShellForbidden));

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::RemoteCommandForbidden)
    );
}

#[test]
fn targets_and_auxiliaries_require_proof() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            unapproved_target_present: true,
            unverified_auxiliaries_present: true,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::TargetNotAuthorized)
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::AuxiliariesUnverified)
    );
}

#[test]
fn credentials_and_dispatch_are_denied() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            credential_delivery_requested: true,
            dispatch_requested: true,
            ..RequestSurface::default()
        },
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::CredentialDeliveryUnverified)
    );

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::DispatchForbidden)
    );

    assert!(!review.dispatch_allowed);
}

#[test]
fn all_risky_surfaces_report_independent_blockers() {
    let review = evaluate(
        PROFILE_IDS[0],
        RequestSurface {
            configuration: ConfigurationMode::ExplicitFile,
            environment: EnvironmentMode::Inherited,
            materialized_arguments: 3,
            uses_shell: true,
            remote_command_present: true,
            unapproved_target_present: true,
            unverified_auxiliaries_present: true,
            credential_delivery_requested: true,
            dispatch_requested: true,
        },
    );

    assert_eq!(review.blockers.len(), 12);
    assert!(!review.authorized);
    assert!(!review.dispatch_allowed);
}

#[test]
fn modified_r10_is_rejected_before_profile_review() {
    let mut sources = repository_sources();
    sources.r10 = b"{}";

    let review = inspect_profile(PROFILE_IDS[0], &sources, RequestSurface::default());

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::DocumentaryBoundaryRejected)
    );
    assert!(review.symbolic_operation.is_none());
}

#[test]
fn modified_r12_is_rejected_before_profile_review() {
    let mut sources = repository_sources();
    sources.r12 = b"{}";

    let review = inspect_profile(PROFILE_IDS[0], &sources, RequestSurface::default());

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::DocumentaryBoundaryRejected)
    );
}

#[test]
fn modified_r35_is_rejected_before_profile_review() {
    let mut sources = repository_sources();

    sources.documents[13] = b"{}";

    let review = inspect_profile(PROFILE_IDS[0], &sources, RequestSurface::default());

    assert!(
        review
            .blockers
            .contains(&AdmissionBlocker::DocumentaryBoundaryRejected)
    );
}

#[test]
fn repeated_assessments_are_deterministic() {
    let sources = repository_sources();
    let surface = RequestSurface::default();

    let first = inspect_profile(PROFILE_IDS[0], &sources, surface);
    let second = inspect_profile(PROFILE_IDS[0], &sources, surface);

    assert_eq!(first, second);
    assert!(!first.dispatch_allowed);
}

#[test]
fn no_blocker_can_be_duplicated() {
    let review = evaluate(PROFILE_IDS[0], RequestSurface::default());

    for (index, blocker) in review.blockers.iter().enumerate() {
        assert!(!review.blockers[index + 1..].contains(blocker));
    }
}
