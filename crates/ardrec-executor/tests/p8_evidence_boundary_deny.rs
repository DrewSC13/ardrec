//! Pruebas de integración de evidencia documental P8-R65.
//!
//! Confirman identidad, separación de catálogos y denegación.

use ardrec_executor::p8_evidence_boundary::{
    DOCUMENT_COUNT, EvidenceError, repository_sources, review,
};

#[test]
fn historical_sources_remain_unproven_and_denied() {
    let result = review(&repository_sources()).unwrap();

    assert_eq!(result.documents, 14);
    assert_eq!(result.profiles, 29);
    assert_eq!(result.candidate_materials, 15);
    assert_eq!(result.r35_terms, 39);
    assert_eq!(result.documentary_questions, 312);
    assert_eq!(result.unbound_material_fields, 348);
    assert_eq!(result.unverified_runtime_gates, 261);
    assert_eq!(result.cleanup_unproven, 5);
    assert_eq!(result.unmapped_r13_r35_terms, 22);

    assert!(!result.semantic_crosswalk_verified);
    assert_eq!(result.authorized_cases, 0);
    assert_eq!(result.verified_operational_capabilities, 0);
    assert!(!result.dispatch_allowed);
}

#[test]
fn sources_are_statically_pinned() {
    let sources = repository_sources();

    assert_eq!(sources.documents.len(), DOCUMENT_COUNT);

    for doc in sources.documents {
        assert!(!doc.is_empty());
    }
}

#[test]
fn r10_substitution_is_rejected() {
    let mut sources = repository_sources();
    sources.r10 = b"{}";

    assert_eq!(review(&sources), Err(EvidenceError::CatalogDrift));
}

#[test]
fn r12_substitution_is_rejected() {
    let mut sources = repository_sources();
    sources.r12 = b"{}";

    assert_eq!(review(&sources), Err(EvidenceError::CatalogDrift));
}

#[test]
fn r13_substitution_is_rejected() {
    let mut sources = repository_sources();
    sources.r13 = b"{}";

    assert_eq!(review(&sources), Err(EvidenceError::CatalogDrift));
}

#[test]
fn coordinated_catalog_substitution_is_rejected() {
    let mut sources = repository_sources();

    sources.r10 = b"{}";
    sources.r12 = b"{}";
    sources.r13 = b"{}";

    assert_eq!(review(&sources), Err(EvidenceError::CatalogDrift));
}

#[test]
fn each_document_has_an_independent_identity_guard() {
    for index in 0..DOCUMENT_COUNT {
        let mut sources = repository_sources();

        sources.documents[index] = b"{}";

        assert_eq!(review(&sources), Err(EvidenceError::SnapshotDrift(index)));
    }
}

#[test]
fn swapped_documents_are_rejected() {
    let mut sources = repository_sources();
    sources.documents.swap(0, 1);

    assert_eq!(review(&sources), Err(EvidenceError::SnapshotDrift(0)));
}

#[test]
fn forged_material_authorization_is_rejected() {
    let mut sources = repository_sources();

    let mut value: serde_json::Value = serde_json::from_slice(sources.documents[0]).unwrap();

    value["authorized_case_count"] = serde_json::json!(1);

    let altered = serde_json::to_vec(&value).unwrap();
    sources.documents[0] = &altered;

    assert_eq!(review(&sources), Err(EvidenceError::SnapshotDrift(0)));
}

#[test]
fn forged_operational_capability_is_rejected() {
    let mut sources = repository_sources();

    let mut value: serde_json::Value = serde_json::from_slice(sources.documents[10]).unwrap();

    value["operational_capability_verified"] = serde_json::json!(true);

    let altered = serde_json::to_vec(&value).unwrap();
    sources.documents[10] = &altered;

    assert_eq!(review(&sources), Err(EvidenceError::SnapshotDrift(10)));
}

#[test]
fn forged_r35_semantic_certification_is_rejected() {
    let mut sources = repository_sources();

    let mut value: serde_json::Value = serde_json::from_slice(sources.documents[13]).unwrap();

    value["entries"][0]["term_semantic_certified"] = serde_json::json!(true);

    let altered = serde_json::to_vec(&value).unwrap();
    sources.documents[13] = &altered;

    assert_eq!(review(&sources), Err(EvidenceError::SnapshotDrift(13)));
}

#[test]
fn repeated_review_never_authorizes() {
    let sources = repository_sources();

    let first = review(&sources).unwrap();
    let second = review(&sources).unwrap();

    assert_eq!(first, second);
    assert!(!first.dispatch_allowed);
    assert!(!second.semantic_crosswalk_verified);
}
