//! P8-R65: frontera de evidencia documental no autorizante.
//!
//! Valida instantáneas R9/R17-R25/R35, la continuidad R12-R13
//! y el puente simbólico R10-R13.
//!
//! No acredita capacidades, configuraciones efectivas, permisos,
//! procedencia externa ni correspondencia semántica R13-R35.
//! No ejecuta clientes, procesos o actividades de red.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::contract_gate::PROFILE_IDS;
use crate::p8_contract_bridge::ContractBridge;

/// Cantidad de documentos de metadatos R64.
pub const DOCUMENT_COUNT: usize = 14;

const R10: &[u8] = include_bytes!("../../../lab/p8-profile-contract-v1/contracts.json");
const R12: &[u8] = include_bytes!("../../../lab/p8-cli-semantics-v1/semantics.json");
const R13: &[u8] = include_bytes!("../../../lab/p8-cli-grammar-v1/spec.json");

const DOCUMENTS: [&[u8]; DOCUMENT_COUNT] = [
    include_bytes!("../../../lab/p8-material-inventory-v1/inventory.json"),
    include_bytes!("../../../lab/p8-material-attestation-v1/contract.json"),
    include_bytes!("../../../lab/p8-binding-contract-v1/contract.json"),
    include_bytes!("../../../lab/p8-r17-material-closure-v1/spec.json"),
    include_bytes!("../../../lab/p8-r18-elf-metadata-v1/spec.json"),
    include_bytes!("../../../lab/p8-r19-offline-graph-v1/spec.json"),
    include_bytes!("../../../lab/p8-r20-samba-candidate-v1/spec.json"),
    include_bytes!("../../../lab/p8-r21-multiarch-reconcile-v1/spec.json"),
    include_bytes!("../../../lab/p8-r22-loader-boundary-v1/spec.json"),
    include_bytes!("../../../lab/p8-r23-profile-obligations-v1/spec.json"),
    include_bytes!("../../../lab/p8-r24-capability-proof-boundary-v1/spec.json"),
    include_bytes!("../../../lab/p8-r25-ssh-source-provenance-v1/spec.json"),
    include_bytes!("../../../lab/p8-r35-source-dossiers-v1/spec.json"),
    include_bytes!("../../../lab/p8-r35-source-dossiers-v1/developer_matrix.json"),
];

/// Fuentes documentales disponibles para revisión.
#[derive(Clone, Debug)]
pub struct EvidenceSources<'a> {
    /// Contratos R10.
    pub r10: &'a [u8],
    /// Semántica de origen R12.
    pub r12: &'a [u8],
    /// Gramática R13.
    pub r13: &'a [u8],
    /// Catorce instantáneas documentales ordenadas.
    pub documents: [&'a [u8]; DOCUMENT_COUNT],
}

/// Obtiene las instantáneas versionadas en esta compilación.
#[must_use]
pub fn repository_sources() -> EvidenceSources<'static> {
    EvidenceSources {
        r10: R10,
        r12: R12,
        r13: R13,
        documents: DOCUMENTS,
    }
}

/// Error de una revisión documental.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// Cambió la identidad de uno de los catálogos.
    CatalogDrift,
    /// Un documento difiere de su instantánea compilada.
    SnapshotDrift(usize),
    /// El puente de perfiles no es consistente.
    ContractMismatch,
    /// Una propiedad obligatoria está ausente o es inválida.
    InvalidInvariant(&'static str),
}

/// Estado resumido de la evidencia sin autoridad operacional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceReview {
    /// Documentos de metadatos inspeccionados.
    pub documents: usize,
    /// Perfiles identificados de forma simbólica.
    pub profiles: usize,
    /// Materiales candidatos, no acreditados.
    pub candidate_materials: usize,
    /// Términos independientes del inventario R35.
    pub r35_terms: usize,
    /// Preguntas documentales R35.
    pub documentary_questions: usize,
    /// Identificadores R13 sin correspondencia literal en R35.
    pub unmapped_r13_r35_terms: usize,
    /// Indica si existe una correspondencia semántica acreditada.
    pub semantic_crosswalk_verified: bool,
    /// Campos materiales sin vinculación operacional.
    pub unbound_material_fields: usize,
    /// Comprobaciones operacionales pendientes.
    pub unverified_runtime_gates: usize,
    /// Variantes de escritura con limpieza no acreditada.
    pub cleanup_unproven: usize,
    /// Casos operacionalmente autorizados.
    pub authorized_cases: usize,
    /// Capacidades operacionales acreditadas.
    pub verified_operational_capabilities: usize,
    /// Ningún resultado documental permite despacho.
    pub dispatch_allowed: bool,
}

fn invalid(field: &'static str) -> EvidenceError {
    EvidenceError::InvalidInvariant(field)
}

fn number(value: &Value, field: &'static str) -> Result<u64, EvidenceError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(field))
}

fn require_number(value: &Value, field: &'static str, expected: u64) -> Result<(), EvidenceError> {
    if number(value, field)? != expected {
        return Err(invalid(field));
    }
    Ok(())
}

fn require_bool(value: &Value, field: &'static str, expected: bool) -> Result<(), EvidenceError> {
    if value.get(field).and_then(Value::as_bool) != Some(expected) {
        return Err(invalid(field));
    }
    Ok(())
}

fn array<'a>(value: &'a Value, field: &'static str) -> Result<&'a Vec<Value>, EvidenceError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field))
}

fn parse(raw: &[u8]) -> Result<Value, EvidenceError> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| invalid("json"))?;

    if !value.is_object() {
        return Err(invalid("json_root"));
    }

    Ok(value)
}

/// Revisa las fuentes sin conceder permiso operacional.
///
/// La igualdad de bytes identifica las instantáneas de esta
/// compilación, pero no demuestra autenticidad externa.
/// R12-R13 se compara directamente; R35 se trata por separado.
pub fn review(sources: &EvidenceSources<'_>) -> Result<EvidenceReview, EvidenceError> {
    if sources.r10 != R10 || sources.r12 != R12 || sources.r13 != R13 {
        return Err(EvidenceError::CatalogDrift);
    }

    for (index, (actual, expected)) in sources.documents.iter().zip(DOCUMENTS.iter()).enumerate() {
        if actual != expected {
            return Err(EvidenceError::SnapshotDrift(index));
        }
    }

    let bridge = ContractBridge::new(sources.r10, sources.r13)
        .map_err(|_| EvidenceError::ContractMismatch)?;

    if bridge.profile_count() != 29 || bridge.dispatch_allowed() {
        return Err(invalid("bridge"));
    }

    let r12 = parse(sources.r12)?;
    let r13 = parse(sources.r13)?;

    let r12_profiles = array(&r12, "profiles")?;
    let r13_profiles = array(&r13, "profiles")?;

    if r12_profiles.len() != PROFILE_IDS.len() || r13_profiles.len() != PROFILE_IDS.len() {
        return Err(invalid("r12_r13_profile_count"));
    }

    let mut r13_terms = BTreeSet::new();

    for ((left, right), expected) in r12_profiles
        .iter()
        .zip(r13_profiles.iter())
        .zip(PROFILE_IDS.iter())
    {
        if left.get("profile_id").and_then(Value::as_str) != Some(*expected)
            || right.get("profile_id").and_then(Value::as_str) != Some(*expected)
            || left.get("source_term_ids") != right.get("source_term_ids")
        {
            return Err(invalid("r12_r13_identity"));
        }

        for term in array(right, "source_term_ids")? {
            let id = term.as_str().ok_or_else(|| invalid("r13_term_type"))?;

            if id.is_empty() {
                return Err(invalid("r13_empty_term"));
            }

            r13_terms.insert(id);
        }
    }

    let mut documents = Vec::with_capacity(DOCUMENT_COUNT);

    for raw in sources.documents {
        documents.push(parse(raw)?);
    }

    for (index, field) in [
        (0, "dispatch_allowed"),
        (0, "experiments_performed"),
        (0, "future_runtime_material_identity_verified"),
        (0, "private_authorization_verified"),
        (0, "trusted_issuer_verified"),
        (1, "dispatch_allowed"),
        (2, "dispatch_enabled"),
        (5, "dispatch_allowed"),
        (5, "loader_resolution_verified"),
        (5, "runtime_identity_verified"),
        (5, "transitive_dependency_closure_verified"),
        (6, "dispatch_allowed"),
        (6, "effective_loader_resolution_verified"),
        (6, "runtime_dependency_closure_verified"),
        (7, "dispatch_allowed"),
        (7, "effective_configuration_verified"),
        (7, "loader_resolution_verified"),
        (7, "runtime_identity_verified"),
        (7, "transitive_dependency_closure_verified"),
        (8, "dispatch_allowed"),
        (8, "effective_configuration_verified"),
        (8, "effective_loader_resolution_verified"),
        (8, "runtime_binary_identity_verified"),
        (9, "dispatch_allowed"),
        (9, "actual_cli_capability_verified"),
        (9, "effective_configuration_verified"),
        (9, "runtime_binary_identity_verified"),
        (10, "dispatch_allowed"),
        (10, "operational_capability_verified"),
        (10, "effective_configuration_verified"),
        (10, "effective_loader_resolution_verified"),
        (10, "executes_guest_binaries"),
        (11, "dispatch_allowed"),
        (11, "client_capability_verified"),
        (11, "effective_configuration_verified"),
        (11, "guest_binaries_execute"),
        (11, "active_vm_access"),
        (12, "dispatch_allowed"),
        (12, "developer_hypotheses_are_authoritative"),
        (12, "full_clause_claim_allowed"),
        (12, "p8_closed"),
        (12, "p9_started"),
        (12, "a1_to_a10_started"),
    ] {
        require_bool(&documents[index], field, false)?;
    }

    for (index, field) in [(1, "no_network"), (1, "no_process_spawn"), (1, "read_only")] {
        require_bool(&documents[index], field, true)?;
    }

    for (index, field) in [
        (0, "selected_profile_count"),
        (0, "authorized_case_count"),
        (1, "real_artifacts_inspected"),
        (1, "real_cases_authorized"),
        (2, "approved_profiles"),
        (5, "authorized_cases"),
        (5, "approved_profiles"),
        (6, "authorized_cases"),
        (6, "authorized_profiles"),
        (7, "authorized_cases"),
        (7, "approved_profiles"),
        (8, "authorized_cases"),
        (8, "authorized_profiles"),
        (9, "authorized_cases"),
        (9, "approved_profiles"),
        (10, "authorized_cases"),
        (10, "authorized_profiles"),
        (11, "authorized_cases"),
        (11, "authorized_profiles"),
        (12, "authorized_cases"),
        (12, "authorized_profiles"),
        (12, "semantic_reviews_completed"),
        (12, "approved_cli_options"),
        (12, "approved_argv_renderers"),
        (13, "allowed_dispatch_count"),
        (13, "local_runtime_proofs_count"),
        (13, "documentary_semantics_approved"),
    ] {
        require_number(&documents[index], field, 0)?;
    }

    if array(&documents[0], "binary_observations")?.len() != 15
        || array(&documents[3], "profile_ids")?.len() != 29
        || array(&documents[3], "binding_fields")?.len() != 12
        || array(&documents[3], "write_profile_ids")?.len() != 5
    {
        return Err(invalid("material_inventory"));
    }

    require_number(&documents[9], "expected_unbound_material_fields", 348)?;
    require_number(&documents[10], "expected_gate_slots", 261)?;
    require_number(&documents[10], "expected_unbound_fields", 348)?;
    require_number(&documents[12], "profiles_blocked", 29)?;
    require_number(&documents[12], "material_fields_unbound", 348)?;
    require_number(&documents[12], "runtime_proof_gates_unverified", 261)?;
    require_number(&documents[12], "write_variants_cleanup_unproven", 5)?;
    require_number(&documents[12], "source_term_count", 39)?;
    require_number(&documents[12], "initial_question_count", 312)?;

    let expected_ids: BTreeSet<&str> = PROFILE_IDS.iter().copied().collect();

    let mut observed_ids = BTreeSet::new();

    for value in array(&documents[3], "profile_ids")? {
        let id = value.as_str().ok_or_else(|| invalid("r17_profile_id"))?;

        if !observed_ids.insert(id) {
            return Err(invalid("r17_duplicate_profile"));
        }
    }

    if observed_ids != expected_ids {
        return Err(invalid("r17_profile_ids"));
    }

    let entries = array(&documents[13], "entries")?;

    if entries.len() != 39 {
        return Err(invalid("r35_term_count"));
    }

    let mut r35_ids = BTreeSet::new();
    let mut question_count = 0usize;

    for entry in entries {
        let id = entry
            .get("term_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("r35_term_id"))?;

        if id.is_empty() || !r35_ids.insert(id) {
            return Err(invalid("r35_term_uniqueness"));
        }

        for field in [
            "cli_approved",
            "local_binary_capability_proven",
            "operational_authorization",
            "term_semantic_certified",
        ] {
            require_bool(entry, field, false)?;
        }

        question_count = question_count
            .checked_add(array(entry, "questions")?.len())
            .ok_or_else(|| invalid("question_overflow"))?;
    }

    if question_count != 312 {
        return Err(invalid("r35_question_count"));
    }

    let unmapped = r13_terms.difference(&r35_ids).count();

    // No se transforma la coincidencia literal de términos
    // en una certificación de equivalencia semántica.
    Ok(EvidenceReview {
        documents: DOCUMENT_COUNT,
        profiles: bridge.profile_count(),
        candidate_materials: 15,
        r35_terms: r35_ids.len(),
        documentary_questions: question_count,
        unmapped_r13_r35_terms: unmapped,
        semantic_crosswalk_verified: false,
        unbound_material_fields: 348,
        unverified_runtime_gates: 261,
        cleanup_unproven: 5,
        authorized_cases: 0,
        verified_operational_capabilities: 0,
        dispatch_allowed: false,
    })
}
