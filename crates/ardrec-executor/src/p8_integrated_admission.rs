//! P8-R73: revisión de admisión integrada y conservadora.
//!
//! Compone:
//! - `contract_gate`: estructura tipada y precondiciones;
//! - `p8_contract_bridge`: correspondencia R10/R13;
//! - `p8_evidence_boundary`: integridad documental R12/R35.
//!
//! No representa autorización de un caso y no ofrece
//! ninguna interfaz de ejecución o despacho.
//!
//! La ausencia de evidencia confiable no se sustituye
//! por declaraciones del solicitante.

use crate::contract_gate::{self, Decision, Definition, Draft, Observation};
use crate::p8_contract_bridge::ContractBridge;
use crate::p8_evidence_boundary::{self, EvidenceSources};

/// Procedencia declarada de configuraciones de cliente.
///
/// Ninguna variante constituye, por sí sola, una
/// acreditación de aislamiento o de contenido.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfigurationMode {
    /// No se ha acreditado qué configuración puede cargarse.
    #[default]
    Unknown,
    /// El solicitante afirma aislamiento, sin prueba externa.
    ClaimedIsolated,
    /// Importación explícita desde un archivo.
    ExplicitFile,
    /// Importación mediante entrada estándar.
    StandardInput,
    /// Puede aplicarse una configuración predeterminada.
    ImplicitDefault,
}

/// Procedencia declarada del entorno de proceso.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvironmentMode {
    /// No se ha acreditado la construcción del entorno.
    #[default]
    Unknown,
    /// Se declara un entorno limpio, todavía no verificado.
    ClaimedClean,
    /// Se heredaría el entorno del proceso solicitante.
    Inherited,
}

/// Características de una propuesta, sin transportar secretos,
/// comandos ni rutas materializadas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestSurface {
    /// Posible lectura de archivos/configuraciones implícitos.
    pub configuration: ConfigurationMode,
    /// Construcción del entorno del cliente.
    pub environment: EnvironmentMode,
    /// Número de argumentos CLI materializados.
    pub materialized_arguments: usize,
    /// Solicita interpretación mediante shell.
    pub uses_shell: bool,
    /// Solicita un comando remoto.
    pub remote_command_present: bool,
    /// Declara un objetivo que no está autorizado.
    pub unapproved_target_present: bool,
    /// Declara auxiliares sin acreditación.
    pub unverified_auxiliaries_present: bool,
    /// Solicita entregar credenciales al cliente.
    pub credential_delivery_requested: bool,
    /// Pretende habilitar despacho.
    pub dispatch_requested: bool,
}

/// Motivos estables, deterministas y no autorizantes.
///
/// Los motivos describen distintos límites; no implican
/// que corregir uno de ellos baste para ejecutar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionBlocker {
    /// Una fuente de evidencia no coincide o no es válida.
    DocumentaryBoundaryRejected,
    /// No existe correspondencia R10/R13 válida.
    SymbolicBridgeRejected,
    /// El identificador no forma parte de los 29 perfiles.
    UnknownProfile,
    /// La política de configuración aún no fue acreditada.
    ConfigurationNotVerified,
    /// La importación de configuración está prohibida.
    ConfigurationImportForbidden,
    /// El entorno solicitado no tiene acreditación efectiva.
    EnvironmentNotVerified,
    /// Heredar el entorno está prohibido.
    InheritedEnvironmentForbidden,
    /// No se permite materializar argumentos.
    MaterializedArgumentsForbidden,
    /// No se admiten shells como superficie de ejecución.
    ShellForbidden,
    /// No se permiten comandos remotos materializados.
    RemoteCommandForbidden,
    /// No existe autoridad para el objetivo indicado.
    TargetNotAuthorized,
    /// No hay identidad acreditada para auxiliares.
    AuxiliariesUnverified,
    /// No existe procedimiento acreditado de credenciales.
    CredentialDeliveryUnverified,
    /// No se puede solicitar despacho desde P8.
    DispatchForbidden,
    /// Persisten campos de vinculación materiales pendientes.
    MaterialBindingsUnverified,
    /// Persisten comprobaciones operacionales pendientes.
    RuntimeProofsUnverified,
    /// No existe autorización de caso independiente.
    CaseAuthorizationAbsent,
    /// El gate tipado produjo un resultado incompatible.
    ContractGateInvariantViolation,
}

/// Resultado unificado, siempre sin permisos operacionales.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionReview {
    /// Perfil solicitado, copiado solo como identificador.
    pub profile_id: String,
    /// Operación simbólica R10/R13, si existe.
    pub symbolic_operation: Option<String>,
    /// Hallazgos aportados por `contract_gate::review`.
    pub contract_findings: usize,
    /// Vinculaciones pendientes para este perfil.
    pub unbound_fields_per_profile: usize,
    /// Comprobaciones pendientes para este perfil.
    pub unverified_gates_per_profile: usize,
    /// Referencias R13 sin equivalencia literal R35 acreditada.
    pub unresolved_documentary_references: usize,
    /// Motivos de rechazo, sin duplicados.
    pub blockers: Vec<AdmissionBlocker>,
    /// Nunca se concede autorización.
    pub authorized: bool,
    /// Nunca se concede despacho.
    pub dispatch_allowed: bool,
}

fn add(blockers: &mut Vec<AdmissionBlocker>, reason: AdmissionBlocker) {
    if !blockers.contains(&reason) {
        blockers.push(reason);
    }
}

fn inspect_surface(surface: RequestSurface, blockers: &mut Vec<AdmissionBlocker>) {
    match surface.configuration {
        ConfigurationMode::Unknown | ConfigurationMode::ClaimedIsolated => {
            add(blockers, AdmissionBlocker::ConfigurationNotVerified);
        }
        ConfigurationMode::ExplicitFile
        | ConfigurationMode::StandardInput
        | ConfigurationMode::ImplicitDefault => {
            add(blockers, AdmissionBlocker::ConfigurationImportForbidden);
        }
    }

    match surface.environment {
        EnvironmentMode::Unknown | EnvironmentMode::ClaimedClean => {
            add(blockers, AdmissionBlocker::EnvironmentNotVerified);
        }
        EnvironmentMode::Inherited => {
            add(blockers, AdmissionBlocker::InheritedEnvironmentForbidden);
        }
    }

    if surface.materialized_arguments != 0 {
        add(blockers, AdmissionBlocker::MaterializedArgumentsForbidden);
    }

    if surface.uses_shell {
        add(blockers, AdmissionBlocker::ShellForbidden);
    }

    if surface.remote_command_present {
        add(blockers, AdmissionBlocker::RemoteCommandForbidden);
    }

    if surface.unapproved_target_present {
        add(blockers, AdmissionBlocker::TargetNotAuthorized);
    }

    if surface.unverified_auxiliaries_present {
        add(blockers, AdmissionBlocker::AuxiliariesUnverified);
    }

    if surface.credential_delivery_requested {
        add(blockers, AdmissionBlocker::CredentialDeliveryUnverified);
    }

    if surface.dispatch_requested {
        add(blockers, AdmissionBlocker::DispatchForbidden);
    }
}

/// Revisión documental y simbólica independiente de un `Draft`.
///
/// Valida las fuentes y la identidad de la operación, además
/// de clasificar las superficies no acreditadas.
/// Nunca transforma un documento en un permiso.
#[must_use]
pub fn inspect_profile(
    profile_id: &str,
    sources: &EvidenceSources<'_>,
    surface: RequestSurface,
) -> AdmissionReview {
    let mut result = AdmissionReview {
        profile_id: profile_id.to_owned(),
        symbolic_operation: None,
        contract_findings: 0,
        unbound_fields_per_profile: 0,
        unverified_gates_per_profile: 0,
        unresolved_documentary_references: 0,
        blockers: Vec::new(),
        authorized: false,
        dispatch_allowed: false,
    };

    inspect_surface(surface, &mut result.blockers);

    let evidence = match p8_evidence_boundary::review(sources) {
        Ok(value) => value,
        Err(_) => {
            add(
                &mut result.blockers,
                AdmissionBlocker::DocumentaryBoundaryRejected,
            );
            return result;
        }
    };

    let bridge = match ContractBridge::new(sources.r10, sources.r13) {
        Ok(value) => value,
        Err(_) => {
            add(
                &mut result.blockers,
                AdmissionBlocker::SymbolicBridgeRejected,
            );
            return result;
        }
    };

    if bridge.profile_count() != 29 || bridge.dispatch_allowed() {
        add(
            &mut result.blockers,
            AdmissionBlocker::SymbolicBridgeRejected,
        );
        return result;
    }

    let Some(operation) = bridge.operation_id(profile_id) else {
        add(&mut result.blockers, AdmissionBlocker::UnknownProfile);
        return result;
    };

    result.symbolic_operation = Some(operation.to_owned());

    // Son cantidades por perfil, no acreditaciones por perfil.
    // Las igualdades se verifican antes de utilizar los cocientes.
    if evidence.profiles != 29
        || evidence.unbound_material_fields != 348
        || evidence.unverified_runtime_gates != 261
    {
        add(
            &mut result.blockers,
            AdmissionBlocker::DocumentaryBoundaryRejected,
        );
        return result;
    }

    result.unbound_fields_per_profile = evidence.unbound_material_fields / evidence.profiles;
    result.unverified_gates_per_profile = evidence.unverified_runtime_gates / evidence.profiles;
    result.unresolved_documentary_references = evidence.unmapped_r13_r35_terms;

    add(
        &mut result.blockers,
        AdmissionBlocker::MaterialBindingsUnverified,
    );
    add(
        &mut result.blockers,
        AdmissionBlocker::RuntimeProofsUnverified,
    );
    add(
        &mut result.blockers,
        AdmissionBlocker::CaseAuthorizationAbsent,
    );

    result
}

/// Integra la revisión del contrato tipado con R10/R13 y
/// el límite probatorio R12/R35.
///
/// La autoridad del caso no se toma de un campo declarado
/// ni se infiere a partir de la validez del contrato.
#[must_use]
pub fn review_draft(
    definition: &Definition<'_>,
    draft: &Draft,
    observed: &[(&str, Observation)],
    sources: &EvidenceSources<'_>,
    surface: RequestSurface,
) -> AdmissionReview {
    let gate = contract_gate::review(definition, draft, observed);

    let mut result = inspect_profile(definition.profile_id, sources, surface);

    result.contract_findings = gate.findings.len();

    if gate.dispatch_allowed
        || gate.authorized
        || gate.decision != Decision::BlockedUnboundNoExecution
    {
        add(
            &mut result.blockers,
            AdmissionBlocker::ContractGateInvariantViolation,
        );
    }

    // El resultado del gate puede aportar hallazgos sintácticos,
    // pero no puede otorgar autoridad a la solicitud integrada.
    result.authorized = false;
    result.dispatch_allowed = false;

    result
}
