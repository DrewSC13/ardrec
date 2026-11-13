//! Vinculación sintética entre contratos P8-R10, gramáticas P8-R13
//! y captura terminal P8-R59.
//!
//! Ningún resultado de este módulo constituye autorización de ejecución.
//! No se generan argumentos, comandos, credenciales ni procesos.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::contract_gate::PROFILE_IDS;
use crate::p8_bounded_capture::Stream;
use crate::p8_resource_contract::Limits;
use crate::p8_terminal_capture::{TerminalCapture, TerminalError, TerminalStatus};

/// Tamaño máximo de cada documento JSON de entrada.
pub const MAX_CONTRACT_BYTES: usize = 1_048_576;

/// Causa conservadora de rechazo del puente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// Documento vacío o demasiado grande.
    InputSize,
    /// JSON no válido.
    InvalidJson,
    /// El JSON contiene una clave repetida.
    DuplicateKey,
    /// Faltan campos o cambió el esquema esperado.
    InvalidSchema,
    /// La relación de los 29 perfiles es inconsistente.
    ProfileMismatch,
    /// Existe material de ejecución o una autorización no permitida.
    ExecutableMaterial,
    /// No existe el perfil solicitado.
    UnknownProfile,
    /// La operación no coincide exactamente con el perfil.
    OperationMismatch,
    /// El presupuesto sintético es inválido.
    InvalidBudget,
}

struct Unique(Value);

struct UniqueVisitor;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Unique(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Unique(Value::Number(Number::from(value))))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Unique(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        let number = Number::from_f64(value).ok_or_else(|| E::custom("invalid JSON number"))?;
        Ok(Unique(Value::Number(number)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Unique(Value::String(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Unique(Value::String(value)))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();

        while let Some(value) = access.next_element::<Unique>()? {
            values.push(value.0);
        }

        Ok(Unique(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();

        while let Some((key, value)) = access.next_entry::<String, Unique>()? {
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON key"));
            }
        }

        Ok(Unique(Value::Object(values)))
    }
}

fn parse(raw: &[u8]) -> Result<Value, BridgeError> {
    if raw.is_empty() || raw.len() > MAX_CONTRACT_BYTES {
        return Err(BridgeError::InputSize);
    }

    serde_json::from_slice::<Unique>(raw)
        .map(|value| value.0)
        .map_err(|error| {
            if error.to_string().contains("duplicate JSON key") {
                BridgeError::DuplicateKey
            } else {
                BridgeError::InvalidJson
            }
        })
}

fn object(value: &Value) -> Result<&Map<String, Value>, BridgeError> {
    value.as_object().ok_or(BridgeError::InvalidSchema)
}

fn exact_keys(value: &Map<String, Value>, fields: &[&str]) -> bool {
    value.len() == fields.len() && fields.iter().all(|field| value.contains_key(*field))
}

fn is_false(value: &Map<String, Value>, name: &str) -> bool {
    value.get(name) == Some(&Value::Bool(false))
}

fn is_true(value: &Map<String, Value>, name: &str) -> bool {
    value.get(name) == Some(&Value::Bool(true))
}

fn is_zero(value: &Map<String, Value>, name: &str) -> bool {
    value.get(name).and_then(Value::as_u64) == Some(0)
}

fn is_null(value: &Map<String, Value>, name: &str) -> bool {
    value.get(name).is_some_and(Value::is_null)
}

fn string<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a str, BridgeError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(BridgeError::InvalidSchema)
}

fn rows(value: &Map<String, Value>) -> Result<&Vec<Value>, BridgeError> {
    value
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or(BridgeError::InvalidSchema)
}

const R10_ROOT: &[&str] = &[
    "algorithm_implementation",
    "authorized_cases",
    "base_commit",
    "contract_kind",
    "dispatch_allowed",
    "fully_bound_profiles",
    "global_denials",
    "increment",
    "physical_lab_contact",
    "profile_count",
    "profiles",
    "r9_compatibility_sha256",
    "r9_material_inventory_sha256",
    "roadmap_step",
    "schema_version",
    "verified_executable_capabilities",
];

const R13_ROOT: &[&str] = &[
    "algorithms_started",
    "approved_argv_renderers",
    "approved_cli_grammars",
    "approved_cli_options",
    "authorized_cases",
    "authorized_profiles",
    "base_commit",
    "design_only",
    "dispatch_allowed",
    "guest_binaries_executed",
    "image_sha256",
    "increment",
    "kind",
    "physical_laboratory_contact",
    "profile_count",
    "profiles",
    "r12_semantics_sha256",
    "request_scope",
    "request_shape",
    "roadmap_step",
    "schema_version",
    "write_variants",
];

const R10_PROFILE: &[&str] = &[
    "argument_contract",
    "candidate_binary",
    "candidate_binary_sha256",
    "cleanup_contract",
    "contract_status",
    "execution_boundary",
    "family_id",
    "profile_id",
    "protocol",
    "semantic_operation_id",
    "variant",
];

const R13_PROFILE: &[&str] = &[
    "accepted_cli_options",
    "argv_template",
    "assurance_design",
    "cleanup_contract",
    "command_surface",
    "dispatch_allowed",
    "effect_class",
    "grammar_status",
    "profile_id",
    "protocol",
    "remote_command_ast",
    "resource_tag",
    "runtime_permission",
    "semantic_operation_id",
    "smb_command_ast",
    "source_term_ids",
];

const R10_ARGUMENT: &[&str] = &[
    "command_surface",
    "material_reference_names",
    "raw_command_strings_allowed",
    "remote_command_ast",
    "rendered_argv",
    "representation",
    "required_control_atoms",
    "smb_command_ast",
];

const R10_BOUNDARY: &[&str] = &[
    "approved_target",
    "auxiliary_pins",
    "capability_verified",
    "capture_policy",
    "credential_delivery",
    "dispatch_allowed",
    "environment",
    "isolation_verified",
    "issuer_and_revocation_verified",
    "post_execution_cleanup_receipt",
    "private_case_authorization",
    "resource_budget",
    "runtime_binary_identity_verified",
    "working_directory",
];

fn validate_r10(root: &Map<String, Value>) -> Result<(), BridgeError> {
    if !exact_keys(root, R10_ROOT)
        || root.get("profile_count").and_then(Value::as_u64) != Some(29)
        || !is_zero(root, "authorized_cases")
        || !is_zero(root, "fully_bound_profiles")
        || !is_zero(root, "verified_executable_capabilities")
        || !is_false(root, "dispatch_allowed")
    {
        return Err(BridgeError::InvalidSchema);
    }

    if !root.get("global_denials").is_some_and(Value::is_object) {
        return Err(BridgeError::InvalidSchema);
    }

    Ok(())
}

fn validate_r13(root: &Map<String, Value>) -> Result<(), BridgeError> {
    if !exact_keys(root, R13_ROOT)
        || root.get("profile_count").and_then(Value::as_u64) != Some(29)
        || root.get("write_variants").and_then(Value::as_u64) != Some(5)
        || !is_zero(root, "authorized_cases")
        || !is_zero(root, "authorized_profiles")
        || !is_zero(root, "approved_cli_options")
        || !is_zero(root, "approved_cli_grammars")
        || !is_zero(root, "approved_argv_renderers")
        || !is_false(root, "dispatch_allowed")
        || !is_false(root, "algorithms_started")
        || !is_false(root, "guest_binaries_executed")
        || !is_true(root, "design_only")
    {
        return Err(BridgeError::InvalidSchema);
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    profile_id: String,
    operation_id: String,
}

/// Relación validada de los 29 perfiles, sin autoridad operacional.
#[derive(Debug)]
pub struct ContractBridge {
    profiles: Vec<Identity>,
}

impl ContractBridge {
    /// Valida simultáneamente los catálogos R10 y R13.
    ///
    /// Rechaza claves JSON duplicadas, perfiles alterados, discrepancias
    /// de identidad y cualquier material de ejecución admitido.
    pub fn new(r10: &[u8], r13: &[u8]) -> Result<Self, BridgeError> {
        let first = parse(r10)?;
        let second = parse(r13)?;

        let a = object(&first)?;
        let b = object(&second)?;

        validate_r10(a)?;
        validate_r13(b)?;

        let first_rows = rows(a)?;
        let second_rows = rows(b)?;

        if first_rows.len() != PROFILE_IDS.len() || second_rows.len() != PROFILE_IDS.len() {
            return Err(BridgeError::ProfileMismatch);
        }

        let mut profiles = Vec::with_capacity(PROFILE_IDS.len());

        for (index, expected_id) in PROFILE_IDS.iter().enumerate() {
            let left = object(&first_rows[index])?;
            let right = object(&second_rows[index])?;

            if !exact_keys(left, R10_PROFILE) || !exact_keys(right, R13_PROFILE) {
                return Err(BridgeError::InvalidSchema);
            }

            let left_id = string(left, "profile_id")?;
            let right_id = string(right, "profile_id")?;

            let left_operation = string(left, "semantic_operation_id")?;
            let right_operation = string(right, "semantic_operation_id")?;

            let left_protocol = string(left, "protocol")?;
            let right_protocol = string(right, "protocol")?;

            let left_cleanup = string(left, "cleanup_contract")?;
            let right_cleanup = string(right, "cleanup_contract")?;

            if left_id != *expected_id
                || right_id != *expected_id
                || left_operation != right_operation
                || left_operation.is_empty()
                || left_operation.len() > 256
                || left_cleanup != right_cleanup
            {
                return Err(BridgeError::ProfileMismatch);
            }

            let expected_protocol = expected_id
                .split('-')
                .next()
                .ok_or(BridgeError::ProfileMismatch)?;

            let required_r10_protocol = expected_protocol.to_ascii_lowercase();
            if left_protocol != required_r10_protocol.as_str()
                || right_protocol != expected_protocol
            {
                return Err(BridgeError::ProfileMismatch);
            }

            let arguments = object(
                left.get("argument_contract")
                    .ok_or(BridgeError::InvalidSchema)?,
            )?;

            let boundary = object(
                left.get("execution_boundary")
                    .ok_or(BridgeError::InvalidSchema)?,
            )?;

            if !exact_keys(arguments, R10_ARGUMENT) || !exact_keys(boundary, R10_BOUNDARY) {
                return Err(BridgeError::InvalidSchema);
            }

            if string(left, "contract_status")? != "BLOCKED_UNBOUND_NO_EXECUTION"
                || string(arguments, "representation")? != "TYPED_SYMBOLIC_INTENT_NOT_ARGV"
                || string(right, "grammar_status")? != "ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE"
            {
                return Err(BridgeError::InvalidSchema);
            }

            if !is_false(arguments, "raw_command_strings_allowed")
                || !is_null(arguments, "rendered_argv")
                || !is_null(arguments, "remote_command_ast")
                || !is_null(arguments, "smb_command_ast")
                || !is_false(boundary, "dispatch_allowed")
                || !is_false(right, "runtime_permission")
                || !is_false(right, "dispatch_allowed")
                || !is_null(right, "argv_template")
                || !is_null(right, "remote_command_ast")
                || !is_null(right, "smb_command_ast")
            {
                return Err(BridgeError::ExecutableMaterial);
            }

            if right
                .get("accepted_cli_options")
                .and_then(Value::as_array)
                .is_none_or(|options| !options.is_empty())
            {
                return Err(BridgeError::ExecutableMaterial);
            }

            // Se admiten referencias simbólicas, nunca comandos.
            for field in ["material_reference_names", "required_control_atoms"] {
                let Some(items) = arguments.get(field).and_then(Value::as_array) else {
                    return Err(BridgeError::InvalidSchema);
                };

                if !items.iter().all(Value::is_string) {
                    return Err(BridgeError::InvalidSchema);
                }
            }

            if right
                .get("source_term_ids")
                .and_then(Value::as_array)
                .is_none_or(|items| !items.iter().all(Value::is_string))
            {
                return Err(BridgeError::InvalidSchema);
            }

            // Ningún campo de la frontera puede aportar materiales,
            // habilitación o identidades de ejecución.
            for (field, value) in boundary {
                if field == "dispatch_allowed" {
                    continue;
                }

                if !value.is_null() && value != &Value::Bool(false) {
                    return Err(BridgeError::ExecutableMaterial);
                }
            }

            profiles.push(Identity {
                profile_id: left_id.to_owned(),
                operation_id: left_operation.to_owned(),
            });
        }

        Ok(Self { profiles })
    }

    /// Número de perfiles simbólicos alineados.
    #[must_use]
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Ningún catálogo alineado acredita autorización operacional.
    #[must_use]
    pub fn dispatch_allowed(&self) -> bool {
        false
    }

    /// Obtiene la operación simbólica asociada a un perfil conocido.
    #[must_use]
    pub fn operation_id(&self, profile_id: &str) -> Option<&str> {
        self.profiles
            .iter()
            .find(|record| record.profile_id == profile_id)
            .map(|record| record.operation_id.as_str())
    }

    /// Construye una sesión exclusivamente sintética para un perfil.
    ///
    /// No produce argumentos, permisos, clientes ni conexiones.
    pub fn synthetic_case(
        &self,
        profile_id: &str,
        operation_id: &str,
        limits: Limits,
    ) -> Result<SyntheticCase, BridgeError> {
        let expected = self
            .operation_id(profile_id)
            .ok_or(BridgeError::UnknownProfile)?;

        if expected != operation_id {
            return Err(BridgeError::OperationMismatch);
        }

        let capture = TerminalCapture::new(limits).map_err(|_| BridgeError::InvalidBudget)?;

        Ok(SyntheticCase {
            profile_id: profile_id.to_owned(),
            operation_id: operation_id.to_owned(),
            capture,
        })
    }
}

/// Sesión sintética vinculada a un perfil y una operación exactos.
///
/// La instancia solamente acepta contadores y bytes proporcionados
/// por el llamador; no dispone de primitivas de ejecución.
#[derive(Debug)]
pub struct SyntheticCase {
    profile_id: String,
    operation_id: String,
    capture: TerminalCapture,
}

impl SyntheticCase {
    /// Identidad de perfil fijada al crear la sesión.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Identidad de operación fijada al crear la sesión.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Inicia el único intento sintético permitido.
    pub fn begin_attempt(&mut self) -> Result<(), TerminalError> {
        self.capture.begin_attempt()
    }

    /// Incorpora bytes sintéticos respetando el aborto terminal.
    pub fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), TerminalError> {
        self.capture.push(stream, bytes)
    }

    /// Registra bytes declarados sin acceder a una red.
    pub fn account_network_bytes(&mut self, amount: u64) -> Result<(), TerminalError> {
        self.capture.account_network_bytes(amount)
    }

    /// Registra una entrada de resultados declarada.
    pub fn account_result_entry(&mut self) -> Result<(), TerminalError> {
        self.capture.account_result_entry()
    }

    /// Registra tiempo declarado sin consultar procesos.
    pub fn observe_elapsed_ms(&mut self, elapsed_ms: u64) -> Result<(), TerminalError> {
        self.capture.observe_elapsed_ms(elapsed_ms)
    }

    /// Estado de captura y denegación, sin efectos secundarios.
    #[must_use]
    pub fn status(&self) -> TerminalStatus {
        self.capture.status()
    }

    /// Bytes sintéticos de stdout ya aceptados.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        self.capture.stdout()
    }

    /// Bytes sintéticos de stderr ya aceptados.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        self.capture.stderr()
    }
}

/// Conteo de perfiles y operaciones simbólicas, sin autorización.
#[derive(Debug, PartialEq, Eq)]
pub struct BridgeSummary {
    /// Cantidad de perfiles relacionados.
    pub profiles: usize,
    /// Cantidad de perfiles con despacho autorizado.
    pub authorized_profiles: usize,
    /// Indica que ninguna ejecución puede ser despachada.
    pub dispatch_allowed: bool,
}

/// Devuelve un resumen no autorizante del puente.
#[must_use]
pub fn summarize(bridge: &ContractBridge) -> BridgeSummary {
    BridgeSummary {
        profiles: bridge.profile_count(),
        authorized_profiles: 0,
        dispatch_allowed: false,
    }
}

/// Devuelve un inventario de identidades sin materiales operacionales.
#[must_use]
pub fn symbolic_inventory(bridge: &ContractBridge) -> BTreeMap<String, String> {
    bridge
        .profiles
        .iter()
        .map(|entry| (entry.profile_id.clone(), entry.operation_id.clone()))
        .collect()
}
