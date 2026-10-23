//! Diario técnico local: los registros no ejecutan herramientas ni acreditan soportes externos.

mod model;
mod storage;

use serde_json::Value;
use std::{fmt, io};
pub use storage::TechnicalJournal;

/// Límites del contenedor local, independientes de los límites del protocolo.
pub const MAX_RECORDS: u64 = 4096;
/// Tamaño máximo en bytes de un registro serializado.
pub const MAX_RECORD_BYTES: usize = 4 * crate::messages::MAX_MESSAGE_BYTES + 4096;
/// Tamaño máximo acumulado de los registros del historial confirmado.
pub const MAX_HISTORY_BYTES: u64 = 64 * 1024 * 1024;

/// Error estable; cualquier fallo de escritura exige cerrar y recuperar el diario.
#[derive(Debug)]
pub struct JournalError {
    code: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl JournalError {
    /// Código para el futuro adaptador del ejecutor.
    pub fn code(&self) -> &'static str {
        self.code
    }
}
impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Diario rechazado: {}", self.code)
    }
}
impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| &**e as &(dyn std::error::Error + 'static))
    }
}
impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        Self {
            code: "storage_io",
            source: Some(Box::new(e)),
        }
    }
}
impl From<crate::messages::MessageError> for JournalError {
    fn from(e: crate::messages::MessageError) -> Self {
        Self {
            code: e.code(),
            source: Some(Box::new(e)),
        }
    }
}
type Result<T> = std::result::Result<T, JournalError>;
fn need(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(JournalError { code, source: None })
    }
}
fn error(code: &'static str) -> JournalError {
    JournalError { code, source: None }
}
fn canonical(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| error("record_invalid"))
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| error("record_invalid"))
}
fn fields(v: &Value, expected: &[&str]) -> Result<()> {
    let o = v.as_object().ok_or_else(|| error("record_invalid"))?;
    need(
        o.len() == expected.len() && expected.iter().all(|k| o.contains_key(*k)),
        "record_invalid",
    )
}
fn hash(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(raw))
}

/// La repetición idéntica no añade registros ni repite una acción técnica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// La operación quedó registrada por primera vez.
    New,
    /// La operación idéntica ya estaba registrada y no se volvió a escribir.
    Replay,
}

/// Respuesta durable junto con el resultado original, cuando existe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Mensaje de respuesta durable, codificado como JSON canónico UTF-8.
    pub response: Vec<u8>,
    /// Resultado completo cuando la respuesta declara su disponibilidad.
    pub result: Option<Vec<u8>>,
    /// Indica que se recuperó una respuesta previamente registrada.
    pub replay: bool,
}

#[cfg(test)]
mod tests;
