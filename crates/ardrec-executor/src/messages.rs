//! Validación exacta de los perfiles operacionales 1.0 y 2.0.

mod json;
mod temporal;
mod v1;
mod v2;
pub use temporal::correlate_current;

use serde_json::Value;
use std::{collections::BTreeSet, fmt};

/// Tamaño máximo del documento UTF-8, antes de analizarlo.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;
const MAX_INTEGER: i64 = i64::MAX;

/// Rechazo estable; no acredita estados externos ni autoriza ejecuciones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageError(&'static str);

impl MessageError {
    /// Código intercambiable con el validador Python.
    pub fn code(&self) -> &'static str {
        self.0
    }
}
impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mensaje rechazado: {}", self.0)
    }
}
impl std::error::Error for MessageError {}
type Result<T = ()> = std::result::Result<T, MessageError>;
fn check(condition: bool) -> Result {
    coded(condition, "schema_invalid")
}
fn coded(condition: bool, code: &'static str) -> Result {
    if condition {
        Ok(())
    } else {
        Err(MessageError(code))
    }
}
fn fields(v: &Value, names: &str) -> Result {
    let object = v.as_object().ok_or(MessageError("schema_invalid"))?;
    let expected: BTreeSet<_> = names.split_whitespace().collect();
    check(object.len() == expected.len() && object.keys().all(|k| expected.contains(k.as_str())))
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or(MessageError("schema_invalid"))
}
fn one(v: &Value, choices: &str) -> Result {
    check(choices.split_whitespace().any(|x| v.as_str() == Some(x)))
}
fn id(v: &Value) -> Result {
    let s = text(v)?;
    check(
        !s.is_empty()
            && s.len() <= 128
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c)),
    )
}
fn integer(v: &Value, low: i64, high: i64) -> Result {
    check(v.as_i64().is_some_and(|n| low <= n && n <= high))
}
fn digest(v: &Value) -> Result {
    let s = text(v)?;
    check(
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
    )
}
fn references(v: &Value, names: &str) -> Result {
    for k in names.split_whitespace() {
        id(&v[k])?;
    }
    Ok(())
}
fn timestamp(v: &Value) -> Result<[u32; 7]> {
    let s = text(v)?.as_bytes();
    check(s.len() == 20 || (22..=27).contains(&s.len()))?;
    for (i, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        check(s[i] == expected)?;
    }
    check(s.last() == Some(&b'Z'))?;
    let number = |start: usize, end: usize| -> Result<u32> {
        check(s[start..end].iter().all(u8::is_ascii_digit))?;
        Ok(s[start..end]
            .iter()
            .fold(0, |a, c| a * 10 + u32::from(c - b'0')))
    };
    let mut t = [
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
        0,
    ];
    if s.len() > 20 {
        check(s[19] == b'.')?;
        let digits = s.len() - 21;
        t[6] = number(20, s.len() - 1)? * 10_u32.pow(6 - digits as u32);
    }
    let leap = t[0].is_multiple_of(4) && (!t[0].is_multiple_of(100) || t[0].is_multiple_of(400));
    check(t[0] >= 1 && (1..=12).contains(&t[1]))?;
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][t[1] as usize - 1];
    check(t[2] >= 1 && t[2] <= days && t[3] <= 24 && t[4] <= 59 && t[5] <= 59)?;
    // Python 3.14.7 admite 24:00 únicamente como medianoche del día siguiente.
    if t[3] == 24 {
        check(t[4] == 0 && t[5] == 0 && t[6] == 0)?;
        t[3] = 0;
        t[2] += 1;
        if t[2] > days {
            t[2] = 1;
            t[1] += 1;
            if t[1] > 12 {
                t[1] = 1;
                t[0] += 1;
            }
        }
        check(t[0] <= 9999)?;
    }
    Ok(t)
}
fn unique_refs(v: &Value, max: usize) -> Result {
    let values = v.as_array().ok_or(MessageError("schema_invalid"))?;
    check(values.len() <= max)?;
    let mut seen = BTreeSet::new();
    for value in values {
        id(value)?;
        check(seen.insert(text(value)?))?;
    }
    Ok(())
}
fn information(v: &Value) -> Result {
    let a = v.as_array().ok_or(MessageError("schema_invalid"))?;
    check(!a.is_empty() && a.len() <= 4)?;
    let mut seen = BTreeSet::new();
    for value in a {
        one(value, "INICIO TERMINACION RESULTADO LIMPIEZA")?;
        check(seen.insert(text(value)?))?;
    }
    Ok(())
}
fn same(a: &Value, b: &Value, names: &str) -> Result {
    for k in names.split_whitespace() {
        coded(a[k] == b[k], "identifier_mismatch")?;
    }
    Ok(())
}
fn version(v: &Value) -> Result<&str> {
    let o = v.as_object().ok_or(MessageError("schema_invalid"))?;
    let version = o
        .get("schema_version")
        .ok_or(MessageError("schema_invalid"))?;
    match version.as_str() {
        Some(s @ ("1.0" | "2.0")) => Ok(s),
        _ => Err(MessageError("version_incompatible")),
    }
}

/// Validar una estructura sin leer soportes ni ejecutar herramientas.
pub fn validate_message(message: &Value) -> Result {
    match version(message)? {
        "1.0" => v1::validate(message),
        _ => v2::validate(message),
    }
}
/// Decodificar UTF-8 estricto, sin claves repetidas ni números decimales.
pub fn decode_message(raw: &[u8]) -> Result<Value> {
    coded(raw.len() <= MAX_MESSAGE_BYTES, "message_too_large")?;
    let value = json::parse(raw)?;
    validate_message(&value)?;
    Ok(value)
}
/// Serializar canónicamente después de validar, conservando enteros exactos.
pub fn encode_message(message: &Value) -> Result<Vec<u8>> {
    validate_message(message)?;
    // Los campos admitidos contienen exclusivamente cadenas ASCII y enteros.
    let raw = serde_json::to_vec(message).map_err(|_| MessageError("schema_invalid"))?;
    coded(raw.len() <= MAX_MESSAGE_BYTES, "message_too_large")?;
    Ok(raw)
}
/// Comprobar asociación entre dos mensajes de la misma versión.
pub fn correlate(request: &Value, related: &Value) -> Result {
    validate_message(request)?;
    validate_message(related)?;
    coded(
        request["schema_version"] == related["schema_version"],
        "version_incompatible",
    )?;
    if version(request)? == "1.0" {
        v1::correlate(request, related)
    } else {
        v2::correlate(request, related)
    }
}
/// Vincular una consulta 2.0 y su respuesta con la solicitud original.
pub fn correlate_status(request: &Value, query: &Value, response: &Value) -> Result {
    check(query["message_type"] == "attempt_status_request")?;
    v2::correlate(request, query)?;
    v2::correlate(request, response)?;
    v2::correlate(query, response)
}
/// Clasificación de dos entregas; no sustituye al diario durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Identidad y contenido canónico idénticos.
    Replay,
    /// Identidad nueva sin reutilizar el intento de otra solicitud.
    New,
}
/// Detectar conflictos de identidad en dos mensajes 2.0.
pub fn compare_delivery(previous: &Value, incoming: &Value) -> Result<Delivery> {
    v2::validate(previous)?;
    v2::validate(incoming)?;
    if previous["message_id"] == incoming["message_id"] {
        coded(
            encode_message(previous)? == encode_message(incoming)?,
            "duplicate_conflict",
        )?;
        return Ok(Delivery::Replay);
    }
    let request = |v: &Value| {
        matches!(
            v["message_type"].as_str(),
            Some("execution_request" | "discovery_request")
        )
    };
    if request(previous) && request(incoming) {
        coded(
            previous["attempt_id"] != incoming["attempt_id"],
            "duplicate_conflict",
        )?;
    }
    Ok(Delivery::New)
}

#[cfg(test)]
mod tests;
