//! Validación exacta de magnitudes sin convertir enteros grandes a coma flotante.
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::fmt;

/// Límite del documento de una magnitud del contrato Python.
pub const MAX_MAGNITUDE_BYTES: usize = 4096;
/// Límite del registro analítico versionado.
pub const MAX_RECORD_BYTES: usize = 8192;
/// Identidad del formato analítico; no modifica las versiones operacionales.
pub const FORMAT: &str = "ardrec-magnitude-1";

/// Documento fuera del contrato de magnitudes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagnitudeError;
impl fmt::Display for MagnitudeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Magnitud inválida")
    }
}
impl std::error::Error for MagnitudeError {}
type Result<T> = std::result::Result<T, MagnitudeError>;

/// Magnitud validada e inmutable, conservada como JSON canónico exacto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magnitude {
    wire: Vec<u8>,
}
impl Magnitude {
    /// Obtener los bytes exactos sin redondeo ni interpretación como flotante.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Construir el registro versionado que comparte el archivo Python.
    pub fn record_bytes(&self) -> Vec<u8> {
        let mut out = format!("{{\"format\":\"{FORMAT}\",\"magnitude\":").into_bytes();
        out.extend_from_slice(&self.wire);
        out.push(b'}');
        out
    }
}

struct Object(BTreeMap<String, Box<RawValue>>);
impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Objeto de campos únicos")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Object, A::Error> {
                let mut items = BTreeMap::new();
                while let Some(key) = a.next_key::<String>()? {
                    if items.contains_key(&key) {
                        return Err(de::Error::custom("Clave duplicada"));
                    }
                    items.insert(key, a.next_value::<Box<RawValue>>()?);
                }
                Ok(Object(items))
            }
        }
        d.deserialize_map(ObjectVisitor)
    }
}
fn object(raw: &[u8], keys: &[&str]) -> Result<BTreeMap<String, Box<RawValue>>> {
    let Object(value) = serde_json::from_slice(raw).map_err(|_| MagnitudeError)?;
    if value.len() != keys.len() || keys.iter().any(|key| !value.contains_key(*key)) {
        return Err(MagnitudeError);
    }
    Ok(value)
}
fn string(raw: &RawValue) -> Result<String> {
    serde_json::from_str(raw.get()).map_err(|_| MagnitudeError)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct U256([u64; 4]);
impl U256 {
    fn zero(self) -> bool {
        self.0 == [0; 4]
    }
    fn one(self) -> bool {
        self.0 == [1, 0, 0, 0]
    }
    fn even(self) -> bool {
        self.0[0] & 1 == 0
    }
    fn half(&mut self) {
        for i in 0..4 {
            self.0[i] = (self.0[i] >> 1) | if i < 3 { self.0[i + 1] << 63 } else { 0 };
        }
    }
    fn greater(self, other: Self) -> bool {
        self.0.iter().rev().cmp(other.0.iter().rev()).is_gt()
    }
    fn subtract(&mut self, other: Self) {
        let mut borrow = false;
        for i in 0..4 {
            let (v, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (v, b2) = v.overflowing_sub(u64::from(borrow));
            self.0[i] = v;
            borrow = b1 || b2;
        }
    }
}
fn integer(raw: &RawValue) -> Result<(bool, U256, String)> {
    let text = raw.get().trim();
    let negative = text.starts_with('-');
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty()
        || digits.len() > 78
        || !digits.bytes().all(|c| c.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(MagnitudeError);
    }
    let mut value = U256([0; 4]);
    for digit in digits.bytes() {
        let mut carry = u128::from(digit - b'0');
        for limb in &mut value.0 {
            let expanded = u128::from(*limb) * 10 + carry;
            *limb = expanded as u64;
            carry = expanded >> 64;
        }
        if carry != 0 {
            return Err(MagnitudeError);
        }
    }
    let negative = negative && !value.zero();
    Ok((
        negative,
        value,
        if negative {
            format!("-{digits}")
        } else {
            digits.into()
        },
    ))
}
fn coprime(mut a: U256, mut b: U256) -> bool {
    if a.zero() {
        return b.one();
    }
    if a.even() && b.even() {
        return false;
    }
    // El MCD binario requiere solo desplazamientos y restas exactas acotadas.
    loop {
        while a.even() {
            a.half();
        }
        while b.even() {
            b.half();
        }
        if a == b {
            return a.one();
        }
        if a.greater(b) {
            a.subtract(b);
        } else {
            b.subtract(a);
        }
    }
}
fn decode_inner(raw: &[u8]) -> Result<Magnitude> {
    // Leer el discriminante sin admitir campos extra ni claves duplicadas.
    let Object(fields) = serde_json::from_slice(raw).map_err(|_| MagnitudeError)?;
    let status = fields
        .get("status")
        .ok_or(MagnitudeError)
        .and_then(|v| string(v))?;
    let wire = if status == "ND" {
        let values = object(raw, &["status", "reason_code"])?;
        let reason = string(&values["reason_code"])?;
        if reason.is_empty()
            || reason.len() > 64
            || !reason.as_bytes()[0].is_ascii_uppercase()
            || !reason
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err(MagnitudeError);
        }
        format!("{{\"reason_code\":\"{reason}\",\"status\":\"ND\"}}")
    } else if status == "DETERMINADO" {
        let values = object(raw, &["status", "value"])?;
        let fraction = object(
            values["value"].get().as_bytes(),
            &["numerator", "denominator"],
        )?;
        let (_, n, numerator) = integer(&fraction["numerator"])?;
        let (negative, d, denominator) = integer(&fraction["denominator"])?;
        if negative || d.zero() || !coprime(n, d) {
            return Err(MagnitudeError);
        }
        format!(
            "{{\"status\":\"DETERMINADO\",\"value\":{{\"denominator\":{denominator},\"numerator\":{numerator}}}}}"
        )
    } else {
        return Err(MagnitudeError);
    };
    Ok(Magnitude {
        wire: wire.into_bytes(),
    })
}

/// Validar una magnitud del contrato Python y conservar su codificación canónica.
pub fn decode_magnitude(raw: &[u8]) -> Result<Magnitude> {
    if raw.len() > MAX_MAGNITUDE_BYTES {
        return Err(MagnitudeError);
    }
    decode_inner(raw)
}

/// Leer un registro analítico versionado sin aceptar campos operacionales.
pub fn decode_record(raw: &[u8]) -> Result<Magnitude> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(MagnitudeError);
    }
    let fields = object(raw, &["format", "magnitude"])?;
    if string(&fields["format"])? != FORMAT {
        return Err(MagnitudeError);
    }
    decode_inner(fields["magnitude"].get().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_and_nd() {
        let raw = br#"{"status":"DETERMINADO","value":{"numerator":-0,"denominator":1}}"#;
        let m = decode_magnitude(raw).unwrap();
        assert_eq!(
            m.as_bytes(),
            br#"{"status":"DETERMINADO","value":{"denominator":1,"numerator":0}}"#
        );
        assert_eq!(decode_record(&m.record_bytes()).unwrap(), m);
        assert!(decode_magnitude(br#"{"status":"ND","reason_code":"NO_DATA"}"#).is_ok());
    }
    #[test]
    fn invalid_values_and_duplicates() {
        for raw in [
            r#"{"status":"DETERMINADO","value":{"numerator":2,"denominator":4}}"#,
            r#"{"status":"DETERMINADO","value":{"numerator":0,"denominator":2}}"#,
            r#"{"status":"DETERMINADO","value":{"numerator":true,"denominator":1}}"#,
            r#"{"status":"ND","status":"ND","reason_code":"X"}"#,
            r#"{"status":"ND","reason_code":"ñ"}"#,
        ] {
            assert!(decode_magnitude(raw.as_bytes()).is_err());
        }
    }
    #[test]
    fn full_width_and_overflow() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let raw = format!(
            "{{\"status\":\"DETERMINADO\",\"value\":{{\"numerator\":-{max},\"denominator\":1}}}}"
        );
        assert!(decode_magnitude(raw.as_bytes()).is_ok());
        let raw = raw.replace(
            max,
            "115792089237316195423570985008687907853269984665640564039457584007913129639936",
        );
        assert!(decode_magnitude(raw.as_bytes()).is_err());
    }
}
