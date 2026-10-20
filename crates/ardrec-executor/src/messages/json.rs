//! Lectura estricta de JSON antes de validar su significado.
use super::{MessageError, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON sin claves duplicadas ni números decimales")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if values.contains_key(&k) {
                        return Err(de::Error::custom("Clave duplicada"));
                    }
                    values.insert(k, a.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

pub(super) fn parse(raw: &[u8]) -> Result<Value> {
    std::str::from_utf8(raw).map_err(|_| MessageError("schema_invalid"))?;
    // Python interpreta -0 como el entero 0; no se debe convertir a float.
    let mut normalized = Vec::with_capacity(raw.len());
    let (mut i, mut string, mut escaped) = (0, false, false);
    while i < raw.len() {
        let c = raw[i];
        if string {
            normalized.push(c);
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                string = false;
            }
            i += 1;
        } else if c == b'"' {
            string = true;
            normalized.push(c);
            i += 1;
        } else if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i < raw.len() && !b" \t\r\n,]}".contains(&raw[i]) {
                i += 1;
            }
            let token = &raw[start..i];
            let digits = if token[0] == b'-' { &token[1..] } else { token };
            if digits.is_empty()
                || !digits.iter().all(u8::is_ascii_digit)
                || (digits.len() > 1 && digits[0] == b'0')
            {
                return Err(MessageError("schema_invalid"));
            }
            normalized.extend_from_slice(if token == b"-0" { b"0" } else { token });
        } else {
            normalized.push(c);
            i += 1;
        }
    }
    serde_json::from_slice::<Strict>(&normalized)
        .map(|v| v.0)
        .map_err(|_| MessageError("schema_invalid"))
}
