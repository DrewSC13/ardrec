//! P8-R7: strict, pure, deny-only Python/Rust diagnostic interoperability.
//!
//! Input is untrusted synthetic JSON, not an execution request or authority.
//! No file, network, process, VM, or secret access. It cannot dispatch.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::contract_gate::PROFILE_IDS;

/// Maximum diagnostic document size in bytes.
pub const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const INPUT_KIND: &str = "P8_R7_DIAGNOSTIC_PROPOSAL";
const MATERIAL: &str = "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL";
const ACTIVE: &str = "SYNTHETIC_PRECONDITIONS_CONSISTENT_DENY_ALL";
const INVALIDATED: &str = "SYNTHETIC_EXPIRED_OR_INVALIDATED_DENY_ALL";
const FIELDS: [&str; 20] = [
    "schema_version",
    "message_type",
    "stage",
    "case_id",
    "profile_id",
    "snapshot_sha256",
    "r6_snapshot_sha256",
    "material_epoch",
    "r6_material_epoch",
    "authorization_revision",
    "r6_authorization_revision",
    "r5_status",
    "r6_status",
    "r5_dispatch_allowed",
    "r5_case_authorized",
    "r6_dispatch_allowed",
    "r6_operational_authorization",
    "private_issuer_verified",
    "revocation_verified",
    "dispatch_requested",
];

// Recursive JSON visitor prevents serde_json::Value from silently replacing
// duplicate map keys. This applies to nested objects as well as the envelope.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(v)))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
        match serde_json::Number::from_f64(v) {
            Some(number) => Ok(Unique(Value::Number(number))),
            None => Err(E::custom("nonfinite JSON number")),
        }
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(Value::String(v.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(Value::String(v)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Unique, D::Error> {
        Unique::deserialize(de)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<Unique>()? {
            values.push(value.0);
        }
        Ok(Unique(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, Unique>()? {
            if values.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
        }
        Ok(Unique(Value::Object(values)))
    }
}

/// A denial diagnostic without any authorization or executable capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    /// Stable reason code shared with Python.
    pub reason_code: &'static str,
    /// Always false by construction.
    pub authorized: bool,
    /// Always false by construction.
    pub dispatch_allowed: bool,
}

fn deny(reason_code: &'static str) -> Denial {
    Denial {
        reason_code,
        authorized: false,
        dispatch_allowed: false,
    }
}

fn string<'a>(map: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

fn integer(map: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    map.get(key)?.as_u64()
}

fn boolean(map: &serde_json::Map<String, Value>, key: &str) -> Option<bool> {
    map.get(key)?.as_bool()
}

fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn case_format(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() == 4
        && matches!(parts[0], "SSH" | "FTP" | "SMB")
        && parts[1].len() == 3
        && parts[1].starts_with('T')
        && parts[1][1..].bytes().all(|b| b.is_ascii_digit())
        && (3..=5).contains(&parts[2].len())
        && parts[2].starts_with('S')
        && parts[2][1..].bytes().all(|b| b.is_ascii_digit())
        && parts[3].len() == 2
        && parts[3].bytes().all(|b| b.is_ascii_digit())
}

/// Evaluate one untrusted diagnostic JSON document without any side effects.
/// Both correct and incorrect synthetic records are permanently DENIED.
pub fn evaluate(raw: &[u8]) -> Denial {
    if raw.is_empty() || raw.len() > MAX_DIAGNOSTIC_BYTES {
        return deny("P8_R7_INVALID_SCHEMA");
    }
    let Ok(Unique(Value::Object(fields))) = serde_json::from_slice::<Unique>(raw) else {
        return deny("P8_R7_INVALID_SCHEMA");
    };
    if fields.len() != FIELDS.len() || FIELDS.iter().any(|key| !fields.contains_key(*key)) {
        return deny("P8_R7_INVALID_SCHEMA");
    }
    if string(&fields, "schema_version") != Some("1.0")
        || string(&fields, "message_type") != Some(INPUT_KIND)
        || !matches!(string(&fields, "stage"), Some("dev" | "pilot" | "exp"))
        || [
            "case_id",
            "profile_id",
            "snapshot_sha256",
            "r6_snapshot_sha256",
            "r5_status",
            "r6_status",
        ]
        .iter()
        .any(|k| string(&fields, k).is_none())
        || [
            "material_epoch",
            "r6_material_epoch",
            "authorization_revision",
            "r6_authorization_revision",
        ]
        .iter()
        .any(|k| integer(&fields, k).is_none())
        || [
            "r5_dispatch_allowed",
            "r5_case_authorized",
            "r6_dispatch_allowed",
            "r6_operational_authorization",
            "private_issuer_verified",
            "revocation_verified",
            "dispatch_requested",
        ]
        .iter()
        .any(|k| boolean(&fields, k).is_none())
    {
        return deny("P8_R7_INVALID_SCHEMA");
    }
    let profile = string(&fields, "profile_id").unwrap_or("");
    let case_id = string(&fields, "case_id").unwrap_or("");
    if !PROFILE_IDS.contains(&profile) {
        return deny("P8_R7_UNKNOWN_PROFILE");
    }
    if !case_format(case_id) || case_id.split("-S").next() != profile.get(..7) {
        return deny("P8_R7_IDENTITY_MISMATCH");
    }
    let snapshot = string(&fields, "snapshot_sha256").unwrap_or("");
    let r6_snapshot = string(&fields, "r6_snapshot_sha256").unwrap_or("");
    if !digest(snapshot) || !digest(r6_snapshot) {
        return deny("P8_R7_DIGEST_INVALID");
    }
    if snapshot != r6_snapshot {
        return deny("P8_R7_IDENTITY_MISMATCH");
    }
    let material_epoch = integer(&fields, "material_epoch").unwrap_or(0);
    let authorization_revision = integer(&fields, "authorization_revision").unwrap_or(0);
    if material_epoch == 0
        || material_epoch > 2_147_483_647
        || authorization_revision == 0
        || authorization_revision > 2_147_483_647
        || integer(&fields, "r6_material_epoch") != Some(material_epoch)
        || integer(&fields, "r6_authorization_revision") != Some(authorization_revision)
    {
        return deny("P8_R7_REVISION_MISMATCH");
    }
    let r6_status = string(&fields, "r6_status").unwrap_or("");
    if string(&fields, "r5_status") != Some(MATERIAL) || !matches!(r6_status, ACTIVE | INVALIDATED)
    {
        return deny("P8_R7_INVALID_CLAIM");
    }
    if [
        "r5_dispatch_allowed",
        "r5_case_authorized",
        "r6_dispatch_allowed",
        "r6_operational_authorization",
        "private_issuer_verified",
        "revocation_verified",
    ]
    .iter()
    .any(|key| boolean(&fields, key) != Some(false))
    {
        return deny("P8_R7_AUTHORITY_CLAIM");
    }
    if boolean(&fields, "dispatch_requested") == Some(true) {
        return deny("P8_R7_DISPATCH_REQUESTED");
    }
    if r6_status == INVALIDATED {
        return deny("P8_R7_INVALIDATED");
    }
    deny("P8_R7_UNVERIFIED_AUTHORITY")
}

/// Render a stable JSON diagnostic for the test-only probe; never contains inputs.
pub fn diagnostic_json(result: Denial) -> String {
    let mut map: BTreeMap<&str, Value> = BTreeMap::new();
    map.insert("schema_version", Value::from("1.0"));
    map.insert("message_type", Value::from("P8_R7_DENIAL_RESULT"));
    map.insert("decision", Value::from("BLOCKED_UNBOUND_NO_EXECUTION"));
    map.insert("reason_code", Value::from(result.reason_code));
    map.insert("authorized", Value::Bool(false));
    map.insert("dispatch_allowed", Value::Bool(false));
    serde_json::to_string(&map).expect("constant diagnostic serialization")
}
