//! Admisión temporal-v1 sin cambiar los lectores históricos.
use super::*;
/// Comprobar límites UTC necesarios; no acredita hechos ni autoriza ejecución.
pub fn correlate_current(request: &Value, related: &Value) -> Result {
    correlate(request, related)?;
    coded(request["schema_version"] == "2.0", "version_incompatible")?;
    let origin = timestamp(&request["created_at"])?;
    coded(
        timestamp(&related["created_at"])? >= origin,
        "temporal_inversion",
    )?;
    if matches!(
        request["message_type"].as_str(),
        Some("execution_request" | "discovery_request")
    ) {
        let payload = &related["payload"];
        if let Some(snapshot) = payload.get("snapshot") {
            coded(
                timestamp(&snapshot["observed_at"])? >= origin,
                "temporal_inversion",
            )?;
        }
        if let Some(outcome) = payload.get("outcome") {
            for key in ["started_at", "ended_at"] {
                if !outcome[key].is_null() {
                    coded(timestamp(&outcome[key])? >= origin, "temporal_inversion")?;
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_temporal_oracles() {
        let corpus: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/temporal-policy-v1.json"
        )))
        .unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let actual = correlate_current(&case["request"], &case["related"])
                .err()
                .map(|e| e.code());
            assert_eq!(actual, case["expected_error"].as_str(), "{}", case["id"]);
        }
    }
}
