//! Compatibilidad explícita con el perfil inicial.
use super::*;
const IDENTITIES: &str =
    "record_id execution_id correlation_id service_scenario_id derived_case_id attempt_id";

pub(super) fn validate(m: &Value) -> Result {
    fields(
        m,
        "record_id execution_id correlation_id service_scenario_id derived_case_id attempt_id schema_version message_type message_id decision_index created_at producer versions payload",
    )?;
    coded(m["schema_version"] == "1.0", "version_incompatible")?;
    one(
        &m["message_type"],
        "execution_request accepted_for_execution attempt_status_request execution_result",
    )?;
    let kind = text(&m["message_type"])?;
    let producer = if matches!(kind, "execution_request" | "attempt_status_request") {
        "analitico"
    } else {
        "tecnico"
    };
    check(m["producer"] == producer)?;
    references(m, IDENTITIES)?;
    id(&m["message_id"])?;
    integer(&m["decision_index"], 0, MAX_INTEGER)?;
    fields(&m["versions"], "reference")?;
    id(&m["versions"]["reference"])?;
    timestamp(&m["created_at"])?;
    let p = &m["payload"];
    match kind {
        "execution_request" => {
            fields(
                p,
                "host_reference credential_reference case_reference authorization_reference parameters_reference protocol port timeout_seconds simulation",
            )?;
            references(
                p,
                "host_reference credential_reference case_reference authorization_reference parameters_reference",
            )?;
            one(&p["protocol"], "ssh ftp smb")?;
            integer(&p["port"], 1, 65535)?;
            integer(&p["timeout_seconds"], 1, 86400)?;
            check(p["simulation"].is_boolean())?;
            coded(
                p["case_reference"] == m["derived_case_id"],
                "identifier_mismatch",
            )?;
        }
        "accepted_for_execution" => {
            fields(
                p,
                "request_reference attempt_id acceptance_status start_status journal_reference",
            )?;
            references(p, "request_reference attempt_id journal_reference")?;
            check(p["acceptance_status"] == "ACEPTADA" && p["start_status"] == "NO_ACREDITADO")?;
            coded(p["attempt_id"] == m["attempt_id"], "identifier_mismatch")?;
        }
        "attempt_status_request" => {
            fields(p, "attempt_id decision_reference requested_information")?;
            references(p, "attempt_id decision_reference")?;
            information(&p["requested_information"])?;
            coded(
                p["attempt_id"] == m["attempt_id"]
                    && p["decision_reference"] == m["correlation_id"],
                "identifier_mismatch",
            )?;
        }
        _ => {
            fields(
                p,
                "request_reference start_reference termination_reference stdout_reference stderr_reference effective_parameters_reference technical_status start_status exit_code timed_out duration_ms supports cleanup simulation",
            )?;
            references(
                p,
                "request_reference start_reference termination_reference stdout_reference stderr_reference effective_parameters_reference",
            )?;
            check(p["technical_status"] == "completed" && p["start_status"] == "VERIFICADO")?;
            check(p["timed_out"] == false && p["simulation"].is_boolean())?;
            integer(&p["exit_code"], i64::from(i32::MIN), i64::from(i32::MAX))?;
            integer(&p["duration_ms"], 0, MAX_INTEGER)?;
            fields(&p["cleanup"], "status reference")?;
            check(p["cleanup"]["status"] == "completed")?;
            id(&p["cleanup"]["reference"])?;
            unique_refs(&p["supports"], 1024)?;
        }
    }
    Ok(())
}
pub(super) fn correlate(r: &Value, m: &Value) -> Result {
    check(r["message_type"] == "execution_request")?;
    one(
        &m["message_type"],
        "accepted_for_execution attempt_status_request execution_result",
    )?;
    coded(r["message_id"] != m["message_id"], "identifier_mismatch")?;
    same(r, m, IDENTITIES)?;
    same(r, m, "decision_index versions")?;
    if m["message_type"] != "attempt_status_request" {
        coded(
            m["payload"]["request_reference"] == r["message_id"],
            "identifier_mismatch",
        )?;
    }
    if m["message_type"] == "execution_result" {
        same(&r["payload"], &m["payload"], "simulation")?;
    }
    Ok(())
}
