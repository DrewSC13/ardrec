//! Restricciones y correlaciones del perfil completo.
use super::*;
use sha2::{Digest, Sha256};
const IDENTITIES: &str = "record_id execution_id correlation_id decision_index scope service_scenario_id derived_case_id attempt_id versions simulation";
const TYPES: &str = "execution_request discovery_request accepted_for_execution execution_result discovery_result attempt_status_request attempt_status_result supervision_event message_rejection closure_record persisted_state";

fn fact(v: &Value, choices: &str, documented: &str) -> Result {
    fields(v, "status reference")?;
    one(&v["status"], choices)?;
    if documented.split_whitespace().any(|s| v["status"] == s) {
        id(&v["reference"])
    } else {
        check(v["reference"].is_null())
    }
}
fn snapshot(v: &Value) -> Result {
    fields(
        v,
        "phase start termination cleanup result reason_code observed_at journal_reference reconciliation_required new_execution_authorized",
    )?;
    one(
        &v["phase"],
        "accepted running completed interrupted not_started uncertain",
    )?;
    timestamp(&v["observed_at"])?;
    id(&v["journal_reference"])?;
    fact(
        &v["start"],
        "VERIFICADO NO_INICIADO NO_ACREDITADO NO_DETERMINADO",
        "VERIFICADO NO_INICIADO",
    )?;
    fact(
        &v["termination"],
        "VERIFICADO EN_CURSO NO_APLICA NO_DETERMINADO",
        "VERIFICADO",
    )?;
    fact(
        &v["cleanup"],
        "completed not_required pending failed unknown",
        "completed not_required failed",
    )?;
    fact(
        &v["result"],
        "DISPONIBLE PENDIENTE NO_DISPONIBLE",
        "DISPONIBLE",
    )?;
    let phase = text(&v["phase"])?;
    let (start, end, cleanup, result) = (
        text(&v["start"]["status"])?,
        text(&v["termination"]["status"])?,
        text(&v["cleanup"]["status"])?,
        text(&v["result"]["status"])?,
    );
    let clean = matches!(cleanup, "completed" | "not_required");
    if matches!(phase, "accepted" | "running" | "completed") {
        check(v["reason_code"].is_null())?;
    } else {
        one(
            &v["reason_code"],
            "REQUEST_REJECTED SPAWN_FAILED TIMEOUT INTERRUPTED EXECUTOR_FAILURE CONNECTION_LOST STATUS_UNAVAILABLE CLEANUP_FAILED RESULT_UNAVAILABLE",
        )?;
    }
    match phase {
        "accepted" => check(
            (start, end, cleanup, result)
                == ("NO_ACREDITADO", "NO_DETERMINADO", "pending", "PENDIENTE"),
        )?,
        "running" => check(
            (start, end, cleanup, result) == ("VERIFICADO", "EN_CURSO", "pending", "PENDIENTE"),
        )?,
        "completed" | "interrupted" => {
            check(start == "VERIFICADO" && end == "VERIFICADO" && result == "DISPONIBLE")?;
            if phase == "interrupted" {
                one(&v["reason_code"], "TIMEOUT INTERRUPTED EXECUTOR_FAILURE")?;
            }
        }
        "not_started" => {
            check(
                (start, end, cleanup, result)
                    == ("NO_INICIADO", "NO_APLICA", "not_required", "NO_DISPONIBLE"),
            )?;
            one(&v["reason_code"], "REQUEST_REJECTED SPAWN_FAILED")?;
        }
        _ => {
            one(
                &v["reason_code"],
                "TIMEOUT EXECUTOR_FAILURE CONNECTION_LOST STATUS_UNAVAILABLE CLEANUP_FAILED RESULT_UNAVAILABLE",
            )?;
            one(&v["start"]["status"], "VERIFICADO NO_DETERMINADO")?;
            one(&v["termination"]["status"], "VERIFICADO NO_DETERMINADO")?;
            check(result != "DISPONIBLE")?;
            if start == "NO_DETERMINADO" {
                check(end == "NO_DETERMINADO" && matches!(cleanup, "pending" | "unknown"))?;
            }
            if end == "NO_DETERMINADO" {
                check(!clean)?;
            }
            if v["reason_code"] == "TIMEOUT" {
                check(start == "VERIFICADO")?;
            }
            if v["reason_code"] == "CLEANUP_FAILED" {
                check(cleanup == "failed")?;
            }
        }
    }
    let reconcile = matches!(phase, "accepted" | "running" | "uncertain") || !clean;
    check(v["reconciliation_required"].as_bool() == Some(reconcile))?;
    // Ninguna respuesta autoriza automáticamente otro despacho.
    check(v["new_execution_authorized"] == false)
}
fn outcome(v: &Value, state: &Value) -> Result {
    fields(
        v,
        "started_at ended_at exit_code signal timed_out duration_ms stdout_reference stderr_reference stdout_truncated stderr_truncated effective_parameters_reference supports",
    )?;
    for flag in ["timed_out", "stdout_truncated", "stderr_truncated"] {
        check(v[flag].is_boolean())?;
    }
    for k in [
        "stdout_reference",
        "stderr_reference",
        "effective_parameters_reference",
    ] {
        if !v[k].is_null() {
            id(&v[k])?;
        }
    }
    for (flag, reference) in [
        ("stdout_truncated", "stdout_reference"),
        ("stderr_truncated", "stderr_reference"),
    ] {
        check(v[flag] == false || !v[reference].is_null())?;
    }
    unique_refs(&v["supports"], 1024)?;
    if !v["duration_ms"].is_null() {
        integer(&v["duration_ms"], 0, MAX_INTEGER)?;
    }
    if !v["exit_code"].is_null() {
        integer(&v["exit_code"], 0, i64::from(i32::MAX))?;
    }
    if !v["signal"].is_null() {
        integer(&v["signal"], 1, 64)?;
    }
    check(v["exit_code"].is_null() || v["signal"].is_null())?;
    let started = state["start"]["status"] == "VERIFICADO";
    let ended = state["termination"]["status"] == "VERIFICADO";
    if started {
        timestamp(&v["started_at"])?;
        id(&v["effective_parameters_reference"])?;
    } else {
        for k in [
            "started_at",
            "duration_ms",
            "stdout_reference",
            "stderr_reference",
            "effective_parameters_reference",
        ] {
            check(v[k].is_null())?;
        }
        check(v["supports"].as_array().is_some_and(Vec::is_empty) && v["timed_out"] == false)?;
    }
    if ended {
        check(started && timestamp(&v["ended_at"])? >= timestamp(&v["started_at"])?)?;
    } else {
        check(v["ended_at"].is_null() && v["exit_code"].is_null() && v["signal"].is_null())?;
    }
    let phase = text(&state["phase"])?;
    if matches!(phase, "completed" | "interrupted") {
        integer(&v["duration_ms"], 0, MAX_INTEGER)?;
        check(v["exit_code"].is_null() != v["signal"].is_null())?;
    }
    if phase == "completed" {
        check(v["timed_out"] == false && v["signal"].is_null())?;
        references(v, "stdout_reference stderr_reference")?;
    }
    if v["timed_out"] == true {
        check(started && state["reason_code"] == "TIMEOUT")?;
    }
    if state["reason_code"] == "TIMEOUT" {
        check(v["timed_out"] == true)?;
    }
    if matches!(phase, "uncertain" | "not_started") {
        check(v["supports"].as_array().is_some_and(Vec::is_empty))?;
    }
    Ok(())
}

pub(super) fn validate(m: &Value) -> Result {
    fields(
        m,
        "record_id execution_id correlation_id decision_index scope service_scenario_id derived_case_id attempt_id versions simulation schema_version message_type message_id created_at producer payload",
    )?;
    coded(m["schema_version"] == "2.0", "version_incompatible")?;
    one(&m["message_type"], TYPES)?;
    let kind = text(&m["message_type"])?;
    let producers = match kind {
        "execution_request" | "discovery_request" | "attempt_status_request" | "closure_record" => {
            "analitico"
        }
        "supervision_event" => "supervision",
        "persisted_state" => "persistencia",
        "message_rejection" => "analitico tecnico persistencia",
        _ => "tecnico",
    };
    one(&m["producer"], producers)?;
    references(m, "message_id record_id execution_id correlation_id")?;
    integer(&m["decision_index"], 0, MAX_INTEGER)?;
    timestamp(&m["created_at"])?;
    check(m["simulation"].is_boolean())?;
    fields(&m["versions"], "reference sha256")?;
    id(&m["versions"]["reference"])?;
    digest(&m["versions"]["sha256"])?;
    one(&m["scope"], "attempt discovery service observation")?;
    let scope = text(&m["scope"])?;
    for (k, required) in [
        ("service_scenario_id", scope != "observation"),
        ("derived_case_id", scope == "attempt"),
        ("attempt_id", matches!(scope, "attempt" | "discovery")),
    ] {
        if required {
            id(&m[k])?;
        } else {
            check(m[k].is_null())?;
        }
    }
    let scopes = match kind {
        "execution_request" | "execution_result" => "attempt",
        "discovery_request" | "discovery_result" => "discovery",
        "accepted_for_execution" | "attempt_status_request" | "attempt_status_result" => {
            "attempt discovery"
        }
        "supervision_event" => "service observation",
        "closure_record" | "persisted_state" => "observation",
        _ => "attempt discovery service observation",
    };
    one(&m["scope"], scopes)?;
    let p = &m["payload"];
    match kind {
        "execution_request" | "discovery_request" => {
            fields(
                p,
                "host_reference authorization_reference scope_reference profile_reference parameters_reference authentication protocol port limits",
            )?;
            references(
                p,
                "host_reference authorization_reference scope_reference profile_reference parameters_reference",
            )?;
            one(&p["protocol"], "ssh ftp smb")?;
            integer(&p["port"], 1, 65535)?;
            let auth = &p["authentication"];
            one(&auth["mode"], "none referenced")?;
            if auth["mode"] == "none" {
                fields(auth, "mode")?;
            } else {
                fields(auth, "mode credential_reference")?;
                id(&auth["credential_reference"])?;
            }
            let limits = &p["limits"];
            fields(
                limits,
                "timeout_seconds stdout_max_bytes stderr_max_bytes artifact_max_bytes max_supports",
            )?;
            integer(&limits["timeout_seconds"], 1, 86400)?;
            for k in ["stdout_max_bytes", "stderr_max_bytes", "artifact_max_bytes"] {
                integer(&limits[k], 1, MAX_INTEGER)?;
            }
            integer(&limits["max_supports"], 0, 1024)?;
        }
        "attempt_status_request" => {
            fields(p, "request_reference requested_information")?;
            id(&p["request_reference"])?;
            information(&p["requested_information"])?;
        }
        "accepted_for_execution"
        | "attempt_status_result"
        | "execution_result"
        | "discovery_result" => {
            let names = match kind {
                "accepted_for_execution" => "request_reference snapshot",
                "attempt_status_result" => {
                    "request_reference snapshot query_reference requested_information"
                }
                "execution_result" => "request_reference snapshot outcome",
                _ => "request_reference snapshot outcome characterization_reference",
            };
            fields(p, names)?;
            id(&p["request_reference"])?;
            snapshot(&p["snapshot"])?;
            let observed = timestamp(&p["snapshot"]["observed_at"])?;
            check(observed <= timestamp(&m["created_at"])?)?;
            let phase = text(&p["snapshot"]["phase"])?;
            if kind == "accepted_for_execution" {
                check(phase == "accepted")?;
            } else if kind == "attempt_status_result" {
                id(&p["query_reference"])?;
                information(&p["requested_information"])?;
            } else {
                one(
                    &p["snapshot"]["phase"],
                    "completed interrupted uncertain not_started",
                )?;
                outcome(&p["outcome"], &p["snapshot"])?;
                for k in ["started_at", "ended_at"] {
                    if !p["outcome"][k].is_null() {
                        check(timestamp(&p["outcome"][k])? <= observed)?;
                    }
                }
                if matches!(phase, "completed" | "interrupted") {
                    coded(
                        p["snapshot"]["result"]["reference"] == m["message_id"],
                        "identifier_mismatch",
                    )?;
                }
                if kind == "discovery_result" {
                    if phase == "completed" {
                        id(&p["characterization_reference"])?;
                    } else {
                        check(p["characterization_reference"].is_null())?;
                    }
                }
            }
        }
        "message_rejection" => {
            fields(
                p,
                "rejected_message_id rejected_message_type rejected_sha256 error_code reason_reference",
            )?;
            references(p, "rejected_message_id reason_reference")?;
            if !p["rejected_message_type"].is_null() {
                id(&p["rejected_message_type"])?;
                check(p["rejected_message_type"] != "message_rejection")?;
            }
            digest(&p["rejected_sha256"])?;
            one(
                &p["error_code"],
                "schema_invalid version_incompatible identifier_mismatch duplicate_conflict out_of_scope catalog_mismatch message_too_large integrity_failure",
            )?;
        }
        "supervision_event" => {
            fields(
                p,
                "action actor_reference authorization_reference instruction_reference reason_reference",
            )?;
            one(
                &p["action"],
                "record_control request_pause request_stop request_resume",
            )?;
            references(
                p,
                "actor_reference authorization_reference instruction_reference reason_reference",
            )?;
        }
        _ => {
            fields(
                p,
                if kind == "closure_record" {
                    "generation state_reference state_sha256 report_reference reason_reference"
                } else {
                    "generation state_reference state_sha256 request_reference pointer_reference publication_reference status"
                },
            )?;
            integer(&p["generation"], 0, MAX_INTEGER)?;
            coded(
                p["generation"] == m["decision_index"],
                "identifier_mismatch",
            )?;
            id(&p["state_reference"])?;
            digest(&p["state_sha256"])?;
            if kind == "closure_record" {
                references(p, "report_reference reason_reference")?;
            } else {
                references(
                    p,
                    "request_reference pointer_reference publication_reference",
                )?;
                check(p["status"] == "PUBLISHED")?;
            }
        }
    }
    Ok(())
}

pub(super) fn correlate(r: &Value, m: &Value) -> Result {
    validate(r)?;
    validate(m)?;
    coded(r["message_id"] != m["message_id"], "identifier_mismatch")?;
    same(r, m, IDENTITIES)?;
    let p = &m["payload"];
    let kind = text(&r["message_type"])?;
    if m["message_type"] == "message_rejection" {
        check(kind != "message_rejection")?;
        let recipient = match kind {
            "execution_request" | "discovery_request" | "attempt_status_request" => "tecnico",
            "closure_record" => "persistencia",
            _ => "analitico",
        };
        check(m["producer"] == recipient)?;
        coded(
            p["rejected_message_id"] == r["message_id"]
                && p["rejected_message_type"] == r["message_type"],
            "identifier_mismatch",
        )?;
        let hash = format!("{:x}", Sha256::digest(encode_message(r)?));
        coded(p["rejected_sha256"] == hash, "integrity_failure")?;
        return Ok(());
    }
    let related = match kind {
        "execution_request" => {
            "accepted_for_execution attempt_status_request attempt_status_result execution_result"
        }
        "discovery_request" => {
            "accepted_for_execution attempt_status_request attempt_status_result discovery_result"
        }
        "attempt_status_request" => "attempt_status_result",
        "closure_record" => "persisted_state",
        _ => "",
    };
    one(&m["message_type"], related)?;
    if kind == "attempt_status_request" {
        coded(
            p["query_reference"] == r["message_id"]
                && p["request_reference"] == r["payload"]["request_reference"],
            "identifier_mismatch",
        )?;
        let set = |v: &Value| -> Result<BTreeSet<String>> {
            let a = v.as_array().ok_or(MessageError("schema_invalid"))?;
            a.iter().map(|item| text(item).map(str::to_owned)).collect()
        };
        coded(
            set(&p["requested_information"])? == set(&r["payload"]["requested_information"])?,
            "identifier_mismatch",
        )?;
    } else {
        coded(
            p["request_reference"] == r["message_id"],
            "identifier_mismatch",
        )?;
    }
    if kind == "closure_record" {
        same(p, &r["payload"], "generation state_reference state_sha256")?;
    }
    if matches!(
        m["message_type"].as_str(),
        Some("execution_result" | "discovery_result")
    ) {
        let supports = p["outcome"]["supports"]
            .as_array()
            .ok_or(MessageError("schema_invalid"))?;
        let maximum = r["payload"]["limits"]["max_supports"]
            .as_u64()
            .ok_or(MessageError("schema_invalid"))?;
        check(supports.len() as u64 <= maximum)?;
    }
    Ok(())
}
