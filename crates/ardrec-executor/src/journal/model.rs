//! Reducción determinista de registros; se repite al recuperar cada cadena.
use super::*;
use crate::messages::{correlate, correlate_status, decode_message, encode_message};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct Attempt {
    pub request: Value,
    pub snapshot: Value,
    pub result: Option<Value>,
    pub first_reply: Option<Value>,
}
#[derive(Clone, Default)]
pub(super) struct Model {
    pub attempts: BTreeMap<String, Attempt>,
    messages: BTreeMap<String, Vec<u8>>,
    pub answers: BTreeMap<String, (Value, Answer)>,
}

pub(super) fn message(raw: &[u8]) -> Result<Value> {
    let value = decode_message(raw)?;
    need(value["schema_version"] == "2.0", "version_incompatible")?;
    Ok(value)
}
fn validate(v: &Value) -> Result<()> {
    message(&encode_message(v)?).map(|_| ())
}

// El calendario ya fue validado por el protocolo; esta clave normaliza fracciones y 24:00.
fn instant(value: &Value) -> Result<u64> {
    let s = text(value)?;
    let n = |a: usize, b: usize| -> Result<u64> {
        s.get(a..b)
            .ok_or_else(|| error("record_invalid"))?
            .parse()
            .map_err(|_| error("record_invalid"))
    };
    let (year, month, day) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    need(year >= 1 && (1..=12).contains(&month), "record_invalid")?;
    let y = year - 1;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
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
    ];
    let days = y * 365 + y / 4 - y / 100
        + y / 400
        + months[..month as usize - 1].iter().sum::<u64>()
        + day
        - 1;
    let micro = if s.len() > 20 {
        n(20, s.len() - 1)? * 10_u64.pow((27 - s.len()) as u32)
    } else {
        0
    };
    Ok((((days * 24 + n(11, 13)?) * 60 + n(14, 16)?) * 60 + n(17, 19)?) * 1_000_000 + micro)
}
fn unknown(request: &Value) -> Result<Value> {
    Ok(
        json!({"phase":"uncertain", "start":{"status":"NO_DETERMINADO","reference":null},
        "termination":{"status":"NO_DETERMINADO","reference":null},
        "cleanup":{"status":"unknown","reference":null}, "result":{"status":"NO_DISPONIBLE","reference":null},
        "reason_code":"STATUS_UNAVAILABLE", "observed_at":request["created_at"],
        "journal_reference":format!("TJ-{}",hash(&encode_message(request)?)),
        "reconciliation_required":true,"new_execution_authorized":false}),
    )
}
pub(super) fn query_for(request: &Value, id: &str, stamp: &Value) -> Value {
    let mut q = request.clone();
    q["message_type"] = "attempt_status_request".into();
    q["message_id"] = id.into();
    q["created_at"] = stamp.clone();
    q["payload"] = json!({"request_reference":request["message_id"],
                          "requested_information":["INICIO","TERMINACION","RESULTADO","LIMPIEZA"]});
    q
}
pub(super) fn response_for(
    request: &Value,
    query: &Value,
    snapshot: &Value,
    id: &str,
    stamp: &Value,
) -> Value {
    let mut r = request.clone();
    r["message_type"] = "attempt_status_result".into();
    r["message_id"] = id.into();
    r["producer"] = "tecnico".into();
    r["created_at"] = stamp.clone();
    r["payload"] = json!({"request_reference":request["message_id"],"query_reference":query["message_id"],
        "requested_information":query["payload"]["requested_information"],"snapshot":snapshot});
    r
}
fn snapshot_valid(request: &Value, snapshot: &Value) -> Result<()> {
    // Estos identificadores se usan solo para validar; nunca se publican ni se registran.
    let qid = if request["message_id"] == "VALIDATE-Q" {
        "VALIDATE-Q2"
    } else {
        "VALIDATE-Q"
    };
    let rid = if request["message_id"] == "VALIDATE-R" {
        "VALIDATE-R2"
    } else {
        "VALIDATE-R"
    };
    let q = query_for(request, qid, &snapshot["observed_at"]);
    let r = response_for(request, &q, snapshot, rid, &snapshot["observed_at"]);
    validate(&q)?;
    validate(&r)?;
    correlate_status(request, &q, &r)?;
    need(
        instant(&snapshot["observed_at"])? >= instant(&request["created_at"])?,
        "observation_before_request",
    )
}
fn advance(attempt: &Attempt, next: &Value, result: Option<&Value>) -> Result<()> {
    snapshot_valid(&attempt.request, next)?;
    let old = &attempt.snapshot;
    need(
        next["journal_reference"] == old["journal_reference"],
        "journal_identity_conflict",
    )?;
    need(
        instant(&next["observed_at"])? >= instant(&old["observed_at"])?,
        "observation_regression",
    )?;
    for (field, fixed) in [
        ("start", "VERIFICADO NO_INICIADO"),
        ("termination", "VERIFICADO NO_APLICA"),
        ("cleanup", "completed not_required"),
        ("result", "DISPONIBLE"),
    ] {
        if fixed.split_whitespace().any(|x| old[field]["status"] == x) {
            need(next[field] == old[field], "fact_regression")?;
        }
    }
    if matches!(
        old["phase"].as_str(),
        Some("completed" | "interrupted" | "not_started")
    ) {
        need(
            next["phase"] == old["phase"] && next["reason_code"] == old["reason_code"],
            "terminal_regression",
        )?;
    }
    if next["result"]["status"] == "DISPONIBLE" {
        let full = result
            .or(attempt.result.as_ref())
            .ok_or_else(|| error("result_missing"))?;
        need(
            next["result"]["reference"] == full["message_id"],
            "result_identity_conflict",
        )?;
        for field in ["phase", "start", "termination", "result", "reason_code"] {
            need(
                next[field] == full["payload"]["snapshot"][field],
                "result_fact_mismatch",
            )?;
        }
    }
    Ok(())
}
impl Model {
    fn known(&self, v: &Value) -> Result<bool> {
        let key = text(&v["message_id"])?;
        if let Some(raw) = self.messages.get(key) {
            need(*raw == encode_message(v)?, "duplicate_conflict")?;
            return Ok(true);
        }
        Ok(false)
    }
    fn remember(&mut self, v: &Value) -> Result<()> {
        need(!self.known(v)?, "message_identity_reused")?;
        self.messages
            .insert(text(&v["message_id"])?.into(), encode_message(v)?);
        Ok(())
    }
    pub fn attempt(&self, id: &str) -> Result<&Attempt> {
        self.attempts
            .get(id)
            .ok_or_else(|| error("attempt_unknown"))
    }
    pub fn replay_query(&self, q: &Value) -> Result<Option<Answer>> {
        if let Some((old, answer)) = self.answers.get(text(&q["message_id"])?) {
            need(
                encode_message(old)? == encode_message(q)?,
                "duplicate_conflict",
            )?;
            let mut answer = answer.clone();
            answer.replay = true;
            return Ok(Some(answer));
        }
        need(!self.known(q)?, "message_identity_reused")?;
        Ok(None)
    }
    pub fn apply(&mut self, op: &str, args: &Value) -> Result<Recorded> {
        match op {
            "request" => {
                fields(args, &["message"])?;
                let request = &args["message"];
                validate(request)?;
                need(
                    matches!(
                        request["message_type"].as_str(),
                        Some("execution_request" | "discovery_request")
                    ),
                    "request_required",
                )?;
                if self.known(request)? {
                    return Ok(Recorded::Replay);
                }
                let key = text(&request["attempt_id"])?.to_owned();
                need(!self.attempts.contains_key(&key), "duplicate_conflict")?;
                let snapshot = unknown(request)?;
                snapshot_valid(request, &snapshot)?;
                self.remember(request)?;
                self.attempts.insert(
                    key,
                    Attempt {
                        request: request.clone(),
                        snapshot,
                        result: None,
                        first_reply: None,
                    },
                );
            }
            "snapshot" => {
                fields(args, &["attempt_id", "snapshot"])?;
                let id = text(&args["attempt_id"])?;
                let attempt = self.attempt(id)?;
                advance(attempt, &args["snapshot"], None)?;
                if attempt.snapshot == args["snapshot"] {
                    return Ok(Recorded::Replay);
                }
                self.attempts
                    .get_mut(id)
                    .ok_or_else(|| error("attempt_unknown"))?
                    .snapshot = args["snapshot"].clone();
            }
            "report" => {
                fields(args, &["message"])?;
                let report = &args["message"];
                validate(report)?;
                need(
                    matches!(
                        report["message_type"].as_str(),
                        Some(
                            "accepted_for_execution"
                                | "execution_result"
                                | "discovery_result"
                                | "message_rejection"
                        )
                    ),
                    "report_required",
                )?;
                if self.known(report)? {
                    return Ok(Recorded::Replay);
                }
                let id = text(&report["attempt_id"])?.to_owned();
                let attempt = self.attempt(&id)?;
                correlate(&attempt.request, report)?;
                need(
                    instant(&report["created_at"])? >= instant(&attempt.request["created_at"])?,
                    "report_before_request",
                )?;
                let rejection = report["message_type"] == "message_rejection";
                let outcome = matches!(
                    report["message_type"].as_str(),
                    Some("execution_result" | "discovery_result")
                );
                if !rejection {
                    if outcome {
                        need(
                            attempt
                                .result
                                .as_ref()
                                .is_none_or(|v| v["payload"]["snapshot"]["phase"] == "uncertain"),
                            "result_already_recorded",
                        )?;
                    }
                    advance(
                        attempt,
                        &report["payload"]["snapshot"],
                        if outcome { Some(report) } else { None },
                    )?;
                }
                self.remember(report)?;
                let attempt = self
                    .attempts
                    .get_mut(&id)
                    .ok_or_else(|| error("attempt_unknown"))?;
                if !rejection {
                    attempt.snapshot = report["payload"]["snapshot"].clone();
                }
                if outcome {
                    attempt.result = Some(report.clone());
                }
                if attempt.first_reply.is_none()
                    && (rejection || report["message_type"] == "accepted_for_execution")
                {
                    attempt.first_reply = Some(report.clone());
                }
            }
            "answer" => {
                fields(args, &["query", "response", "result"])?;
                let (q, r) = (&args["query"], &args["response"]);
                validate(q)?;
                validate(r)?;
                need(
                    q["message_type"] == "attempt_status_request"
                        && r["message_type"] == "attempt_status_result",
                    "query_required",
                )?;
                if let Some(old) = self.replay_query(q)? {
                    need(
                        old.response == encode_message(r)?
                            && old.result == optional_bytes(&args["result"])?,
                        "duplicate_conflict",
                    )?;
                    return Ok(Recorded::Replay);
                }
                let attempt = self.attempt(text(&q["attempt_id"])?)?;
                correlate_status(&attempt.request, q, r)?;
                need(
                    instant(&q["created_at"])? >= instant(&attempt.request["created_at"])?,
                    "query_before_request",
                )?;
                need(
                    instant(&r["created_at"])? >= instant(&q["created_at"])?,
                    "response_before_query",
                )?;
                need(
                    r["payload"]["snapshot"] == attempt.snapshot,
                    "snapshot_mismatch",
                )?;
                let full = if attempt.snapshot["result"]["status"] == "DISPONIBLE" {
                    attempt.result.as_ref()
                } else {
                    None
                };
                need(
                    full.unwrap_or(&Value::Null) == &args["result"],
                    "result_mismatch",
                )?;
                let answer = Answer {
                    response: encode_message(r)?,
                    result: optional_bytes(&args["result"])?,
                    replay: false,
                };
                self.remember(q)?;
                self.remember(r)?;
                self.answers
                    .insert(text(&q["message_id"])?.into(), (q.clone(), answer));
            }
            _ => return Err(error("operation_unknown")),
        }
        Ok(Recorded::New)
    }
}
fn optional_bytes(v: &Value) -> Result<Option<Vec<u8>>> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(encode_message(v)?))
    }
}
