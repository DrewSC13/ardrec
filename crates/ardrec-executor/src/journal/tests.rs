//! Casos funcionales del diario; las interrupciones reales se prueban en un proceso aparte.
use super::*;
use crate::messages::{correlate_status, decode_message, encode_message};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NUMBER: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "ardrec-journal-test-{}-{}",
            std::process::id(),
            NUMBER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/messages-temporal-v1.json"
    )))
    .unwrap();
    all[name].clone()
}
fn bytes(v: &Value) -> Vec<u8> {
    encode_message(v).unwrap()
}
fn setup() -> (Directory, TechnicalJournal) {
    let d = Directory::new();
    let mut s = TechnicalJournal::create(d.store()).unwrap();
    s.register(&bytes(&fixture("request"))).unwrap();
    (d, s)
}
fn report(s: &TechnicalJournal, name: &str) -> Value {
    let mut r = fixture(name);
    r["payload"]["snapshot"]["journal_reference"] =
        s.snapshot("ATT-1").unwrap()["journal_reference"].clone();
    r
}
fn observe(s: &mut TechnicalJournal, name: &str) {
    let v = report(s, name);
    s.observe("ATT-1", v["payload"]["snapshot"].clone())
        .unwrap();
}
fn answer(s: &mut TechnicalJournal) -> Answer {
    s.answer(
        &bytes(&fixture("query")),
        "ANSWER-1",
        "2026-10-19T12:00:20Z",
    )
    .unwrap()
}
fn reject<T: std::fmt::Debug>(r: Result<T>, code: &str) {
    assert_eq!(r.unwrap_err().code(), code);
}

#[test]
fn request_survives_and_duplicate_is_noop() {
    let (d, mut s) = setup();
    assert_eq!(
        s.register(&bytes(&fixture("request"))).unwrap(),
        Recorded::Replay
    );
    assert_eq!(s.sequence().unwrap(), 1);
    drop(s);
    let mut s = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(
        s.register(&bytes(&fixture("request"))).unwrap(),
        Recorded::Replay
    );
    assert_eq!(
        s.snapshot("ATT-1").unwrap()["start"]["status"],
        "NO_DETERMINADO"
    );
}
#[test]
fn new_identifier_does_not_reuse_attempt() {
    let (_d, mut s) = setup();
    let mut r = fixture("request");
    r["message_id"] = "REQ-2".into();
    reject(s.register(&bytes(&r)), "duplicate_conflict");
    assert_eq!(s.sequence().unwrap(), 1);
}
#[test]
fn changed_duplicate_is_rejected() {
    let (_d, mut s) = setup();
    let mut r = fixture("request");
    r["payload"]["port"] = 23.into();
    reject(s.register(&bytes(&r)), "duplicate_conflict");
}
#[test]
fn whitespace_delivery_is_canonicalized() {
    let (_d, mut s) = setup();
    let raw = serde_json::to_vec_pretty(&fixture("request")).unwrap();
    assert_eq!(s.register(&raw).unwrap(), Recorded::Replay);
}
#[test]
fn invalid_json_and_duplicate_keys_are_rejected() {
    let (_d, mut s) = setup();
    for raw in [
        b"{invalid".as_slice(),
        b"{\"schema_version\":\"2.0\",\"schema_version\":\"1.0\"}",
        b"\xff",
    ] {
        assert!(s.register(raw).is_err());
    }
    assert_eq!(s.sequence().unwrap(), 1);
}
#[test]
fn incompatible_version_is_rejected() {
    let (_d, mut s) = setup();
    let mut r = fixture("request");
    r["schema_version"] = "9.0".into();
    reject(
        s.register(&serde_json::to_vec(&r).unwrap()),
        "version_incompatible",
    );
}
#[test]
fn request_size_limit_is_enforced() {
    let (_d, mut s) = setup();
    reject(
        s.register(&vec![b' '; crate::messages::MAX_MESSAGE_BYTES + 1]),
        "message_too_large",
    );
}
#[test]
fn acceptance_does_not_accredit_start() {
    let (d, mut s) = setup();
    let r = report(&s, "acceptance");
    s.record_report(&bytes(&r)).unwrap();
    drop(s);
    let s = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(s.first_reply("ATT-1").unwrap(), Some(bytes(&r)));
    assert_eq!(
        s.snapshot("ATT-1").unwrap()["start"]["status"],
        "NO_ACREDITADO"
    );
}
#[test]
fn rejection_does_not_prove_absence() {
    let (_d, mut s) = setup();
    s.record_report(&bytes(&fixture("rejection"))).unwrap();
    assert_eq!(s.snapshot("ATT-1").unwrap()["phase"], "uncertain");
    assert!(s.first_reply("ATT-1").unwrap().is_some());
}
#[test]
fn running_is_retained_without_authorizing_execution() {
    let (d, mut s) = setup();
    observe(&mut s, "status_running");
    drop(s);
    let s = TechnicalJournal::open(d.store()).unwrap();
    let v = s.snapshot("ATT-1").unwrap();
    assert_eq!(v["start"]["status"], "VERIFICADO");
    assert_eq!(v["new_execution_authorized"], false);
    assert_eq!(v["reconciliation_required"], true);
}
#[test]
fn verified_start_cannot_be_erased() {
    let (_d, mut s) = setup();
    observe(&mut s, "status_running");
    let r = report(&s, "status_uncertain");
    reject(
        s.observe("ATT-1", r["payload"]["snapshot"].clone()),
        "fact_regression",
    );
}
#[test]
fn terminal_snapshot_requires_full_result() {
    let (_d, mut s) = setup();
    let r = report(&s, "status_completed");
    reject(
        s.observe("ATT-1", r["payload"]["snapshot"].clone()),
        "result_missing",
    );
    assert_eq!(s.sequence().unwrap(), 1);
}
#[test]
fn full_result_and_snapshot_recover_together() {
    let (d, mut s) = setup();
    let r = report(&s, "result_completed");
    s.record_report(&bytes(&r)).unwrap();
    drop(s);
    let s = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(s.result("ATT-1").unwrap(), Some(bytes(&r)));
    assert_eq!(s.snapshot("ATT-1").unwrap(), r["payload"]["snapshot"]);
}
#[test]
fn result_duplicate_never_changes_state() {
    let (_d, mut s) = setup();
    let r = report(&s, "result_completed");
    s.record_report(&bytes(&r)).unwrap();
    let n = s.sequence().unwrap();
    assert_eq!(s.record_report(&bytes(&r)).unwrap(), Recorded::Replay);
    assert_eq!(s.sequence().unwrap(), n);
    let mut changed = r;
    changed["payload"]["outcome"]["exit_code"] = 1.into();
    reject(s.record_report(&bytes(&changed)), "duplicate_conflict");
}
#[test]
fn terminal_state_cannot_regress() {
    let (_d, mut s) = setup();
    let r = report(&s, "result_completed");
    s.record_report(&bytes(&r)).unwrap();
    let mut v = report(&s, "status_running")["payload"]["snapshot"].clone();
    v["observed_at"] = "2026-10-19T12:00:30Z".into();
    assert!(s.observe("ATT-1", v).is_err());
}
#[test]
fn query_reply_and_outcome_replay_exactly() {
    let (d, mut s) = setup();
    let r = report(&s, "result_completed");
    s.record_report(&bytes(&r)).unwrap();
    let a = answer(&mut s);
    assert_eq!(a.result, Some(bytes(&r)));
    let response = decode_message(&a.response).unwrap();
    correlate_status(&fixture("request"), &fixture("query"), &response).unwrap();
    let n = s.sequence().unwrap();
    drop(s);
    let mut s = TechnicalJournal::open(d.store()).unwrap();
    let b = s
        .answer(
            &bytes(&fixture("query")),
            "IGNORED-ID",
            "2026-10-20T00:00:00Z",
        )
        .unwrap();
    assert!(b.replay);
    assert_eq!(a.response, b.response);
    assert_eq!(a.result, b.result);
    assert_eq!(s.sequence().unwrap(), n);
}
#[test]
fn old_query_preserves_historical_answer() {
    let (_d, mut s) = setup();
    let a = answer(&mut s);
    let r = report(&s, "result_completed");
    s.record_report(&bytes(&r)).unwrap();
    let b = answer(&mut s);
    assert_eq!(a.response, b.response);
    assert!(b.result.is_none());
    assert!(s.result("ATT-1").unwrap().is_some());
}
#[test]
fn unknown_attempt_does_not_fabricate_absence() {
    let (_d, mut s) = setup();
    let mut q = fixture("query");
    q["attempt_id"] = "ATT-UNKNOWN".into();
    reject(
        s.answer(&bytes(&q), "ANS", "2026-10-19T12:00:20Z"),
        "attempt_unknown",
    );
    assert_eq!(s.sequence().unwrap(), 1);
}
#[test]
fn query_identity_conflicts_are_rejected() {
    let (_d, mut s) = setup();
    answer(&mut s);
    let mut q = fixture("query");
    q["payload"]["requested_information"] = json!(["INICIO"]);
    reject(
        s.answer(&bytes(&q), "ANS", "2026-10-19T12:00:20Z"),
        "duplicate_conflict",
    );
}
#[test]
fn response_identifier_cannot_reuse_request() {
    let (_d, mut s) = setup();
    assert!(
        s.answer(&bytes(&fixture("query")), "REQ-1", "2026-10-19T12:00:20Z")
            .is_err()
    );
    assert_eq!(s.sequence().unwrap(), 1);
}
#[test]
fn cross_context_query_is_rejected() {
    let (_d, mut s) = setup();
    let mut q = fixture("query");
    q["simulation"] = true.into();
    assert!(s.answer(&bytes(&q), "ANS", "2026-10-19T12:00:20Z").is_err());
}
#[test]
fn earlier_response_is_rejected() {
    let (_d, mut s) = setup();
    let mut q = fixture("query");
    q["created_at"] = "2026-10-19T12:00:10Z".into();
    reject(
        s.answer(&bytes(&q), "ANS", "2026-10-19T12:00:02Z"),
        "response_before_query",
    );
}
#[test]
fn exact_integer_identity_survives() {
    let d = Directory::new();
    let mut s = TechnicalJournal::create(d.store()).unwrap();
    let mut r = fixture("request");
    r["decision_index"] = json!(9_007_199_254_740_993_u64);
    s.register(&bytes(&r)).unwrap();
    let mut q = fixture("query");
    q["decision_index"] = r["decision_index"].clone();
    let a = s.answer(&bytes(&q), "ANS", "2026-10-19T12:00:20Z").unwrap();
    assert_eq!(
        decode_message(&a.response).unwrap()["decision_index"],
        r["decision_index"]
    );
    drop(s);
    let mut s = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(
        s.answer(&bytes(&q), "IGNORED", "2026-10-19T12:00:20Z")
            .unwrap()
            .response,
        a.response
    );
}
#[test]
fn discovery_result_is_supported() {
    let d = Directory::new();
    let mut s = TechnicalJournal::create(d.store()).unwrap();
    s.register(&bytes(&fixture("discovery_request"))).unwrap();
    let r = report(&s, "discovery_result");
    s.record_report(&bytes(&r)).unwrap();
    assert!(s.result("ATT-1").unwrap().is_some());
}
#[test]
fn terminal_variants_are_preserved() {
    for name in [
        "result_interrupted",
        "result_not_started",
        "result_uncertain",
    ] {
        let (d, mut s) = setup();
        let r = report(&s, name);
        s.record_report(&bytes(&r)).unwrap();
        drop(s);
        let s = TechnicalJournal::open(d.store()).unwrap();
        assert_eq!(
            s.snapshot("ATT-1").unwrap()["phase"],
            r["payload"]["snapshot"]["phase"]
        );
    }
}
#[test]
fn cleanup_can_resolve_without_rewriting_outcome() {
    let (_d, mut s) = setup();
    let mut r = report(&s, "result_completed");
    r["payload"]["snapshot"]["cleanup"] = json!({"status":"pending","reference":null});
    r["payload"]["snapshot"]["reconciliation_required"] = true.into();
    s.record_report(&bytes(&r)).unwrap();
    let mut next = r["payload"]["snapshot"].clone();
    next["cleanup"] = json!({"status":"completed","reference":"CLEAN-NEW"});
    next["reconciliation_required"] = false.into();
    next["observed_at"] = "2026-10-19T12:00:25Z".into();
    s.observe("ATT-1", next).unwrap();
    assert_eq!(s.result("ATT-1").unwrap(), Some(bytes(&r)));
}
#[test]
fn locks_exclude_concurrent_open_and_release_on_drop() {
    let (d, s) = setup();
    assert_eq!(
        TechnicalJournal::open(d.store()).err().unwrap().code(),
        "lock_busy"
    );
    drop(s);
    assert!(TechnicalJournal::open(d.store()).is_ok());
}
#[test]
fn corrupt_head_never_falls_back() {
    let (d, s) = setup();
    drop(s);
    fs::write(d.store().join("HEAD"), b"broken").unwrap();
    assert!(TechnicalJournal::open(d.store()).is_err());
}
#[test]
fn corrupt_record_never_falls_back() {
    let (d, s) = setup();
    drop(s);
    let head: Value = serde_json::from_slice(&fs::read(d.store().join("HEAD")).unwrap()).unwrap();
    let p = d
        .store()
        .join("records")
        .join(format!("{}.json", head["tip"].as_str().unwrap()));
    fs::write(p, b"{}").unwrap();
    assert!(TechnicalJournal::open(d.store()).is_err());
}
#[test]
fn unreferenced_files_have_no_authority() {
    let (d, s) = setup();
    let n = s.sequence().unwrap();
    drop(s);
    fs::write(d.store().join("records/unreferenced.json"), b"invalid").unwrap();
    let s = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(s.sequence().unwrap(), n);
}
#[test]
fn missing_head_is_not_an_empty_journal() {
    let (d, s) = setup();
    drop(s);
    fs::remove_file(d.store().join("HEAD")).unwrap();
    assert!(TechnicalJournal::open(d.store()).is_err());
    assert!(TechnicalJournal::create(d.store()).is_err());
}
#[test]
fn symlink_paths_are_rejected() {
    let (d, s) = setup();
    drop(s);
    let alias = d.0.join("alias");
    std::os::unix::fs::symlink(d.store(), &alias).unwrap();
    assert_eq!(
        TechnicalJournal::open(alias).err().unwrap().code(),
        "symlink_rejected"
    );
}
#[test]
fn io_failure_poison_requires_recovery() {
    for point in ["record:partial", "record:linked", "head:replaced"] {
        let (d, mut s) = setup();
        s.set_fault_hook(move |p| {
            if p == point {
                Err(io::Error::other("fallo inyectado"))
            } else {
                Ok(())
            }
        });
        let r = report(&s, "result_completed");
        assert!(s.record_report(&bytes(&r)).is_err());
        reject(s.sequence(), "recovery_required");
        drop(s);
        let mut s = TechnicalJournal::open(d.store()).unwrap();
        assert_eq!(
            s.result("ATT-1").unwrap().is_some(),
            point == "head:replaced"
        );
        s.record_report(&bytes(&r)).unwrap();
        assert!(s.result("ATT-1").unwrap().is_some());
    }
}
#[test]
fn invalid_sequence_and_unknown_operation_are_rejected() {
    let (d, s) = setup();
    drop(s);
    let headpath = d.store().join("HEAD");
    let mut head: Value = serde_json::from_slice(&fs::read(&headpath).unwrap()).unwrap();
    let old = d
        .store()
        .join("records")
        .join(format!("{}.json", head["tip"].as_str().unwrap()));
    let mut entry: Value = serde_json::from_slice(&fs::read(old).unwrap()).unwrap();
    entry["operation"] = "unknown".into();
    let raw = canonical(&entry).unwrap();
    let digest = hash(&raw);
    fs::write(
        d.store().join("records").join(format!("{digest}.json")),
        raw,
    )
    .unwrap();
    head["tip"] = digest.into();
    fs::write(&headpath, canonical(&head).unwrap()).unwrap();
    assert_eq!(
        TechnicalJournal::open(d.store()).err().unwrap().code(),
        "operation_unknown"
    );
    head["sequence"] = (MAX_RECORDS + 1).into();
    fs::write(headpath, canonical(&head).unwrap()).unwrap();
    assert!(TechnicalJournal::open(d.store()).is_err());
}

#[test]
fn current_admission_rejects_early_start_without_writing() {
    let (_d, mut s) = setup();
    let mut result = report(&s, "result_completed");
    result["payload"]["outcome"]["started_at"] = "2026-10-18T23:59:59Z".into();
    let sequence = s.sequence().unwrap();
    assert_eq!(
        s.record_report(&bytes(&result)).unwrap_err().code(),
        "temporal_inversion"
    );
    assert_eq!(s.sequence().unwrap(), sequence);
    assert!(s.result("ATT-1").unwrap().is_none());
}
#[test]
fn legacy_temporal_inversion_is_readable_but_blocked() {
    use std::os::unix::fs::PermissionsExt;
    let d = Directory::new();
    drop(TechnicalJournal::create(d.store()).unwrap());
    let old: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/messages-v2.json"
    )))
    .unwrap();
    let request = &old["request"];
    let mut result = old["result_completed"].clone();
    result["payload"]["snapshot"]["journal_reference"] =
        format!("TJ-{}", hash(&bytes(request))).into();
    let mut previous = "0".repeat(64);
    let mut original = Vec::new();
    for (i, (operation, message)) in [("request", request.clone()), ("report", result.clone())]
        .into_iter()
        .enumerate()
    {
        let raw=canonical(&json!({"format":"ardrec-technical-journal-1","sequence":i+1,"previous":previous,"operation":operation,"args":{"message":message}})).unwrap();
        previous = hash(&raw);
        let path = d.store().join("records").join(format!("{previous}.json"));
        fs::write(&path, &raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        original.push((path, raw));
    }
    let head =
        canonical(&json!({"format":"ardrec-technical-journal-1","sequence":2,"tip":previous}))
            .unwrap();
    fs::write(d.store().join("HEAD"), &head).unwrap();
    let mut store = TechnicalJournal::open(d.store()).unwrap();
    assert_eq!(store.result("ATT-1").unwrap(), Some(bytes(&result)));
    assert_eq!(
        store.audit_temporal().unwrap_err().code(),
        "temporal_inversion"
    );
    assert_eq!(
        store.record_report(&bytes(&result)).unwrap_err().code(),
        "temporal_inversion"
    );
    assert_eq!(store.sequence().unwrap(), 2);
    drop(store);
    assert_eq!(fs::read(d.store().join("HEAD")).unwrap(), head);
    for (path, raw) in original {
        assert_eq!(fs::read(path).unwrap(), raw);
    }
}
