//! Pruebas de integración del estado terminal de captura P8.
//!
//! Verifica que el primer rechazo bloquee permanentemente
//! la instancia sintética, sin autorizar ejecución operacional.

use ardrec_executor::contract_gate::PROFILE_IDS;
use ardrec_executor::p8_bounded_capture::{CaptureError, Stream};
use ardrec_executor::p8_resource_contract::{Limits, Violation};
use ardrec_executor::p8_terminal_capture::{Phase, TerminalCapture, TerminalError};

fn limits() -> Limits {
    Limits {
        total_time_ms: 1_000,
        stdout_bytes: 64,
        stderr_bytes: 64,
        total_capture_bytes: 100,
        network_bytes: 4_096,
        result_entries: 10,
        attempts: 1,
    }
}

fn started() -> TerminalCapture {
    let mut c = TerminalCapture::new(limits()).unwrap();
    c.begin_attempt().unwrap();
    c
}

#[test]
fn valid_capture_does_not_authorize() {
    let mut c = started();

    c.push(Stream::Stdout, b"abc").unwrap();
    c.push(Stream::Stderr, b"error").unwrap();
    c.account_network_bytes(100).unwrap();
    c.account_result_entry().unwrap();
    c.observe_elapsed_ms(500).unwrap();

    assert_eq!(c.status().phase, Phase::Active);
    assert!(c.status().counters_within_declared_limits);
    assert!(!c.status().dispatch_allowed);
    assert_eq!(c.stdout(), b"abc");
    assert_eq!(c.stderr(), b"error");
}

#[test]
fn invalid_budget_rejected_before_construction() {
    let mut l = limits();
    l.total_time_ms = 0;

    assert!(matches!(
        TerminalCapture::new(l),
        Err(CaptureError::InvalidLimits)
    ));
}

#[test]
fn stdout_before_attempt_aborts() {
    let mut c = TerminalCapture::new(limits()).unwrap();

    assert_eq!(
        c.push(Stream::Stdout, b"x"),
        Err(TerminalError::Rejected(CaptureError::AttemptRequired))
    );

    assert_eq!(c.status().phase, Phase::Aborted);
    assert_eq!(c.begin_attempt(), Err(TerminalError::AlreadyAborted));
}

#[test]
fn time_before_attempt_aborts() {
    let mut c = TerminalCapture::new(limits()).unwrap();

    assert_eq!(
        c.observe_elapsed_ms(1),
        Err(TerminalError::Rejected(CaptureError::AttemptRequired))
    );

    assert_eq!(c.status().phase, Phase::Aborted);
}

#[test]
fn repeated_attempt_is_terminal() {
    let mut c = started();

    c.push(Stream::Stdout, b"abc").unwrap();

    assert_eq!(
        c.begin_attempt(),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::AttemptsExceeded
        )))
    );

    assert_eq!(
        c.push(Stream::Stdout, b"d"),
        Err(TerminalError::AlreadyAborted)
    );

    assert_eq!(c.stdout(), b"abc");
    assert_eq!(c.status().phase, Phase::Aborted);
}

#[test]
fn stdout_overflow_latches_and_preserves_bytes() {
    let mut c = started();

    c.push(Stream::Stdout, &[1; 64]).unwrap();

    assert_eq!(
        c.push(Stream::Stdout, b"x"),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::StdoutExceeded
        )))
    );

    assert_eq!(
        c.push(Stream::Stdout, b""),
        Err(TerminalError::AlreadyAborted)
    );

    assert_eq!(c.stdout().len(), 64);
    assert_eq!(c.status().counters.stdout_bytes, 64);
}

#[test]
fn stderr_overflow_latches_and_preserves_bytes() {
    let mut c = started();

    c.push(Stream::Stderr, &[1; 64]).unwrap();

    assert_eq!(
        c.push(Stream::Stderr, b"x"),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::StderrExceeded
        )))
    );

    assert_eq!(c.stderr().len(), 64);
    assert_eq!(c.account_result_entry(), Err(TerminalError::AlreadyAborted));
}

#[test]
fn aggregate_capture_excess_is_terminal() {
    let mut c = started();

    c.push(Stream::Stdout, &[1; 60]).unwrap();

    assert_eq!(
        c.push(Stream::Stderr, &[2; 41]),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::CaptureExceeded
        )))
    );

    assert!(c.stderr().is_empty());
    assert_eq!(c.stdout().len(), 60);
    assert_eq!(c.status().phase, Phase::Aborted);
}

#[test]
fn exact_capture_boundary_is_accepted_without_permission() {
    let mut c = started();

    c.push(Stream::Stdout, &[1; 64]).unwrap();
    c.push(Stream::Stderr, &[2; 36]).unwrap();

    assert_eq!(c.stdout().len() + c.stderr().len(), 100);
    assert_eq!(c.status().phase, Phase::Active);
    assert!(!c.status().dispatch_allowed);
}

#[test]
fn transfer_limit_aborts_atomically() {
    let mut c = started();

    c.account_network_bytes(4_096).unwrap();

    assert_eq!(
        c.account_network_bytes(1),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::TransferExceeded
        )))
    );

    assert_eq!(c.status().counters.network_bytes, 4_096);

    assert_eq!(
        c.account_network_bytes(0),
        Err(TerminalError::AlreadyAborted)
    );
}

#[test]
fn result_limit_aborts_atomically() {
    let mut c = started();

    for _ in 0..10 {
        c.account_result_entry().unwrap();
    }

    assert_eq!(
        c.account_result_entry(),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::EntriesExceeded
        )))
    );

    assert_eq!(c.status().counters.result_entries, 10);
    assert_eq!(c.status().phase, Phase::Aborted);
}

#[test]
fn deadline_aborts_and_cannot_resume() {
    let mut c = started();

    c.observe_elapsed_ms(1_000).unwrap();

    assert_eq!(
        c.observe_elapsed_ms(1_001),
        Err(TerminalError::Rejected(CaptureError::LimitExceeded(
            Violation::TimeExceeded
        )))
    );

    assert_eq!(c.status().counters.elapsed_ms, 1_000);

    assert_eq!(
        c.observe_elapsed_ms(1_000),
        Err(TerminalError::AlreadyAborted)
    );
}

#[test]
fn clock_regression_is_terminal() {
    let mut c = started();

    c.observe_elapsed_ms(500).unwrap();

    assert_eq!(
        c.observe_elapsed_ms(499),
        Err(TerminalError::Rejected(CaptureError::TimeRegression))
    );

    assert_eq!(
        c.observe_elapsed_ms(501),
        Err(TerminalError::AlreadyAborted)
    );

    assert_eq!(c.status().counters.elapsed_ms, 500);
}

#[test]
fn arithmetic_overflow_aborts() {
    let mut l = limits();
    l.network_bytes = u64::MAX - 1;

    let mut c = TerminalCapture::new(l).unwrap();
    c.begin_attempt().unwrap();

    c.account_network_bytes(u64::MAX - 1).unwrap();

    assert_eq!(
        c.account_network_bytes(2),
        Err(TerminalError::Rejected(CaptureError::ArithmeticOverflow))
    );

    assert_eq!(
        c.account_network_bytes(0),
        Err(TerminalError::AlreadyAborted)
    );

    assert_eq!(c.status().counters.network_bytes, u64::MAX - 1);
}

#[test]
fn first_failure_reason_remains_immutable() {
    let mut c = started();
    c.push(Stream::Stdout, &[1; 64]).unwrap();

    let expected = CaptureError::LimitExceeded(Violation::StdoutExceeded);

    assert_eq!(
        c.push(Stream::Stdout, b"x"),
        Err(TerminalError::Rejected(expected))
    );

    for _ in 0..3 {
        assert_eq!(c.account_result_entry(), Err(TerminalError::AlreadyAborted));
    }

    assert_eq!(c.status().first_rejection, Some(expected));
    assert!(!c.status().dispatch_allowed);
}

#[test]
fn all_29_profiles_remain_denied() {
    assert_eq!(PROFILE_IDS.len(), 29);

    for _profile in PROFILE_IDS {
        let c = started();
        assert!(!c.status().dispatch_allowed);
    }
}
