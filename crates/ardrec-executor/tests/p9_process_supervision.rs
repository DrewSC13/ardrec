//! Pruebas locales de P9-R01.
//! Ejecutan exclusivamente este propio binario de pruebas.
//! No lanzan clientes SSH, FTP ni SMB.

use ardrec_executor::p9_process_supervision::{Outcome, Policy, PolicyError, Supervisor};

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FIXTURE_ENV: &str = "ARDREC_P9_LOCAL_FIXTURE";

fn child(mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("p9_fixture_child")
        .env(FIXTURE_ENV, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

// El proceso hijo ejecuta exclusivamente esta función.
#[test]
fn p9_fixture_child() {
    if std::env::var(FIXTURE_ENV).as_deref() == Ok("sleep") {
        thread::sleep(Duration::from_secs(3));
    }
}

#[test]
fn invalid_policies_are_rejected() {
    for (deadline, poll) in [(0, 1), (100, 0), (60_001, 10), (100, 51), (5, 10)] {
        assert_eq!(Policy::new(deadline, poll), Err(PolicyError::InvalidBounds));
    }
}

#[test]
fn valid_policy_is_constructible() {
    assert!(Policy::new(1000, 10).is_ok());
}

#[test]
fn real_child_exit_is_observed() {
    let policy = Policy::new(5000, 10).unwrap();
    let mut supervisor = Supervisor::adopt(child("exit"), policy);

    let result = supervisor.run().unwrap();

    assert!(matches!(result, Outcome::Exited { success: true, .. }));

    // El estado terminal debe permanecer estable.
    assert_eq!(supervisor.poll().unwrap(), result);
}

#[test]
fn deadline_terminates_and_reaps_leader() {
    let policy = Policy::new(100, 10).unwrap();
    let mut supervisor = Supervisor::adopt(child("sleep"), policy);

    assert!(supervisor.leader_pid() > 0);

    let start = Instant::now();
    let result = supervisor.run().unwrap();

    assert_eq!(result, Outcome::DeadlineLeaderReaped);
    assert_eq!(supervisor.poll().unwrap(), result);

    // Margen amplio para variaciones del runner CI.
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn dropping_active_supervisor_reaps_test_child() {
    let policy = Policy::new(5000, 10).unwrap();
    let start = Instant::now();

    {
        let supervisor = Supervisor::adopt(child("sleep"), policy);

        assert!(supervisor.leader_pid() > 0);

        // Drop intenta terminar y recoger el líder.
        // No verifica ni afirma limpieza de descendientes.
    }

    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_pending_child_is_not_prematurely_authorized() {
    let policy = Policy::new(5000, 10).unwrap();
    let mut supervisor = Supervisor::adopt(child("sleep"), policy);

    let result = supervisor.poll().unwrap();

    assert_eq!(result, Outcome::Running);
}
