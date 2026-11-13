//! Pruebas de integración del supervisor P9/R03.
//!
//! Se utilizan exclusivamente procesos locales benignos.
//! No se ejecutan clientes SSH, FTP ni SMB y estos
//! resultados no autorizan el despacho operacional.

#![cfg(target_os = "linux")]

use ardrec_executor::p9_process_supervision::Policy;
use ardrec_executor::p9_process_supervision::process_group::{GroupOutcome, GroupSupervisor};
use rustix::process::{Pid, getpgid};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FIXTURE: &str = "ARDREC_P9_R03_FIXTURE";

fn command(mode: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());

    cmd.arg("--exact")
        .arg("p9_group_fixture")
        .env(FIXTURE, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd
}

#[test]
fn p9_group_fixture() {
    match std::env::var(FIXTURE).as_deref() {
        Ok("hold") => {
            thread::sleep(Duration::from_secs(3));
        }
        Ok("short") => {
            thread::sleep(Duration::from_millis(400));
        }
        Ok("descendant") => {
            thread::sleep(Duration::from_millis(2000));
        }
        Ok("tree") => {
            let mut descendant = command("descendant").spawn().unwrap();

            descendant.wait().unwrap();
        }
        _ => {}
    }
}

fn grouped(mode: &str) -> Child {
    let mut cmd = command(mode);
    cmd.process_group(0);
    cmd.spawn().unwrap()
}

fn adopt(child: Child, deadline: u64, grace: u64) -> GroupSupervisor {
    match GroupSupervisor::adopt(child, Policy::new(deadline, 10).unwrap(), grace) {
        Ok(supervisor) => supervisor,
        Err((error, mut child)) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("adoption failed: {error}");
        }
    }
}

#[test]
fn invalid_grace_is_rejected() {
    for grace in [0, 5001] {
        let child = grouped("hold");

        match GroupSupervisor::adopt(child, Policy::new(100, 10).unwrap(), grace) {
            Ok(_) => panic!("invalid grace accepted"),
            Err((error, mut child)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[test]
fn shared_process_group_is_rejected() {
    let child = command("hold").spawn().unwrap();

    match GroupSupervisor::adopt(child, Policy::new(100, 10).unwrap(), 100) {
        Ok(_) => panic!("shared group accepted"),
        Err((_, mut child)) => {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn isolated_group_identity_matches_leader() {
    let child = grouped("hold");
    let pid = child.id();

    let supervisor = adopt(child, 100, 100);

    assert_eq!(supervisor.leader_pid(), pid);
    assert_eq!(supervisor.group_id(), pid as i32);
    assert_ne!(supervisor.group_id(), std::process::id() as i32);
}

#[test]
fn real_descendant_inherits_process_group() {
    let child = grouped("tree");
    let mut supervisor = adopt(child, 5000, 100);

    let leader = supervisor.leader_pid();
    // El ejecutable de pruebas es multihilo.
    // Los hijos se registran por TID, no únicamente
    // bajo task/<PID>/children.
    let tasks_dir = format!("/proc/{leader}/task");

    let mut observed_descendant = false;

    for _ in 0..250 {
        if let Ok(tasks) = std::fs::read_dir(&tasks_dir) {
            'scan: for task in tasks.flatten() {
                let children_file = task.path().join("children");

                if let Ok(contents) = std::fs::read_to_string(children_file) {
                    for raw in contents.split_whitespace() {
                        if let Ok(child_pid) = raw.parse::<i32>() {
                            let belongs_to_group = Pid::from_raw(child_pid)
                                .and_then(|pid| getpgid(Some(pid)).ok())
                                .is_some_and(|group| group.as_raw_pid() == leader as i32);

                            if belongs_to_group {
                                observed_descendant = true;
                                break 'scan;
                            }
                        }
                    }
                }
            }
        }

        if observed_descendant {
            break;
        }

        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        observed_descendant,
        "fixture descendant not observed across task threads"
    );

    // Permitir la terminación natural del árbol;
    // no interrumpir el descendiente de prueba.
    assert!(matches!(
        supervisor.run().unwrap(),
        GroupOutcome::LeaderExited { .. }
    ));
}

#[test]
fn deadline_signals_isolated_group() {
    let child = grouped("hold");
    let mut supervisor = adopt(child, 100, 150);

    let started = Instant::now();
    let outcome = supervisor.run().unwrap();

    assert!(matches!(
        outcome,
        GroupOutcome::DeadlineTerminated { .. } | GroupOutcome::DeadlineEscalated { .. }
    ));

    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(supervisor.poll().unwrap(), outcome);
}

#[test]
fn natural_exit_is_observed_without_authorization() {
    let child = grouped("short");
    let mut supervisor = adopt(child, 3000, 100);

    assert!(matches!(
        supervisor.run().unwrap(),
        GroupOutcome::LeaderExited { .. }
    ));
}

#[test]
fn dropping_supervisor_reaps_its_leader() {
    let child = grouped("hold");

    let started = Instant::now();

    {
        let supervisor = adopt(child, 3000, 100);
        assert!(supervisor.leader_pid() > 1);
    }

    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn terminal_outcome_is_stable() {
    let child = grouped("short");
    let mut supervisor = adopt(child, 3000, 100);

    let outcome = supervisor.run().unwrap();

    assert_eq!(supervisor.poll().unwrap(), outcome);
    assert_eq!(supervisor.poll().unwrap(), outcome);
}
