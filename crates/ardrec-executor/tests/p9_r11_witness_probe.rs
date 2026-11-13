//! P9-R11: pruebas observacionales, exclusivamente con procesos benignos.
//! No habilitan el despacho operacional y no prueban la limpieza de árboles.

#![cfg(target_os = "linux")]

use ardrec_executor::p9_r11_witness_probe::{
    WitnessClaim, WitnessObservation, observe_owned_witness,
};
use rustix::process::{getpgrp, getuid};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const FIXTURE_ENV: &str = "ARDREC_P9_R11_FIXTURE";

#[test]
fn p9_r11_fixture() {
    if std::env::var(FIXTURE_ENV).as_deref() == Ok("hold") {
        thread::sleep(Duration::from_secs(4));
    }
}

struct OwnedFixture(Child);

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

fn fixture() -> (OwnedFixture, WitnessClaim) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("p9_r11_fixture")
        .env(FIXTURE_ENV, "hold")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.process_group(0);
    let child = command.spawn().unwrap();
    let pid = child.id();
    let claim = WitnessClaim {
        pid,
        expected_parent_pid: std::process::id(),
        original_pgid: getpgrp().as_raw_pid(),
        expected_pgid: i32::try_from(pid).unwrap(),
        expected_uid: getuid().as_raw(),
        expected_start_ticks: start_ticks(pid),
    };
    (OwnedFixture(child), claim)
}

#[test]
fn observes_owned_benign_fixture_in_another_pgid() {
    let (_owned, claim) = fixture();
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::BoundAtProbe
    );
}

#[test]
fn wrong_start_ticks_fail_closed() {
    let (_owned, mut claim) = fixture();
    claim.expected_start_ticks += 1;
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::AttributionNotProven
    );
}

#[test]
fn wrong_parent_and_uid_fail_closed() {
    let (_owned, mut claim) = fixture();
    claim.expected_parent_pid += 1;
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::AttributionNotProven
    );
    claim.expected_parent_pid -= 1;
    claim.expected_uid = claim.expected_uid.wrapping_add(1);
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::AttributionNotProven
    );
}

#[test]
fn original_group_is_not_a_detached_witness() {
    let (_owned, mut claim) = fixture();
    claim.original_pgid = claim.expected_pgid;
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::AttributionNotProven
    );
}

#[test]
fn reaped_witness_is_only_absent_not_certified_clean() {
    let (mut owned, claim) = fixture();
    owned.0.kill().unwrap();
    owned.0.wait().unwrap();
    assert_eq!(
        observe_owned_witness(claim),
        WitnessObservation::NotPresentAtProbe
    );
}
