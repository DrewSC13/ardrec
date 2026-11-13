//! P9-R11: observación de identidad de un testigo Linux benigno.
//!
//! No inicia procesos, no envía señales y no autoriza P8.
//! El pidfd solo estabiliza la identidad durante esta observación.
//! Ningún resultado de este módulo acredita limpieza global del árbol.

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, getuid, pidfd_open};
use std::fs;

/// Afirmación acotada sobre un testigo propiedad del observador.
/// Los valores declarados no constituyen evidencia por sí mismos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessClaim {
    /// PID del testigo; no es identidad durable sin tick de inicio.
    pub pid: u32,
    /// PID del proceso que afirma haber adoptado al testigo.
    pub expected_parent_pid: u32,
    /// PGID original del proceso líder.
    pub original_pgid: i32,
    /// PGID que declara el testigo después del cambio.
    pub expected_pgid: i32,
    /// UID real declarado del testigo.
    pub expected_uid: u32,
    /// Campo 22 de /proc/<pid>/stat, en ticks de reloj del kernel.
    pub expected_start_ticks: u64,
}

/// Resultado del sondeo local. Ninguna variante autoriza despacho o limpieza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessObservation {
    /// Se observó identidad, padre, UID y grupo de un testigo vivo.
    BoundAtProbe,
    /// El kernel no encontró ese PID al solicitar pidfd.
    /// La ausencia puntual no demuestra que el árbol esté limpio.
    NotPresentAtProbe,
    /// El testigo es zombi y debe recogerse por su padre.
    ZombieNotReaped,
    /// Las identidades o precondiciones no coinciden, o /proc es insuficiente.
    AttributionNotProven,
    /// El kernel carece de la interfaz pidfd requerida.
    UnsupportedPidfd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcIdentity {
    ppid: u32,
    pgid: i32,
    start_ticks: u64,
    state: char,
    real_uid: u32,
}

/// Analiza campos Linux sin confundir paréntesis dentro del nombre del proceso.
fn parse_stat(stat: &str) -> Option<(u32, i32, u64, char)> {
    let (_, tail) = stat.rsplit_once(") ")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    let state = fields[0].chars().next()?;
    if fields[0].chars().count() != 1 {
        return None;
    }
    Some((
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
        fields[19].parse().ok()?,
        state,
    ))
}

fn parse_real_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.trim_start_matches("Uid:")
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn read_identity(pid: u32) -> Option<ProcIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let (ppid, pgid, start_ticks, state) = parse_stat(&stat)?;
    Some(ProcIdentity {
        ppid,
        pgid,
        start_ticks,
        state,
        real_uid: parse_real_uid(&status)?,
    })
}

/// Verifica un solo testigo propio mediante un pidfd y dos lecturas de /proc.
///
/// Se requiere que el padre esperado sea el proceso actual y que el UID
/// declarado corresponda al UID real del observador. Los pidfd se abren antes
/// de leer /proc para evitar atribuir al testigo un PID reciclado.
/// Esta función solo observa: NO envía señales, NO recoge procesos ni
/// certifica la limpieza de otros descendientes.
#[must_use]
pub fn observe_owned_witness(claim: WitnessClaim) -> WitnessObservation {
    if claim.pid <= 1
        || claim.expected_parent_pid != std::process::id()
        || claim.expected_pgid <= 1
        || claim.original_pgid <= 0
        || claim.expected_pgid == claim.original_pgid
        || claim.expected_start_ticks == 0
        || claim.expected_uid != getuid().as_raw()
    {
        return WitnessObservation::AttributionNotProven;
    }

    let Ok(raw_pid) = i32::try_from(claim.pid) else {
        return WitnessObservation::AttributionNotProven;
    };
    let Some(pid) = Pid::from_raw(raw_pid) else {
        return WitnessObservation::AttributionNotProven;
    };

    // Mantener vivo el descriptor durante ambas observaciones.
    let _pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::SRCH) => return WitnessObservation::NotPresentAtProbe,
        Err(Errno::NOSYS) => return WitnessObservation::UnsupportedPidfd,
        Err(_) => return WitnessObservation::AttributionNotProven,
    };

    let Some(before) = read_identity(claim.pid) else {
        return WitnessObservation::AttributionNotProven;
    };
    let Some(after) = read_identity(claim.pid) else {
        return WitnessObservation::AttributionNotProven;
    };

    if before != after
        || before.ppid != claim.expected_parent_pid
        || before.pgid != claim.expected_pgid
        || before.real_uid != claim.expected_uid
        || before.start_ticks != claim.expected_start_ticks
    {
        return WitnessObservation::AttributionNotProven;
    }

    if before.state == 'Z' || before.state == 'X' {
        return WitnessObservation::ZombieNotReaped;
    }

    WitnessObservation::BoundAtProbe
}

#[cfg(test)]
mod tests {
    use super::{parse_real_uid, parse_stat};

    #[test]
    fn parses_stat_with_inner_parentheses() {
        // Campos después de comm: estado, PPID, PGID y, en el índice 19, starttime.
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[1] = "42";
        fields[2] = "44";
        fields[19] = "123456";
        let sample = format!("88 (some ) tricky) {}", fields.join(" "));
        assert_eq!(parse_stat(&sample), Some((42, 44, 123456, 'S')));
        assert_eq!(parse_stat("bad"), None);
    }

    #[test]
    fn parses_uid_without_accepting_missing_data() {
        assert_eq!(
            parse_real_uid("Name:\tworker\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(parse_real_uid("Name:\tworker\n"), None);
    }
}
