//! P9-R01: supervisión efectiva de un único proceso hijo.
//!
//! Este módulo recibe un `Child` ya creado. No lanza
//! comandos ni concede autorización de ejecución.
//!
//! La supervisión de descendientes, cgroups, permisos,
//! aislamiento, límites de recursos y limpieza global
//! NO está implementada por este incremento.
//!
//! No conectar este módulo al despacho de P8.

use std::io;
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

/// Error de validación de una política de prueba.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Plazo o intervalo de sondeo fuera de límites.
    InvalidBounds,
}

/// Política de supervisión, validada antes de adoptar
/// un proceso. No equivale a un presupuesto de caso aprobado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    deadline_ms: u64,
    poll_ms: u64,
}

impl Policy {
    /// Construye una política acotada para esta fase.
    pub fn new(deadline_ms: u64, poll_ms: u64) -> Result<Self, PolicyError> {
        if deadline_ms == 0
            || deadline_ms > 60_000
            || poll_ms == 0
            || poll_ms > 50
            || poll_ms > deadline_ms
        {
            return Err(PolicyError::InvalidBounds);
        }

        Ok(Self {
            deadline_ms,
            poll_ms,
        })
    }
}

/// Estado observable de un proceso hijo individual.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// El proceso todavía no ha terminado.
    Running,
    /// Se observó su estado de terminación.
    Exited {
        /// Código de salida, si el sistema lo proporciona.
        code: Option<i32>,
        /// Éxito informado por el sistema operativo.
        success: bool,
    },
    /// Venció el plazo y se terminó/recogió el proceso
    /// principal. NO acredita limpieza de descendientes.
    DeadlineLeaderReaped,
}

/// Supervisor de propiedad exclusiva sobre un hijo.
///
/// Su plazo comienza al adoptar el `Child`; no demuestra
/// todavía la correspondencia con el inicio efectivo de
/// una ejecución operacional autorizada.
pub struct Supervisor {
    child: Child,
    policy: Policy,
    started: Instant,
    terminal: Option<Outcome>,
}

impl Supervisor {
    /// Adopta un hijo ya existente; no inicia procesos.
    pub fn adopt(child: Child, policy: Policy) -> Self {
        Self {
            child,
            policy,
            started: Instant::now(),
            terminal: None,
        }
    }

    fn exited(&mut self, status: ExitStatus) -> Outcome {
        let result = Outcome::Exited {
            code: status.code(),
            success: status.success(),
        };
        self.terminal = Some(result);
        result
    }

    /// Consulta la terminación o aplica el plazo.
    ///
    /// Un error de E/S no se interpreta como éxito.
    pub fn poll(&mut self) -> io::Result<Outcome> {
        if let Some(terminal) = self.terminal {
            return Ok(terminal);
        }

        if let Some(status) = self.child.try_wait()? {
            return Ok(self.exited(status));
        }

        if self.started.elapsed() < Duration::from_millis(self.policy.deadline_ms) {
            return Ok(Outcome::Running);
        }

        // Se intenta terminar únicamente el proceso líder.
        // No se afirma haber terminado descendientes.
        match self.child.kill() {
            Ok(()) => {
                self.child.wait()?;
                self.terminal = Some(Outcome::DeadlineLeaderReaped);
                Ok(Outcome::DeadlineLeaderReaped)
            }
            Err(error) => {
                // Puede haber terminado entre try_wait y kill.
                if let Some(status) = self.child.try_wait()? {
                    return Ok(self.exited(status));
                }

                Err(error)
            }
        }
    }

    /// Supervisa el hijo hasta un estado terminal.
    pub fn run(&mut self) -> io::Result<Outcome> {
        loop {
            let outcome = self.poll()?;

            if outcome != Outcome::Running {
                return Ok(outcome);
            }

            thread::sleep(Duration::from_millis(self.policy.poll_ms));
        }
    }

    /// Identificador informativo del proceso líder.
    pub fn leader_pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if self.terminal.is_none() {
            // Recuperación de mejor esfuerzo sobre el líder.
            // No implica limpieza global ni garantía
            // de terminación acotada de descendientes.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// -----------------------------------------------------------------------------
// P9-R03 / Linux process-group supervision
// -----------------------------------------------------------------------------

/// Supervisión de grupos POSIX mediante interfaces seguras.
/// No inicia procesos ni habilita el despacho P8.
#[cfg(target_os = "linux")]
pub mod process_group {
    use super::Policy;
    use rustix::io::Errno;
    use rustix::process::{
        Pid, Signal, getpgid, getpgrp, kill_process_group, test_kill_process_group,
    };
    use std::io;
    use std::process::Child;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Resultado observado. No certifica limpieza global.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GroupOutcome {
        /// El líder continúa bajo supervisión.
        Running,

        /// Se observó la terminación natural del líder.
        LeaderExited {
            /// Código de salida, cuando está disponible.
            code: Option<i32>,
            /// Ausencia del grupo en una observación puntual.
            group_absent_at_probe: bool,
        },

        /// El líder terminó, pero sigue existiendo un grupo
        /// o no pudo acreditarse su ausencia.
        ///
        /// El líder ya fue recogido. No se permite señalizar
        /// nuevamente el PGID desde esta instancia.
        LeaderExitedGroupNotProvenAbsent {
            /// Código de salida del líder, si está disponible.
            code: Option<i32>,
        },

        /// Tras SIGTERM se observó la ausencia del grupo.
        DeadlineTerminated {
            /// Resultado puntual, sin certificar limpieza global.
            group_absent_at_probe: bool,
        },

        /// Se emitió SIGKILL después del plazo de gracia.
        DeadlineEscalated {
            /// Resultado puntual, sin certificar limpieza global.
            group_absent_at_probe: bool,
        },
    }

    /// Supervisor que conserva propiedad del proceso líder.
    pub struct GroupSupervisor {
        leader: Child,
        pgid: Pid,
        policy: Policy,
        grace: Duration,
        started: Instant,
        term_sent_at: Option<Instant>,
        terminal: Option<GroupOutcome>,
    }

    impl GroupSupervisor {
        /// Requiere que el líder pertenezca a un grupo
        /// independiente. Ante error devuelve el Child.
        pub fn adopt(
            leader: Child,
            policy: Policy,
            grace_ms: u64,
        ) -> Result<Self, (io::Error, Child)> {
            if grace_ms == 0 || grace_ms > 5000 {
                return Err((
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid grace period"),
                    leader,
                ));
            }

            let raw = match i32::try_from(leader.id()) {
                Ok(value) if value > 1 => value,
                _ => {
                    return Err((
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid leader PID"),
                        leader,
                    ));
                }
            };

            let Some(pid) = Pid::from_raw(raw) else {
                return Err((
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid PID"),
                    leader,
                ));
            };

            let isolated = matches!(
                getpgid(Some(pid)),
                Ok(group) if group == pid && group != getpgrp()
            );

            if !isolated {
                return Err((
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "child must own an independent group",
                    ),
                    leader,
                ));
            }

            Ok(Self {
                leader,
                pgid: pid,
                policy,
                grace: Duration::from_millis(grace_ms),
                started: Instant::now(),
                term_sent_at: None,
                terminal: None,
            })
        }

        fn signal_group(&self, signal: Signal) -> io::Result<()> {
            kill_process_group(self.pgid, signal)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
        }

        fn group_absent(&self) -> bool {
            matches!(test_kill_process_group(self.pgid), Err(Errno::SRCH))
        }

        fn finish(&mut self, outcome: GroupOutcome) -> GroupOutcome {
            self.terminal = Some(outcome);
            outcome
        }

        /// Observa el líder y controla el plazo monotónico.
        ///
        /// Después de SIGTERM conserva el líder sin recoger
        /// hasta la escalada. No señala un PGID después de
        /// haber recogido al líder.
        pub fn poll(&mut self) -> io::Result<GroupOutcome> {
            if let Some(outcome) = self.terminal {
                return Ok(outcome);
            }

            if let Some(sent_at) = self.term_sent_at {
                // El grupo puede haber desaparecido tras SIGTERM.
                // No es necesario escalar en ese caso.
                if self.group_absent() {
                    self.leader.wait()?;
                    return Ok(self.finish(GroupOutcome::DeadlineTerminated {
                        group_absent_at_probe: true,
                    }));
                }

                if sent_at.elapsed() >= self.grace {
                    // Todavía no se ha recogido al líder.
                    // Si el grupo desaparece entre la consulta
                    // y la señal, ESRCH no acredita una escalada.
                    let kill_sent = match self.signal_group(Signal::KILL) {
                        Ok(()) => true,
                        Err(error) if error.raw_os_error() == Some(Errno::SRCH.raw_os_error()) => {
                            false
                        }
                        Err(error) => return Err(error),
                    };

                    self.leader.wait()?;
                    let absent = self.group_absent();

                    let outcome = if kill_sent {
                        GroupOutcome::DeadlineEscalated {
                            group_absent_at_probe: absent,
                        }
                    } else {
                        GroupOutcome::DeadlineTerminated {
                            group_absent_at_probe: absent,
                        }
                    };

                    return Ok(self.finish(outcome));
                }

                return Ok(GroupOutcome::Running);
            }

            if let Some(status) = self.leader.try_wait()? {
                // try_wait recoge al líder. A partir de aquí
                // no se enviarán señales usando su antiguo PGID.
                let absent = self.group_absent();

                if !absent {
                    return Ok(self.finish(GroupOutcome::LeaderExitedGroupNotProvenAbsent {
                        code: status.code(),
                    }));
                }

                return Ok(self.finish(GroupOutcome::LeaderExited {
                    code: status.code(),
                    group_absent_at_probe: true,
                }));
            }

            if self.started.elapsed() >= Duration::from_millis(self.policy.deadline_ms) {
                self.signal_group(Signal::TERM)?;
                self.term_sent_at = Some(Instant::now());
            }

            Ok(GroupOutcome::Running)
        }

        /// Supervisa hasta observar un resultado terminal.
        ///
        /// No certifica la ausencia de procesos fuera del grupo.
        pub fn run(&mut self) -> io::Result<GroupOutcome> {
            loop {
                let outcome = self.poll()?;

                if outcome != GroupOutcome::Running {
                    return Ok(outcome);
                }

                thread::sleep(Duration::from_millis(self.policy.poll_ms));
            }
        }

        /// Identificador del proceso líder adoptado.
        pub fn leader_pid(&self) -> u32 {
            self.leader.id()
        }

        /// PGID inicial del grupo supervisado.
        ///
        /// No es una identidad persistente reutilizable.
        pub fn group_id(&self) -> i32 {
            self.pgid.as_raw_pid()
        }
    }

    impl Drop for GroupSupervisor {
        fn drop(&mut self) {
            if self.terminal.is_none() {
                let _ = self.signal_group(Signal::KILL);
                let _ = self.leader.kill();
                let _ = self.leader.wait();
            }
        }
    }
}
