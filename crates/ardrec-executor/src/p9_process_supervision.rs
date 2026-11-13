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
