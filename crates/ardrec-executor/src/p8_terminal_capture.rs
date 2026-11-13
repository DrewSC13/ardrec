//! Frontera de captura sintética con aborto irreversible.
//!
//! El primer rechazo bloquea permanentemente la instancia.
//! No existe supervisor de procesos, ejecución de clientes,
//! autorización operacional ni acceso a red.

use crate::p8_bounded_capture::{BoundedCapture, CaptureError, Stream};
use crate::p8_resource_contract::{Counters, Limits};

/// Estado de la instancia de captura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Sin intento iniciado.
    AwaitingAttempt,
    /// Intento sintético iniciado.
    Active,
    /// Aborto irreversible.
    Aborted,
}

/// Error de la frontera terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    /// Primer rechazo del contrato subyacente.
    Rejected(CaptureError),
    /// La instancia había sido abortada.
    AlreadyAborted,
}

/// Instantánea de solo lectura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalStatus {
    /// Estado actual.
    pub phase: Phase,
    /// Causa del primer rechazo.
    pub first_rejection: Option<CaptureError>,
    /// Contadores aceptados antes de un posible rechazo.
    pub counters: Counters,
    /// Validez aritmética de los contadores aceptados.
    pub counters_within_declared_limits: bool,
    /// El despacho siempre está prohibido.
    pub dispatch_allowed: bool,
}

/// Contrato sintético de captura terminal.
///
/// No expone acceso mutable al componente interno.
#[derive(Debug)]
pub struct TerminalCapture {
    inner: BoundedCapture,
    phase: Phase,
    first_rejection: Option<CaptureError>,
}

impl TerminalCapture {
    /// Construye una instancia con límites declarados.
    ///
    /// Una construcción inválida no produce instancia.
    pub fn new(limits: Limits) -> Result<Self, CaptureError> {
        Ok(Self {
            inner: BoundedCapture::new(limits)?,
            phase: Phase::AwaitingAttempt,
            first_rejection: None,
        })
    }

    fn complete(&mut self, result: Result<(), CaptureError>) -> Result<(), TerminalError> {
        match result {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.first_rejection = Some(reason);
                self.phase = Phase::Aborted;
                Err(TerminalError::Rejected(reason))
            }
        }
    }

    fn require_active(&mut self) -> Result<(), TerminalError> {
        match self.phase {
            Phase::Active => Ok(()),
            Phase::Aborted => Err(TerminalError::AlreadyAborted),
            Phase::AwaitingAttempt => {
                let reason = CaptureError::AttemptRequired;
                self.first_rejection = Some(reason);
                self.phase = Phase::Aborted;
                Err(TerminalError::Rejected(reason))
            }
        }
    }

    /// Inicia el único intento sintético permitido.
    ///
    /// Un segundo intento produce aborto irreversible.
    pub fn begin_attempt(&mut self) -> Result<(), TerminalError> {
        if self.phase == Phase::Aborted {
            return Err(TerminalError::AlreadyAborted);
        }

        let result = self.inner.begin_attempt();
        self.complete(result)?;

        self.phase = Phase::Active;
        Ok(())
    }

    /// Incorpora una salida sintética si cumple los límites.
    ///
    /// Un rechazo no incorpora parcialmente el fragmento.
    pub fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), TerminalError> {
        self.require_active()?;
        let result = self.inner.push(stream, bytes);
        self.complete(result)
    }

    /// Contabiliza bytes de transferencia declarados.
    pub fn account_network_bytes(&mut self, amount: u64) -> Result<(), TerminalError> {
        self.require_active()?;
        let result = self.inner.account_network_bytes(amount);
        self.complete(result)
    }

    /// Contabiliza una entrada de resultados declarada.
    pub fn account_result_entry(&mut self) -> Result<(), TerminalError> {
        self.require_active()?;
        let result = self.inner.account_result_entry();
        self.complete(result)
    }

    /// Registra tiempo declarado no decreciente.
    pub fn observe_elapsed_ms(&mut self, elapsed_ms: u64) -> Result<(), TerminalError> {
        self.require_active()?;
        let result = self.inner.observe_elapsed_ms(elapsed_ms);
        self.complete(result)
    }

    /// Consulta el estado sin modificarlo.
    #[must_use]
    pub fn status(&self) -> TerminalStatus {
        TerminalStatus {
            phase: self.phase,
            first_rejection: self.first_rejection,
            counters: self.inner.counters(),
            counters_within_declared_limits: self.inner.assessment().within_declared_limits,
            dispatch_allowed: false,
        }
    }

    /// Consulta stdout previamente aceptado.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        self.inner.stdout()
    }

    /// Consulta stderr previamente aceptado.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        self.inner.stderr()
    }
}
