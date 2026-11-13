//! Captura acotada en memoria para pruebas de P8.
//!
//! Este módulo no observa procesos reales ni impone cuotas del SO.
//! Los contadores proceden exclusivamente de llamadas del consumidor.
//! Ningún resultado concede autoridad ni permite despacho.
//!
//! Pure bounded in-memory capture for P8 tests.
//! No operating-system enforcement, client execution or authorization.

use crate::p8_resource_contract::{Assessment, Counters, Limits, Violation, assess};

/// Canal de captura simulado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// Salida estándar.
    Stdout,
    /// Salida de error.
    Stderr,
}

/// Errores conservadores del control de captura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// Límites ausentes, inválidos o superiores al máximo de desarrollo.
    InvalidLimits,
    /// Se intenta registrar datos sin un intento declarado.
    AttemptRequired,
    /// Desbordamiento aritmético.
    ArithmeticOverflow,
    /// Una observación temporal retrocede.
    TimeRegression,
    /// Se incumple un límite específico.
    LimitExceeded(Violation),
}

/// Captura sintética con contabilidad transaccional.
///
/// No contiene un supervisor ni una primitiva de ejecución.
#[derive(Debug)]
pub struct BoundedCapture {
    limits: Limits,
    counters: Counters,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl BoundedCapture {
    /// Crea una captura, rechazando límites inválidos.
    ///
    /// El máximo de almacenamiento es un techo de desarrollo
    /// heredado del contrato simbólico, no un presupuesto piloto.
    pub fn new(limits: Limits) -> Result<Self, CaptureError> {
        let counters = Counters {
            elapsed_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            network_bytes: 0,
            result_entries: 0,
            attempts: 0,
        };

        let max_capture = u64::from(crate::contract_gate::MAX_DRAFT_OUTPUT_BYTES);

        if !assess(limits, counters).within_declared_limits
            || limits.stdout_bytes > max_capture
            || limits.stderr_bytes > max_capture
            || limits.total_capture_bytes > max_capture
        {
            return Err(CaptureError::InvalidLimits);
        }

        Ok(Self {
            limits,
            counters,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    fn check(&self, next: Counters) -> Result<(), CaptureError> {
        if let Some(violation) = assess(self.limits, next).violations.into_iter().next() {
            return Err(CaptureError::LimitExceeded(violation));
        }

        Ok(())
    }

    fn require_attempt(&self) -> Result<(), CaptureError> {
        if self.counters.attempts != 1 {
            return Err(CaptureError::AttemptRequired);
        }

        Ok(())
    }

    /// Registra un único intento declarado.
    ///
    /// Intentos adicionales se rechazan antes de alterar el estado.
    pub fn begin_attempt(&mut self) -> Result<(), CaptureError> {
        let mut next = self.counters;

        next.attempts = next
            .attempts
            .checked_add(1)
            .ok_or(CaptureError::ArithmeticOverflow)?;

        self.check(next)?;
        self.counters = next;
        Ok(())
    }

    /// Acepta un fragmento de salida únicamente si cabrá completo.
    ///
    /// Nunca conserva una fracción del fragmento rechazado.
    pub fn push(&mut self, stream: Stream, fragment: &[u8]) -> Result<(), CaptureError> {
        self.require_attempt()?;

        let amount = u64::try_from(fragment.len()).map_err(|_| CaptureError::ArithmeticOverflow)?;

        let mut next = self.counters;

        match stream {
            Stream::Stdout => {
                next.stdout_bytes = next
                    .stdout_bytes
                    .checked_add(amount)
                    .ok_or(CaptureError::ArithmeticOverflow)?;
            }
            Stream::Stderr => {
                next.stderr_bytes = next
                    .stderr_bytes
                    .checked_add(amount)
                    .ok_or(CaptureError::ArithmeticOverflow)?;
            }
        }

        self.check(next)?;

        match stream {
            Stream::Stdout => self.stdout.extend_from_slice(fragment),
            Stream::Stderr => self.stderr.extend_from_slice(fragment),
        }

        self.counters = next;
        Ok(())
    }

    /// Agrega bytes de transferencia declarados.
    ///
    /// La operación es exclusivamente aritmética; no lee redes.
    pub fn account_network_bytes(&mut self, amount: u64) -> Result<(), CaptureError> {
        self.require_attempt()?;

        let mut next = self.counters;

        next.network_bytes = next
            .network_bytes
            .checked_add(amount)
            .ok_or(CaptureError::ArithmeticOverflow)?;

        self.check(next)?;
        self.counters = next;
        Ok(())
    }

    /// Cuenta una entrada declarada, sin enumerar directorios.
    pub fn account_result_entry(&mut self) -> Result<(), CaptureError> {
        self.require_attempt()?;

        let mut next = self.counters;

        next.result_entries = next
            .result_entries
            .checked_add(1)
            .ok_or(CaptureError::ArithmeticOverflow)?;

        self.check(next)?;
        self.counters = next;
        Ok(())
    }

    /// Registra tiempo declarado no decreciente.
    ///
    /// No constituye una medición confiable del reloj.
    pub fn observe_elapsed_ms(&mut self, elapsed_ms: u64) -> Result<(), CaptureError> {
        if elapsed_ms < self.counters.elapsed_ms {
            return Err(CaptureError::TimeRegression);
        }

        let mut next = self.counters;
        next.elapsed_ms = elapsed_ms;

        self.check(next)?;
        self.counters = next;
        Ok(())
    }

    /// Devuelve una instantánea de contadores declarados.
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Devuelve una evaluación que nunca habilita ejecución.
    #[must_use]
    pub fn assessment(&self) -> Assessment {
        assess(self.limits, self.counters)
    }

    /// Consulta los bytes sintéticos de stdout.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Consulta los bytes sintéticos de stderr.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn started() -> BoundedCapture {
        let mut capture = BoundedCapture::new(limits()).unwrap();
        capture.begin_attempt().unwrap();
        capture
    }

    #[test]
    fn valid_capture_never_authorizes() {
        let mut capture = started();
        capture.push(Stream::Stdout, b"abc").unwrap();
        capture.push(Stream::Stderr, b"error").unwrap();
        capture.account_network_bytes(100).unwrap();
        capture.account_result_entry().unwrap();
        capture.observe_elapsed_ms(500).unwrap();

        assert_eq!(capture.stdout(), b"abc");
        assert_eq!(capture.stderr(), b"error");
        assert!(capture.assessment().within_declared_limits);
        assert!(!capture.assessment().dispatch_allowed);
    }

    #[test]
    fn invalid_zero_budget_is_rejected() {
        let mut l = limits();
        l.total_time_ms = 0;

        assert!(matches!(
            BoundedCapture::new(l),
            Err(CaptureError::InvalidLimits)
        ));
    }

    #[test]
    fn unbounded_storage_is_rejected() {
        let mut l = limits();
        l.total_capture_bytes = u64::from(crate::contract_gate::MAX_DRAFT_OUTPUT_BYTES) + 1;

        assert!(matches!(
            BoundedCapture::new(l),
            Err(CaptureError::InvalidLimits)
        ));
    }

    #[test]
    fn capture_before_attempt_is_rejected() {
        let mut capture = BoundedCapture::new(limits()).unwrap();

        assert_eq!(
            capture.push(Stream::Stdout, b"x"),
            Err(CaptureError::AttemptRequired)
        );

        assert!(capture.stdout().is_empty());
    }

    #[test]
    fn repeated_attempt_is_rejected_atomically() {
        let mut capture = started();

        assert_eq!(
            capture.begin_attempt(),
            Err(CaptureError::LimitExceeded(Violation::AttemptsExceeded))
        );

        assert_eq!(capture.counters().attempts, 1);
    }

    #[test]
    fn stdout_excess_preserves_previous_content() {
        let mut capture = started();
        capture.push(Stream::Stdout, &[1; 60]).unwrap();

        assert_eq!(
            capture.push(Stream::Stdout, &[2; 5]),
            Err(CaptureError::LimitExceeded(Violation::StdoutExceeded))
        );

        assert_eq!(capture.stdout().len(), 60);
        assert_eq!(capture.counters().stdout_bytes, 60);
    }

    #[test]
    fn stderr_excess_preserves_previous_content() {
        let mut capture = started();
        capture.push(Stream::Stderr, &[1; 64]).unwrap();

        assert_eq!(
            capture.push(Stream::Stderr, b"x"),
            Err(CaptureError::LimitExceeded(Violation::StderrExceeded))
        );

        assert_eq!(capture.stderr().len(), 64);
        assert_eq!(capture.counters().stderr_bytes, 64);
    }

    #[test]
    fn aggregate_capture_excess_is_atomic() {
        let mut capture = started();
        capture.push(Stream::Stdout, &[1; 60]).unwrap();

        assert_eq!(
            capture.push(Stream::Stderr, &[2; 41]),
            Err(CaptureError::LimitExceeded(Violation::CaptureExceeded))
        );

        assert_eq!(capture.stdout().len(), 60);
        assert!(capture.stderr().is_empty());
        assert_eq!(capture.counters().stderr_bytes, 0);
    }

    #[test]
    fn exact_capture_boundary_is_accepted() {
        let mut capture = started();

        capture.push(Stream::Stdout, &[1; 64]).unwrap();
        capture.push(Stream::Stderr, &[2; 36]).unwrap();

        assert_eq!(
            capture.counters().stdout_bytes + capture.counters().stderr_bytes,
            100
        );

        assert!(capture.assessment().within_declared_limits);
        assert!(!capture.assessment().dispatch_allowed);
    }

    #[test]
    fn transfer_and_entry_excesses_are_atomic() {
        let mut capture = started();

        capture.account_network_bytes(4_096).unwrap();

        assert_eq!(
            capture.account_network_bytes(1),
            Err(CaptureError::LimitExceeded(Violation::TransferExceeded))
        );

        assert_eq!(capture.counters().network_bytes, 4_096);

        for _ in 0..10 {
            capture.account_result_entry().unwrap();
        }

        assert_eq!(
            capture.account_result_entry(),
            Err(CaptureError::LimitExceeded(Violation::EntriesExceeded))
        );

        assert_eq!(capture.counters().result_entries, 10);
    }

    #[test]
    fn clock_regression_and_timeout_are_rejected() {
        let mut capture = started();

        capture.observe_elapsed_ms(500).unwrap();

        assert_eq!(
            capture.observe_elapsed_ms(499),
            Err(CaptureError::TimeRegression)
        );

        assert_eq!(
            capture.observe_elapsed_ms(1_001),
            Err(CaptureError::LimitExceeded(Violation::TimeExceeded))
        );

        assert_eq!(capture.counters().elapsed_ms, 500);
    }

    #[test]
    fn arithmetic_overflow_is_rejected() {
        let mut l = limits();
        l.network_bytes = u64::MAX - 1;

        let mut capture = BoundedCapture::new(l).unwrap();
        capture.begin_attempt().unwrap();

        capture.account_network_bytes(u64::MAX - 1).unwrap();

        assert_eq!(
            capture.account_network_bytes(2),
            Err(CaptureError::ArithmeticOverflow)
        );

        assert_eq!(capture.counters().network_bytes, u64::MAX - 1);
    }

    #[test]
    fn all_29_profiles_remain_denied() {
        assert_eq!(crate::contract_gate::PROFILE_IDS.len(), 29);

        for _profile in crate::contract_gate::PROFILE_IDS {
            let capture = started();

            assert!(!capture.assessment().dispatch_allowed);
        }
    }
}
