//! Contrato puro de consumo P8.
//!
//! Evalúa contadores sintéticos frente a límites declarados.
//! No mide procesos, no ejecuta herramientas ni autoriza despacho.
//!
//! Pure P8 resource-consumption contract.
//! No process monitoring, client execution or authorization.

/// Límites sintéticos declarados para una operación.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Tiempo total máximo, en milisegundos.
    pub total_time_ms: u64,
    /// Máximo de bytes capturados de stdout.
    pub stdout_bytes: u64,
    /// Máximo de bytes capturados de stderr.
    pub stderr_bytes: u64,
    /// Máximo conjunto de captura.
    pub total_capture_bytes: u64,
    /// Presupuesto máximo de transferencia.
    pub network_bytes: u64,
    /// Máximo de elementos contabilizados.
    pub result_entries: u64,
    /// Número permitido de intentos.
    pub attempts: u32,
}

/// Contadores suministrados para evaluación pura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    /// Tiempo transcurrido declarado.
    pub elapsed_ms: u64,
    /// Bytes declarados de stdout.
    pub stdout_bytes: u64,
    /// Bytes declarados de stderr.
    pub stderr_bytes: u64,
    /// Bytes de transferencia declarados.
    pub network_bytes: u64,
    /// Elementos declarados.
    pub result_entries: u64,
    /// Intentos declarados.
    pub attempts: u32,
}

/// Incumplimientos comprobables del contrato.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// Existe un límite inválido o ilimitado.
    InvalidLimit,
    /// La política declara reintentos.
    InvalidAttemptPolicy,
    /// El tiempo declarado supera su límite.
    TimeExceeded,
    /// La salida estándar supera su límite.
    StdoutExceeded,
    /// La salida de error supera su límite.
    StderrExceeded,
    /// La suma de las capturas produce desbordamiento.
    CaptureOverflow,
    /// El conjunto de captura supera su límite.
    CaptureExceeded,
    /// La transferencia supera el presupuesto.
    TransferExceeded,
    /// El número de elementos supera su límite.
    EntriesExceeded,
    /// Se supera el número de intentos.
    AttemptsExceeded,
}

/// Resultado analítico que nunca concede autorización.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    /// Cumplimiento aritmético, no prueba operacional.
    pub within_declared_limits: bool,
    /// Incumplimientos observados en los datos recibidos.
    pub violations: Vec<Violation>,
    /// El despacho permanece permanentemente deshabilitado.
    pub dispatch_allowed: bool,
}

/// Evalúa datos suministrados sin afirmar su procedencia.
///
/// Incluso si todos los contadores cumplen los límites,
/// el resultado no constituye autorización.
#[must_use]
pub fn assess(limits: Limits, counters: Counters) -> Assessment {
    use Violation::{
        AttemptsExceeded, CaptureExceeded, CaptureOverflow, EntriesExceeded, InvalidAttemptPolicy,
        InvalidLimit, StderrExceeded, StdoutExceeded, TimeExceeded, TransferExceeded,
    };

    let mut violations = Vec::new();

    let bounds = [
        limits.total_time_ms,
        limits.stdout_bytes,
        limits.stderr_bytes,
        limits.total_capture_bytes,
        limits.network_bytes,
        limits.result_entries,
    ];

    if bounds.iter().any(|&n| n == 0 || n == u64::MAX) {
        violations.push(InvalidLimit);
    }

    if limits.attempts != 1 {
        violations.push(InvalidAttemptPolicy);
    }

    if counters.elapsed_ms > limits.total_time_ms {
        violations.push(TimeExceeded);
    }

    if counters.stdout_bytes > limits.stdout_bytes {
        violations.push(StdoutExceeded);
    }

    if counters.stderr_bytes > limits.stderr_bytes {
        violations.push(StderrExceeded);
    }

    match counters.stdout_bytes.checked_add(counters.stderr_bytes) {
        Some(total) if total > limits.total_capture_bytes => {
            violations.push(CaptureExceeded);
        }
        None => {
            violations.push(CaptureOverflow);
        }
        _ => {}
    }

    if counters.network_bytes > limits.network_bytes {
        violations.push(TransferExceeded);
    }

    if counters.result_entries > limits.result_entries {
        violations.push(EntriesExceeded);
    }

    if counters.attempts > limits.attempts {
        violations.push(AttemptsExceeded);
    }

    Assessment {
        within_declared_limits: violations.is_empty(),
        violations,
        dispatch_allowed: false,
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

    fn counters() -> Counters {
        Counters {
            elapsed_ms: 100,
            stdout_bytes: 20,
            stderr_bytes: 10,
            network_bytes: 100,
            result_entries: 2,
            attempts: 1,
        }
    }

    fn rejects(limits: Limits, counters: Counters, expected: Violation) {
        let assessment = assess(limits, counters);
        assert!(assessment.violations.contains(&expected));
        assert!(!assessment.dispatch_allowed);
        assert!(!assessment.within_declared_limits);
    }

    #[test]
    fn bounded_data_never_authorizes() {
        let assessment = assess(limits(), counters());
        assert!(assessment.within_declared_limits);
        assert!(assessment.violations.is_empty());
        assert!(!assessment.dispatch_allowed);
    }

    #[test]
    fn zero_limit_rejected() {
        let mut l = limits();
        l.total_time_ms = 0;
        rejects(l, counters(), Violation::InvalidLimit);
    }

    #[test]
    fn unbounded_limit_rejected() {
        let mut l = limits();
        l.network_bytes = u64::MAX;
        rejects(l, counters(), Violation::InvalidLimit);
    }

    #[test]
    fn hidden_retries_rejected() {
        let mut l = limits();
        l.attempts = 2;
        rejects(l, counters(), Violation::InvalidAttemptPolicy);
    }

    #[test]
    fn total_deadline_rejected() {
        let mut c = counters();
        c.elapsed_ms = 1_001;
        rejects(limits(), c, Violation::TimeExceeded);
    }

    #[test]
    fn stdout_and_stderr_limits_rejected() {
        let mut c = counters();
        c.stdout_bytes = 65;
        rejects(limits(), c, Violation::StdoutExceeded);

        let mut c = counters();
        c.stderr_bytes = 65;
        rejects(limits(), c, Violation::StderrExceeded);
    }

    #[test]
    fn aggregate_capture_limit_rejected() {
        let mut c = counters();
        c.stdout_bytes = 60;
        c.stderr_bytes = 50;
        rejects(limits(), c, Violation::CaptureExceeded);
    }

    #[test]
    fn capture_overflow_rejected() {
        let mut c = counters();
        c.stdout_bytes = u64::MAX;
        c.stderr_bytes = 1;
        rejects(limits(), c, Violation::CaptureOverflow);
    }

    #[test]
    fn transfer_and_entries_rejected() {
        let mut c = counters();
        c.network_bytes = 4_097;
        rejects(limits(), c, Violation::TransferExceeded);

        let mut c = counters();
        c.result_entries = 11;
        rejects(limits(), c, Violation::EntriesExceeded);
    }

    #[test]
    fn excess_attempts_rejected() {
        let mut c = counters();
        c.attempts = 2;
        rejects(limits(), c, Violation::AttemptsExceeded);
    }

    #[test]
    fn all_existing_profile_ids_remain_denied() {
        assert_eq!(crate::contract_gate::PROFILE_IDS.len(), 29);

        for _profile in crate::contract_gate::PROFILE_IDS {
            let result = assess(limits(), counters());
            assert!(!result.dispatch_allowed);
        }
    }
}
