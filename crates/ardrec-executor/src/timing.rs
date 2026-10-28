//! Duración local sin restar UTC ni restaurar orígenes persistidos.
use std::time::Instant;
/// Temporizador del proceso actual, sin Clone ni serialización.
/// La suspensión del host debe excluirse en el laboratorio Linux.
pub struct MonotonicTimer {
    origin: Instant,
    pid: u32,
}
impl Default for MonotonicTimer {
    fn default() -> Self {
        Self::new()
    }
}
impl MonotonicTimer {
    /// Capturar origen local; no acredita inicio de una herramienta.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            pid: std::process::id(),
        }
    }
    /// Milisegundos enteros truncados con rechazo ante cambio de proceso.
    pub fn elapsed_ms(&self) -> Result<i64, &'static str> {
        self.elapsed_at(Instant::now(), std::process::id())
    }
    fn elapsed_at(&self, now: Instant, pid: u32) -> Result<i64, &'static str> {
        if pid != self.pid {
            return Err("clock_origin_changed");
        }
        let elapsed = now
            .checked_duration_since(self.origin)
            .ok_or("monotonic_regression")?;
        i64::try_from(elapsed.as_millis()).map_err(|_| "duration_overflow")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn exact_integer_milliseconds() {
        let t = MonotonicTimer::new();
        for (n, e) in [
            (0, 0),
            (999_999, 0),
            (1_000_000, 1),
            (1_999_999, 1),
            (2_000_000, 2),
        ] {
            assert_eq!(
                t.elapsed_at(t.origin + Duration::from_nanos(n), t.pid),
                Ok(e)
            );
        }
    }
    #[test]
    fn changed_process_and_regression_rejected() {
        let t = MonotonicTimer::new();
        assert_eq!(
            t.elapsed_at(t.origin, t.pid.wrapping_add(1)),
            Err("clock_origin_changed")
        );
        assert_eq!(
            t.elapsed_at(t.origin - Duration::from_nanos(1), t.pid),
            Err("monotonic_regression")
        );
    }
    #[test]
    fn actual_clock_available() {
        assert!(MonotonicTimer::new().elapsed_ms().unwrap() >= 0);
    }
}
