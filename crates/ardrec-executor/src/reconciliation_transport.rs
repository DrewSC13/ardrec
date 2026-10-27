//! Intercambio de una consulta durable; el socket pertenece exclusivamente a esta operación.
use crate::{
    journal::TechnicalJournal,
    messages::{decode_message, encode_message},
    transport::{read_frame, write_frame},
};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Plazo agotado"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Atender una consulta 2.0 y cerrar el canal, incluso si falla el intercambio.
///
/// El llamador autentica al par y entrega un socket exclusivo, sin otros lectores.
/// El plazo cubre las operaciones del socket; no interrumpe un fsync del diario.
/// El retorno no acredita recepción en Python. Un error puede seguir a un registro durable.
/// La misma consulta se recupera con su identidad original en una conexión nueva.
pub fn serve_query(
    journal: &mut TechnicalJournal,
    connection: UnixStream,
    response_id: &str,
    created_at: &str,
    timeout: Duration,
) -> io::Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Plazo inválido",
        ));
    }
    connection.set_nonblocking(false)?;
    let mut stream = DeadlineStream {
        stream: connection,
        deadline: Instant::now() + timeout,
    };
    let raw = read_frame(&mut stream)?;
    let message = decode_message(raw.as_bytes()).map_err(io::Error::other)?;
    if message["schema_version"] != "2.0"
        || message["message_type"] != "attempt_status_request"
        || encode_message(&message).map_err(io::Error::other)? != raw.as_bytes()
    {
        return Err(invalid("Se requiere una consulta canónica 2.0"));
    }
    // La entrada completa se delimita antes de modificar el diario.
    let mut extra = [0];
    if stream.read(&mut extra)? != 0 {
        return Err(invalid("Bytes posteriores a la consulta"));
    }
    stream.remaining()?;
    let answer = journal
        .answer(raw.as_bytes(), response_id, created_at)
        .map_err(io::Error::other)?;
    // answer confirma el registro durable antes de entregar el primer byte.
    write_frame(
        &mut stream,
        std::str::from_utf8(&answer.response).map_err(io::Error::other)?,
    )?;
    if let Some(result) = answer.result {
        write_frame(
            &mut stream,
            std::str::from_utf8(&result).map_err(io::Error::other)?,
        )?;
    }
    stream.remaining()?;
    stream.stream.shutdown(Shutdown::Write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "ardrec-channel-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture(key: &str) -> Vec<u8> {
        let f: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/messages-temporal-v1.json"
        ))
        .unwrap();
        encode_message(&f[key]).unwrap()
    }
    fn exchange(
        journal: &mut TechnicalJournal,
        raw: Vec<u8>,
        extra: bool,
    ) -> (io::Result<()>, Vec<u8>) {
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client.write_all(&raw).unwrap();
            if extra {
                client.write_all(b"x").unwrap();
            }
            client.shutdown(Shutdown::Write).unwrap();
            let mut bytes = Vec::new();
            let _ = client.read_to_end(&mut bytes);
            bytes
        });
        let result = serve_query(
            journal,
            server,
            "ANSWER-SOCKET",
            "2026-10-19T12:00:30Z",
            Duration::from_secs(1),
        );
        (result, worker.join().unwrap())
    }
    fn framed(raw: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, std::str::from_utf8(raw).unwrap()).unwrap();
        bytes
    }
    #[test]
    fn answer_is_durable_and_replay_is_exact() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        journal.register(&fixture("request")).unwrap();
        let query = framed(&fixture("query"));
        let (outcome, bytes) = exchange(&mut journal, query.clone(), false);
        outcome.unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(journal.sequence().unwrap(), 2);
        drop(journal);
        let mut journal = TechnicalJournal::open(&directory.0).unwrap();
        let (outcome, replay) = exchange(&mut journal, query, false);
        outcome.unwrap();
        assert_eq!(bytes, replay);
        assert_eq!(journal.sequence().unwrap(), 2);
    }
    #[test]
    fn execution_request_cannot_be_dispatched() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        let (error, bytes) = exchange(&mut journal, framed(&fixture("request")), false);
        assert!(error.is_err());
        assert!(bytes.is_empty());
        assert_eq!(journal.sequence().unwrap(), 0);
    }
    #[test]
    fn extra_bytes_do_not_record_query() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        journal.register(&fixture("request")).unwrap();
        assert!(
            exchange(&mut journal, framed(&fixture("query")), true)
                .0
                .is_err()
        );
        assert_eq!(journal.sequence().unwrap(), 1);
    }
    #[test]
    fn malformed_frames_do_not_record_query() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        for raw in [
            vec![0],
            vec![0, 0, 0, 0],
            vec![0, 16, 0, 1],
            vec![0, 0, 0, 1, 255],
            framed(b"{}"),
            framed(b"{"),
        ] {
            let (outcome, bytes) = exchange(&mut journal, raw, false);
            assert!(outcome.is_err());
            assert!(bytes.is_empty());
            assert_eq!(journal.sequence().unwrap(), 0);
        }
    }
    #[test]
    fn unknown_attempt_does_not_fabricate_absence() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        let (outcome, bytes) = exchange(&mut journal, framed(&fixture("query")), false);
        assert!(outcome.is_err());
        assert!(bytes.is_empty());
        assert_eq!(journal.sequence().unwrap(), 0);
    }
    #[test]
    fn incompatible_and_noncanonical_queries_rejected() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        journal.register(&fixture("request")).unwrap();
        let text = String::from_utf8(fixture("query")).unwrap();
        for raw in [format!(" {text}"), text.replace("\"2.0\"", "\"9.0\"")] {
            assert!(
                exchange(&mut journal, framed(raw.as_bytes()), false)
                    .0
                    .is_err()
            );
            assert_eq!(journal.sequence().unwrap(), 1);
        }
    }
    #[test]
    fn waiting_for_eof_has_a_deadline() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        journal.register(&fixture("request")).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&framed(&fixture("query"))).unwrap();
        let start = Instant::now();
        assert!(
            serve_query(
                &mut journal,
                server,
                "A",
                "2026-10-19T12:00:30Z",
                Duration::from_millis(20)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(journal.sequence().unwrap(), 1);
    }
    #[test]
    fn invalid_deadline_closes_channel() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        for duration in [Duration::ZERO, Duration::from_secs(61)] {
            let (server, mut client) = UnixStream::pair().unwrap();
            assert!(
                serve_query(&mut journal, server, "A", "2026-10-19T12:00:30Z", duration).is_err()
            );
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
        }
    }
    #[test]
    fn slow_fragments_do_not_renew_deadline() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            for byte in framed(&fixture("query")) {
                if client.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        assert!(
            serve_query(
                &mut journal,
                server,
                "A",
                "2026-10-19T12:00:30Z",
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        worker.join().unwrap();
        assert_eq!(journal.sequence().unwrap(), 0);
    }
    #[test]
    fn conflicting_duplicate_does_not_change_answer() {
        let directory = TestDirectory::new();
        let mut journal = TechnicalJournal::create(&directory.0).unwrap();
        journal.register(&fixture("request")).unwrap();
        let query = fixture("query");
        let (_, original) = exchange(&mut journal, framed(&query), false);
        let mut changed = decode_message(&query).unwrap();
        changed["created_at"] = Value::from("2026-10-19T12:00:29Z");
        let (result, bytes) = exchange(
            &mut journal,
            framed(&encode_message(&changed).unwrap()),
            false,
        );
        assert!(result.is_err());
        assert!(bytes.is_empty());
        assert_eq!(journal.sequence().unwrap(), 2);
        assert_eq!(exchange(&mut journal, framed(&query), false).1, original);
    }
}
