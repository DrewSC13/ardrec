//! R99: observación TCP real de identificación SSH, solo loopback.
//!
//! No hay autenticación SSH, ejecución remota ni autorización P8.
//! El destino está fijado a 127.0.0.1; ningún IP externo es aceptado.

use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// Máximo de bytes recibidos para una identificación SSH.
pub const MAX_BANNER_BYTES: usize = 255;

/// Tiempo total máximo para conexión y recepción.
pub const DEADLINE_MS: u64 = 1500;

/// Resultado de transporte; nunca constituye evidencia A6 acreditada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Identificación SSH recibida de un servicio local.
    pub identification: String,
    /// SHA-256 de los bytes de identificación recibidos, incluido LF.
    pub banner_sha256: String,
    /// Número de bytes recibidos.
    pub bytes_received: usize,
    /// Duración local monotónica, en milisegundos.
    pub elapsed_ms: u128,
    /// Nunca autoriza despacho operacional.
    pub dispatch_allowed: bool,
    /// Nunca convierte una lectura local en evidencia acreditada.
    pub evidence_accredited: bool,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Conecta una sola vez exclusivamente al loopback IPv4.
///
/// No recibe direcciones IP, nombres de host, comandos ni credenciales.
/// No implementa SSH completo: recibe únicamente la identificación inicial.
pub fn observe_local_ssh_banner(port: u16) -> io::Result<Observation> {
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "R99_PORT_ZERO"));
    }

    let started = Instant::now();
    let deadline = started + Duration::from_millis(DEADLINE_MS);

    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(1000))?;

    let mut wire = Vec::with_capacity(MAX_BANNER_BYTES);

    for _ in 0..MAX_BANNER_BYTES {
        let remaining = deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "R99_DEADLINE_EXCEEDED",
            ));
        }

        stream.set_read_timeout(Some(remaining))?;

        let mut one = [0_u8; 1];
        let size = stream.read(&mut one)?;

        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "R99_PREMATURE_EOF",
            ));
        }

        wire.push(one[0]);

        if one[0] == b'\n' {
            let mut content = &wire[..wire.len() - 1];

            if content.last() == Some(&b'\r') {
                content = &content[..content.len() - 1];
            }

            if !content.iter().all(u8::is_ascii_graphic) {
                return Err(invalid("R99_NONPRINTABLE_BANNER"));
            }

            let text = std::str::from_utf8(content).map_err(|_| invalid("R99_INVALID_UTF8"))?;

            if !(text.starts_with("SSH-2.0-") || text.starts_with("SSH-1.99-")) || text.len() <= 8 {
                return Err(invalid("R99_NOT_SSH_IDENTIFICATION"));
            }

            let hash = Sha256::digest(&wire);

            return Ok(Observation {
                identification: text.to_owned(),
                banner_sha256: format!("{hash:x}"),
                bytes_received: wire.len(),
                elapsed_ms: started.elapsed().as_millis(),
                dispatch_allowed: false,
                evidence_accredited: false,
            });
        }
    }

    Err(invalid("R99_BANNER_TOO_LONG"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};

    fn serve(bytes: Vec<u8>) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let _ = client.write_all(&bytes);
        });

        (port, worker)
    }

    fn exercise(bytes: Vec<u8>) -> io::Result<Observation> {
        let (port, worker) = serve(bytes);
        let result = observe_local_ssh_banner(port);
        worker.join().unwrap();
        result
    }

    #[test]
    fn r99_valid_ssh_2_identification() {
        let result = exercise(b"SSH-2.0-ARDREC_R99_LOCAL\r\n".to_vec()).unwrap();

        assert_eq!(result.identification, "SSH-2.0-ARDREC_R99_LOCAL");
        assert_eq!(result.bytes_received, b"SSH-2.0-ARDREC_R99_LOCAL\r\n".len());
        assert_eq!(result.banner_sha256.len(), 64);
        assert!(!result.dispatch_allowed);
        assert!(!result.evidence_accredited);
    }

    #[test]
    fn r99_valid_legacy_compatibility_identification() {
        let result = exercise(b"SSH-1.99-ARDREC_TEST\n".to_vec()).unwrap();

        assert_eq!(result.identification, "SSH-1.99-ARDREC_TEST");
        assert!(!result.dispatch_allowed);
    }

    #[test]
    fn r99_non_ssh_banner_rejected() {
        let result = exercise(b"HTTP/1.1 200 OK\r\n".to_vec());

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn r99_nonprintable_banner_rejected() {
        let result = exercise(b"SSH-2.0-TEST\x00BAD\r\n".to_vec());

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn r99_oversized_banner_rejected() {
        let mut bytes = b"SSH-2.0-".to_vec();
        bytes.extend(vec![b'X'; 260]);
        bytes.push(b'\n');

        assert_eq!(
            exercise(bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r99_eof_rejected() {
        assert_eq!(
            exercise(Vec::new()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn r99_zero_port_never_connects() {
        assert_eq!(
            observe_local_ssh_banner(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
