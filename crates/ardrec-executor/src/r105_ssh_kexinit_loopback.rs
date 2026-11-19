//! R105: intercambio SSHv2 inicial y lectura acotada de KEXINIT en loopback.
//!
//! Una conexion TCP IPv4 a 127.0.0.1, una identificacion de cliente y
//! un paquete KEXINIT del servidor. No negocia claves, no autentica, no
//! ejecuta comandos y nunca concede autoridad operacional.

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// Limite de identificacion del servidor, incluido LF.
pub const MAX_IDENTIFICATION_BYTES: usize = 255;
/// Limite de packet_length SSH sin el prefijo de cuatro bytes.
pub const MAX_PACKET_BYTES: usize = 8192;
/// Plazo monotono total para el intercambio local.
pub const DEADLINE_MS: u64 = 2500;
const CLIENT_IDENTIFICATION: &[u8] = b"SSH-2.0-ARDREC_R105_LOCAL\r\n";
const MAX_NAME_LIST_BYTES: usize = 2048;

/// Datos observables del transporte inicial; no son evidencia A6 acreditada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KexObservation {
    /// Identificacion recibida del servidor local.
    pub server_identification: String,
    /// SHA-256 de la identificacion, incluido LF.
    pub identification_sha256: String,
    /// SHA-256 del paquete KEXINIT completo, incluido packet_length.
    pub kexinit_sha256: String,
    /// Tamano total del paquete KEXINIT recibido.
    pub kexinit_bytes: usize,
    /// Algoritmos KEX anunciados, sin seleccion ni negociacion.
    pub offered_kex_algorithms: Vec<String>,
    /// Algoritmos de clave de host anunciados, sin verificar identidad.
    pub offered_host_key_algorithms: Vec<String>,
    /// Duracion monotona local en milisegundos.
    pub elapsed_ms: u128,
    /// La negociacion de claves no se realiza.
    pub keys_negotiated: bool,
    /// No se realiza autenticacion.
    pub authenticated: bool,
    /// No se ejecuta ningun comando remoto.
    pub remote_commands: u32,
    /// Nunca se autoriza el despacho P8.
    pub dispatch_allowed: bool,
    /// Nunca se acredita una condicion tecnica A6.
    pub evidence_accredited: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct KexLists {
    kex: Vec<String>,
    host_keys: Vec<String>,
}

fn invalid(code: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, code)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let value = deadline.saturating_duration_since(Instant::now());
    if value.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "R105_DEADLINE"));
    }
    Ok(value)
}

fn read_exact_before(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    stream.read_exact(bytes)
}

fn parse_identification(wire: &[u8]) -> io::Result<String> {
    if wire.is_empty() || wire.len() > MAX_IDENTIFICATION_BYTES || wire.last() != Some(&b'\n') {
        return Err(invalid("R105_IDENTIFICATION_FRAME"));
    }
    let mut content = &wire[..wire.len() - 1];
    if content.last() == Some(&b'\r') {
        content = &content[..content.len() - 1];
    }
    if !content.iter().all(u8::is_ascii_graphic) {
        return Err(invalid("R105_IDENTIFICATION_CHARACTERS"));
    }
    let value = std::str::from_utf8(content).map_err(|_| invalid("R105_IDENTIFICATION_UTF8"))?;
    if !value.starts_with("SSH-2.0-") || value.len() <= "SSH-2.0-".len() {
        return Err(invalid("R105_SSHV2_REQUIRED"));
    }
    Ok(value.to_owned())
}

fn take_u32(bytes: &[u8], position: &mut usize) -> io::Result<usize> {
    let end = position
        .checked_add(4)
        .ok_or_else(|| invalid("R105_OFFSET_OVERFLOW"))?;
    let raw: [u8; 4] = bytes
        .get(*position..end)
        .ok_or_else(|| invalid("R105_TRUNCATED_U32"))?
        .try_into()
        .map_err(|_| invalid("R105_TRUNCATED_U32"))?;
    *position = end;
    Ok(u32::from_be_bytes(raw) as usize)
}

fn take_names(bytes: &[u8], position: &mut usize) -> io::Result<Vec<String>> {
    let count = take_u32(bytes, position)?;
    if count > MAX_NAME_LIST_BYTES {
        return Err(invalid("R105_NAME_LIST_OVERSIZE"));
    }
    let end = position
        .checked_add(count)
        .ok_or_else(|| invalid("R105_OFFSET_OVERFLOW"))?;
    let raw = bytes
        .get(*position..end)
        .ok_or_else(|| invalid("R105_NAME_LIST_TRUNCATED"))?;
    *position = end;
    if count == 0 {
        return Ok(Vec::new());
    }
    if !raw.iter().all(u8::is_ascii_graphic) {
        return Err(invalid("R105_NAME_LIST_CHARACTERS"));
    }
    let value = std::str::from_utf8(raw).map_err(|_| invalid("R105_NAME_LIST_UTF8"))?;
    let mut names = Vec::new();
    for name in value.split(',') {
        if name.is_empty() || name.len() > 128 || names.len() >= 64 {
            return Err(invalid("R105_NAME_INVALID"));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn parse_kexinit(packet: &[u8]) -> io::Result<KexLists> {
    if packet.len() < 4 {
        return Err(invalid("R105_PACKET_SHORT_HEADER"));
    }
    let mut offset = 0;
    let packet_len = take_u32(packet, &mut offset)?;
    if !(6..=MAX_PACKET_BYTES).contains(&packet_len)
        || packet_len.checked_add(4) != Some(packet.len())
        || (packet_len + 4) % 8 != 0
    {
        return Err(invalid("R105_PACKET_LENGTH_OR_ALIGNMENT"));
    }
    let padding = usize::from(packet[4]);
    if padding < 4 || padding + 1 >= packet_len {
        return Err(invalid("R105_PADDING_INVALID"));
    }
    let payload_end = packet.len() - padding;
    let payload = packet
        .get(5..payload_end)
        .ok_or_else(|| invalid("R105_EMPTY_PAYLOAD"))?;
    if payload.len() < 17 || payload[0] != 20 {
        return Err(invalid("R105_NOT_KEXINIT"));
    }
    let mut cursor = 17; // SSH_MSG_KEXINIT + cookie[16]
    let mut lists = Vec::with_capacity(10);
    for _ in 0..10 {
        lists.push(take_names(payload, &mut cursor)?);
    }
    if payload.get(cursor..).map(|tail| tail.len()) != Some(5) {
        return Err(invalid("R105_KEXINIT_TRAILING_LAYOUT"));
    }
    if !matches!(payload[cursor], 0 | 1)
        || payload[cursor + 1..cursor + 5] != [0_u8; 4]
        || lists[0].is_empty()
        || lists[1].is_empty()
    {
        return Err(invalid("R105_KEXINIT_REQUIRED_FIELDS"));
    }
    Ok(KexLists {
        kex: lists.remove(0),
        host_keys: lists.remove(0),
    })
}

/// Ejecuta un intercambio inicial SSHv2 en una unica conexion TCP IPv4 local.
///
/// Envia solamente una identificacion fija, recibe identificacion y un
/// KEXINIT del servidor. No continua hacia NEWKEYS, usuario o autenticacion.
/// No se permiten nombres de host, IP arbitrarias, comandos ni credenciales.
pub fn observe_local_ssh_kexinit(port: u16) -> io::Result<KexObservation> {
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "R105_PORT_ZERO",
        ));
    }
    let started = Instant::now();
    let deadline = started + Duration::from_millis(DEADLINE_MS);
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(1000))?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(CLIENT_IDENTIFICATION)?;

    let mut banner = Vec::with_capacity(MAX_IDENTIFICATION_BYTES);
    let mut found_lf = false;
    for _ in 0..MAX_IDENTIFICATION_BYTES {
        let mut byte = [0_u8; 1];
        read_exact_before(&mut stream, &mut byte, deadline)?;
        banner.push(byte[0]);
        if byte[0] == b'\n' {
            found_lf = true;
            break;
        }
    }
    if !found_lf {
        return Err(invalid("R105_IDENTIFICATION_TOO_LONG"));
    }
    let identification = parse_identification(&banner)?;
    let mut prefix = [0_u8; 4];
    read_exact_before(&mut stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(6..=MAX_PACKET_BYTES).contains(&length) {
        return Err(invalid("R105_PACKET_BOUNDS"));
    }
    let mut packet = Vec::with_capacity(4 + length);
    packet.extend_from_slice(&prefix);
    packet.resize(4 + length, 0);
    read_exact_before(&mut stream, &mut packet[4..], deadline)?;
    let lists = parse_kexinit(&packet)?;

    Ok(KexObservation {
        server_identification: identification,
        identification_sha256: format!("{:x}", Sha256::digest(&banner)),
        kexinit_sha256: format!("{:x}", Sha256::digest(&packet)),
        kexinit_bytes: packet.len(),
        offered_kex_algorithms: lists.kex,
        offered_host_key_algorithms: lists.host_keys,
        elapsed_ms: started.elapsed().as_millis(),
        keys_negotiated: false,
        authenticated: false,
        remote_commands: 0,
        dispatch_allowed: false,
        evidence_accredited: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn packet_with_kex(kex: &str) -> Vec<u8> {
        let names = [
            kex,
            "ssh-ed25519",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        let mut payload = vec![20_u8];
        payload.extend_from_slice(&[0_u8; 16]);
        for name in names {
            payload.extend_from_slice(&(name.len() as u32).to_be_bytes());
            payload.extend_from_slice(name.as_bytes());
        }
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0_u8; 4]); // reserved
        let mut pad = (8 - ((5 + payload.len()) % 8)) % 8;
        if pad < 4 {
            pad += 8;
        }
        let len = 1 + payload.len() + pad;
        let mut result = Vec::new();
        result.extend_from_slice(&(len as u32).to_be_bytes());
        result.push(pad as u8);
        result.extend_from_slice(&payload);
        result.resize(result.len() + pad, 0);
        result
    }

    fn packet() -> Vec<u8> {
        packet_with_kex("curve25519-sha256")
    }

    fn served(banner: &[u8], frame: &[u8]) -> io::Result<KexObservation> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let b = banner.to_vec();
        let f = frame.to_vec();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut client = vec![0_u8; CLIENT_IDENTIFICATION.len()];
            assert!(stream.read_exact(&mut client).is_ok());
            assert_eq!(client, CLIENT_IDENTIFICATION);
            let _ = stream.write_all(&b);
            let _ = stream.write_all(&f);
        });
        let result = observe_local_ssh_kexinit(port);
        worker.join().unwrap();
        result
    }

    #[test]
    fn r105_real_local_handshake_and_kexinit() {
        let result = served(b"SSH-2.0-ARDREC_FIXTURE\r\n", &packet()).unwrap();
        assert_eq!(result.server_identification, "SSH-2.0-ARDREC_FIXTURE");
        assert_eq!(
            result.offered_kex_algorithms,
            vec!["curve25519-sha256".to_owned()]
        );
        assert_eq!(
            result.offered_host_key_algorithms,
            vec!["ssh-ed25519".to_owned()]
        );
        assert_eq!(result.kexinit_sha256.len(), 64);
        assert!(!result.keys_negotiated);
        assert!(!result.authenticated);
        assert_eq!(result.remote_commands, 0);
        assert!(!result.dispatch_allowed);
        assert!(!result.evidence_accredited);
        println!("R105_REAL_LOOPBACK_KEXINIT=PASS");
    }

    #[test]
    fn r105_rejects_non_ssh() {
        assert_eq!(
            served(b"HTTP/1.1 200 OK\r\n", &packet())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_legacy_id() {
        assert_eq!(
            served(b"SSH-1.99-OLD\r\n", &packet()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_wrong_packet_type() {
        let mut frame = packet();
        frame[5] = 21;
        assert_eq!(
            served(b"SSH-2.0-TEST\r\n", &frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_wrong_alignment() {
        let mut frame = packet();
        frame[3] = frame[3].wrapping_sub(1);
        assert_eq!(
            parse_kexinit(&frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_invalid_padding() {
        let mut frame = packet();
        frame[4] = 2;
        assert_eq!(
            parse_kexinit(&frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_truncated_packet() {
        let mut frame = packet();
        frame.pop();
        assert_eq!(
            parse_kexinit(&frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_oversized_packet_before_read() {
        let header = (MAX_PACKET_BYTES as u32 + 1).to_be_bytes();
        assert_eq!(
            served(b"SSH-2.0-TEST\r\n", &header).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_empty_required_algorithms() {
        let frame = packet_with_kex("");
        assert_eq!(
            parse_kexinit(&frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r105_rejects_port_zero() {
        assert_eq!(
            observe_local_ssh_kexinit(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
