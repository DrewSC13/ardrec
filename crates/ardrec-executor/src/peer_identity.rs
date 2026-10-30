//! Identidad Linux fijada por una política externa al canal Unix.
use std::{io, os::unix::net::UnixStream};

/// Credenciales esperadas al conectar; no identifica el ejecutable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pid: u32,
    uid: u32,
    gid: u32,
}
impl PeerIdentity {
    /// Construir una identidad exacta sin PID cero ni cuentas sin mapear.
    pub fn new(pid: u32, uid: u32, gid: u32) -> io::Result<Self> {
        if pid == 0 || pid > i32::MAX as u32 || uid == u32::MAX || gid == u32::MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "peer_identity_invalid",
            ));
        }
        Ok(Self { pid, uid, gid })
    }
}
/// Verificar SO_PEERCRED antes del intercambio, sin consumir bytes.
/// Las credenciales no identifican un receptor posterior de un descriptor transferido.
#[cfg(target_os = "linux")]
pub fn authenticate_peer(
    connection: &UnixStream,
    expected: PeerIdentity,
) -> io::Result<PeerIdentity> {
    use rustix::net::{AddressFamily, SocketType, sockopt};
    if sockopt::socket_domain(connection)? != AddressFamily::UNIX
        || sockopt::socket_type(connection)? != SocketType::STREAM
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix_stream_required",
        ));
    }
    connection.peer_addr()?;
    let c = sockopt::socket_peercred(connection)?;
    let actual = PeerIdentity::new(
        c.pid.as_raw_nonzero().get() as u32,
        c.uid.as_raw(),
        c.gid.as_raw(),
    )?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer_identity_mismatch",
        ));
    }
    Ok(actual)
}
/// Rechazar plataformas sin la política Linux implementada.
#[cfg(not(target_os = "linux"))]
pub fn authenticate_peer(
    _connection: &UnixStream,
    _expected: PeerIdentity,
) -> io::Result<PeerIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer_platform_unsupported",
    ))
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn expected() -> PeerIdentity {
        PeerIdentity::new(
            std::process::id(),
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
        .unwrap()
    }
    #[test]
    fn exact_credentials_without_consumption() {
        let (mut connection, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();
        assert_eq!(
            authenticate_peer(&connection, expected()).unwrap(),
            expected()
        );
        let mut data = [0];
        connection.read_exact(&mut data).unwrap();
        assert_eq!(data, *b"x");
    }
    #[test]
    fn rejects_each_different_field() {
        let (connection, _peer) = UnixStream::pair().unwrap();
        let policy = expected();
        for candidate in [
            PeerIdentity {
                pid: policy.pid + 1,
                ..policy
            },
            PeerIdentity {
                uid: policy.uid ^ 1,
                ..policy
            },
            PeerIdentity {
                gid: policy.gid ^ 1,
                ..policy
            },
        ] {
            assert_eq!(
                authenticate_peer(&connection, candidate)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    #[test]
    fn rejects_invalid_identity() {
        for (pid, uid, gid) in [
            (0, 0, 0),
            (u32::MAX, 0, 0),
            (1, u32::MAX, 0),
            (1, 0, u32::MAX),
        ] {
            assert!(PeerIdentity::new(pid, uid, gid).is_err());
        }
    }
}
