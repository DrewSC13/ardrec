"""Identidad Linux del extremo Unix; la política esperada es externa al canal."""
from dataclasses import dataclass
import socket
import struct
import sys

class PeerError(ValueError):
    """Par ausente, no verificable o distinto: no intercambiar mensajes."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)

@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """Credenciales esperadas al establecer la conexión, sin comodines."""
    pid: int
    uid: int
    gid: int

    def __post_init__(self):
        if type(self.pid) is not int or not 0 < self.pid < 2**31:
            raise PeerError('peer_pid_invalid')
        for value in (self.uid, self.gid):
            if type(value) is not int or not 0 <= value < 2**32 - 1:
                raise PeerError('peer_account_invalid')

def authenticate_peer(connection, expected):
    """Comparar SO_PEERCRED con la política sin cerrar ni consumir bytes.

    No identifica el ejecutable ni un receptor posterior de un descriptor heredado.
    PID/UID/GID son los registrados al conectar/listen/socketpair.
    """
    if type(expected) is not PeerIdentity:
        raise PeerError('peer_identity_required')
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        raise PeerError('peer_platform_unsupported')
    if not isinstance(connection, socket.socket):
        raise PeerError('unix_stream_required')
    try:
        if (connection.family != socket.AF_UNIX or
                connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
            raise PeerError('unix_stream_required')
        connection.getpeername()
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('=iII'))
        if len(raw) != struct.calcsize('=iII'):
            raise PeerError('peer_credentials_invalid')
        actual = PeerIdentity(*struct.unpack('=iII', raw))
    except (OSError, struct.error) as error:
        raise PeerError('peer_credentials_unavailable') from error
    if actual != expected:
        raise PeerError('peer_identity_mismatch')
    return actual
