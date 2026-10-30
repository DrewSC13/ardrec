"""Intercambiar una consulta durable por un canal Unix de uso exclusivo."""

import math
import socket
import time

from ardrec.peer_identity import PeerError, authenticate_peer
from ardrec.messages import MessageError, decode_message, encode_message
from ardrec.reconciliation import ReconciliationError, complete_query, inspect_recovery
from ardrec.transport import FrameError, read_frame, write_frame


class ExchangeError(ValueError):
    """Fallo de transporte; no acredita ausencia, rechazo ni terminación."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"Intercambio incompleto: {code}")


class _DeadlineStream:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Plazo de intercambio agotado")
        self.connection.settimeout(remaining)

    def read(self, size):
        self.remaining()
        return self.connection.recv(size)

    def write(self, data):
        self.remaining()
        return self.connection.send(data)

    def flush(self):
        self.remaining()


def _message(stream):
    raw = read_frame(stream).encode("utf-8")
    message = decode_message(raw)
    if message["schema_version"] != "2.0" or encode_message(message) != raw:
        raise ExchangeError("noncanonical_or_version")
    return raw, message


def exchange_query(store, connection, *, expected_peer=None, timeout=10.0):
    """Consumir y cerrar el socket; confirmar únicamente una respuesta completa.

    El llamador fija expected_peer desde su política y proporciona un socket exclusivo.
    Se verifica la identidad antes de acceder al diario o enviar mensajes.
    La consulta debe estar abierta en el diario. No se crea ni reenvía un intento.
    """
    if not isinstance(connection, socket.socket):
        raise ExchangeError("unix_stream_required")
    try:
        if connection.family != socket.AF_UNIX or connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_TYPE
        ) != socket.SOCK_STREAM:
            raise ExchangeError("unix_stream_required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 60 or not math.isfinite(timeout):
            raise ExchangeError("invalid_timeout")
        authenticate_peer(connection, expected_peer)
        stream = _DeadlineStream(connection, time.monotonic() + timeout)
        decision = inspect_recovery(store)
        if decision.action != "QUERY_INCOMPLETE" or decision.open_query is None:
            raise ExchangeError("open_query_required")
        query = decision.open_query
        # El medio cierre delimita una consulta; cualquier byte adicional se rechaza.
        write_frame(stream, query.decode("utf-8"))
        connection.shutdown(socket.SHUT_WR)
        response, message = _message(stream)
        if message["message_type"] != "attempt_status_result":
            raise ExchangeError("status_response_required")
        result = None
        if message["payload"]["snapshot"]["result"]["status"] == "DISPONIBLE":
            result, _ = _message(stream)
        if stream.read(1):
            raise ExchangeError("trailing_bytes")
        stream.remaining()
        # La correlación y la publicación durable se realizan juntas, después del EOF.
        return complete_query(store, query, response, result=result)
    except PeerError as error:
        raise ExchangeError(error.code) from error
    except TimeoutError as error:
        raise ExchangeError("timeout") from error
    except (OSError, EOFError) as error:
        raise ExchangeError("connection_incomplete") from error
    except (MessageError, FrameError, ReconciliationError) as error:
        raise ExchangeError("invalid_response") from error
    finally:
        connection.close()
