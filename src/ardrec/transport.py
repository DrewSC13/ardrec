"""Tramas UTF-8 con prefijo de longitud de cuatro bytes."""

from typing import BinaryIO

MAX_FRAME_BYTES = 1_048_576


class FrameError(ValueError):
    """La trama incumple el contrato de transporte."""


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    # Una lectura parcial no equivale a recibir la trama completa.
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise EOFError("Conexión cerrada antes de completar la trama")
        data.extend(part)
    return bytes(data)


def read_frame(stream: BinaryIO) -> str:
    """Leer una trama; el llamador debe descartar el canal ante cualquier error."""
    size = int.from_bytes(_read_exact(stream, 4), "big")
    # Validar antes de reservar memoria para el contenido recibido.
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise FrameError("Longitud de trama fuera del límite permitido")
    try:
        return _read_exact(stream, size).decode("utf-8")
    except UnicodeDecodeError as error:
        raise FrameError("El contenido no es UTF-8 válido") from error


def write_frame(stream: BinaryIO, text: str) -> None:
    """Enviar una trama sin reintentar mensajes ni confirmar acciones técnicas."""
    if type(text) is not str:
        raise FrameError("El contenido debe ser str")
    # Evitar codificar una entrada cuyo tamaño ya excede el máximo.
    if not 1 <= len(text) <= MAX_FRAME_BYTES:
        raise FrameError("Longitud de texto fuera del límite permitido")
    try:
        payload = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise FrameError("El texto no admite codificación UTF-8") from error
    if len(payload) > MAX_FRAME_BYTES:
        raise FrameError("El contenido UTF-8 excede el límite de bytes")

    # La longitud cuenta bytes, no caracteres; importa para tildes y otros idiomas.
    data = memoryview(len(payload).to_bytes(4, "big") + payload)
    while data:
        written = stream.write(data)
        if written is None or written <= 0:
            raise OSError("No se pudo completar la escritura de la trama")
        data = data[written:]
    stream.flush()
