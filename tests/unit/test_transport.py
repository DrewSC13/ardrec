"""Pruebas del encuadre de mensajes y de sus errores de entrada/salida."""

import io
import unittest

from ardrec.transport import FrameError, MAX_FRAME_BYTES, read_frame, write_frame


class Fragmented(io.BytesIO):
    """Forzar transferencias de un byte, independientemente del sistema operativo."""

    def read(self, size=-1):
        return super().read(min(size, 1))

    def write(self, data):
        return super().write(data[:1])


class Stalled(io.BytesIO):
    """Simular una escritura que no progresa."""

    def write(self, data):
        return 0


class TransportTests(unittest.TestCase):
    """Comprobar límites, fragmentación y separación de tramas."""

    def test_fragmented_unicode(self):
        stream = Fragmented()
        text = '{"mensaje":"áλ🙂"}'
        write_frame(stream, text)
        self.assertEqual(stream.getvalue()[:4], len(text.encode()).to_bytes(4, "big"))
        stream.seek(0)
        self.assertEqual(read_frame(stream), text)

    def test_consecutive_frames(self):
        stream = io.BytesIO()
        for text in ['{"id":1}', '{"id":2}']:
            write_frame(stream, text)
        stream.seek(0)
        self.assertEqual(read_frame(stream), '{"id":1}')
        self.assertEqual(read_frame(stream), '{"id":2}')
        with self.assertRaises(EOFError):
            read_frame(stream)

    def test_truncation(self):
        for raw in [b'', b'\x00', b'\x00\x00\x00', b'\x00\x00\x00\x03ab']:
            with self.subTest(raw=raw), self.assertRaises(EOFError):
                read_frame(io.BytesIO(raw))

    def test_invalid_length_without_body_read(self):
        for size in [0, MAX_FRAME_BYTES + 1, 0xffffffff]:
            stream = io.BytesIO(size.to_bytes(4, 'big') + b'body')
            with self.subTest(size=size), self.assertRaises(FrameError):
                read_frame(stream)
            self.assertEqual(stream.tell(), 4)

    def test_invalid_utf8(self):
        with self.assertRaises(FrameError):
            read_frame(io.BytesIO(b'\x00\x00\x00\x01\xff'))

    def test_send_limits(self):
        for text in ['', 'a' * (MAX_FRAME_BYTES + 1), 'á' * MAX_FRAME_BYTES,
                     '\ud800', None, b'{}']:
            stream = io.BytesIO()
            with self.subTest(kind=type(text).__name__), self.assertRaises(FrameError):
                write_frame(stream, text)
            self.assertEqual(stream.getvalue(), b'')

    def test_maximum_size(self):
        stream = io.BytesIO()
        text = 'a' * MAX_FRAME_BYTES
        write_frame(stream, text)
        stream.seek(0)
        self.assertEqual(read_frame(stream), text)

    def test_stalled_writer(self):
        with self.assertRaises(OSError):
            write_frame(Stalled(), '{}')


if __name__ == '__main__':
    unittest.main()
