//! Encuadre UTF-8 con longitud de cuatro bytes en orden de red.

use std::io::{self, Read, Write};

/// Máximo inicial de bytes del contenido de una trama.
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Leer una trama completa; el llamador descarta el canal ante cualquier error.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<String> {
    let mut header = [0_u8; 4];
    // read_exact reúne lecturas parciales y rechaza el cierre prematuro.
    reader.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    // El límite se comprueba antes de reservar el contenido.
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Longitud inválida",
        ));
    }
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    String::from_utf8(payload)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UTF-8 inválido"))
}

/// Escribir una trama sin reintentar mensajes ni confirmar acciones técnicas.
pub fn write_frame<W: Write>(writer: &mut W, text: &str) -> io::Result<()> {
    let payload = text.as_bytes();
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Longitud inválida",
        ));
    }
    // El prefijo expresa bytes UTF-8, no el número de caracteres.
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Fragmented(Cursor<Vec<u8>>);

    impl Read for Fragmented {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let size = buf.len().min(1);
            self.0.read(&mut buf[..size])
        }
    }

    impl Write for Fragmented {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(&buf[..buf.len().min(1)])
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fragmented_unicode() {
        let mut stream = Fragmented::default();
        let text = "{\"mensaje\":\"áλ🙂\"}";
        write_frame(&mut stream, text).unwrap();
        assert_eq!(&stream.0.get_ref()[..4], &(text.len() as u32).to_be_bytes());
        stream.0.set_position(0);
        assert_eq!(read_frame(&mut stream).unwrap(), text);
    }

    #[test]
    fn consecutive_frames() {
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, "{}").unwrap();
        write_frame(&mut stream, "[]").unwrap();
        stream.set_position(0);
        assert_eq!(read_frame(&mut stream).unwrap(), "{}");
        assert_eq!(read_frame(&mut stream).unwrap(), "[]");
        assert_eq!(
            read_frame(&mut stream).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn invalid_size_before_body() {
        for size in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
            let mut bytes = size.to_be_bytes().to_vec();
            bytes.extend_from_slice(b"body");
            let mut stream = Cursor::new(bytes);
            assert_eq!(
                read_frame(&mut stream).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(stream.position(), 4);
        }
    }

    #[test]
    fn truncated_frames() {
        let cases: &[&[u8]] = &[b"", b"\0", b"\0\0\0", b"\0\0\0\x03ab"];
        for raw in cases {
            assert_eq!(
                read_frame(&mut Cursor::new(*raw)).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[test]
    fn invalid_utf8() {
        let mut stream = Cursor::new(b"\0\0\0\x01\xff");
        assert_eq!(
            read_frame(&mut stream).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn size_boundaries() {
        for text in [
            String::new(),
            "a".repeat(MAX_FRAME_BYTES + 1),
            "á".repeat(MAX_FRAME_BYTES),
        ] {
            let mut stream = Vec::new();
            assert!(write_frame(&mut stream, &text).is_err());
            assert!(stream.is_empty());
        }
        let text = "a".repeat(MAX_FRAME_BYTES);
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, &text).unwrap();
        stream.set_position(0);
        assert_eq!(read_frame(&mut stream).unwrap(), text);
    }

    #[test]
    fn write_failure() {
        // Un destino sin capacidad obliga a detectar una escritura incompleta.
        let mut buffer = [0_u8; 0];
        let mut writer = Cursor::new(buffer.as_mut_slice());
        assert_eq!(
            write_frame(&mut writer, "{}").unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
