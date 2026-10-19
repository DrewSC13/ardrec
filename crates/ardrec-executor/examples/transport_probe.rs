//! Sonda de pruebas: devuelve dos tramas sin ejecutar acciones técnicas.

use ardrec_executor::transport::{read_frame, write_frame};
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn main() -> io::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Falta la ruta del socket"))?;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    // La sonda termina ante un error; nunca reconecta ni repite el mensaje.
    for _ in 0..2 {
        let text = read_frame(&mut stream)?;
        write_frame(&mut stream, &text)?;
    }
    Ok(())
}
