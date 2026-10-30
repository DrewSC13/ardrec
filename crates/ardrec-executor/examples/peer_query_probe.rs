//! Sonda sintética: conexión nueva y política PID/UID/GID explícita.
use ardrec_executor::{
    journal::TechnicalJournal, peer_identity::PeerIdentity, reconciliation_transport::serve_query,
};
use std::{
    error::Error,
    io::{self, Write},
    os::unix::net::UnixListener,
    thread,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("Se requiere diario, socket y PID/UID/GID esperado".into());
    }
    let expected = PeerIdentity::new(args[3].parse()?, args[4].parse()?, args[5].parse()?)?;
    let mut journal = TechnicalJournal::open(&args[1])?;
    // El script crea el directorio privado; no sustituir una ruta previa.
    let listener = UnixListener::bind(&args[2])?;
    listener.set_nonblocking(true)?;
    println!("READY");
    io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let connection = loop {
        match listener.accept() {
            Ok((connection, _)) => break connection,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.into()),
        }
    };
    serve_query(
        &mut journal,
        connection,
        "PEER-ANSWER-1",
        "2026-10-19T12:00:30Z",
        Duration::from_secs(5),
        expected,
    )?;
    println!("DONE");
    Ok(())
}
