//! Par sintético de prueba: una conexión, ninguna ejecución de herramientas.
use ardrec_executor::{
    journal::TechnicalJournal, peer_identity::PeerIdentity, reconciliation_transport::serve_query,
};
use std::{
    error::Error,
    io::{self, Write},
    os::{fd::AsFd, unix::net::UnixStream},
    time::Duration,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("Se requiere diario, punto o none, PID/UID/GID; stdin recibe el socket".into());
    }
    let expected = PeerIdentity::new(args[3].parse()?, args[4].parse()?, args[5].parse()?)?;
    let mut journal = TechnicalJournal::open(&args[1])?;
    let point = args[2].clone();
    if point != "none" {
        // La inyección solo existe en esta sonda; el padre termina el proceso con SIGKILL.
        journal.set_fault_hook(move |current| {
            if current == point {
                println!("ARDREC_FAULT_POINT={current}");
                io::stdout().flush()?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        });
    }
    let connection = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
    println!("READY");
    io::stdout().flush()?;
    serve_query(
        &mut journal,
        connection,
        "SOCKET-ANSWER-1",
        "2026-10-19T12:00:30Z",
        Duration::from_secs(5),
        expected,
    )?;
    println!("DONE");
    Ok(())
}
