//! R99: ejemplo ejecutable de observación SSH local; P8 permanece NO-GO.

use ardrec_executor::r99_ssh_loopback::observe_local_ssh_banner;
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "R99_REQUIRES_ONLY_LOCAL_PORT").into(),
        );
    }

    let port = args[1].parse::<u16>()?;
    let result = observe_local_ssh_banner(port)?;

    let report = serde_json::json!({
        "schema": "ardrec-r99-local-tcp-ssh-identification-v1",
        "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
        "identification": result.identification,
        "banner_sha256": result.banner_sha256,
        "bytes_received": result.bytes_received,
        "elapsed_ms": result.elapsed_ms,
        "tcp_connections": 1,
        "ssh_authentication": false,
        "remote_commands": 0,
        "a5_operational_attempts": 0,
        "a6_classification": "ND",
        "rf_confirmed": null,
        "evidence_accredited": result.evidence_accredited,
        "dispatch_allowed": result.dispatch_allowed,
        "p8_operational": "NO-GO"
    });

    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
