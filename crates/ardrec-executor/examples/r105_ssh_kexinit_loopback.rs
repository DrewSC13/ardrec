//! R105: observacion SSHv2 KEXINIT real en loopback; P8 siempre NO-GO.

use ardrec_executor::r105_ssh_kexinit_loopback::observe_local_ssh_kexinit;
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "R105_LOCAL_PORT_ONLY").into());
    }
    let port = args[1].parse::<u16>()?;
    let obs = observe_local_ssh_kexinit(port)?;
    let report = serde_json::json!({
        "schema": "ardrec-r105-sshv2-loopback-kexinit-v1",
        "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
        "server_identification": obs.server_identification,
        "identification_sha256": obs.identification_sha256,
        "kexinit_sha256": obs.kexinit_sha256,
        "kexinit_bytes": obs.kexinit_bytes,
        "offered_kex_algorithms": obs.offered_kex_algorithms,
        "offered_host_key_algorithms": obs.offered_host_key_algorithms,
        "elapsed_ms": obs.elapsed_ms,
        "tcp_connections": 1,
        "client_identifications_sent": 1,
        "keys_negotiated": obs.keys_negotiated,
        "authenticated": obs.authenticated,
        "remote_commands": obs.remote_commands,
        "a5_operational_attempts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": null,
        "evidence_accredited": obs.evidence_accredited,
        "dispatch_allowed": obs.dispatch_allowed,
        "p8_operational": "NO-GO"
    });
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
