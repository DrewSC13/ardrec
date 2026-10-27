//! Contrastar registros exactos con Python mediante entrada y salida acotadas.
use ardrec_executor::magnitudes::{MAX_RECORD_BYTES, decode_magnitude, decode_record};
use std::io::{self, BufRead, Read, Write};
fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let size = (&mut input)
            .take((MAX_RECORD_BYTES * 2 + 16) as u64)
            .read_line(&mut line)?;
        if size == 0 {
            break;
        }
        if !line.ends_with('\n') {
            return Err(io::Error::other("Entrada excesiva o incompleta"));
        }
        let (kind, hex) = line
            .trim_end_matches('\n')
            .split_once(' ')
            .ok_or_else(|| io::Error::other("Modo ausente"))?;
        let mut raw = Vec::new();
        let valid = hex.len() % 2 == 0 && hex.is_ascii();
        if valid {
            for i in (0..hex.len()).step_by(2) {
                match u8::from_str_radix(&hex[i..i + 2], 16) {
                    Ok(v) => raw.push(v),
                    Err(_) => return Err(io::Error::other("Hexadecimal inválido")),
                }
            }
        }
        if !valid {
            return Err(io::Error::other("Hexadecimal inválido"));
        }
        let result = match kind {
            "m" => decode_magnitude(&raw).map(|m| m.as_bytes().to_vec()),
            "r" => decode_record(&raw).map(|m| m.record_bytes()),
            _ => return Err(io::Error::other("Modo inválido")),
        };
        match result {
            Ok(bytes) => {
                write!(output, "OK ")?;
                for b in bytes {
                    write!(output, "{b:02x}")?;
                }
                writeln!(output)?;
            }
            Err(_) => writeln!(output, "ERR")?,
        }
        output.flush()?;
    }
    Ok(())
}
