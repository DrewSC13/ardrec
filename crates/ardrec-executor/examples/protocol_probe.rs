//! Sonda de pruebas: valida documentos recibidos por stdin sin ejecutar acciones.
use ardrec_executor::messages::{self, Delivery};
use serde_json::{Value, json};
use std::io::{self, Read};

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Hexadecimal incompleto".into());
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16).map(|n| n as u8);
            match (digit(pair[0]), digit(pair[1])) {
                (Some(a), Some(b)) => Ok(a * 16 + b),
                _ => Err("Hexadecimal inválido".into()),
            }
        })
        .collect()
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(raw.len() * 2);
    for b in raw {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
fn evaluate(command: &Value) -> Result<Value, String> {
    let op = command["op"].as_str().ok_or("Falta la operación")?;
    let a = command["args"].as_array().ok_or("Faltan argumentos")?;
    let count = match op {
        "correlate" | "correlate_current" | "compare_delivery" => 2,
        "correlate_status" => 3,
        "decode_message" | "encode_message" | "validate_message" => 1,
        _ => return Err("Operación desconocida".into()),
    };
    if a.len() != count {
        return Err("Cantidad de argumentos inválida".into());
    }
    let answer = match op {
        "decode_message" => {
            let raw = unhex(a[0].as_str().ok_or("Faltan bytes hexadecimales")?)?;
            messages::decode_message(&raw)
                .and_then(|v| messages::encode_message(&v))
                .map(|b| json!({"hex":hex(&b)}))
        }
        "encode_message" => messages::encode_message(&a[0]).map(|b| json!({"hex":hex(&b)})),
        "validate_message" => messages::validate_message(&a[0]).map(|()| json!({})),
        "correlate" => messages::correlate(&a[0], &a[1]).map(|()| json!({})),
        "correlate_current" => messages::correlate_current(&a[0], &a[1]).map(|()| json!({})),
        "correlate_status" => messages::correlate_status(&a[0], &a[1], &a[2]).map(|()| json!({})),
        _ => messages::compare_delivery(&a[0], &a[1])
            .map(|v| json!({"delivery":match v {Delivery::Replay=>"REPLAY",Delivery::New=>"NEW"}})),
    };
    Ok(match answer {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(e) => json!({"ok":false,"code":e.code()}),
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Acotar también la envoltura de pruebas, que transporta bytes hexadecimales.
    const LIMIT: u64 = 8 * 1024 * 1024;
    let mut raw = Vec::new();
    io::stdin().lock().take(LIMIT + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > LIMIT {
        return Err("Entrada de prueba demasiado grande".into());
    }
    let command: Value = serde_json::from_slice(&raw)?;
    println!("{}", evaluate(&command)?);
    Ok(())
}
