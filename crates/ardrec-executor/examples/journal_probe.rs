//! Sonda de pruebas con entradas sintéticas; nunca lanza herramientas de evaluación.
use ardrec_executor::{journal::TechnicalJournal, messages::encode_message};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, Write},
};
fn pause(point: &str) -> io::Result<()> {
    println!("ARDREC_FAULT_POINT={point}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Err(io::Error::other("El proceso de prueba debía interrumpirse"))
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err("Se requiere operación y directorio".into());
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let data: Value = serde_json::from_str(&line)?;
    let mut store = if args[1] == "create" {
        TechnicalJournal::create(&args[2])?
    } else {
        TechnicalJournal::open(&args[2])?
    };
    if let Some(point) = args.get(3).cloned() {
        store.set_fault_hook(move |p| if p == point { pause(p) } else { Ok(()) });
    }
    let output = match args[1].as_str() {
        "create" => json!({"sequence":store.sequence()?}),
        "register" => json!({"recorded":format!("{:?}",store.register(&encode_message(&data)?)?)}),
        "report" => {
            json!({"recorded":format!("{:?}",store.record_report(&encode_message(&data)?)?)})
        }
        "observe" => json!({"recorded":format!("{:?}",store.observe("ATT-1",data)?)}),
        "answer" => {
            let answer =
                store.answer(&encode_message(&data)?, "ANSWER-1", "2026-10-19T12:00:30Z")?;
            json!({"response":serde_json::from_slice::<Value>(&answer.response)?,
                   "result":answer.result.as_ref().map(|b|serde_json::from_slice::<Value>(b)).transpose()?,"replay":answer.replay})
        }
        "inspect" => {
            let snapshot = match store.snapshot("ATT-1") {
                Ok(v) => Some(v),
                Err(e) if e.code() == "attempt_unknown" => None,
                Err(e) => return Err(e.into()),
            };
            let result = if snapshot.is_some() {
                store.result("ATT-1")?
            } else {
                None
            };
            json!({"sequence":store.sequence()?,"snapshot":snapshot,"result":result.as_ref().map(|r|serde_json::from_slice::<Value>(r)).transpose()?})
        }
        "hold" => {
            pause("LOCK_HELD")?;
            Value::Null
        }
        _ => return Err("Operación desconocida".into()),
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
