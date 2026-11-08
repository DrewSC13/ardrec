//! P8-R7 synthetic stdin diagnostic probe; no tools, sockets or network.
use std::io::{self, Read};

use ardrec_executor::p8_diagnostic::{MAX_DIAGNOSTIC_BYTES, diagnostic_json, evaluate};

fn main() {
    let mut buffer = Vec::new();
    // A hard cap prevents unbounded reads even for adversarial standard input.
    let read = io::stdin()
        .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
        .read_to_end(&mut buffer);
    if read.is_err() {
        buffer.clear();
    }
    let result = evaluate(&buffer);
    println!("{}", diagnostic_json(result));
}
