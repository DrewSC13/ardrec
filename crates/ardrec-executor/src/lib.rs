//! # Español
//!
//! Base compilable del ejecutor técnico de ARDREC.
//! Esta etapa establece únicamente la identidad del paquete.
//! La ejecución de herramientas y el protocolo permanecen pendientes.
//!
//! # English
//!
//! Buildable baseline for the ARDREC technical executor.
//! This stage establishes only the package identity.
//! Tool execution and the protocol remain pending.

/// Versión de desarrollo declarada en Cargo.
///
/// Development version declared in Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Encuadre de mensajes para el canal local.
pub mod transport;

/// Contratos de mensajes sin efectos operacionales.
pub mod messages;

/// Diario técnico durable con recuperación y consultas.
pub mod journal;

/// Consultas durables por un canal Unix de uso exclusivo.
pub mod reconciliation_transport;

/// Magnitudes analíticas exactas independientes del protocolo operacional.
pub mod magnitudes;

/// Duración monotónica local independiente de UTC.
pub mod timing;

/// Identidad del par antes de intercambiar consultas.
pub mod peer_identity;

/// Contratos tipados no ejecutables / Non-executable typed contract review.
pub mod contract_gate;

/// Diagnóstico sintético P8-R7; solo denegación / deny-only synthetic diagnostics.
pub mod p8_diagnostic;

/// Contrato puro de presupuesto y consumo P8; nunca autoriza despacho.
pub mod p8_resource_contract;

/// Captura acotada sintética sin ejecución ni autorización.
pub mod p8_bounded_capture;
