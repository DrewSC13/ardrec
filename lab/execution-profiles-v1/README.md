# P8 R1 — Perfiles de ejecución / Execution-profile binding slots

## Español

**Referencia de tesis:** SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, secciones 3.7.5 y 3.9.2. Base Git: `009393f34cd548bb79de122de90e992ff285bb5a`, correspondiente a la integración de P7.

Este incremento crea una **estructura de perfiles bloqueados**, no perfiles operativos autorizados. El catálogo P7 posee 25 familias y cuatro familias bifurcadas; por eso el registro contiene **29 espacios de vinculación** (SSH 8, FTP 10, SMB 11). Cada espacio enlaza la familia/variante con precondiciones, referencias de parámetros materiales, soportes y limpieza. La distinción entre las variantes FTP TLS/control-datos, FTP lectura-escritura, SMB firma-cifrado y SMB lectura-escritura es obligatoria.

Para admitir posteriormente un perfil deben verificarse, de forma independiente y con autorización privada vigente: ruta absoluta del binario, huella SHA-256 y versión, vector tipado de argumentos sin shell, entorno explícitamente permitido sin herencia implícita, directorio de trabajo, auxiliares con huellas, identidad del caso, destino autorizado, límites finitos fijados por pilotaje, política de captura y constancia de limpieza. **Ninguno de estos valores está resuelto**. Todos figuran como `null`, no como comodín ni autorización. Los nombres de herramientas o comandos específicos tampoco se infieren de una familia.

En particular, este incremento no establece `argv` concretos, no comprueba ejecutables ni los ejecuta. No puede producir `std::process::Command`, abrir conexiones, consultar credenciales, despachar procesos ni registrar resultados experimentales. Un `preview` puramente en memoria solo devuelve `BLOCKED_UNBOUND_NO_EXECUTION` y las dependencias pendientes, nunca una invocación. Cualquier `ND`/`FALSO` impide habilitación; no hay reintentos ocultos, sustitución automática de parámetros, búsqueda por PATH, herencia del entorno ni ejecución mediante `sh -c` o `bash -c`.

**Continuidad de P8:** fijar cada programa real compatible con el laboratorio, versión, rutas, argumentos tipados y opciones, definiendo artefactos de autorización privados y pruebas de denegación; el presupuesto temporal y de recursos deberá calibrarse en piloto. Solo después de acreditar aislamiento, integridad, permisos efectivos y límites podrán evaluarse perfiles para despacho por el supervisor Rust del punto 9. La prueba documental no constituye aceptación funcional ni autorización.

Para verificar: `python3 lab/verify_execution_profiles.py`. Para pruebas: `python3 -m unittest discover -s lab/tests -p test_execution_profiles.py -v`.

## English

P8 R1 provides **29 unbound, non-executable profile slots** derived from the 25 P7 families and four variant splits. No binaries, argument vectors, helper executables, environments, protected credentials, cases, numeric budgets or real authorizations have been pinned. The read-only validator and synthetic negative oracles prevent premature promotion of these slots. System functional acceptance and experimental validation are not claimed.
