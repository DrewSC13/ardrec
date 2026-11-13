# P14-R21 — Ensamblaje determinista del contrato sintético inicial A2

**Base inmutable:** `aec09553415d01f152d37ed85424cd659fada33a` (PR #86).
**Alcance:** únicamente síntesis local de R17–R20. No se afirma cierre de A1/A2/A3.

## Función verificable

R16 implementó el núcleo de reglas de tres valores. R17 congeló reglas y
servicios; R18 congeló los riesgos racionales y contadores iniciales;
R19 verificó las dependencias caso-locales; R20 verificó referencias de
controles a reglas y casos del servicio. R21 **une los cuatro resultados**
mediante un contrato de solo lectura. No agrega un segundo evaluador A1,
no ejecuta controles A3 y no introduce un proveedor operativo.

Cada servicio del documento R21 declara el protocolo, `PREPARADO`, `R0`,
criticidad normalizada, evidencia inicial `0`, `Rf=R0`, orden estable de casos,
orden estable de controles, presupuestos iniciales, referencias de
prerrequisitos y los controles declarativos que apuntan a cada caso. El orden
de controles **no** es una agenda autorizada. Se permiten casos sin controles,
que quedan reflejados como referencias vacías (sin permiso implícito).

El documento canónico tiene SHA-256 propio y conserva las huellas exactas de
R17, R18, R19 y R20. `verify` vuelve a comprobar recursivamente las fuentes,
reconstruye el documento desde ellas y compara los bytes y registros en memoria.
No basta cambiar un SHA y volver a serializar para falsificar contenido.

## Límites y exclusiones

- Máximo **64 servicios** derivado del preflight anterior y 262.144 bytes de
  contrato serializado. No se incorporan comandos, credenciales ni perfiles
  de ataque al contrato.
- Las fuentes de origen deben ser de tipos exactos; contenido o huellas
  alterados se rechazan antes del ensamblaje.
- Todos los casos y controles se vinculan al mismo servicio. Las dependencias
  y referencias deben haber pasado las validaciones R17–R20.
- El SHA-256 demuestra integridad del contenido, no autenticidad externa,
  autoridad de A3, aceptación de P8 ni publicación durable A9.
- No se publican generaciones ni se modifica el estado de origen. La
  interpretación operacional continúa **DENY-ALL / NO-GO**.

## Evidencia y pruebas

- `lab/tests/test_p14_r21_a2_integrated_preview.py`: pruebas positivas,
  permutaciones, oráculos de fuente corrupta, serialización no canónica,
  mutación en memoria, rebinding de fuentes y ausencia de autoridad.
- `scripts/demo_p14_r21_a2_integrated_preview.py`: **54 unidades sintéticas**
  (18 SSH / 18 FTP / 18 SMB), 108 casos y 108 controles de referencia.
- CI incorpora únicamente las pruebas del contrato y la demostración. No
  ejecuta servicios SSH, FTP, SMB, systemd ni escenarios experimentales reales.

## Pendiente

`A1_FULL=NOT_CLOSED`, `A2_FULL=NOT_CLOSED`, `A3_FULL=NOT_CLOSED`,
`P8_OPERATIONAL=NO-GO`, `EXPERIMENTAL_VALIDATION=NOT_RUN`.

Siguen pendientes: semántica completa de configuración de la tesis A2,
contratos de capacidad, dependencias interservicio, autoridad y consumo A3,
publicación de generación A9, integración A1–A10 y las 54 observaciones físicas.
