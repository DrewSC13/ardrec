# ARDREC R125 — Integración verificable de FTP-T01 y cobertura planificada de 54 unidades

**Base contractual:** `main=2db609afcd6fcdd0148179713aad9d5baa14516c` (PR #208). **Modalidad del paquete:** `SOURCE_ONLY`, sin apertura de red, arranque de VM, cambios en nftables, habilitación P8, falsificación A6, publicación A9 ni consumo de intentos. El paquete debe recibir un PR firmado y pasar los checks obligatorios antes de incorporarse a `main`.

## Resultado implementado

`r125_integrated_acceptance.py` compone y verifica **las fuentes ya existentes**, sin reemplazarlas: F5 y F16 vía R122, F13/F14 y A7/A8 vía R121 cuando se selecciona un caso, contrato del supervisión temporal R123 y observación **real** del guardián raíz R116-F1 mediante R124. La CLI revalida el HEAD instalado y el catálogo P7 fijado. Genera una cadena SHA-256 ordenada de once puertas de aceptación, un estado final conservador A5→A10, bloqueos explícitos y un informe A10 privado recuperable con relectura de F5/F13. No utiliza `DurableStore` como archivo de auditoría temporal.

El verificador de trazas monotónicas ejecuta `r123.guard_model` y rechaza retrocesos de tiempo, intervalos incompatibles, permisos de tráfico falsificados, conexiones o arranques. **Toda traza no autenticada sigue siendo MODEL_ONLY**; nunca se transforma en comprobación física de cierre. Una lectura R124 exitosa, un temporizador R34 activo o un timer de sesión presente tampoco acreditan por sí solos un cierre dentro de 60 segundos.

`coverage(catalog_raw)` valida el catálogo SHA-256 P7 y presenta **54 posiciones de planificación** (18 SSH, 18 FTP, 18 SMB) asociadas a la cobertura de **25 familias** (8/8/9), con `case_id`, `scenario_id`, `family_id`, intentos, soportes, riesgo y generación A9 en `null`. Estas posiciones son ranuras contables, **NO unidades experimentales seleccionadas** ni evidencia de 54 ejecuciones. El estado de P7 es `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE` y el número de casos derivados reales es cero, conforme al catálogo.

## Alcance necesario para terminar la implementación, SIN confundirlo con R125 aceptado

| # | Entregable verificable de la ruta funcional | Prueba objetiva de cierre | Estado tras este parche |
|---|---|---|---|
| 1 | Autoridad independiente vigente, firma y revocación por caso FTP-T01, una sola sesión | Validación criptográfica desde fuentes raíz independientes; frescura, vigencia, alcance, unicidad y revocación; nunca aprobación autogenerada | **PENDIENTE** |
| 2 | Guardia R116-F1 y temporizador de sesión autónomo armado antes de cualquier despacho | Topología física 5 DENY / 1 OFF y `systemd` unit única vinculada al intento | **PENDIENTE** |
| 3 | Restauración DENY tras caída del ejecutor en plazo máximo 60 s | Recibo autenticado independiente, reloj monotónico del mismo boot, `t_restore_end−t_window_start ≤ 60 s`, lectura final nft/libvirt | **PENDIENTE** |
| 4 | Cadena de recibos de la sesión con marca de boot, identidad, hash y tiempo | Anti-replay, comprobación de origen raíz, `fsync`, manifest con hashes, cotejo con temporizador y guardián | **PENDIENTE** |
| 5 | Cortar el despacho cuando cualquier guarda falla | Inyección de faltas: firma inválida, revocación, timeout, VM inesperada, 6.º enlace, pérdida del guardián | **Contrato de rechazo probado; falta ciclo físico** |
| 6 | Supervisor raíz independiente instalado y probado | Servicio raíz dedicado, sin dependencia del ejecutor, recuperación ante SIGKILL; revisiones de arranque y cierre | **Guardián DENY R116 instalado, ciclo físico no probado** |
| 7 | Estado reciente A3/F11/R34, definición de VM y topología 5/1 | Lectura fresca F5/F16/R124 antes y después de ventana, sin confundir R34 periódico con sesión | **Lectura y conciliación integradas; 5/1 no acreditado** |
| 8 | Autoridad P8 operacional actual y revocación independiente | Doble control separado y permisos por sesión, no reutilizar aprobaciones F5B/R118 fuente | **PENDIENTE** |
| 9 | Un intento real FTP-T01 con presupuesto, límites y limpieza | F13 reserva antes de conexión, F12 límites fijados, recibo del ejecutor, origen independiente del socket | **PENDIENTE** |
| 10 | A5→A6→A7→A8→A9→A10 autoritativo | Soportes admitidos independiente A6, `Rf` calculado sin forzar ND, estados válidos, transacción DurableStore y recuperación | **Revisión matemática/auditoría conectada, admisión/publicación pendiente** |
| 11 | SSH/SMB y 54 unidades experimentales | Escenarios reales identificados, P7 calibrado/congelado después del piloto, pruebas por familia y 54 observaciones reales con recibos | **Matriz de cobertura implementada; 0 reales asignados** |

## Secuencia física que deberá ser ejecutada en Prometheus por operadores autorizados

1. Congelar el HEAD específico, instalaciones y contrato del intento. Verificar autoridad externa y revocación vigentes; los comprobantes antiguos de instalación sirven **solo** como trazabilidad.
2. Verificar F11/R34, host/VM, arranque F7/F8 y red aislada 5/1. El SSH, runner y FTP deben figurar `RUNNING`, SMB `OFF`, cinco enlaces DENY y uno ausente. La captura anterior 0/6 no es prueba 5/1.
3. **Antes** de cualquier acceso a FTP, armar y acreditar la unidad `systemd` de restauración DENY autónoma, y vincular la unidad al intento y al límite temporal. Un timer cuya mera propiedad `ActiveState=active` no pruebe su vencimiento no es suficiente.
4. Probar cierre autónomo con fallo acotado del ejecutor, en un procedimiento aislado y autorizado. Registrar los tiempos y el resultado efectivamente observado por un testigo independiente. Sin esa prueba, no habilitar una ventana de tráfico.
5. Ejecutar FTP-T01 con **una sola reserva F13 y un solo intento preaprobado**, sobre destino y puerto anclados por A3; no asumir que recibir `220` implica verdad técnica A6.
6. Conciliar A5 con soportes independientes y clasificación A6, calcular A7 con racionales exactos, decidir A8, publicar A9 sólo bajo transacción autorizada de `DurableStore`, y recuperar la misma generación A10. Si la evidencia no basta, conservar `ND` y la no publicación cuando así lo exijan las guardas.
7. Tras aceptar el piloto, calibrar límites y congelar el catálogo P7 mediante su propia autoridad; entonces asignar escenarios y las 54 unidades, ejecutar las 25 familias compatibles y comprobar 18 registros reales por protocolo, sin asumir correspondencia 1:1 entre familia y unidad.

**Condición final de aceptación de todo ARDREC:** 25 familias descritas y verificadas, 54 unidades realmente admitidas o justificadas según diseño experimental, A1–A10 instrumentado de extremo a extremo, registro durable transaccional, recuperación y determinismo auditados, aislamiento físico acreditado, firma/revocación sin reuso y CI Python/Rust PASS. Ninguna de estas pruebas físicas se puede sustituir por un resultado sintético.

## Uso en terminal Zsh

Desde `/home/cicada/Development/GitHub/ardrec`, con el usuario `cicada` (nunca ejecutar todo el CLI como root):

```shell
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r125_integrated_acceptance.py --capabilities | more
sudo -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r125_integrated_acceptance.py --inspect \
  --head "$(git rev-parse HEAD)" \
  --capture /home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1/capture-xgwi5e2_ \
  --save | more
sudo -k
```

`--save` escribe exclusivamente una copia privada A10 sin autoridad y añade comprobación inmediata de replay de las fuentes. La captura F5 histórica mantiene su bloqueo de frescura. Para verificar un recibo R125 guardado, utilice `--verify-audit /ruta/absoluta/audit-...`. Es un análisis de preparación, no una autorización operacional.

## Garantías y límites

- No se utilizan comandos de tráfico, arranque, apertura de puertos ni modificación de permisos desde este incremento.
- P8 se mantiene en `NO-GO`; ningún estado es promovido por hashes sin autoridad.
- R116-F1 sigue anclado al SHA-256 instalado. No reinstalarlo ni armar su reserva única desde el CLI de R125.
- R34 periódico activo no sustituye un temporizador de sesión de 45 s ni prueba restauración dentro de 60 s.
- Una traza R123 de reloj monotónico solo prueba propiedades algebraicas, no procedencia física: el testigo raíz independiente debe quedar implementado, instalado y acreditado en una intervención específica.
- La conexión de A6/A9 que aún está pendiente es una **brecha real**, no un resultado implícito de haber ejecutado tests Python y Rust.
