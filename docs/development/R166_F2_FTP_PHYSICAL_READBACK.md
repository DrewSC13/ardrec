# R166-F2 — Diagnóstico R119 de las precondiciones físicas FTP

**Contexto:** el recibo R166-F1 de Prometheus del 23/11/2026 confirmó el paquete, la ruta documental CLI y 74/74 pruebas, pero la captura R119 tuvo cuatro estados de VM en `ND`, F11/R34 `ND/ND/ND` y `P8=NO-GO`. `R119_CAPTURE_EXIT=0` acredita la operación de captura, **no** el éxito de cada `sudo -n virsh` ni `nft`.

## Implementación

No se introduce un segundo capturador ni un controlador que duplique R115/R119. La entrada normal existente `python -m ardrec live` incorpora la opción **`--diagnostico`**, disponible con `--capturar --texto` y `--reproducir RECIBO_F5 --texto`.

La salida se deriva exclusivamente de los resultados ya capturados por el catálogo cerrado de sondas R115-F5. La función `diagnostic_lines` reevalúa estrictamente el informe con `f5.report(capture)` y rechaza un informe sustituido. No ejecuta nuevas órdenes, no presenta stdout/stderr de sondas y no registra cambios físicos. Cada sonda emite `RC_0`, `RC_N`, `TIMEOUT`, `OUTPUT_TRUNCATED` o `COMMAND_UNAVAILABLE` sin atribuir una causa que los originales no acrediten. Los originales siguen privados dentro de R115-F5.

El informe de FTP 5/1 se marca `FIVE_DENY_ONE_ABSENT_READBACK_ONLY` solamente si la captura verifica simultáneamente:

- VM `runner`, `ssh` y `ftp` en `RUNNING`; `smb` en `OFF`.
- Las cuatro definiciones de VM coinciden con el catálogo R115.
- `nft`, helper de recuperación y hook F11 verificados (`MATCH`).
- Cinco vínculos DENY verificados **individualmente**, incluidos los tres de Runner y los de SSH y FTP; la interfaz de SMB está `ABSENT_WHILE_OFF`.

Un resultado favorable solo constata la **topología DENY observada en la captura**. No acredita vigencia de autorizaciones, independencia A6, restauración autónoma menor o igual a 60 segundos, apertura de tráfico, ni publicación A9. La salida conserva `R166_F2_P8=NO-GO`, `R166_F2_A3_AUTHORIZED=NO`, `R166_F2_A6_PHYSICAL_ADMITTED=NO`, `R166_F2_A9_PUBLISHED=NO`.

## Procedimiento en Prometheus

1. Antes de la instalación o liberación, ejecutar `python -m ardrec live --capturar --texto --diagnostico --repo ...` sin root; preservar la carpeta `R119_CAPTURE_ROOT` y el SHA mostrado. Se usa el mismo capturador R115-F5 que ya pasó en R166-F1.
2. Si las sondas reportan `RC_N`, inspeccionar los permisos **de lectura** y la política `sudo -n` para `virsh`, `nft` y lecturas SHA previstas. No atribuir `RC_1` automáticamente a `sudo`: puede ser falta de una VM o comando de libvirt; la causa exacta requiere revisión privada del original.
3. Antes de utilizar un agente privilegiado R163, cotejar inventario original firmado, commit, hashes y fuentes realmente instaladas. El código de `scripts/ardrec_p14_r163_v3_root_stage_agent.py` está marcado `SOURCE_CANDIDATE`, no implica instalación. Solo la **instalación externa root** permite `--preflight` de `/opt/ardrec/r163-installer-v1/installer.py` con Python aislado y autoridad vigente. Nunca interpretar `--capabilities` como aprobación.
4. Los resultados actuales 5/1 no autorizan arranque de invitadas ni cambios de filtros. Hasta que un procedimiento físico autorizado produzca los estados requeridos, registrar `NOT_ESTABLISHED` como resultado correcto.
5. Cuando se hayan acreditado R163, la restauración autónoma y P8, repetir la captura actual antes y después del piloto FTP-T01. La recepción FTP de 220 solo acredita la respuesta de control observada; el soporte físico y la rúbrica independiente siguen sujetos al protocolo de la tesis.

## Trazabilidad de las pruebas

- `test_p14_r166_f2_physical_readback.py`: 10 pruebas de la proyección diagnóstica, sin máquinas ni tráfico.
- `test_p14_r119_live_readonly.py`: 28 pruebas preexistentes de captura/replay y vista de los diez bloques, sin tráfico.
- `test_p14_r166_f1_case_archive_cli.py`: 13 pruebas previas de manifiesto, archivo y relectura.
- El experimento definitivo permanece en **0/54 observaciones admitidas** hasta contar con soportes originales y congelamiento de I1–I8.

## Mapa requisito–función–salida–prueba

| Requisito | Fuente reutilizada | Función modificada/nueva | Salida | Prueba |
|---|---|---|---|---|
| Identificar fallo de sonda | R115-F5 `capture`, `report` | `r119.diagnostic_lines` | `R166_F2_PROBE_*`, `FAILED_PROBES` | F2 1, 2, 8, 9, 10 |
| Reconocer FTP 5/1 | `r115_f5_lifecycle_readiness`, `r113_f6_six_binding_guard` | `r119.ftp_phase_deny_readback` | `FIVE_DENY_ONE_ABSENT_READBACK_ONLY` o `NOT_ESTABLISHED` | F2 3–7 |
| CLI sin nuevas sondas | `ardrec.__main__.main` y `r119.main` | parámetro `--diagnostico` | líneas de lectura de captura o replay | R119 22, 26; F2 9 |
| Conservar NO-GO | A3/A6/A9 según R119 y R163 | constantes explícitas | `P8=NO-GO`, A6 no admitida, A9 no publicada | F2 1, 3, 8, 9 |

**Se requiere captura nueva de Prometheus para aceptar una afirmación física:** fuente, fecha UTC, manifiesto/recibo R115-F5, hashes, códigos por sonda, número de vinculaciones verificadas, guardas actuales P8 y recibos R163. Los ficheros crudos no se publican ni se adjuntan a GitHub.
