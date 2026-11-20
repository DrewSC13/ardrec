# ARDREC — R116-F2. Autorización vigente y preflight físico FTP-T01 (sin despacho)

## Alcance y defecto corregido

R116-F1 terminó con HEAD `f2a18f75250bb266f740e2a117fa36529121a1cf` (firma G; 1.378 tests). El recuperador raíz 5/1 de F1 todavía no ha sido instalado, armado ni ensayado físicamente. Las VM SSH, runner, FTP y SMB permanecían apagadas durante la última inspección R115-F16. No es correcto dar por acreditado un piloto o liberar P8.

**Hallazgo de integración:** `r115_f6_signed_scope_and_activation.scope` exige el commit histórico `a652195a544a549dbad6a44120e3d447cf4d4994`, mientras `r115_f15_p7_independent_pilot.request` exige que `contract.source_commit == head` actual. Con una rama R116 real estas obligaciones son incompatibles. R116-F2 **no modifica** los artefactos históricos protegidos por F17: aporta un revisor de alcance versionado, vuelve a verificar la firma Ed25519 y la revocación mediante las raíces de confianza del operador en `/etc/ardrec`, valida el HEAD presente en el contrato y conecta el resultado con el revisor firmado F15 mediante `scope_reviewer`.

## Archivos

- `src/ardrec/coordination/r116_f2_current_pilot_gate.py`: `current_scope_review`, `signed_pilot`, comprobador de F1 5/1, y preflight acumulativo físico/F8/F15.
- `scripts/ardrec_p14_r116_f2_current_pilot_gate.py`: solo `--capabilities` o `--inspect-current` de lectura. La segunda requiere cinco rutas absolutas explícitas (contrato, autorización de alcance, piloto firmado, plan F8 y arranque F8) y el recuperador F1 instalado expresamente con su `--check`. No instala nada, no solicita aprobación y no ejecuta tráfico. Los documentos son leídos con las utilidades privadas R115; los anclajes de confianza usan rutas ROOT fijas.
- `lab/tests/test_p14_r116_f2_current_pilot_gate.py`: 40 regresiones, incluidas firmas Ed25519 genuinas (solo test), revocaciones, vigencias y topología 5/1.
- `.github/workflows/ci.yml`: R116-F2 añadido a Python, con recuento estricto.

## Contratos de seguridad

1. Cuatro documentos de confianza/estado firmados y anclados externamente (alcance y revocación, piloto y revocación), sin generar claves de autoridad ni autoaprobarse.
2. Vigencia y revocaciones frescas; el contrato tiene que vincular el HEAD de caso real. El catálogo debe permanecer con su SHA-256 de P7 DRAFT exacto; solo FTP-T01, destino fijo `10.203.31.2:21`.
3. Estado físico SSH+runner+FTP en RUNNING y SMB OFF; los cinco bindings DENY originales presentes (incluido `runner_smb`) y SMB ausente por ciclo de vida; NFT/F11 R34 MATCH.
4. Verificación de la cadena de arranque F7/F8 y recibo de F1 `--check`, cuya salida no se trata como firma independiente. El preflight es un *instante de lectura*, no una capacidad transferible ni una apertura permitida.
5. El controlador raíz pendiente debe **reverificar independientemente** política, firmantes, revocación, tiempo y topología, crear reserva durable antes de cualquier operación, armar y comprobar watchdog autónomo, aplicar una ventana no mayor de 60 s y restaurar DENY antes/después incluso ante fallos. F2 no contiene ese despacho: no puede sustituirse por su reporte.
6. Sin `sudo` en la instalación, sin arranques, sin escrituras nftables, sin sockets, sin P7 mutación, sin autorización P8, sin promover A5→A6 ni generaciones A9.

## Estado y continuidad

Resultado de fuente esperado: R116-F2 40 PASS; R116-F1 35 PASS; R115 440 PASS; R114 250 PASS; R113 350 PASS; R112 303 PASS = **1.418** pruebas sin omisiones. Es un cierre de código y preflight, no una atestación real de resultados físicos.

**Siguiente entrega:** integrar en un controlador raíz autónomo la verificación de autorización reciente bajo un entorno aislado de confianza, la reserva de intento físico, transición FTP acotada, lector/ejecutor runner y restauración DENY. Luego medir/calibrar el piloto real solo con aprobación externa específica y pruebas destructivas de seguridad controladas.
