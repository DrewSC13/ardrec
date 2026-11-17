# ARDREC P14 / R59-F — Identidad A5 v2 con variante desde su origen

**Nuevo contrato funcional, no migración retroactiva.** R59-F registra `variant` en el intento v2 *antes* de declarar un resultado. El identificador de familia, caso derivado, ventana de evaluación, sesión, intento, configuración, método y variante quedan integrados en la huella del mismo intento. Las cuatro familias con variantes explícitas son FTP-T02, FTP-T08, SMB-T03 y SMB-T09; los 25 identificadores y los requisitos concretos se validan usando **P7 fijado por SHA-256** y los módulos existentes R58-H/I/J a través de R59-E.

La proyección v2→v1 R59-D y el puente v1→A6 R59-E son **compatibilidad documental**: los registros v1 no se reescriben ni convierten falsamente en registros v2. En R59-E se mantiene `variant_in_original_a5_intent=false` porque el origen *proyectado v1* no incluye variante. En el nuevo origen v2 sí se conserva explícitamente `variant_bound_at_origin=true`. Ninguna de las dos afirmaciones atribuye autoridad física a un recibo.

## Persistencia y replay

- Tres directorios privados distintos, propiedad del operador, modo 0700: intención v2, candidatos v1 y puentes A6.
- Informe v2 inmutable por `attempt_id` dentro de su registro privado, escrito con `O_EXCL`, modo 0600, fsync e inspección de vuelta. Reutilizar el mismo identificador con otro caso, variante, configuración o resultado se rechaza antes de modificar cualquier fuente.
- El resultado v2 solo puede representar un inicio **declarado**, nunca acreditado. `NO_START` carece de tiempos y soportes. Si hay soporte, se comprueban tipo, tamaño y SHA-256 al persistir y reabrir a través de R59-D. R59-E evalúa requisitos P7 exclusivamente como revisión no acreditada.
- La operación es idempotente por reconstrucción. No es transacción atómica entre los tres directorios: un fallo de proceso tras persistir v1 o A6 y antes de v2 puede dejar fuentes hijas verificables; la repetición idéntica permite terminar. Nunca se descartan fuentes por reparación automática.
- Se comprueban de nuevo P7, requisitos de familia, fuentes v1 y puente A6 al reabrir. Alteraciones, permisos incompatibles, variantes erróneas, cambios de soporte y falsos permisos se rechazan.
- SHA-256 y permisos del propietario aportan integridad local y detección de conflictos; **no constituyen firma externa ni prueba de autenticidad independiente**. El propietario con control total de todas las fuentes podría sustituir íntegramente una historia sin un anclaje externo.

## Seguridad y límites científicos

R59-F **no contiene** despachador, tráfico, acciones de guest o inicio de VM. No instala F11, no cambia nftables, libvirt, systemd, Git ni la TUI R38/R42.5. `A5` físico no acreditado; `A6=ND`, `Rf` no confirmado, transición A8 no aplicada, generación A9 no publicada, `P8=NO-GO`. Los ejemplos de todos los 25 tipos y 29 selecciones de variante son sintéticos y NO validan experimentalmente la hipótesis.

## Uso en Prometheus (con directorios privados preexistentes)

```bash
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59f_variant_origin.py --catalogue-check
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59f_variant_origin.py --demo-no-start --v2-root /home/cicada/ardrec-lab/r59f/v2 --a5-root /home/cicada/ardrec-lab/r59f/a5 --a6-root /home/cicada/ardrec-lab/r59f/a6
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59f_variant_origin.py --verify --v2-root /home/cicada/ardrec-lab/r59f/v2 --a5-root /home/cicada/ardrec-lab/r59f/a5 --a6-root /home/cicada/ardrec-lab/r59f/a6
```
