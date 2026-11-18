# ARDREC R72-F4 — auditoría F11-P compatible con el drop-in observado (solo lectura)

**Base de fuente:** `main` R71 `705ed30e32bd7a6a15e1ff3c28cd5b18da39eaa4`. **No se despliega código ni configuración privilegiada.** Este incremento corrige una incompatibilidad estrictamente documental/de auditoría: R58-A prohibía todos los drop-ins de `ardrec-r34-boot-deny.service`, mientras el host Prometheus, según R72-F3 del operador, tiene exactamente un drop-in de serialización que sustituye `ExecStart` por `flock`.

## Datos observados, separados de las pruebas

- Fuente: `systemctl cat ardrec-r34-boot-deny.service`, `systemctl show`, `stat`, `sha256sum` proporcionados por el operador el 17/18 de noviembre de 2026.
- Ruta: `/etc/systemd/system/ardrec-r34-boot-deny.service.d/90-ardrec-r34-serialized.conf`.
- SHA-256 del archivo **observado externamente**: `39c4c472481428328decc3ffd3a44e98d49077bcd2166f9f4ad08105d95c3634`.
- Metadatos informados: `root:root`, `0644`, enlace físico único; otra sección `[Service]` agrega `ExecStart=` y exactamente `/usr/bin/flock --exclusive --timeout 30 /var/lib/ardrec/r58a-r34-boot /usr/bin/python3 -I -B /var/lib/ardrec/r58a-r34-boot/boot-guard.py`.
- `systemctl show` informó `NeedDaemonReload=no`, `active/exited`, una invocación satisfactoria, y `libvirtd` incluye `Requires=` y `After=` respecto del servicio R34.
- Un comentario dentro del archivo afirma `CANDIDATE ONLY, NOT INSTALLED`; la presencia efectiva y `DropInPaths` contradicen el comentario de fase. **No se conoce una fuente Git versionada que autentique el historial de instalación de ese archivo.** Su hash solo identifica los bytes que el operador observó; no acredita procedencia ni aprobación humana.
- El contrato antiguo R58-A y sus tests de rechazo de drop-ins desconocidos quedan conservados.

## Cambio permitido en el auditor

1. R58-A admite su unidad original **sin drop-in** exactamente como antes, para no romper las pruebas históricas y CI.
2. Si `systemctl cat` contiene el único encabezado del drop-in R72-F3, el auditor lee el archivo local sin privilegios ni escritura, con `O_NOFOLLOW`, verifica ruta, padres sin enlaces simbólicos, propietario/grupo root, modo 0644, un enlace físico, tamaño limitado, identidad estable y SHA-256 exacto.
3. Solo admite un fragmento de texto idéntico al archivo leído, con un único bloque `[Service]`, borrado `ExecStart=` y la línea nueva con `flock` exacta. Mantiene las directivas base obligatorias, sin permisividad general para otros drop-ins, rutas, argumentos o `ExecStartPre`.
4. La afirmación de salida `boot_unit_source_contract=PINNED_SERIALIZED_DROPIN_READONLY` significa **estructura autenticada respecto del hash observado**, NO certificación externa o habilitación de una VM. Siempre `first_boot_attested=false`, `manual_vm_boot_block_attested=false`, `independent_runtime_watchdog_attested=false`, `host_mutations=0`, `P8=NO-GO`.
5. R58-C reutiliza esta función, puede pasar a inventario de host si todas las demás lecturas y reglas continúan correctas, pero mantiene `decision=BLOCKED_SEPARATE_PHYSICAL_AUTHORIZATION_REQUIRED`, no instala F11, no reinicia `libvirtd` ni habilita ejecución.

## Cobertura y límites

Las nuevas pruebas rechazan reemplazo por SHA diferente, rehash de `ExecStart` modificado, unidades base con drift, fragmentos duplicados, add-ons no autorizados y alteraciones de permisos de rol. También conservan el rechazo legado y el significado `NO-GO` de F11. La suite no puede certificar una lectura efectiva del host: Prometheus debe ejecutar el auditor con permisos de lectura apropiados, sin `sudo` aplicado al proceso completo.

La protección del primer arranque, hook de bloqueo manual, watchdog independiente, prueba negativa física, ejecución A5 y riesgo final A7 permanecen pendientes. No se debe cambiar catálogos P7/P8 ni poner `execution_enabled=true` por esta corrección.

### Comprobación manual desde repositorio principal

```text
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r72_f11_serialized_pin.py' -v
python3 -B scripts/ardrec_p14_r58a_f11p_boot_readiness.py --host-readonly
python3 -B scripts/ardrec_p14_r58c_f11_deployment_plan.py --host-readonly
```

La segunda llamada puede devolver código 22 con lectura válida pero bloqueo operacional. La tercera puede devolver 21 con inventario válido y `P8=NO-GO`. Cualquier 23 requiere revisión y NO desbloquea instalaciones.

## R72-F4.1 — propagación comprobada del pin desde `host_readonly`

La comprobación aislada de la unidad con el drop-in exacto R72-F3 devolvía
`PINNED_SERIALIZED_DROPIN_READONLY`, pero el `host_readonly` original de R72-F4
no transmitía `serialized_raw` al `assess`; por ello el auditor completo devolvía
`UNIT_OR_DROPIN_DRIFT` pese a autenticar previamente el archivo y el `ExecStart`
efectivo. Se corrige únicamente el argumento olvidado y se agrega el test 25
que ejecuta la ruta host completa con fuentes exclusivamente simuladas. Este
test reproduce el fallo en la versión anterior y lo resuelve con la versión
corregida. No se altera el PIN original, el `sudo -n`, el mapa de comandos
permitidos, la configuración instalada ni las condiciones NO-GO.
