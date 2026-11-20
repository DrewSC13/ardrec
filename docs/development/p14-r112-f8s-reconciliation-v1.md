# ARDREC R112-F8S — Reconciliación histórica del arranque SSH

**Base exacta:** `b39dac34e9b7af9134d72373c3a9076208293dba` en `feat/p14-r111-r114-real-lab`.

## Finalidad

Reexaminar el intento físico F8 existente `boot-bgtqj5r2` mediante las funciones vigentes de clasificación de ARDREC, el inventario F11/R34 y la normalización estricta R112-F8R, sin repetir `virsh start`, ni tocar los recibos originales, redes, filtros, leases o VM. Producir un nuevo recibo privado, enlazado mediante hashes con los archivos históricos, **solo si** se verifican sus contratos.

## Restricciones

- No valida el protocolo SSH ni habilita tráfico; `P8=NO-GO` permanece invariable.
- No valida A5–A10 en una observación física.
- El plan F8 contiene la huella de procedencia del resultado físico negativo F7; este comando **no reproduce de manera independiente los recibos F7 originales**. El recibo lo declara explícitamente.
- Las pruebas unitarias se ejecutan con datos de referencia y no son evidencia de laboratorio.
- El resultado físico depende de ejecutar este parche en el anfitrión Prometheus. No se ejecuta desde el entorno donde se fabrica el ZIP.
- El recibo nuevo se escribe exclusivamente bajo `/home/cicada/ardrec-lab/r112-f8s-reconciliation-v1/`; nunca se modifica `plan-ld19q3ok`, `boot-bgtqj5r2` ni `/run/ardrec-f11-boot-v1`.

## Instalación y ejecución

El archivo ZIP contiene el payload de tres archivos versionables y un aplicador reproducible. Desde la raíz del repositorio, verificar la huella SHA-256 indicada externamente, extraer de modo seguro los miembros esperados a un directorio privado dentro de `ardrec-patches`, ejecutar `sudo -v`, y luego `python3 APPLY_R112_F8S.py` desde el directorio de staging. La aplicación comprueba HEAD, rama, estado limpio, SHA de origen y contenido, realiza pruebas R112 y luego reconcilia el incidente. Solo si todo aprueba crea el commit local firmado. No se hace push ni merge.

### Criterio de parada

Cualquier falta de autenticidad, cambio de archivo original, diferencia de aislamiento, estado físico no observado, prueba fallida o error de firma detiene el cierre. Si el programa se detiene, no reintentar a ciegas ni borrar el recibo parcial: conservar staging y el registro de ejecución.
