# P8-R9 — Inventario material del runner / Runner material inventory

## Español — alcance y procedencia

**Punto del roadmap: 8, Definir perfiles de ejecución autorizados.** Este incremento no
implementa A1–A10, no inicia P9 y no instala herramientas, procesos o redes.
La base de código es el merge P8-R8 `9bb8e06c5d007cac82a102a97a87ab909bb35d7b`.
Secciones de tesis: 3.7.5 y 3.9.2. La imagen analizada es el runner de desarrollo,
no un destino real ni una instancia activa.

`inventory.json` recoge **observaciones reportadas por el operador**, obtenidas con
`qemu-img`, `virt-cat` y `guestfish --ro`: imagen QCOW2 24 GiB virtuales,
SHA-256 `fc9244fe...bf2103`, 15 archivos regulares en `/usr/bin`, ninguna ruta
enlazada en el conjunto consultado y `/usr/bin/sshpass` ausente. Los cuatro paquetes
contrastados son openssh-client, curl, smbclient y python3. Los cuatro hashes
individuales ya observados permanecen idénticos; para los otros once no se inventan
tamaños, paquetes propietarios ni rutas auxiliares. Las versiones de paquetes son
observaciones de `dpkg status`, **no** una prueba de origen confiable de cada binario.

`compatibility.json` contiene 29 **candidatos por protocolo**, no equivalencia funcional
comprobada para 29 operaciones. SSH se referencia a `/usr/bin/ssh`, FTP/FTPS a
`/usr/bin/curl` y SMB a `/usr/bin/smbclient`; se exige una revisión de opciones,
operaciones permitidas, soportes y limpieza por **familia y variante**. SSH-T03 exige
investigar su mecanismo de autenticación sin `sshpass`. Los perfiles que escriben
marcadores requieren limpieza independiente. Ningún `argv`, entorno, auxiliar,
autorización, cuenta, destino, caso o presupuesto de piloto ha sido fijado.

**Verificación:** `python3 lab/verify_p8_material_inventory.py` contrasta los JSON
con P6, P7, P8 y hashes congelados de las fuentes, sin tocar VM o ejecutables.
`python3 lab/verify_p8_material_inventory.py --offline-image` repite por lectura
la observación QCOW2 original; requiere `sudo -v` previo para que `sudo -n`
solo eleve `stat`, `sha256sum`, `qemu-img`, `virt-cat` y `guestfish`. Nunca ejecutar
**el Python del repositorio con sudo**. El inspector no inicia el guest ni clientes.

**Límites:** la huella de la imagen acredita los bytes observados en ese corte, no
la selección futura de un ejecutable por el supervisor ni su custodia material.
Faltan validación de origen independiente, autoridad y revocación privadas,
resolución de los casos P6, argumentos tipados efectivos, entorno, dependencias,
permisos efectivos, límites piloto, monitorización de recursos y control TOCTOU.
AL-06/AL-07 y las siete obligaciones residuales siguen abiertos. Los 29 perfiles
continúan `BLOCKED_UNBOUND_NO_EXECUTION`; cero autorización y cero despacho.

## English — boundaries

P8-R9 records **operator-reported read-only QCOW2 observations** and maps the 29
existing blocked profile slots to *protocol-level candidate binaries only*. Each
binary digest is a point-in-time observation, not a trusted live executable pin.
No verified per-family arguments, real case authority, pilot budget, tool coverage,
revocation, process supervision, dispatch, experiment, or A1–A10 implementation is
claimed. `--offline-image` rechecks the original image without running any guest
binary and requires explicit sudo credentials for fixed read-only utilities only.
